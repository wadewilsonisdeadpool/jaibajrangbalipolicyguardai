"""Real tool implementations. Only ever called by the ToolBroker after a
policy ALLOW or a human APPROVE. Each tool also enforces its own limits
(defence in depth): sandbox paths, per-chat scoping, SSRF protection,
least-privilege DB roles, email limits."""
import ipaddress
import logging
import re
import socket
import time
from typing import Any
from urllib.parse import urljoin, urlparse

import requests

from apps.api import documents
from apps.api.context import ExecutionContext
from apps.api.web_domains import classify_host
from apps.api.workspace import (
    OUTPUTS_DIR,
    READABLE_EXTENSIONS,
    WorkspaceError,
    check_chat_scope,
    relative,
    safe_path,
    unique_path,
)

MAX_WEB_CHARS = 5000
log = logging.getLogger("uvicorn.error")  # shows up in the uvicorn console


def _ok(tool: str, result: Any, **extra: Any) -> dict[str, Any]:
    return {"status": "success", "tool": tool, "result": result, **extra}


def _err(tool: str, message: str) -> dict[str, Any]:
    return {"status": "error", "tool": tool, "result": message}


class ToolExecutor:
    def execute(self, tool_name: str, arguments: dict[str, Any], ctx: ExecutionContext | None = None) -> dict[str, Any]:
        ctx = ctx or ExecutionContext(run_id="direct")
        handler = getattr(self, f"_tool_{tool_name}", None)
        if handler is None:
            return _err(tool_name, "Unknown or unsupported tool.")
        started = time.perf_counter()
        try:
            result = handler(arguments or {}, ctx)
        except (WorkspaceError, ValueError) as exc:
            result = _err(tool_name, str(exc))
        except Exception as exc:  # noqa: BLE001
            result = _err(tool_name, f"{type(exc).__name__}: {exc}")
        ms = (time.perf_counter() - started) * 1000
        log.info("[tool] %-16s %-8s %6.0f ms  %s", tool_name, result.get("status"), ms,
                 "" if result.get("status") == "success" else str(result.get("result"))[:160])
        return result

    # ---------------- files ----------------
    def _resolve_readable(self, path_arg: str, ctx: ExecutionContext):
        path = safe_path(path_arg)
        check_chat_scope(path, ctx.workspace_key)
        if not path.is_file():
            raise WorkspaceError(f"File not found: {path_arg}")
        if path.suffix.lower() not in READABLE_EXTENSIONS:
            raise WorkspaceError(f"Unsupported file type: {path.suffix}")
        return path

    def _record_file(self, ctx: ExecutionContext, path) -> dict[str, Any]:
        info = {"name": path.name, "path": relative(path), "size": path.stat().st_size}
        ctx.files_created.append(info)
        return info

    def _tool_file_reader(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        path = self._resolve_readable(str(args.get("path", "")), ctx)
        text, truncated = documents.read_text(path)
        return _ok("file_reader", text, path=relative(path), truncated=truncated)

    def _tool_create_document(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        target = unique_path(OUTPUTS_DIR / ctx.workspace_key, str(args.get("filename") or "document.md"))
        documents.create(target, str(args.get("content", "")))
        info = self._record_file(ctx, target)
        return _ok("create_document", f"Created {info['path']} ({info['size']} bytes).", file=info)

    def _tool_modify_file_copy(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        source = self._resolve_readable(str(args.get("source_path", "")), ctx)
        name = args.get("output_name") or f"{source.stem}_edited{source.suffix}"
        if not str(name).lower().endswith(source.suffix.lower()):
            name = f"{name}{source.suffix}"
        target = unique_path(OUTPUTS_DIR / ctx.workspace_key, str(name))
        changes = documents.modify_copy(source, target, args)
        info = self._record_file(ctx, target)
        return _ok("modify_file_copy", f"Original untouched. Edited copy saved as {info['path']}: {'; '.join(changes)}.",
                   file=info)

    # ---------------- network ----------------
    @staticmethod
    def _assert_public_host(host: str) -> None:
        try:
            infos = socket.getaddrinfo(host, None)
        except socket.gaierror:
            raise ValueError(f"Could not resolve {host}")
        for info in infos:
            ip = ipaddress.ip_address(info[4][0])
            if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast:
                raise ValueError("Refusing to fetch an internal/private network address (SSRF protection).")

    def _tool_web_fetch(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        url = str(args.get("url", "")).strip()
        for _ in range(4):  # follow up to 3 redirects, re-checking every hop
            parsed = urlparse(url)
            host = (parsed.hostname or "").lower()
            if parsed.scheme not in {"http", "https"} or not host:
                return _err("web_fetch", "Only http(s) URLs are supported.")
            if classify_host(host) == "blocked":
                return _err("web_fetch", f"{host} is on the blocklist.")
            self._assert_public_host(host)
            resp = requests.get(url, timeout=12, allow_redirects=False,
                                headers={"User-Agent": "Mozilla/5.0 (PolicyGuard-AI research agent)"})
            log.info("[api]  GET %s%s -> HTTP %s", host, parsed.path[:60], resp.status_code)
            if resp.is_redirect and resp.headers.get("location"):
                url = urljoin(url, resp.headers["location"])
                continue
            resp.raise_for_status()
            html = resp.text[:400_000]
            title = re.search(r"(?is)<title[^>]*>(.*?)</title>", html)
            html = re.sub(r"(?is)<(script|style|nav|footer|noscript|svg)\b.*?</\1>", " ", html)
            text = re.sub(r"\s+", " ", re.sub(r"(?s)<[^>]+>", " ", html)).strip()
            return _ok("web_fetch", text[:MAX_WEB_CHARS], url=url,
                       title=(title.group(1).strip() if title else None), truncated=len(text) > MAX_WEB_CHARS)
        return _err("web_fetch", "Too many redirects.")

    @staticmethod
    def _openweather(path: str, params: dict[str, Any]) -> Any:
        """Call OpenWeather without ever leaking the API key: request errors
        contain the full URL (including appid), so they are re-raised clean."""
        from apps.api.settings import OPENWEATHER_API_KEY
        if not OPENWEATHER_API_KEY:
            raise ValueError("OPENWEATHER_API_KEY is not set in apps/api/.env")
        try:
            resp = requests.get(f"https://api.openweathermap.org{path}",
                                params={**params, "appid": OPENWEATHER_API_KEY}, timeout=10)
        except requests.RequestException as exc:
            raise ValueError(f"OpenWeather unreachable ({exc.__class__.__name__})") from None
        log.info("[api]  GET api.openweathermap.org%s -> HTTP %s", path, resp.status_code)
        if resp.status_code == 401:
            raise ValueError("OpenWeather rejected the API key (new keys can take up to 2 hours to activate).")
        if resp.status_code == 429:
            raise ValueError("OpenWeather rate limit reached; try again shortly.")
        if not resp.ok:
            raise ValueError(f"OpenWeather error {resp.status_code}")
        return resp.json()

    def _tool_weather_lookup(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        from collections import Counter, defaultdict
        from datetime import datetime, timedelta, timezone

        city = str(args.get("city", "")).strip()
        days = max(1, min(5, int(args.get("days") or 1)))
        if not city:
            return _err("weather_lookup", "City is required.")

        geo = self._openweather("/geo/1.0/direct", {"q": city, "limit": 1})
        if not geo:
            return _err("weather_lookup", f"City not found: {city}")
        place = geo[0]
        coords = {"lat": place["lat"], "lon": place["lon"], "units": "metric"}

        now = self._openweather("/data/2.5/weather", coords)
        fc = self._openweather("/data/2.5/forecast", coords)  # free tier: 5 days in 3-hour steps
        offset = timedelta(seconds=fc.get("city", {}).get("timezone", 0))

        buckets: dict[str, list[dict[str, Any]]] = defaultdict(list)
        for item in fc.get("list", []):
            local_day = (datetime.fromtimestamp(item["dt"], tz=timezone.utc) + offset).date().isoformat()
            buckets[local_day].append(item)

        forecast = []
        for day in sorted(buckets)[:days]:
            items = buckets[day]
            forecast.append({
                "date": day,
                "conditions": Counter(i["weather"][0]["description"] for i in items).most_common(1)[0][0],
                "max_c": round(max(i["main"]["temp_max"] for i in items), 1),
                "min_c": round(min(i["main"]["temp_min"] for i in items), 1),
                "rain_chance_pct": round(100 * max(i.get("pop", 0) for i in items)),
                "rain_mm": round(sum(i.get("rain", {}).get("3h", 0) for i in items), 1),
                "humidity_pct": round(sum(i["main"]["humidity"] for i in items) / len(items)),
            })

        location = ", ".join(x for x in (place.get("name"), place.get("state"), place.get("country")) if x)
        return _ok("weather_lookup", {
            "location": location,
            "current": {
                "conditions": now["weather"][0]["description"],
                "temp_c": now["main"]["temp"], "feels_like_c": now["main"]["feels_like"],
                "humidity_pct": now["main"]["humidity"], "wind_ms": now.get("wind", {}).get("speed"),
            },
            "forecast": forecast,
            "note": "OpenWeather free tier provides up to 5 days of forecast.",
            "source": "openweathermap.org",
        })

    # ---------------- delegation ----------------
    def _tool_handoff_to_agent(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        agent, instructions = str(args.get("agent", "")).strip(), str(args.get("instructions", "")).strip()
        if not agent or not instructions:
            return _err("handoff_to_agent", "Both 'agent' and 'instructions' are required.")
        return _ok("handoff_to_agent", f"Handing off to {agent}.", agent=agent, instructions=instructions[:2000])

    # ---------------- database ----------------
    def _tool_database_query(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        from apps.api import business_db
        return _ok("database_query", business_db.query(str(args.get("sql", ""))))

    def _tool_database_writer(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        from apps.api import business_db
        values = args.get("values") or {}
        if not isinstance(values, dict):
            return _err("database_writer", "values must be an object of column: value")
        row_id = args.get("id")
        result = business_db.write(str(args.get("table", "")), str(args.get("operation") or "insert"),
                                   int(row_id) if row_id not in (None, "") else None, values)
        return _ok("database_writer", result)

    # ---------------- communication ----------------
    def _tool_email_sender(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        from apps.api import email_service
        raw = args.get("to", "")
        recipients = raw if isinstance(raw, list) else str(raw).split(",")
        attachments = [self._resolve_readable(str(p), ctx) for p in (args.get("attachments") or [])]
        for p in attachments:
            if not relative(p).startswith("outputs/"):
                raise WorkspaceError("Only files created in this chat (outputs/...) can be attached.")
        result = email_service.send(recipients, str(args.get("subject", "")), str(args.get("body", "")),
                                    attachments, ctx.user_email or "a PolicyGuard user")
        return _ok("email_sender", result)

    # ---------------- privileged ----------------
    def _tool_admin_shell(self, args: dict[str, Any], ctx: ExecutionContext) -> dict[str, Any]:
        return {"status": "blocked", "tool": "admin_shell",
                "result": "Privileged shell execution is disabled in this research environment."}
