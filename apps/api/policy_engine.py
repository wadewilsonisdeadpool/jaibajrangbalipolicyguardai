"""PolicyGuard policy engine v3.

Layer 1  hard rules      -> unconditional DENY
Layer 2  weighted risk   -> ALLOW / REVIEW / DENY by thresholds
Layer 3  floors          -> context that forces at least REVIEW
Every decision returns human-readable reasons and per-factor contributions.
"""
from dataclasses import dataclass, field
from enum import Enum
from typing import Any
from urllib.parse import urlparse

from apps.api.settings import EMAIL_TRUSTED_DOMAINS
from apps.api.web_domains import classify_host


class Decision(str, Enum):
    ALLOW = "ALLOW"
    REVIEW = "REVIEW"
    DENY = "DENY"


DENY_THRESHOLD = 0.75
REVIEW_THRESHOLD = 0.45

WEIGHTS = {
    "sensitivity": 0.40,
    "agent_distrust": 0.15,
    "user_distrust": 0.10,
    "action": 0.12,
    "tainted_context": 0.25,
    "content": 0.35,
    "request_intent": 0.15,
}
ACTION_RISK = {"read": 0.0, "delegate": 0.0, "create": 0.3, "write": 0.5, "delete": 0.9, "send": 0.8, "execute": 1.0}
DESTINATION_RISK = {"internal": 0.0, "trusted": -0.05, "known_external": 0.05, "unvetted": 0.15, "blocked": 0.3}
SIDE_EFFECTS = {"create", "write", "delete", "send", "execute"}

# Egress (send) is judged by the most sensitive data the conversation has touched:
# a public weather summary to a new address is routine; customer data is not.
DATA_LEVELS = {0: "public data only", 1: "internal files", 2: "confidential business data"}
EGRESS_SENSITIVITY_SCALE = {0: 0.5, 1: 1.0, 2: 1.2}
EGRESS_DESTINATION_SCALE = {0: 0.2, 1: 1.0, 2: 1.5}


# ---------------- destination intelligence ----------------

def classify_destination(tool_name: str, arguments: dict[str, Any], user_email: str | None) -> tuple[str, str]:
    if tool_name == "web_fetch":
        host = (urlparse(str(arguments.get("url", ""))).hostname or "").lower()
        return classify_host(host), host or "invalid url"
    if tool_name == "weather_lookup":
        return "known_external", "openweathermap.org"
    if tool_name == "email_sender":
        raw = arguments.get("to", "")
        recipients = [r.strip().lower() for r in (raw if isinstance(raw, list) else str(raw).split(",")) if r.strip()]
        if not recipients:
            return "unvetted", "no recipient"
        trusted = {(user_email or "").lower()}
        if all(r in trusted or r.split("@")[-1] in EMAIL_TRUSTED_DOMAINS for r in recipients):
            return "trusted", ", ".join(recipients)
        return "unvetted", ", ".join(recipients)
    return "internal", "sandbox / internal system"


@dataclass
class PolicyInput:
    tool_name: str
    tool_def: dict[str, Any] | None
    action: str
    agent_trust: float            # pessimistic trust
    agent_tier: str
    agent_active: bool
    agent_quarantined: bool
    allowed_tools: list[str]
    user_trust: float = 0.68
    user_tier: str = "standard"
    destination: str = "internal"
    destination_detail: str = ""
    content: dict[str, Any] = field(default_factory=lambda: {"score": 0.0, "findings": [], "critical": False})
    context_tainted: bool = False
    taint_sources: list[str] = field(default_factory=list)
    request_risk: float = 0.0
    data_level: int = 0
    data_sources: list[str] = field(default_factory=list)


@dataclass
class PolicyResult:
    decision: Decision
    risk_score: float
    reasons: list[str]
    factors: dict[str, float]
    rule: str | None = None


def evaluate(inp: PolicyInput) -> PolicyResult:
    if inp.tool_def is None:
        return PolicyResult(Decision.DENY, 1.0, [f"Unknown tool '{inp.tool_name}'."], {}, "unknown_tool")

    tool, action = inp.tool_def, inp.action
    side_effect = action in SIDE_EFFECTS
    content_score = float(inp.content.get("score", 0.0))

    egress = action == "send"
    level = max(0, min(2, inp.data_level))
    sens_scale = EGRESS_SENSITIVITY_SCALE[level] if egress else 1.0
    dest_scale = EGRESS_DESTINATION_SCALE[level] if egress else 1.0

    factors = {
        "sensitivity": WEIGHTS["sensitivity"] * tool["sensitivity"] * sens_scale,
        "agent_distrust": WEIGHTS["agent_distrust"] * (1 - inp.agent_trust),
        "user_distrust": WEIGHTS["user_distrust"] * (1 - inp.user_trust),
        "action": WEIGHTS["action"] * ACTION_RISK.get(action, 1.0),
        "destination": DESTINATION_RISK.get(inp.destination, 0.15) * dest_scale,
        "tainted_context": WEIGHTS["tainted_context"] * ACTION_RISK.get(action, 1.0) if inp.context_tainted and side_effect else 0.0,
        "content": WEIGHTS["content"] * content_score,
        "request_intent": WEIGHTS["request_intent"] * inp.request_risk,
    }
    factors = {k: round(v, 4) for k, v in factors.items()}
    risk = round(min(1.0, max(0.0, sum(factors.values()))), 4)

    reasons = [
        f"Tool '{inp.tool_name}' ({action}), base sensitivity {tool['sensitivity']:.2f}.",
        f"Agent trust {inp.agent_trust:.2f} ({inp.agent_tier}); user trust {inp.user_trust:.2f} ({inp.user_tier}).",
    ]
    if inp.destination != "internal":
        reasons.append(f"Destination: {inp.destination.replace('_', ' ')} ({inp.destination_detail}).")
    if egress:
        src = f" ({', '.join(sorted(set(inp.data_sources)))})" if inp.data_sources else ""
        reasons.append(f"Outgoing data classification: {DATA_LEVELS[level]}{src}.")
    if factors["tainted_context"]:
        reasons.append(f"Run already read untrusted content ({', '.join(sorted(set(inp.taint_sources)))}); side effects are riskier.")
    for f in inp.content.get("findings", []):
        reasons.append(f"Content check [{f['severity']}]: {f['finding']}.")
    if inp.request_risk >= 0.3:
        reasons.append(f"The user's request itself looked risky (intent score {inp.request_risk:.2f}).")

    def result(decision: Decision, rule: str, lead: str | None = None) -> PolicyResult:
        return PolicyResult(decision, risk, ([lead] if lead else []) + reasons, factors, rule)

    # ---- Layer 1: hard rules ----
    if not inp.agent_active:
        return result(Decision.DENY, "agent_inactive", "Agent is deactivated.")
    if inp.agent_quarantined:
        return result(Decision.DENY, "agent_quarantined", "Agent is quarantined after repeated violations.")
    if inp.tool_name not in inp.allowed_tools:
        return result(Decision.DENY, "not_in_allowlist", f"'{inp.tool_name}' is outside this agent's allowlist (privilege boundary).")
    if tool.get("privileged"):
        return result(Decision.DENY, "privileged_tool", "Privileged tool: never executed autonomously.")
    if inp.destination == "blocked":
        return result(Decision.DENY, "blocked_destination", "Destination is on the blocklist (known exfiltration/tunnel service).")
    if inp.content.get("critical"):
        return result(Decision.DENY, "critical_content", "Payload contains critical-severity content.")

    # ---- Layer 2: thresholds ----
    if risk >= DENY_THRESHOLD:
        return result(Decision.DENY, "risk_threshold")
    if risk >= REVIEW_THRESHOLD:
        return result(Decision.REVIEW, "risk_threshold")

    # ---- Layer 3: floors (context that forces a human look) ----
    if inp.destination == "unvetted" and not (egress and level == 0):
        return result(Decision.REVIEW, "unvetted_destination", "Destination is not on the vetted list; a human must confirm.")
    if side_effect and inp.agent_tier in {"probation", "restricted"}:
        return result(Decision.REVIEW, "agent_probation", f"Agent is on {inp.agent_tier}; side effects need approval.")
    if side_effect and inp.user_tier in {"probation", "restricted"}:
        return result(Decision.REVIEW, "user_probation", f"User is on {inp.user_tier}; side effects need approval.")

    return result(Decision.ALLOW, "risk_threshold")
