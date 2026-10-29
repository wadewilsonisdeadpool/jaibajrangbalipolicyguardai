# PolicyGuard-AI v2 update — how to apply

Extract this zip over your project root (`policyguard-ai-fixed/`) and
choose "replace" for existing files. Your `.env`, `auth_routes.py`,
`auth_utils.py`, `lib/auth.ts` and `login/page.tsx` are NOT touched.

## Run once, in order (Windows cmd, repo root, venv active)

```
pip install -r apps\api\requirements.txt
python -m apps.api.migrate_v2
python -m apps.api.seed_data
uvicorn apps.api.main:app --reload --port 8000
```
Frontend: stop `npm run dev`, then `rmdir /s /q apps\web\.next`, then `npm run dev`.

## What changed

Backend
- tool_registry.py   single source of truth: 8 tools with security metadata
- tool_executor.py   REAL tools: file_reader (txt/md/pdf/docx), file_writer,
                     web_fetch (domain allowlist), weather_lookup (Open-Meteo API),
                     database_query (read-only SQL), database_writer, email_sender
                     (local outbox), admin_shell (always blocked)
- workspace.py       sandboxed workspace + demo company DB + sample files
                     (incl. vendor_invoice.txt with a prompt-injection payload)
- policy_engine.py   v2: hard rules + weighted risk, reasons, factor breakdown,
                     taint tracking, EWMA trust
- tool_broker.py     looks up trust/allowlist/sensitivity server-side
- qwen_agent.py      multi-agent aware, taint tracking, Ollama error handling
- models.py          new columns + AgentRun table;  migrate_v2.py adds them in place
- seed_data.py       3 agents with separate allowlists
- new routes: /api/agents, /api/runs, /api/events, /api/tools, /api/users
- dashboard now requires login; approvals feed back into trust

Frontend
- components/AppShell.tsx  one auth guard + working sidebar for every page
- pages: Dashboard, Agents, Agent Console, Live Trace, Approvals,
         Audit Explorer (CSV export), Tool Registry, Users (admin)
