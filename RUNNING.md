# Running PolicyGuard-AI locally

This file didn't exist before — added because there was previously no
documented, repeatable way to start the stack, which is a likely
contributor to the last presentation not working.

## 1. Start Postgres

```bash
cd infra
docker compose up -d
```

This starts Postgres 17 with the credentials already baked into
`apps/api/.env` (user `policyguard`, db `policyguard`). No manual
database setup needed — `main.py` creates all tables automatically
on first boot via `Base.metadata.create_all`.

## 2. Start the backend API

From the **repository root** (important — the `apps.api.*` imports
are resolved relative to this directory):

```bash
cd apps/api
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate
pip install -r requirements.txt
cd ../..                          # back to repo root
uvicorn apps.api.main:app --reload --port 8000
```

Verify it's up: `curl http://127.0.0.1:8000/health` should return
`{"status": "ok", ...}`.

Seed the database with the starter agent + tools (safe to re-run,
skips anything already present):

```bash
python -m apps.api.seed_data
```

## 3. Start the frontend

```bash
cd apps/web
npm install
npm run dev
```

Open http://localhost:3000 — the Dashboard should show live data.
If you see "Unable to connect to the PolicyGuard API," check that
step 2's server is actually running on port 8000 and that
`NEXT_PUBLIC_API_URL` (if set) points at it.

## 4. (Optional) Run the agent through Ollama

Requires Ollama running locally with `qwen3:8b` pulled
(`ollama pull qwen3:8b`). Once the backend is up, you can hit the
agent loop directly:

```bash
curl -X POST http://127.0.0.1:8000/api/agent/chat \
  -H "Content-Type: application/json" \
  -d '{"agent_id": 1, "message": "Read the file report.txt"}'
```

## Common failure modes (and what they actually mean)

- **CORS error in the browser console** → the backend isn't running,
  or isn't running on the port the frontend expects.
- **`ModuleNotFoundError: No module named 'apps'`** → you're running
  `uvicorn` from inside `apps/api` instead of the repo root. Run it
  from the root as shown above.
- **`psycopg.OperationalError: connection refused`** → Postgres isn't
  running. `docker compose ps` in `infra/` to check.
- **Empty dashboard, no error** → the database has no data yet. Run
  the seed script (step 2).
