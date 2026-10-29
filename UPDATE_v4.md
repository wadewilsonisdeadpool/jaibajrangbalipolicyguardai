# PolicyGuard-AI v4 update

Extract over the project root, choose "Replace". Your .env and auth files are not touched.

## Steps (repo root, venv active)
1. Add to apps/api/.env:
       OPENWEATHER_API_KEY=<your key>
   (New OpenWeather keys can take up to ~2 hours to activate; until then you get
   "OpenWeather rejected the API key".)
2. python -m apps.api.migrate_v4
3. python -m apps.api.seed_data        (adds handoff_to_agent to every agent)
4. Restart uvicorn. Frontend hot-reloads.

## What changed
- Weather: OpenWeather (current + up to 5-day daily forecast, free tier). The API key
  is never included in tool results, logs or error messages.
- Agent handoff: an agent finishes its part and delegates the rest
  (e.g. Research: weather + text file -> Operations: email). Taint and data
  sensitivity carry across handoffs. Max 3 handoffs per message.
- Data-sensitivity-aware email: public-only data (weather/web) to a new address -> ALLOW;
  internal files -> REVIEW; confidential DB data -> REVIEW, or DENY with bulk PII / taint.
  The chat remembers the most sensitive data it has touched.
- Privacy: files, uploads, chats, live-trace runs, audit events and approvals are
  owner-only. Admin is the only exception. Approvers still see pending approvals
  (arguments only, not files). Agent Console files go to a per-user folder.
- Delete chat: soft delete. Hidden from the user (and their files), but messages,
  runs, security events, approvals and trust events are kept for audit; admin can still read them.
