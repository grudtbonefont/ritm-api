# ritm-api

Backend for «Ритм» planner sync (accounts + offline-first merge).

## Endpoints
- `GET /health`
- `POST /auth/register` `{email,password}`
- `POST /auth/login` `{email,password}`
- `GET /auth/me` (Bearer)
- `GET /sync?since=ISO` (Bearer)
- `POST /sync` `{changes:[...]}` (Bearer)

Secrets via Render env vars only. Uses free Render Postgres schema `ritm` (workspace allows one free DB).
