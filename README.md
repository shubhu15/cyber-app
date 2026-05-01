# Simple Log Analyser

Small full-stack log analysis app with:
- React + TypeScript frontend
- Go API
- Go worker
- Postgres for users, sessions, uploads, event logs, findings, and summaries
- Local disk file storage for uploaded `.log` files

## Current behavior

- Register and log in (email + password)
- Upload a single VPC flow log file and wait for processing
- Browse findings, timeline, charts, and raw parsed rows
- Run **AI analysis** if `ANTHROPIC_API_KEY` is set (Docker: in `docker-compose.yml` for the `backend` service)


## Run with Docker (simplest path)

Install [Docker Desktop](https://www.docker.com/products/docker-desktop/) (includes Docker Compose).
From the project root:
```bash
docker compose up --build
```

**You do not need** a local Postgres install, `npm`, or Go tooling for this. Compose builds and runs everything for you.

| What | URL |
|------|-----|
| App (UI) | http://localhost:5173 |
| API | http://localhost:8080 |
| Health check | http://localhost:8080/health |

**Behind the scenes:** one **backend** container runs the HTTP server and the log-processing worker together; Postgres and the uploads folder stay in Docker volumes.

- **`docker compose down`** — stops containers; Postgres data and uploads are kept until you wipe volumes.
- **`docker compose down -v`** — also deletes those volumes (fresh start).

---

## Optional: run without Docker

Use this when you want to edit code and run processes directly on your machine (hot reload for the UI, `go run`, etc.).

1. **Postgres** — install and start it, or use `make db-init` / `make db-start` from the repo `Makefile` if you use that workflow.
2. **Backend** — copy `backend/dev.env.example` to `backend/dev.env` and adjust paths/URLs. In one terminal: `make api`. In another: `make worker`.
3. **Frontend** — `cd frontend && npm install && npm run dev` (uses `frontend/.env.development` to talk to the API on port 8080).

Stop with `Ctrl+C` in each terminal and `make db-stop` if you used the Makefile for Postgres.

---

## Project layout

| Folder | Role |
|--------|------|
| `frontend/` | Vite + React app |
| `backend/` | API, worker, parser, Postgres schema, Docker image |

Sample log for testing: `backend/testdata/sample-vpc-flow.log`

---

## Important env vars for the **backend** container:

| Variable | Purpose |
|----------|---------|
| `DATABASE_URL` | Postgres connection string |
| `UPLOAD_DIR` | Where uploaded `.log` files live (persist this directory) |
| `ALLOWED_ORIGINS` | Comma-separated frontend URLs allowed to send cookies (CORS/credentials) |
| `APP_ENV` | Use `production` for secure cross-site cookies |
| `ANTHROPIC_API_KEY` | Optional; enables AI analysis from the UI |

For the frontend image or build pipeline, set **`VITE_API_BASE_URL`** at **build time** to your public API URL (for example `https://api.example.com`). Vite bakes this into the JavaScript bundle.

## Development attribution

This project was scoped and designed deliberately before coding. Implementation then **iterated with AI-assisted tooling**: **Cursor** and **Claude Code** were used to draft features, refactor, review suggestions, and help with commits. Human judgment applied throughout; nonetheless, much of the code was produced or revised with AI collaboration and should be read with that context in mind.