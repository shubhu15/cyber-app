# Simple Log Analyser

Small full-stack log analysis app with:
- React + TypeScript frontend
- Go API
- Go worker
- Postgres for users, sessions, uploads, event logs, findings, and summaries
- Local disk file storage for uploaded `.log` files

## Current behavior

- Register with `email + password`
- Login with Basic Auth
- Upload one AWS VPC Flow Log text file
- Upload status polls until processing finishes
- View findings, timeline entries, charts, and parsed flow records
- Click ai-analysis for ai-generated findings 

## Project layout

- `frontend/` - Vite React app
- `backend/` - Go API, worker, parser, storage, schema, and tests

## One-time setup

Install frontend packages:

```bash
cd frontend
npm install
```

Create the local Postgres cluster once:

```bash
make db-init
```

That script will:
- create the local Postgres cluster if missing
- start Postgres if needed
- create the `simple_log_analyser` database if missing

## Start the app

Open four terminals from the project root.


### 1. Start Postgres

```bash
make db-start
```

### 2. Start the API

```bash
make api
```

### 3. Start the worker

```bash
make worker
```

### 4. Start the frontend

```bash
make frontend
```

## App URLs

- Frontend: `http://127.0.0.1:5173/`
- API health: `http://127.0.0.1:8080/health`

## Stop the app

Stop frontend, API, and worker with `Ctrl+C` in their terminals.

Stop Postgres with:

```bash
make db-stop
```

## Useful commands

Run frontend build:

```bash
make build
```

Run backend tests:

```bash
make test
```

## Sample test file

A sample VPC flow log file is available at:

`backend/testdata/sample-vpc-flow.log`

## Notes

- `frontend/.env.development` points the Vite app at `http://127.0.0.1:8080`
- `backend/dev.env` sets `DATABASE_URL`, `UPLOAD_DIR`, `GOCACHE`, `HTTP_ADDR`, and `ALLOWED_ORIGINS`
- `make api` and `make worker` load `backend/dev.env` for you
- The worker expects the AWS default VPC Flow Logs v2 record format in this phase

## Run with Docker (one command)

If you don't want the four-terminal dance, the whole stack runs in containers:

```bash
docker compose up --build
```

That starts:

- `postgres`  on `localhost:5432` (data persisted in the `pgdata` volume)
- `api`       on `http://localhost:8080`
- `worker`    in the background (no exposed port)
- `frontend`  on `http://localhost:5173`

The API and worker share an `uploads` volume so the worker can read what the API wrote. Postgres data and uploads survive `docker compose down`; use `docker compose down -v` to wipe them.

## Deployment

The app is split into four moving parts:

1. **Frontend** — React static bundle. Build with `npm run build`, serve the `dist/` folder.
2. **API** — Go HTTP server, long-running.
3. **Worker** — Go process that polls the DB. Long-running, must always be up.
4. **Postgres** — managed DB.

The Dockerfiles in `backend/` and `frontend/` are host-agnostic: the same images run on Render, Railway, Fly.io, a VPS with Docker, or anywhere else that runs containers. Whichever host you choose, set these production env vars on the API + worker:

| Variable | Example | Notes |
|---|---|---|
| `APP_ENV` | `production` | Switches cookies to `SameSite=None; Secure` |
| `DATABASE_URL` | `postgres://user:pass@host/db?sslmode=require` | From your managed Postgres provider |
| `UPLOAD_DIR` | `/data/uploads` | Mount a persistent disk here on both API and worker |
| `ALLOWED_ORIGINS` | `https://your-app.vercel.app` | Comma-separated allowlist; required for the browser to send the session cookie |
| `APP_MODE` | `api` (web) / `worker` (worker) | Passed as the container command on the worker service |
| `ANTHROPIC_API_KEY` | (your key) | Optional; omit to disable AI analysis |

For the frontend, set `VITE_API_BASE_URL` at **build time** (Vite inlines it into the bundle) to your API's public URL, e.g. `https://your-api.onrender.com`.

### Database in production

You don't ship `users.db` or any local Postgres data. Schema is auto-created on first boot via `initializeDatabase()` in `backend/main.go`. So the deploy flow is:

1. Provision a managed Postgres (Neon, Render Postgres, Supabase, RDS, etc.).
2. Copy its connection string into `DATABASE_URL`.
3. Boot the API once — it creates all tables.
4. Boot the worker — it picks up uploads from the shared `UPLOAD_DIR` volume.

The local `backend/users.db` file is a leftover from an earlier SQLite version and is not used; it's already gitignored.
