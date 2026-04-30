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
- Receive an HttpOnly session cookie
- Upload one AWS VPC Flow Log text file
- Poll upload status until processing finishes
- View findings, timeline entries, charts, and parsed flow records

## Project layout

- `frontend/` - Vite React app
- `backend/` - Go API, worker, parser, storage, schema, and tests
- `backend/dev.env` - local backend environment values
- `frontend/.env.development` - frontend API URL for Vite dev mode

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
- `backend/dev.env` sets `DATABASE_URL`, `UPLOAD_DIR`, `GOCACHE`, and `HTTP_ADDR`
- `make api` and `make worker` load `backend/dev.env` for you
- The worker expects the AWS default VPC Flow Logs v2 record format in this phase
