#!/bin/zsh

set -euo pipefail

cd "$(dirname "$0")/.."

if [[ -d backend/data/postgres/PG_VERSION ]]; then
  echo "Postgres cluster already exists at backend/data/postgres"
else
  initdb -D backend/data/postgres -A trust -U postgres
fi

mkdir -p /tmp/pgsla
pg_ctl -D backend/data/postgres -l backend/data/postgres.log -o "-k /tmp/pgsla -c listen_addresses=''" start || true

if psql -h /tmp/pgsla -U postgres -d postgres -tAc "SELECT 1 FROM pg_database WHERE datname = 'simple_log_analyser'" | grep -q 1; then
  echo "Database simple_log_analyser already exists"
else
  createdb -h /tmp/pgsla -U postgres simple_log_analyser
fi
