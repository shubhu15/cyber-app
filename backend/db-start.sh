#!/bin/zsh

set -euo pipefail

cd "$(dirname "$0")/.."

mkdir -p /tmp/pgsla
pg_ctl -D backend/data/postgres -l backend/data/postgres.log -o "-k /tmp/pgsla -c listen_addresses=''" start
