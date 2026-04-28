#!/bin/zsh

set -euo pipefail

cd "$(dirname "$0")/.."

pg_ctl -D backend/data/postgres stop
