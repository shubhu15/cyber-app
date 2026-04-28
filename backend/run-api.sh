#!/bin/zsh

set -euo pipefail

cd "$(dirname "$0")"
set -a
source ./dev.env
set +a

go run .
