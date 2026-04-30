#!/bin/sh
set -eu

# Start the worker in the background.
APP_MODE=worker /usr/local/bin/app &
WORKER_PID=$!

# Forward signals so Render can shut us down cleanly.
trap 'kill -TERM "$WORKER_PID" 2>/dev/null; exit 0' TERM INT

# Run the API in the foreground (its exit decides the container's exit).
APP_MODE=api exec /usr/local/bin/app