SHELL := /bin/zsh

.PHONY: db-init db-start db-stop api worker frontend build test

db-init:
	./backend/db-init.sh

db-start:
	./backend/db-start.sh

db-stop:
	./backend/db-stop.sh

api:
	./backend/run-api.sh

worker:
	./backend/run-worker.sh

frontend:
	cd frontend && npm run dev -- --host 127.0.0.1 --port 5173

build:
	cd frontend && npm run build
	cd backend && ./run-build.sh

test:
	cd backend && ./run-test.sh
