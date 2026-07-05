# Use bash explicitly. `make` defaults to /bin/sh which on many systems
# is bash invoked in POSIX mode — and POSIX-mode `source` searches $PATH
# instead of the current directory, so `source .env` fails with
# "file not found" even when .env exists locally. Forcing /bin/bash
# (non-POSIX) keeps the natural bash semantics in every recipe.
SHELL := /bin/bash

.PHONY: help build start stop restart dev debug \
       docker-start docker-stop docker-restart docker-build docker-logs docker-ps docker-clean \
       test test-integration test-cli \
       migrate migrate-status migrate-reset db-create seed setup \
       install-hooks \
       clean

# ─── Help ────────────────────────────────────────────────────────────
help: ## Show this help
	@echo ""
	@echo "  Vendidit Auth Server — available commands"
	@echo "  ──────────────────────────────────────────"
	@echo ""
	@grep -E '^[a-zA-Z_-]+:.*?## .*$$' $(MAKEFILE_LIST) | \
		awk 'BEGIN {FS = ":.*?## "}; {printf "  \033[36m%-22s\033[0m %s\n", $$1, $$2}'
	@echo ""

# ─── Local (non-Docker) ─────────────────────────────────────────────
build: ## Compile the auth server binary to bin/
	go build -o bin/auth-server ./cmd/server/main.go

start: build ## Build and start the auth server
	@set -a && source .env && set +a && ./bin/auth-server

dev: start ## Alias for start (build + run)

stop: ## Stop the running auth server (kills process on port 8080)
	@pid=$$(lsof -ti tcp:8080 2>/dev/null) && \
		if [ -n "$$pid" ]; then kill $$pid && echo "Stopped PID $$pid"; \
		else echo "No process on port 8080"; fi

restart: stop start ## Rebuild and restart the auth server

# ─── Docker ──────────────────────────────────────────────────────────
docker-start: ## Start all services via docker-compose (detached)
	docker compose up -d
	@echo "Services: Auth=http://localhost:8080  PG=localhost:5433  Redis=localhost:6380"

docker-stop: ## Stop all docker-compose services
	docker compose down

docker-restart: ## Restart all docker-compose services
	docker compose down && docker compose up -d

docker-build: ## Rebuild and start docker-compose services
	docker compose up -d --build

docker-logs: ## Tail logs from all docker-compose services
	docker compose logs -f

docker-ps: ## Show running docker-compose containers
	docker compose ps

docker-clean: ## Stop services and remove all volumes/data
	docker compose down -v --remove-orphans
	docker rmi ven-auth-server 2>/dev/null || true

# ─── Tests ───────────────────────────────────────────────────────────
test: ## Run unit tests
	go test ./internal/... -v -count=1

test-integration: ## Run integration tests (requires Docker)
	./scripts/run-tests.sh

test-cli: ## Open the interactive test runner TUI (requires: cd tests && npm install)
	node tests/node_modules/.bin/test-cli --config tests/testtools.config.json

# ─── Database & Migrations ───────────────────────────────────────────
db-create: ## Create the database if it doesn't exist
	@set -a && source .env 2>/dev/null; set +a; \
	PGPASSWORD=$${DB_PASSWORD:-postgres} psql -U $${DB_USER:-postgres} -h $${DB_HOST:-localhost} -p $${DB_PORT:-5432} -d postgres \
		-c "SELECT 1 FROM pg_database WHERE datname = '$${DB_NAME:-auth}'" | grep -q 1 \
		|| PGPASSWORD=$${DB_PASSWORD:-postgres} psql -U $${DB_USER:-postgres} -h $${DB_HOST:-localhost} -p $${DB_PORT:-5432} -d postgres \
			-c "CREATE DATABASE $${DB_NAME:-auth};"
	@echo "Database ready."

setup: db-create migrate ## Full setup: create DB + run all migrations

migrate: ## Apply pending migrations
	@./scripts/migrate.sh up

migrate-status: ## Show migration status
	@./scripts/migrate.sh status

migrate-reset: ## Drop and recreate DB, re-run all migrations
	@./scripts/migrate.sh reset

seed: migrate ## Seed demo data (runs all migrations including seeds)

# ─── Deploy ─────────────────────────────────────────────────────────
DEPLOY_HOST ?= 3.12.0.133
DEPLOY_KEY  ?= ~/Sites/ven/_keys/dev-admins.pem
DEPLOY_USER ?= ec2-user
DEPLOY_DIR  ?= ~/apps/auth-server

build-linux: ## Cross-compile for Linux (amd64)
	GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o bin/auth-server-linux ./cmd/server/main.go

deploy: build-linux ## Build + deploy to ven-internal (new-auth.vendidit.com)
	scp -i $(DEPLOY_KEY) bin/auth-server-linux $(DEPLOY_USER)@$(DEPLOY_HOST):$(DEPLOY_DIR)/auth-server.new
	scp -i $(DEPLOY_KEY) -r migrations $(DEPLOY_USER)@$(DEPLOY_HOST):$(DEPLOY_DIR)/
	ssh -i $(DEPLOY_KEY) $(DEPLOY_USER)@$(DEPLOY_HOST) "cd $(DEPLOY_DIR) && mv -f auth-server.new auth-server && chmod +x auth-server && sudo systemctl restart auth-server && sleep 2 && curl -sf http://localhost:8090/health"
	@echo ""
	@echo "  Deployed to $(DEPLOY_HOST) — auth-server restarted"
	@echo "  Health: https://new-auth.vendidit.com/health"
	@echo ""

deploy-binary: build-linux ## Deploy binary only (no migrations), faster
	scp -i $(DEPLOY_KEY) bin/auth-server-linux $(DEPLOY_USER)@$(DEPLOY_HOST):$(DEPLOY_DIR)/auth-server
	ssh -i $(DEPLOY_KEY) $(DEPLOY_USER)@$(DEPLOY_HOST) "sudo systemctl restart auth-server"
	@echo "  Binary deployed + restarted"

deploy-status: ## Check auth server status on ven-internal
	@ssh -i $(DEPLOY_KEY) $(DEPLOY_USER)@$(DEPLOY_HOST) "sudo systemctl status auth-server --no-pager | head -8 && echo '---' && curl -s http://localhost:8090/health"

# ─── Git hooks ───────────────────────────────────────────────────────
install-hooks: ## Install repo git hooks (pre-push: build + test)
	@mkdir -p .git/hooks
	@cp scripts/git-hooks/pre-push .git/hooks/pre-push
	@chmod +x .git/hooks/pre-push
	@echo "  pre-push hook installed -> .git/hooks/pre-push"
	@echo "  bypass (emergency only):  git push --no-verify"

# ─── Misc ────────────────────────────────────────────────────────────
clean: ## Remove build artifacts
	rm -rf bin/
