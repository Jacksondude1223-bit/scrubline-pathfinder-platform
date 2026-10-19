.PHONY: build test bench certs spec-check demo up down logs creds

build:
	cargo build --locked --release --bins
	mkdir -p bin
	cp target/release/scrub-api target/release/scrub-node target/release/scrubctl target/release/scrub-traffic bin/

test:
	cargo test --locked --all-targets

certs:
	sh scripts/gen-dev-certs.sh -dir certs -host 127.0.0.1,localhost

spec-check:
	python3 scripts/spec-check.py

bench:
	cargo bench --locked --bench pipeline

# Each recipe line runs in its own shell, so a backgrounded server started on one
# line cannot be reached by "kill %1" on the next: the API was left running and
# holding its port after make exited. Keep the whole demo in one shell and trap
# the exit so the server always comes down.
demo: build
	@set -e; \
	SCRUBLINE_API_TOKEN=$${SCRUBLINE_API_TOKEN:-dev-scrubline-token}; \
	SCRUBLINE_ENROLL_TOKEN=$${SCRUBLINE_ENROLL_TOKEN:-dev-scrubline-enroll}; \
	export SCRUBLINE_API_TOKEN SCRUBLINE_ENROLL_TOKEN; \
	state=$$(mktemp -d)/state.json; \
	./bin/scrub-api -addr 127.0.0.1:8080 -state $$state & \
	api_pid=$$!; \
	trap 'kill $$api_pid 2>/dev/null || true; wait $$api_pid 2>/dev/null || true' EXIT INT TERM; \
	for i in $$(seq 1 50); do \
	  if curl -sf -o /dev/null http://127.0.0.1:8080/health; then break; fi; \
	  if ! kill -0 $$api_pid 2>/dev/null; then echo "scrub-api exited during startup" >&2; exit 1; fi; \
	  sleep 0.2; \
	done; \
	./scripts/demo.sh

# A demo fabric in containers: control plane, three scrubbers, a seeded policy
# with two customers, and traffic driven through the datapath so the analytics
# have something real to report. deploy/README.md covers exposing it on a URL.
COMPOSE = docker compose -f deploy/docker-compose.yml

up: deploy/.env
	$(COMPOSE) up --build -d
	@echo "  seeding the fabric and onboarding the demo customers..."
	@$(COMPOSE) wait seed >/dev/null 2>&1 || true
	@$(MAKE) --no-print-directory creds
	@echo "  control plane: http://127.0.0.1:8080   (make creds, make logs, make down)"
	@echo "  a public URL: see deploy/README.md — do not just bind this to 0.0.0.0"

# Compose reads deploy/.env on its own; this only stops the first run failing
# on three unset variables with nothing saying where they come from.
deploy/.env:
	@echo "deploy/.env is missing. Copying the example — change the tokens before exposing this." >&2
	cp deploy/.env.example deploy/.env

down:
	$(COMPOSE) down

logs:
	$(COMPOSE) logs -f

# A restarted seeder appends to the same log, and every run rotates the credentials, so only the
# last banner holds tokens that still work.
creds:
	@$(COMPOSE) logs --no-log-prefix seed 2>/dev/null \
	  | awk '/seeded:/ {banner = ""; on = 1} on {banner = banner $$0 "\n"} END {printf "%s", banner}' | grep . \
	  || echo "  the seeder has not finished yet; try 'make logs' or run 'make creds' again"

.PHONY: rust-build rust-test rust-check runtime-test snapshot-check

rust-build: build
rust-test: test
rust-check:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings

runtime-test:
	cargo build --locked --bins
	python3 scripts/runtime-e2e.py

snapshot-check:
	sh vercel-test/sync.sh
	cargo check --locked --manifest-path vercel-test/Cargo.toml
