.PHONY: build test bench certs spec-check demo up down logs creds

build:
	mkdir -p bin
	go build -o bin/scrub-api ./cmd/scrub-api
	go build -o bin/scrub-node ./cmd/scrub-node
	go build -o bin/scrubctl ./cmd/scrubctl
	go build -o bin/scrub-traffic ./cmd/scrub-traffic

# -race is the cheap safety net for the Pipeline and Store, both of which are
# written for concurrent use.
test:
	go test -race ./...

# Throwaway CA and server certificate for trying TLS locally. Not for deployment.
certs:
	go run scripts/gen-dev-certs.go -dir certs -host 127.0.0.1,localhost

# Checks the OpenAPI specs resolve, and that the routes they document match the
# dispatch switch in both directions: a spec that drifts from the code is worse
# than none.
spec-check:
	python3 scripts/spec-check.py

bench:
	go test -run xxx -bench . -benchmem ./internal/pipeline/

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

creds:
	@$(COMPOSE) logs --no-log-prefix seed 2>/dev/null | sed -n '/seeded:/,$$p' | grep . \
	  || echo "  the seeder has not finished yet; try 'make logs' or run 'make creds' again"

.PHONY: rust-build rust-test rust-check rust-reference

# Rust migration targets run separately until both servers have native replacements.
rust-build:
	cargo build --locked --release --bin scrubctl

rust-test:
	cargo test --locked --all-targets

rust-check:
	cargo fmt --all -- --check
	cargo clippy --locked --all-targets -- -D warnings

rust-reference:
	go run ./scripts/rust-reference > tests/fixtures/go-reference.json
