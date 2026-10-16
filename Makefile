.PHONY: build test bench demo

build:
	mkdir -p bin
	go build -o bin/scrub-api ./cmd/scrub-api
	go build -o bin/scrub-node ./cmd/scrub-node
	go build -o bin/scrubctl ./cmd/scrubctl

# -race is the cheap safety net for the Pipeline and Store, both of which are
# written for concurrent use.
test:
	go test -race ./...

bench:
	go test -run xxx -bench . -benchmem ./internal/pipeline/

# Each recipe line runs in its own shell, so a backgrounded server started on one
# line cannot be reached by "kill %1" on the next: the API was left running and
# holding its port after make exited. Keep the whole demo in one shell and trap
# the exit so the server always comes down.
demo: build
	@set -e; \
	SCRUBLINE_API_TOKEN=$${SCRUBLINE_API_TOKEN:-dev-scrubline-token}; \
	export SCRUBLINE_API_TOKEN; \
	./bin/scrub-api -addr 127.0.0.1:8080 & \
	api_pid=$$!; \
	trap 'kill $$api_pid 2>/dev/null || true; wait $$api_pid 2>/dev/null || true' EXIT INT TERM; \
	for i in $$(seq 1 50); do \
	  if curl -sf -o /dev/null http://127.0.0.1:8080/health; then break; fi; \
	  if ! kill -0 $$api_pid 2>/dev/null; then echo "scrub-api exited during startup" >&2; exit 1; fi; \
	  sleep 0.2; \
	done; \
	./scripts/demo.sh
