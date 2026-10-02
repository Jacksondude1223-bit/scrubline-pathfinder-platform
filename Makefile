.PHONY: build test demo

build:
	mkdir -p bin
	go build -o bin/scrub-api ./cmd/scrub-api
	go build -o bin/scrub-node ./cmd/scrub-node
	go build -o bin/scrubctl ./cmd/scrubctl

test:
	go test ./...

demo: build
	SCRUBLINE_API_TOKEN=dev-scrubline-token ./bin/scrub-api -addr 127.0.0.1:8080 &
	sleep 0.4
	SCRUBLINE_API_TOKEN=dev-scrubline-token ./scripts/demo.sh
	kill %1 || true
