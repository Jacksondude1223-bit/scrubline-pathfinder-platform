FROM golang:1.22-alpine AS build
WORKDIR /src
# Resolve dependencies in their own layer so editing source does not re-download
# them. The previous "COPY go.mod" was immediately followed by "COPY . .", which
# invalidated the module layer on every source change and cached nothing.
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/scrub-api ./cmd/scrub-api \
 && CGO_ENABLED=0 go build -o /out/scrub-node ./cmd/scrub-node \
 && CGO_ENABLED=0 go build -o /out/scrubctl ./cmd/scrubctl

FROM alpine:3.20
RUN apk add --no-cache ca-certificates
COPY --from=build /out/scrub-api /usr/local/bin/scrub-api
COPY --from=build /out/scrub-node /usr/local/bin/scrub-node
COPY --from=build /out/scrubctl /usr/local/bin/scrubctl
EXPOSE 8080 9091
ENTRYPOINT ["scrub-api"]
