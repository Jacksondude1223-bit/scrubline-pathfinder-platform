FROM golang:1.22-alpine AS build
WORKDIR /src
COPY go.mod ./
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
