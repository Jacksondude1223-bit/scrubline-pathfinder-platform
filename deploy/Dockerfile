# The toolchain is pinned at or above what go.mod asks for, and matches what
# the tests are run against. A build image older than the module's go directive
# fails late and confusingly.
FROM golang:1.24-alpine AS build
WORKDIR /src
# Resolve dependencies in their own layer so editing source does not re-download
# them. The previous "COPY go.mod" was immediately followed by "COPY . .", which
# invalidated the module layer on every source change and cached nothing.
COPY go.mod ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -o /out/scrub-api ./cmd/scrub-api \
 && CGO_ENABLED=0 go build -o /out/scrub-node ./cmd/scrub-node \
 && CGO_ENABLED=0 go build -o /out/scrubctl ./cmd/scrubctl \
 && CGO_ENABLED=0 go build -o /out/scrub-traffic ./cmd/scrub-traffic

FROM alpine:3.20
# curl and jq are for the seed step and for poking the API from inside the
# stack. They are a megabyte between them and save guessing at what busybox
# wget supports.
RUN apk add --no-cache ca-certificates curl jq
COPY --from=build /out/scrub-api /usr/local/bin/scrub-api
COPY --from=build /out/scrub-node /usr/local/bin/scrub-node
COPY --from=build /out/scrubctl /usr/local/bin/scrubctl
COPY --from=build /out/scrub-traffic /usr/local/bin/scrub-traffic
COPY deploy/seed.sh /usr/local/bin/seed.sh
COPY configs/ /etc/scrubline/

# Nothing here needs root: the ports are above 1024 and the only writable path
# is the state directory. A named volume takes its ownership from the image on
# first creation, so chowning here is what makes the volume writable as this
# user rather than only as root.
RUN adduser -D -u 10001 scrubline \
 && mkdir -p /var/lib/scrubline \
 && chown -R scrubline:scrubline /var/lib/scrubline \
 && chmod +x /usr/local/bin/seed.sh
USER scrubline

EXPOSE 8080 9091
ENTRYPOINT ["scrub-api"]
