FROM rust:1.88.0-bookworm AS build
WORKDIR /src
COPY . .
RUN cargo build --locked --release --bins

FROM debian:bookworm-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates curl jq \
 && rm -rf /var/lib/apt/lists/* \
 && useradd --system --uid 10001 --create-home scrubline \
 && mkdir -p /var/lib/scrubline \
 && chown scrubline:scrubline /var/lib/scrubline
COPY --from=build /src/target/release/scrub-api /usr/local/bin/scrub-api
COPY --from=build /src/target/release/scrub-node /usr/local/bin/scrub-node
COPY --from=build /src/target/release/scrubctl /usr/local/bin/scrubctl
COPY --from=build /src/target/release/scrub-traffic /usr/local/bin/scrub-traffic
COPY --chmod=755 deploy/seed.sh /usr/local/bin/seed.sh
COPY configs/ /etc/scrubline/
USER scrubline
EXPOSE 8080 9091
CMD ["scrub-api"]
