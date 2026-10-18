# Temporary Rust control-plane test

This folder is a self-contained Rust Vercel Function using the same API and
pipeline modules as the native application. Set the Vercel project Root Directory
to `vercel-test`, select Framework Preset **Other**, and clear the old Go build
command override. `vercel.json` rewrites requests to `api/control.rs`, following
[Vercel's Rust Axum template](https://github.com/vercel/examples/tree/main/rust/axum).

Set `SCRUBLINE_API_TOKEN` and `SCRUBLINE_ENROLL_TOKEN` to distinct values. The API
keeps the same routes and bearer-token roles. The root returns test metadata;
all responses carry `Cache-Control: no-store` and
`X-Scrubline-Test-Mode: ephemeral-memory`.

State is local to a warm function instance and resets on cold starts. Requests
may reach different instances. Use the native Rust deployment with a durable
state file for a persistent control plane. Node agents run separately.

From the repository root:

```sh
sh vercel-test/sync.sh
cargo check --locked --manifest-path vercel-test/Cargo.toml
cargo test --locked --manifest-path vercel-test/Cargo.toml
```

The sync script refreshes `src/`, dependencies, and the pinned toolchain from the
root package. It preserves the Vercel handler and configuration. Commit the
refreshed source before deploying. CI checks source drift, formatting, lint,
tests, and release compilation without requiring Go.
