#!/bin/sh
set -eu
cd "$(dirname "$0")/.."
python3 - <<'PY'
from pathlib import Path
import shutil
root=Path.cwd();target=root/'vercel-test'
shutil.rmtree(target/'src',ignore_errors=True)
(target/'src').mkdir(parents=True,exist_ok=True)
for source in (root/'src').iterdir():
    if source.is_file(): shutil.copy2(source,target/'src'/source.name)
manifest=(root/'Cargo.toml').read_text().replace('name = "scrubline-pathfinder"','name = "scrubline-pathfinder-vercel-test"',1).replace('publish = false','publish = false\nautobins = false',1)
manifest=manifest.split('\n[[bench]]')[0]
manifest=manifest.replace('[profile.release]','vercel_runtime = { version = "2.4", features = ["axum"] }\ntower = "0.5"\n\n[[bin]]\nname = "control"\npath = "api/control.rs"\n\n[profile.release]')
(target/'Cargo.toml').write_text(manifest)
shutil.copy2(root/'rust-toolchain.toml',target/'rust-toolchain.toml')
PY
