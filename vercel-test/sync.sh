#!/bin/sh
# Refresh this folder's snapshot of the control-plane source from the parent
# repository.
#
# The folder is a self-contained copy so Vercel can build it with its Root
# Directory set here, which means it does not track the parent and silently
# goes stale. It did: the first snapshot sat three feature commits behind
# before anyone noticed. Running this is the whole update.
#
# The package list is derived rather than written down. The control plane's
# imports move — two packages appeared the last time this was resynced — and
# a hardcoded list would be one more thing to forget.
set -eu

cd "$(dirname "$0")/.."
root=$(pwd)
dest="$root/vercel-test/internal"

module=$(go list -m)
packages=$(go list -deps ./internal/api ./internal/store |
	grep "^$module/internal/" |
	sed "s|^$module/internal/||" |
	sort -u)

rm -rf "$dest"
for pkg in $packages; do
	mkdir -p "$dest/$pkg"
	cp "$root/internal/$pkg"/*.go "$dest/$pkg/"
done

echo "synced $(echo "$packages" | wc -l | tr -d ' ') packages from $(git rev-parse --short HEAD)"
echo "$packages" | sed 's/^/  /'
