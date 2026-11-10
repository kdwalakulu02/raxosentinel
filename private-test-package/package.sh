#!/usr/bin/env bash
set -euo pipefail
umask 077
root=$(cd "$(dirname "$0")/.." && pwd)
store=${1:?Usage: package.sh PRIVATE_STORE OUTPUT_DIRECTORY}
out=${2:?Usage: package.sh PRIVATE_STORE OUTPUT_DIRECTORY}
gen=phase2d6-unified
commit=$(git -C "$root" rev-parse HEAD)
test "$commit" = 38a6a14da123687943a665e410f630c776e9b729 || { echo 'Unexpected source commit' >&2; exit 1; }
test "$(uname -m)" = x86_64
mkdir -p "$out"
out=$(cd "$out" && pwd)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
cargo build --manifest-path "$root/Cargo.toml" --release --locked --bin raxosentinel
mkdir -p "$work/bin-package/bin" "$work/db-package/$gen"
install -m 755 "$root/target/release/raxosentinel" "$work/bin-package/bin/raxosentinel"
install -m 644 "$root/LICENSE" "$work/bin-package/LICENSE"
install -m 755 "$root/private-test-package/install-staging.sh" "$work/bin-package/install-staging.sh"
install -m 644 "$root/private-test-package/README.md" "$work/bin-package/README.md"
cp -a "$store/$gen/." "$work/db-package/$gen/"
printf '%s' "$gen" > "$work/db-package/current"
if test -f "$store/update_status.json"; then cp "$store/update_status.json" "$work/db-package/"; fi
chmod -R go-rwx "$work/db-package"
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -C "$work/bin-package" -czf "$out/raxosentinel-38a6a14-linux-x86_64.tar.gz" .
tar --sort=name --mtime='@0' --owner=0 --group=0 --numeric-owner -C "$work/db-package" -czf "$out/raxosentinel-private-phase2d6-unified.tar.gz" .
(cd "$out" && sha256sum raxosentinel-38a6a14-linux-x86_64.tar.gz raxosentinel-private-phase2d6-unified.tar.gz > SHA256SUMS)
mkdir -m 700 "$work/clean"
tar -xzf "$out/raxosentinel-private-phase2d6-unified.tar.gz" -C "$work/clean"
"$work/bin-package/bin/raxosentinel" db sources --root "$work/clean" --generation "$gen"
printf 'Source commit: %s\nTarget: x86_64-unknown-linux-gnu\nGeneration: %s\n' "$commit" "$gen"
ls -lh "$out"/*.tar.gz
