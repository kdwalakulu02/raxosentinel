#!/usr/bin/env bash
set -euo pipefail
umask 077
[ "$(id -u)" = 0 ] || { echo 'Run as root.' >&2; exit 1; }
[ "$(uname -m)" = x86_64 ] || { echo 'Requires x86_64.' >&2; exit 1; }
[ "$#" = 1 ] || { echo 'Usage: install-staging.sh VERIFIED_ARTIFACT_DIRECTORY' >&2; exit 1; }
a=$(realpath "$1")
(cd "$a" && sha256sum -c SHA256SUMS)
base=/opt/raxosentinel-staging
state=/var/lib/raxosentinel-staging
unit=/etc/systemd/system/raxosentinel-staging.service
for path in "$base" "$state" "$unit"; do [ ! -e "$path" ] || { echo "Already exists: $path; refusing to overwrite" >&2; exit 1; }; done
if getent passwd raxosentinel-staging >/dev/null; then echo 'Service account already exists; refusing to reuse' >&2; exit 1; fi
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
mkdir -m 700 "$work/db" "$work/bin"
tar -xzf "$a/raxosentinel-38a6a14-linux-x86_64.tar.gz" -C "$work/bin"
tar -xzf "$a/raxosentinel-private-phase2d6-unified.tar.gz" -C "$work/db"
ldd "$work/bin/bin/raxosentinel" | tee "$work/ldd"
! grep -q 'not found' "$work/ldd"
useradd --system --user-group --home-dir "$state" --no-create-home --shell /usr/sbin/nologin raxosentinel-staging
install -d -m 755 "$base/bin"
install -m 755 "$work/bin/bin/raxosentinel" "$base/bin/raxosentinel"
install -d -m 700 -o raxosentinel-staging -g raxosentinel-staging "$state"
cp -a "$work/db/." "$state/"
chown -R raxosentinel-staging:raxosentinel-staging "$state"
chmod -R go-rwx "$state"
runuser -u raxosentinel-staging -- "$base/bin/raxosentinel" db sources --root "$state" --generation phase2d6-unified
cat > "$unit" <<'UNIT'
[Unit]
Description=RaxoSentinel isolated staging scanner
After=local-fs.target
[Service]
Type=simple
User=raxosentinel-staging
Group=raxosentinel-staging
RuntimeDirectory=raxosentinel-staging
RuntimeDirectoryMode=0700
UMask=0077
ExecStart=/opt/raxosentinel-staging/bin/raxosentinel serve --socket /run/raxosentinel-staging/scan.sock --private-db-root /var/lib/raxosentinel-staging --private-generation phase2d6-unified --max-workers 1 --worker-memory 1073741824 --worker-timeout-ms 10000
MemoryMax=4G
NoNewPrivileges=true
Restart=on-failure
[Install]
WantedBy=multi-user.target
UNIT
systemctl daemon-reload
systemctl start raxosentinel-staging.service
systemctl is-active --quiet raxosentinel-staging.service
printf 'Staging service started. Socket access is limited to its service account.\n'
