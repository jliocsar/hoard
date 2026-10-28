#!/usr/bin/env bash
# Deploys hoard to its exe.dev VM. It syncs the source, installs and builds on
# the VM, then restarts the systemd unit. It's safe to re-run, and the first run
# also provisions the VM: Bun, the hoard user, /etc/hoard and the unit.
#
# Secrets come from apps/web/.env and land in /etc/hoard/env, which the unit
# loads with `bun --env-file` so `\$` escapes parse exactly as they do locally.
set -euo pipefail

HOST="${HOARD_HOST:-jc-hoard.exe.xyz}"
BUN_VERSION="1.4.4"
# From https://github.com/oven-sh/bun/releases/download/bun-v$BUN_VERSION/SHASUMS256.txt.
# Update them together with BUN_VERSION.
BUN_SHA256_X64="bf8ccbfb2b0b80159e0f9a6d15c55317add8077534dbc6130a3edb52fccb395c"
BUN_SHA256_X64_BASELINE="e0446eb55995772eb9894bebae9a6be368d985a8b9271ee124486f9946eedd76"
BUN_SHA256_AARCH64="baa6bb36f51d6e58561e02bbea825038a9df454f673d6d776e8bbf86f8c7850e"
APP_DIR="/opt/hoard"
ENV_FILE="apps/web/.env"

cd "$(dirname "$0")/.."

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE" >&2
  exit 1
fi

echo "→ provisioning $HOST"
ssh "$HOST" BUN_VERSION="$BUN_VERSION" APP_DIR="$APP_DIR" \
  BUN_SHA256_X64="$BUN_SHA256_X64" BUN_SHA256_X64_BASELINE="$BUN_SHA256_X64_BASELINE" \
  BUN_SHA256_AARCH64="$BUN_SHA256_AARCH64" bash -s <<'EOF'
set -euo pipefail
if [[ "$(/usr/local/bin/bun --version 2>/dev/null || true)" != "$BUN_VERSION" ]]; then
  case "$(uname -m)" in
    x86_64)
      if grep -q avx2 /proc/cpuinfo; then
        target=bun-linux-x64 sha="$BUN_SHA256_X64"
      else
        target=bun-linux-x64-baseline sha="$BUN_SHA256_X64_BASELINE"
      fi
      ;;
    aarch64 | arm64) target=bun-linux-aarch64 sha="$BUN_SHA256_AARCH64" ;;
    *) echo "no pinned Bun build for $(uname -m)" >&2; exit 1 ;;
  esac
  work="$(mktemp -d)"
  trap 'rm -rf "$work"' EXIT
  curl -fsSL -o "$work/bun.zip" \
    "https://github.com/oven-sh/bun/releases/download/bun-v$BUN_VERSION/$target.zip"
  echo "$sha  $work/bun.zip" | sha256sum -c --quiet
  unzip -q "$work/bun.zip" -d "$work"
  sudo install -m 755 "$work/$target/bun" /usr/local/bin/bun
  sudo ln -sf bun /usr/local/bin/bunx
fi
if ! id hoard >/dev/null 2>&1; then
  sudo useradd --system --home-dir /var/lib/hoard --shell /usr/sbin/nologin hoard
fi
sudo install -d -o "$USER" -g "$USER" "$APP_DIR"
sudo install -d -m 750 -o root -g hoard /etc/hoard
EOF

echo "→ syncing source"
rsync -az --delete \
  --exclude .git --exclude .agents --exclude .claude --exclude tmp/ \
  --exclude .env --exclude '*.db' --exclude '*.db-*' --exclude .alchemy \
  --filter=':- .gitignore' \
  ./ "$HOST:$APP_DIR/"

echo "→ syncing secrets"
ssh "$HOST" 'sudo install -m 640 -o root -g hoard /dev/stdin /etc/hoard/env' <"$ENV_FILE"

echo "→ installing and building"
ssh "$HOST" APP_DIR="$APP_DIR" bash -s <<'EOF'
set -euo pipefail
cd "$APP_DIR"
bun install --frozen-lockfile --ignore-scripts
cd apps/web
bun run build
sudo install -m 644 "$APP_DIR/deploy/hoard.service" /etc/systemd/system/hoard.service
sudo systemctl daemon-reload
sudo systemctl enable --quiet hoard
sudo systemctl restart hoard
EOF

echo "→ waiting for it to answer"
for _ in $(seq 1 30); do
  if ssh "$HOST" 'curl -fsS -o /dev/null http://127.0.0.1:8000/login'; then
    echo "✓ up at https://${HOST}/"
    exit 0
  fi
  sleep 1
done

echo "✗ no answer on :8000; see: ssh $HOST journalctl -u hoard -n 50" >&2
exit 1
