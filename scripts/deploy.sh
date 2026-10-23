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
APP_DIR="/opt/hoard"
ENV_FILE="apps/web/.env"

cd "$(dirname "$0")/.."

if [[ ! -f "$ENV_FILE" ]]; then
  echo "missing $ENV_FILE" >&2
  exit 1
fi

echo "→ provisioning $HOST"
ssh "$HOST" BUN_VERSION="$BUN_VERSION" APP_DIR="$APP_DIR" bash -s <<'EOF'
set -euo pipefail
if [[ "$(/usr/local/bin/bun --version 2>/dev/null || true)" != "$BUN_VERSION" ]]; then
  curl -fsSL https://bun.sh/install | sudo BUN_INSTALL=/usr/local bash -s "bun-v$BUN_VERSION" >/dev/null
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
