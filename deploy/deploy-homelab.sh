#!/usr/bin/env bash
# deploy-homelab.sh — build the Go report server for linux/amd64 and deploy to docker-svc.
# Run from the repo root:  bash deploy/deploy-homelab.sh
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
SSH_TARGET="${BB_SSH_TARGET:-docker-svc@10.20.0.193}"
REMOTE_BIN="/opt/docker/services/browserbleed/server"
REMOTE_SESSIONTEST="/opt/docker/services/browserbleed/sessiontest.py"
SSH_KEY="${BB_SSH_KEY:-$HOME/.ssh/bb_deploy}"
SSH_OPTS=(-i "$SSH_KEY" -o IdentitiesOnly=yes)

echo "[*] Building server binary for linux/amd64..."
(cd "$REPO_ROOT/server" && GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o "$SCRIPT_DIR/server-linux" ./cmd/server/)
echo "[+] Built: $(du -sh "$SCRIPT_DIR/server-linux" | cut -f1)"

echo "[*] Uploading to $SSH_TARGET ..."
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "mv $REMOTE_BIN ${REMOTE_BIN}.old 2>/dev/null || true"
scp "${SSH_OPTS[@]}" "$SCRIPT_DIR/server-linux" "$SSH_TARGET:/tmp/server-linux"
scp "${SSH_OPTS[@]}" "$REPO_ROOT/sessiontest.py" "$SSH_TARGET:/tmp/sessiontest.py"
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "mv /tmp/server-linux $REMOTE_BIN && chmod +x $REMOTE_BIN && mv /tmp/sessiontest.py $REMOTE_SESSIONTEST && docker restart browserbleed"
rm -f "$SCRIPT_DIR/server-linux"

echo ""
echo "[+] Deploy complete."
ssh "${SSH_OPTS[@]}" "$SSH_TARGET" "docker ps --filter name=browserbleed --format '{{.Names}} | {{.Status}}'"
echo "    UI:     https://browserbleed.lanarchy.net/"
echo "    Upload: https://browserbleed.lanarchy.net/upload"
