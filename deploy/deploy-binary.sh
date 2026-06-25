#!/usr/bin/env bash
# deploy-binary.sh — cross-compile the Go server and push it to EC2.
# Uses EC2 Instance Connect (AWS SSO) — no PEM file required.
#
# Prerequisites:
#   aws sso login   (if your SSO session has expired)
#
# Run from the repo root:
#   bash deploy/deploy-binary.sh

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
REPO_ROOT="$(cd "$SCRIPT_DIR/.." && pwd)"
source "$SCRIPT_DIR/config"
source "$SCRIPT_DIR/.provision-state"

OS_USER="ec2-user"
TEMP_KEY="$(mktemp /tmp/bb-deploy-key.XXXXXX)"
TEMP_PUB="${TEMP_KEY}.pub"

cleanup() { rm -f "$TEMP_KEY" "$TEMP_PUB"; }
trap cleanup EXIT

# ── Build Linux binary ────────────────────────────────────────────────────────
echo "[*] Building server binary for linux/amd64..."
(cd "$SCRIPT_DIR/../server" && GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o ../deploy/server-linux ./cmd/server/)
echo "[+] Built: $(du -sh "$SCRIPT_DIR/server-linux" | cut -f1)"

# ── EC2 Instance Connect: push a temp key (valid 60s) ────────────────────────
echo "[*] Pushing temporary SSH key via EC2 Instance Connect..."
rm -f "$TEMP_KEY"
ssh-keygen -t rsa -b 2048 -f "$TEMP_KEY" -N "" -q
aws ec2-instance-connect send-ssh-public-key \
  --instance-id "$INSTANCE_ID" \
  --instance-os-user "$OS_USER" \
  --ssh-public-key "$(cat "$TEMP_PUB")" \
  --region "${REGION:-us-east-1}" \
  --output json | grep -q '"Success": true'
echo "[+] Key pushed (60s window)"

SSH_OPTS="-o StrictHostKeyChecking=no -o ConnectTimeout=10 -i $TEMP_KEY"
REMOTE="${OS_USER}@${PUBLIC_IP}"

# ── Upload binary ─────────────────────────────────────────────────────────────
echo "[*] Uploading binary..."
scp $SSH_OPTS "$SCRIPT_DIR/server-linux" "${REMOTE}:/tmp/server-linux"

# ── Install and restart ───────────────────────────────────────────────────────
echo "[*] Installing and restarting service..."
# Re-push the key before the SSH session (SCP may have used the 60s window)
aws ec2-instance-connect send-ssh-public-key \
  --instance-id "$INSTANCE_ID" \
  --instance-os-user "$OS_USER" \
  --ssh-public-key "$(cat "$TEMP_PUB")" \
  --region "${REGION:-us-east-1}" \
  --output json > /dev/null

ssh $SSH_OPTS "$REMOTE" bash << 'ENDSSH'
  sudo mv /tmp/server-linux /opt/bb-reports/server
  sudo chmod +x /opt/bb-reports/server
  sudo chown bb-reports:bb-reports /opt/bb-reports/server
  sudo systemctl restart bb-reports
  sudo systemctl status bb-reports --no-pager -l
ENDSSH

rm -f "$SCRIPT_DIR/server-linux"

echo ""
echo "[+] Deploy complete."
echo "    Reports UI:  https://${DOMAIN}/"
echo "    Upload URL:  https://${DOMAIN}/upload"
echo "    Builds UI:   https://${DOMAIN}/payloads"
echo ""
echo "    To process build jobs: python build_agent.py (run on your Windows machine)"
