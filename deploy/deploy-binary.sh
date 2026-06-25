#!/usr/bin/env bash
# deploy-binary.sh — builds the Linux server binary and pushes it to the EC2.
# Run from the repo root: bash deploy/deploy-binary.sh

set -euo pipefail

source "$(dirname "$0")/config" 2>/dev/null || {
  echo "[!] Copy deploy/config.example to deploy/config and fill in your values."
  exit 1
}

source "$(dirname "$0")/.provision-state"

KEY="$(dirname "$0")/${KEY_NAME}.pem"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no ec2-user@$PUBLIC_IP"
SCP="scp -i $KEY -o StrictHostKeyChecking=no"

# ── Build Linux binary ────────────────────────────────────────────────────────
echo "[*] Building server binary for linux/amd64..."
(cd server && GOOS=linux GOARCH=amd64 go build -ldflags "-s -w" -o ../deploy/server-linux ./cmd/server/)
echo "[+] Binary built: $(du -sh deploy/server-linux | cut -f1)"

# ── Upload binary ─────────────────────────────────────────────────────────────
echo "[*] Uploading binary..."
$SCP deploy/server-linux "ec2-user@$PUBLIC_IP:/tmp/server-linux"
$SSH "sudo mv /tmp/server-linux /opt/bb-reports/server && sudo chmod +x /opt/bb-reports/server && sudo chown bb-reports:bb-reports /opt/bb-reports/server"

# ── Create .env if it doesn't exist ──────────────────────────────────────────
if ! $SSH "sudo test -f /opt/bb-reports/.env"; then
  echo ""
  echo "[*] First deploy — setting up credentials."
  read -rp    "    API_KEY (used by BrowserBleed --exfil-key and browser login): " BB_API_KEY
  read -rp    "    ENCRYPTION_KEY (64-char hex, run: openssl rand -hex 32):      " BB_ENC_KEY
  BASE_URL_DEFAULT="https://${DOMAIN}"
  read -rp    "    BASE_URL [${BASE_URL_DEFAULT}]:                               " BB_BASE_URL
  BB_BASE_URL="${BB_BASE_URL:-$BASE_URL_DEFAULT}"
  TTL_DEFAULT="${REPORT_TTL:-24h}"
  read -rp    "    REPORT_TTL [${TTL_DEFAULT}]:                                  " BB_TTL
  BB_TTL="${BB_TTL:-$TTL_DEFAULT}"

  $SSH "sudo tee /opt/bb-reports/.env > /dev/null" << EOF
API_KEY=${BB_API_KEY}
ENCRYPTION_KEY=${BB_ENC_KEY}
BASE_URL=${BB_BASE_URL}
REPORT_TTL=${BB_TTL}
EOF
  $SSH "sudo chmod 600 /opt/bb-reports/.env && sudo chown bb-reports:bb-reports /opt/bb-reports/.env"
  echo "[+] Credentials saved to /opt/bb-reports/.env on server."
fi

# ── Restart service ───────────────────────────────────────────────────────────
echo "[*] Restarting bb-reports service..."
$SSH "sudo systemctl restart bb-reports"
sleep 2
$SSH "sudo systemctl status bb-reports --no-pager -l"

echo ""
echo "[+] Deploy complete."
echo "    Reports UI:  https://${DOMAIN}/"
echo "    Upload URL:  https://${DOMAIN}/upload"
