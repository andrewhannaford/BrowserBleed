#!/usr/bin/env bash
# setup-server.sh - SSHes into the EC2 and configures nginx + TLS + systemd
# Run after provision.sh: bash deploy/setup-server.sh

set -euo pipefail

source "$(dirname "$0")/config" 2>/dev/null || {
  echo "[!] Copy deploy/config.example to deploy/config and fill in your values."
  exit 1
}

source "$(dirname "$0")/.provision-state"

KEY="$(dirname "$0")/${KEY_NAME}.pem"
SSH="ssh -i $KEY -o StrictHostKeyChecking=no ec2-user@$PUBLIC_IP"

echo "[*] Waiting for SSH on $PUBLIC_IP..."
until $SSH "echo ok" 2>/dev/null; do sleep 5; done
echo "[+] SSH ready."

# ── Render configs with domain substitution ───────────────────────────────────
echo "[*] Rendering nginx config..."
NGINX_RENDERED="$(dirname "$0")/nginx-rendered.conf"
sed "s/DOMAIN_PLACEHOLDER/${DOMAIN}/g" "$(dirname "$0")/nginx.conf" > "$NGINX_RENDERED"

# ── Upload configs ────────────────────────────────────────────────────────────
echo "[*] Uploading nginx config and systemd unit..."
scp -i "$KEY" -o StrictHostKeyChecking=no \
  "$NGINX_RENDERED" \
  "$(dirname "$0")/bb-reports.service" \
  "ec2-user@$PUBLIC_IP:/tmp/"
rm -f "$NGINX_RENDERED"

# ── Run remote setup ─────────────────────────────────────────────────────────
$SSH "DOMAIN=${DOMAIN} EMAIL=${EMAIL} sudo -E bash -s" << 'REMOTE'
set -euo pipefail

systemctl is-active nginx || systemctl start nginx

certbot certonly \
  --webroot \
  --webroot-path /var/www/certbot \
  -d "$DOMAIN" \
  --non-interactive \
  --agree-tos \
  --email "$EMAIL"

cp /tmp/nginx-rendered.conf /etc/nginx/conf.d/bb-reports.conf
nginx -t && systemctl reload nginx

cp /tmp/bb-reports.service /etc/systemd/system/bb-reports.service
systemctl daemon-reload
systemctl enable bb-reports

echo "[+] Server configured."
REMOTE

echo ""
echo "[+] Setup complete."
echo "    https://${DOMAIN} is live."
echo ""
echo "Next: bash deploy/deploy-binary.sh"
