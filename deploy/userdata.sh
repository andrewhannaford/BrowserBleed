#!/bin/bash
# Runs on first boot via EC2 user data.
# DOMAIN_PLACEHOLDER is substituted by provision.sh before upload.
set -euo pipefail

dnf update -y
dnf install -y nginx python3-certbot-nginx

useradd -r -s /sbin/nologin bb-reports 2>/dev/null || true

mkdir -p /opt/bb-reports/data
mkdir -p /var/www/certbot/.well-known/acme-challenge
chown -R bb-reports:bb-reports /opt/bb-reports

cat > /etc/nginx/conf.d/bb-reports.conf << 'NGINXCONF'
server {
    listen 80;
    server_name DOMAIN_PLACEHOLDER;

    location /.well-known/acme-challenge/ {
        root /var/www/certbot;
    }

    location / {
        return 200 'Service Unavailable';
        add_header Content-Type text/plain;
    }
}
NGINXCONF

systemctl enable nginx
systemctl start nginx
