#!/usr/bin/env bash
# provision.sh - spins up the BrowserBleed report server on AWS
# Run from Git Bash on Windows: bash deploy/provision.sh
# Requires: aws cli (authenticated), deploy/config filled in

set -euo pipefail

source "$(dirname "$0")/config" 2>/dev/null || {
  echo "[!] Copy deploy/config.example to deploy/config and fill in your values."
  exit 1
}

echo "=== BrowserBleed Report Server Provisioner ==="
echo "    Domain: $DOMAIN  Region: $REGION"

# ── Key pair ──────────────────────────────────────────────────────────────────
if ! aws ec2 describe-key-pairs --key-names "$KEY_NAME" --region "$REGION" &>/dev/null; then
  echo "[*] Creating SSH key pair '$KEY_NAME'..."
  aws ec2 create-key-pair \
    --key-name "$KEY_NAME" \
    --region "$REGION" \
    --query 'KeyMaterial' \
    --output text > "deploy/${KEY_NAME}.pem"
  chmod 600 "deploy/${KEY_NAME}.pem"
  echo "[+] Key saved to deploy/${KEY_NAME}.pem"
else
  echo "[*] Key pair '$KEY_NAME' already exists."
fi

# ── Security group ────────────────────────────────────────────────────────────
MY_IP=$(curl -sf https://checkip.amazonaws.com)
echo "[*] Your public IP: $MY_IP"

SG_NAME="bb-reports-sg"
if ! aws ec2 describe-security-groups --group-names "$SG_NAME" --region "$REGION" &>/dev/null; then
  echo "[*] Creating security group..."
  SG_ID=$(aws ec2 create-security-group \
    --group-name "$SG_NAME" \
    --description "BrowserBleed report server" \
    --region "$REGION" \
    --query 'GroupId' --output text)

  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 22 \
    --cidr "${MY_IP}/32" --region "$REGION"
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 80 \
    --cidr "0.0.0.0/0" --region "$REGION"
  aws ec2 authorize-security-group-ingress --group-id "$SG_ID" --protocol tcp --port 443 \
    --cidr "0.0.0.0/0" --region "$REGION"

  echo "[+] Security group created: $SG_ID"
else
  SG_ID=$(aws ec2 describe-security-groups \
    --group-names "$SG_NAME" --region "$REGION" \
    --query 'SecurityGroups[0].GroupId' --output text)
  echo "[*] Using existing security group: $SG_ID"
fi

# ── AMI - latest Amazon Linux 2023 ───────────────────────────────────────────
echo "[*] Finding latest Amazon Linux 2023 AMI..."
AMI_ID=$(aws ec2 describe-images \
  --owners amazon \
  --filters \
    "Name=name,Values=al2023-ami-2023.*-x86_64" \
    "Name=state,Values=available" \
  --region "$REGION" \
  --query 'sort_by(Images, &CreationDate)[-1].ImageId' \
  --output text)
echo "[*] AMI: $AMI_ID"

# ── EC2 instance ──────────────────────────────────────────────────────────────
echo "[*] Rendering userdata with domain substitution..."
RENDERED="$(dirname "$0")/userdata-rendered.sh"
sed "s/DOMAIN_PLACEHOLDER/${DOMAIN}/g" "$(dirname "$0")/userdata.sh" > "$RENDERED"
# Convert to a Windows-style path so the native AWS CLI can read it via file://
RENDERED_WIN=$(cygpath -m "$(realpath "$RENDERED")")

echo "[*] Launching EC2 instance ($INSTANCE_TYPE)..."
INSTANCE_ID=$(aws ec2 run-instances \
  --image-id "$AMI_ID" \
  --instance-type "$INSTANCE_TYPE" \
  --key-name "$KEY_NAME" \
  --security-group-ids "$SG_ID" \
  --user-data "file://$RENDERED_WIN" \
  --block-device-mappings '[{"DeviceName":"/dev/xvda","Ebs":{"VolumeSize":8,"VolumeType":"gp3","DeleteOnTermination":true}}]' \
  --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=bb-reports}]" \
  --region "$REGION" \
  --query 'Instances[0].InstanceId' --output text)
rm -f "$RENDERED"

echo "[*] Waiting for instance to reach running state..."
aws ec2 wait instance-running --instance-ids "$INSTANCE_ID" --region "$REGION"
echo "[+] Instance running: $INSTANCE_ID"

# ── Elastic IP ────────────────────────────────────────────────────────────────
echo "[*] Allocating Elastic IP..."
ALLOC_ID=$(aws ec2 allocate-address \
  --domain vpc \
  --region "$REGION" \
  --query 'AllocationId' --output text)

aws ec2 associate-address \
  --instance-id "$INSTANCE_ID" \
  --allocation-id "$ALLOC_ID" \
  --region "$REGION" > /dev/null

PUBLIC_IP=$(aws ec2 describe-addresses \
  --allocation-ids "$ALLOC_ID" \
  --region "$REGION" \
  --query 'Addresses[0].PublicIp' --output text)
echo "[+] Elastic IP: $PUBLIC_IP"

# ── Route 53 ─────────────────────────────────────────────────────────────────
echo "[*] Creating DNS record: $DOMAIN -> $PUBLIC_IP"
ZONE_ID=$(aws route53 list-hosted-zones \
  --query "HostedZones[?Name=='${ROOT_DOMAIN}'].Id" \
  --output text | cut -d'/' -f3)

aws route53 change-resource-record-sets \
  --hosted-zone-id "$ZONE_ID" \
  --change-batch "{
    \"Changes\": [{
      \"Action\": \"UPSERT\",
      \"ResourceRecordSet\": {
        \"Name\": \"${DOMAIN}\",
        \"Type\": \"A\",
        \"TTL\": 60,
        \"ResourceRecords\": [{\"Value\": \"${PUBLIC_IP}\"}]
      }
    }]
  }" > /dev/null
echo "[+] DNS record set."

# ── Save state for later steps ────────────────────────────────────────────────
cat > "$(dirname "$0")/.provision-state" << EOF
INSTANCE_ID=$INSTANCE_ID
PUBLIC_IP=$PUBLIC_IP
ALLOC_ID=$ALLOC_ID
ZONE_ID=$ZONE_ID
SG_ID=$SG_ID
DOMAIN=$DOMAIN
EOF

echo ""
echo "=== Provisioning complete ==="
echo "    Instance: $INSTANCE_ID"
echo "    IP:       $PUBLIC_IP"
echo "    Domain:   $DOMAIN"
echo ""
echo "Next steps:"
echo "  1. Wait ~60s for SSH to be ready, then:"
echo "     bash deploy/setup-server.sh"
echo "  2. Build and deploy the binary:"
echo "     bash deploy/deploy-binary.sh"
