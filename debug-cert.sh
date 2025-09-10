#!/usr/bin/env bash
# Debug ACME certificate details for Kubernetes authentication

set -e

FQDN="k3s-dev.batonac.com"
TEMP_CERTS_DIR=$(mktemp -d)

cleanup() {
    rm -rf "$TEMP_CERTS_DIR"
}
trap cleanup EXIT

echo "🔍 Fetching and analyzing ACME certificate..."

# SCP the certificates
if ! scp -q "root@${FQDN}:/var/lib/acme/${FQDN}/cert.pem" "$TEMP_CERTS_DIR/"; then
    echo "❌ Failed to fetch certificate"
    exit 1
fi

echo ""
echo "📋 Certificate Details:"
echo "======================"

# Show certificate subject and issuer
echo "Subject:"
openssl x509 -in "$TEMP_CERTS_DIR/cert.pem" -noout -subject

echo ""
echo "Subject Alternative Names:"
openssl x509 -in "$TEMP_CERTS_DIR/cert.pem" -noout -text | grep -A1 "Subject Alternative Name" || echo "None found"

echo ""
echo "Common Name (CN):"
CN=$(openssl x509 -in "$TEMP_CERTS_DIR/cert.pem" -noout -subject | sed -n 's/.*CN=\([^,]*\).*/\1/p')
echo "  $CN"

echo ""
echo "🎯 For Kubernetes RBAC, the user will be identified as: '$CN'"
echo ""
echo "💡 Current ClusterRoleBinding in flake.nix should bind user '$CN' to cluster-admin"

# Check if this matches what we expect
if [ "$CN" = "$FQDN" ]; then
    echo "✅ Certificate CN matches expected FQDN"
else
    echo "⚠️  Certificate CN '$CN' does not match expected FQDN '$FQDN'"
    echo "   You may need to update the ClusterRoleBinding subject name"
fi