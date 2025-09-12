#!/usr/bin/env bash
# Generate kubeconfig locally by fetching ACME certificates via SCP

set -e

echo "🔧 Generating kubeconfig locally using ACME certificates..."

# Configuration
CLUSTER_NAME="k3s-dev"
FQDN="k3s-dev.batonac.com"
SERVER_URL="https://${FQDN}:6443"
CONFIG_FILE="kubeconfig-${CLUSTER_NAME}.yaml"
TEMP_CERTS_DIR=$(mktemp -d)
REMOTE_CERT_DIR="/var/lib/acme/${FQDN}"

# Cleanup function
cleanup() {
    rm -rf "$TEMP_CERTS_DIR"
}
trap cleanup EXIT

echo "📥 Fetching certificates from ${FQDN}..."

# SCP the certificates from the server
if ! scp -q "root@${FQDN}:${REMOTE_CERT_DIR}/cert.pem" "$TEMP_CERTS_DIR/"; then
    echo "❌ Failed to fetch cert.pem. Make sure:"
    echo "  1. SSH access to root@${FQDN} is working"
    echo "  2. ACME certificates exist on the server"
    echo "  3. The server has been deployed and certificates generated"
    exit 1
fi

if ! scp -q "root@${FQDN}:${REMOTE_CERT_DIR}/key.pem" "$TEMP_CERTS_DIR/"; then
    echo "❌ Failed to fetch key.pem"
    exit 1
fi

if ! scp -q "root@${FQDN}:${REMOTE_CERT_DIR}/chain.pem" "$TEMP_CERTS_DIR/"; then
    echo "❌ Failed to fetch chain.pem"
    exit 1
fi

echo "✅ Certificates fetched successfully"

# Get certificate expiry for info
CERT_EXPIRY=$(openssl x509 -in "$TEMP_CERTS_DIR/cert.pem" -noout -enddate | cut -d= -f2)
echo "📅 Certificate expires: $CERT_EXPIRY"

# Generate kubeconfig locally
echo "🔨 Generating kubeconfig..."

cat > "$CONFIG_FILE" << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: $(base64 -w 0 "$TEMP_CERTS_DIR/chain.pem")
    server: ${SERVER_URL}
  name: ${CLUSTER_NAME}
contexts:
- context:
    cluster: ${CLUSTER_NAME}
    user: kubernetes-admin
  name: ${CLUSTER_NAME}
current-context: ${CLUSTER_NAME}
users:
- name: kubernetes-admin
  user:
    client-certificate-data: $(base64 -w 0 "$TEMP_CERTS_DIR/cert.pem")
    client-key-data: $(base64 -w 0 "$TEMP_CERTS_DIR/key.pem")
EOF

echo "✅ Kubeconfig generated: $CONFIG_FILE"
echo ""
echo "🧪 Testing connection..."
if command -v kubectl >/dev/null 2>&1; then
    if kubectl --kubeconfig="$CONFIG_FILE" cluster-info --request-timeout=5s >/dev/null 2>&1; then
        echo "✅ Connection successful!"
        echo ""
        echo "📊 Cluster info:"
        kubectl --kubeconfig="$CONFIG_FILE" cluster-info
    else
        echo "⚠️  Connection failed - cluster might be starting up"
    fi
else
    echo "💡 Install kubectl to test the connection"
fi

echo ""
echo "Usage:"
echo "  kubectl --kubeconfig=$CONFIG_FILE get nodes"
echo "  export KUBECONFIG=$PWD/$CONFIG_FILE"
echo ""
echo "For Lens: Import $PWD/$CONFIG_FILE in Lens to connect to your cluster"
echo ""
echo "🔄 To refresh after certificate renewal:"
echo "   Just re-run this script - certificates auto-renew every ~60-90 days"