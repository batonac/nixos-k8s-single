#!/usr/bin/env bash
# Generate kubeconfig using easyCerts client certs but ACME server certificates

set -e

echo "🔧 Generating kubeconfig using easyCerts client authentication..."

# Configuration
CLUSTER_NAME="k3s-dev"
FQDN="k3s-dev.batonac.com"
SERVER_URL="https://${FQDN}:6443"
CONFIG_FILE="kubeconfig-${CLUSTER_NAME}.yaml"
TEMP_FILES_DIR=$(mktemp -d)

# Cleanup function
cleanup() {
    rm -rf "$TEMP_FILES_DIR"
}
trap cleanup EXIT

echo "📥 Fetching certificates and kubeconfig from ${FQDN}..."

# Fetch the ACME CA certificate (for server verification)
if ! scp -q "root@${FQDN}:/var/lib/acme/${FQDN}/chain.pem" "$TEMP_FILES_DIR/server-ca.pem"; then
    echo "❌ Failed to fetch ACME CA certificate. Make sure:"
    echo "  1. SSH access to root@${FQDN} is working"
    echo "  2. ACME certificates exist on the server"
    echo "  3. The server has been deployed with easyCerts enabled"
    exit 1
fi

# Fetch the easyCerts kubeconfig (contains client certificates)
if ! scp -q "root@${FQDN}:/etc/kubernetes/cluster-admin.kubeconfig" "$TEMP_FILES_DIR/"; then
    echo "❌ Failed to fetch easyCerts kubeconfig from /etc/kubernetes/cluster-admin.kubeconfig"
    echo "Make sure easyCerts is enabled and the cluster is running"
    exit 1
fi

echo "✅ Files fetched successfully"

# Get certificate expiry for info
CERT_EXPIRY=$(openssl x509 -in "$TEMP_FILES_DIR/server-ca.pem" -noout -enddate | cut -d= -f2)
echo "📅 Server certificate expires: $CERT_EXPIRY"

# Parse the easyCerts kubeconfig and extract client certificates
echo "🔨 Generating hybrid kubeconfig..."

# Extract client certificate and key from easyCerts kubeconfig
CLIENT_CERT_DATA=$(grep "client-certificate-data" "$TEMP_FILES_DIR/cluster-admin.kubeconfig" | awk '{print $2}')
CLIENT_KEY_DATA=$(grep "client-key-data" "$TEMP_FILES_DIR/cluster-admin.kubeconfig" | awk '{print $2}')

if [ -z "$CLIENT_CERT_DATA" ] || [ -z "$CLIENT_KEY_DATA" ]; then
    echo "❌ Failed to extract client certificates from easyCerts kubeconfig"
    echo "The kubeconfig might not be in the expected format"
    exit 1
fi

# Generate new kubeconfig with ACME server CA but easyCerts client authentication
cat > "$CONFIG_FILE" << EOF
apiVersion: v1
kind: Config
clusters:
- cluster:
    certificate-authority-data: $(base64 -w 0 "$TEMP_FILES_DIR/server-ca.pem")
    server: ${SERVER_URL}
  name: ${CLUSTER_NAME}
contexts:
- context:
    cluster: ${CLUSTER_NAME}
    user: cluster-admin
  name: ${CLUSTER_NAME}
current-context: ${CLUSTER_NAME}
users:
- name: cluster-admin
  user:
    client-certificate-data: ${CLIENT_CERT_DATA}
    client-key-data: ${CLIENT_KEY_DATA}
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
echo "   Just re-run this script - both easyCerts and ACME certificates will be fetched fresh"