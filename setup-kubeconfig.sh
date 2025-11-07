#!/bin/bash

# Script to decrypt and set up local kubeconfig for cluster access
# Run this after the system is deployed and certificates are generated

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "🔐 Setting up local kubeconfig for cluster access..."

# Check if agenix is available
if ! command -v agenix &> /dev/null; then
    echo "❌ Error: agenix is not available. Please run this from the nix development shell."
    echo "   nix develop"
    exit 1
fi

# Create .kube directory if it doesn't exist
mkdir -p ~/.kube

# Decrypt the admin kubeconfig
echo "📋 Decrypting admin kubeconfig..."
cd "$SCRIPT_DIR"
agenix -d secrets/k8s-admin.kubeconfig.age -i ~/.ssh/id_agenix > ~/.kube/config

# Set proper permissions
chmod 600 ~/.kube/config

echo "✅ Kubeconfig setup complete!"
echo ""
echo "You can now use kubectl to interact with your cluster:"
echo "  kubectl get nodes"
echo "  kubectl get pods --all-namespaces"
echo ""
echo "To test cluster connectivity:"
echo "  kubectl cluster-info"