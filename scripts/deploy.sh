#!/usr/bin/env bash
set -euo pipefail

# Parse FQDN argument
FQDN="${1:-k3s-dev.batonac.com}"
HOSTNAME="${FQDN%%.*}"  # Extract hostname from FQDN (everything before first dot)

# Ensure AGENIX_KEY is set
if [[ -z "${AGENIX_KEY:-}" ]]; then
  echo "❌ AGENIX_KEY environment variable is not set."
  echo "   Export the shared age key before deploying:"
  echo "   export AGENIX_KEY='AGE-SECRET-KEY-...'"
  exit 1
fi

echo "🚀 Deploying NixOS to $FQDN (hostname: $HOSTNAME)"
echo ""

# Create a temporary directory for extra files
temp=$(mktemp -d)

# Function to cleanup temporary directory on exit
cleanup() {
  rm -rf "$temp"
}
trap cleanup EXIT

# Deploy the agenix key so the host can decrypt secrets
# AGENIX_KEY stores the key with literal \n for line breaks; convert them back
echo "🔑 Deploying agenix key..."
install -d -m700 "$temp/etc/agenix"
printf '%b\n' "$AGENIX_KEY" > "$temp/etc/agenix/key"
chmod 600 "$temp/etc/agenix/key"

echo "🔧 Running nixos-anywhere..."
# Install NixOS to the host system with our secrets
nix run github:nix-community/nixos-anywhere -- \
  --extra-files "$temp" \
  --flake ".#${HOSTNAME}" \
  --target-host "root@${FQDN}"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "The system is now running with:"
echo "  - Agenix key deployed to /etc/agenix/key"
echo "  - All secrets decrypted using the shared age key"
echo ""
echo "To access the cluster:"
echo "  ssh root@${FQDN}"
echo "  export KUBECONFIG=/etc/kubernetes/admin.kubeconfig"
echo "  kubectl get nodes"