#!/usr/bin/env bash
set -euo pipefail



# Parse FQDN argument
FQDN="${1:-k3s-dev.batonac.com}"
IP_ADDRESS="192.168.0.121"
HOSTNAME="k3s-dev"  # Extract hostname from FQDN (everything before first dot)

# # Parse FQDN argument
# FQDN="${1:-k3s-dev.batonac.com}"
# HOSTNAME="${FQDN%%.*}"  # Extract hostname from FQDN (everything before first dot)

echo "🚀 Deploying NixOS to $FQDN (hostname: $HOSTNAME)"
echo ""

# Create a temporary directory for host keys
temp=$(mktemp -d)

# Function to cleanup temporary directory on exit
cleanup() {
  rm -rf "$temp"
}
trap cleanup EXIT

# Create the directory where sshd expects to find the host keys
install -d -m755 "$temp/etc/ssh"

echo "📥 Retrieving host SSH key from Bitwarden..."
# Decrypt private key from Bitwarden and copy it to the temporary directory
bw get item "${FQDN}-host-key" | jq -r '.sshKey.privateKey, .sshKey.publicKey' | { read -r private; cat > "$temp/etc/ssh/ssh_host_ed25519_key" <<< "$private"; cat > "$temp/etc/ssh/ssh_host_ed25519_key.pub"; }

# Set the correct permissions so sshd will accept the key
chmod 600 "$temp/etc/ssh/ssh_host_ed25519_key"

echo "🔧 Running nixos-anywhere..."
# Install NixOS to the host system with our secrets
nix run github:nix-community/nixos-anywhere -- \
  --extra-files "$temp" \
  --flake ".#${HOSTNAME}" \
  --target-host "root@${IP_ADDRESS}"

echo ""
echo "✅ Deployment complete!"
echo ""
echo "The system is now running with:"
echo "  - Host key from Bitwarden"
echo "  - All secrets encrypted for this host key"
echo ""
echo "To access the cluster:"
echo "  ssh root@${FQDN}"
echo "  export KUBECONFIG=/etc/kubernetes/admin.kubeconfig"
echo "  kubectl get nodes"