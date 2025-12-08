#!/usr/bin/env bash
set -euo pipefail

# Parse FQDN argument
FQDN="${1:-k3s-dev.batonac.com}"
HOSTNAME="${FQDN%%.*}"

echo "🔄 Updating NixOS configuration on $FQDN"

# Update flake inputs
echo "📦 Updating flake inputs..."
nix flake update

# Deploy to remote host
echo "🚀 Deploying to $FQDN..."
nixos-rebuild switch --flake ".#${HOSTNAME}" \
  --target-host "root@${FQDN}" \
  --use-remote-sudo

echo "✅ Update complete!"