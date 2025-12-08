#!/bin/bash
set -euo pipefail

HOST="${1:-k3s-dev}"
FQDN="${2:-${HOST}.batonac.com}"

echo "🔐 Generating SSH host key for $FQDN in Bitwarden"
echo ""
echo "1. Open Bitwarden and create a new 'SSH Key' item"
echo "2. Name it: ${FQDN}-host-key"
echo "3. Generate an ED25519 key"
echo "4. Save it"
echo ""
echo "Then retrieve the public key:"
bw get item "${FQDN}-host-key" | jq -r '.sshKey.publicKey'

echo ""
echo "Add this public key to your secrets.nix as the systemKey"
