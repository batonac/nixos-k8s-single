#!/bin/bash
set -euo pipefail

HOSTNAME="${1:-k3s-dev}"

echo "# Host: $HOSTNAME"
echo "  $(bw get item "${HOSTNAME}-host-key" | jq -r '.sshKey.publicKey')"
