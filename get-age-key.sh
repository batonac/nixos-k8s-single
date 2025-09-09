#!/usr/bin/env bash
# Get the age public key from SSH host key for secrets.nix

set -e

HOST="k3s-dev.batonac.com"

echo "Getting age public key for host: $HOST"
echo "Make sure SSH access is working to the host first!"
echo ""

# Get the SSH host key and convert it to age format
echo "Running: ssh-keyscan -t ed25519 $HOST 2>/dev/null | ssh-to-age"
AGE_KEY=$(ssh-keyscan -t ed25519 "$HOST" 2>/dev/null | ssh-to-age)

if [ -z "$AGE_KEY" ]; then
    echo "Failed to get age key. Make sure:"
    echo "1. The host $HOST is accessible"
    echo "2. You have ssh-to-age installed: nix profile install nixpkgs#ssh-to-age"
    exit 1
fi

echo "Age public key for $HOST:"
echo "$AGE_KEY"
echo ""
echo "Update your secrets.nix file with this key as the systemKey value."