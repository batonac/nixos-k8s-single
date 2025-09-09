#!/usr/bin/env bash
# Setup script for agenix secrets

set -e

echo "Setting up agenix secrets..."

# Create secrets directory
mkdir -p secrets

# Check if we have the agenix command available
if ! command -v agenix &> /dev/null; then
    echo "Installing agenix..."
    nix profile install github:ryantm/agenix
fi

echo "Creating encrypted secret files..."
echo "You'll be prompted to enter each secret value."

# Create Cloudflare email secret
echo "Enter your Cloudflare email:"
read -r cloudflare_email
echo "$cloudflare_email" | agenix -e secrets/cloudflare-email.age

# Create Cloudflare API token secret
echo "Enter your Cloudflare DNS API token:"
read -rs cloudflare_token
echo "$cloudflare_token" | agenix -e secrets/cloudflare-dns-api-token.age

echo "Secrets created successfully!"
echo "You can now remove your .env file if you want."
echo ""
echo "To edit secrets later, use:"
echo "  agenix -e secrets/cloudflare-email.age"
echo "  agenix -e secrets/cloudflare-dns-api-token.age"