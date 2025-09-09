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

# Check if secrets.nix exists
if [ ! -f "secrets.nix" ]; then
    echo "Error: secrets.nix not found. Please make sure it exists."
    exit 1
fi

echo "Creating encrypted secret files..."
echo "You'll be prompted to enter each secret value."

# Create Cloudflare email secret
echo "Enter your Cloudflare email:"
read -r cloudflare_email
echo -n "$cloudflare_email" | agenix -e secrets/cloudflare-email.age

# Create Cloudflare API token secret  
echo "Enter your Cloudflare DNS API token:"
read -rs cloudflare_token
echo -n "$cloudflare_token" | agenix -e secrets/cloudflare-dns-api-token.age

echo ""
echo "Secrets created successfully!"
echo ""
echo "Files created:"
echo "  secrets/cloudflare-email.age"
echo "  secrets/cloudflare-dns-api-token.age"
echo ""
echo "You can now remove your .env file if you want."
echo ""
echo "To edit secrets later, use:"
echo "  agenix -e secrets/cloudflare-email.age"
echo "  agenix -e secrets/cloudflare-dns-api-token.age"