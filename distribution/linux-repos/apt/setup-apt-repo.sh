#!/bin/bash
# setup-apt-repo.sh
# Phase H.2 Batch 4/5: APT Repository Setup Script

set -e

REPO_URL="https://apt.rawrxd.ai"
KEY_URL="https://apt.rawrxd.ai/rawrxd-archive-keyring.gpg"
KEYRING_PATH="/usr/share/keyrings/rawrxd-archive-keyring.gpg"
LIST_PATH="/etc/apt/sources.list.d/rawrxd.list"

echo "Setting up RawrXD APT repository..."

# Download GPG key
echo "Downloading GPG key..."
wget -qO - "$KEY_URL" | sudo gpg --dearmor -o "$KEYRING_PATH"

# Add repository
echo "Adding repository..."
echo "deb [arch=amd64 signed-by=$KEYRING_PATH] $REPO_URL stable main" | sudo tee "$LIST_PATH" > /dev/null

# Update package list
echo "Updating package list..."
sudo apt-get update

echo ""
echo "RawrXD APT repository configured successfully!"
echo ""
echo "To install RawrXD:"
echo "  sudo apt-get install rawrxd"
echo ""
echo "To install with GPU support:"
echo "  sudo apt-get install rawrxd-rocm"
echo ""
