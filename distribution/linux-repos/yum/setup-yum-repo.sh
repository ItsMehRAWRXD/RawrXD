#!/bin/bash
# setup-yum-repo.sh
# Phase H.2 Batch 4/5: YUM/DNF Repository Setup Script

set -e

REPO_URL="https://yum.rawrxd.ai/rawrxd.repo"
REPO_PATH="/etc/yum.repos.d/rawrxd.repo"

echo "Setting up RawrXD YUM/DNF repository..."

# Download repo file
echo "Downloading repository configuration..."
sudo curl -fsSL "$REPO_URL" -o "$REPO_PATH"

# Import GPG key
echo "Importing GPG key..."
sudo rpm --import https://yum.rawrxd.ai/rawrxd-pubkey.gpg

# Update cache
echo "Updating package cache..."
if command -v dnf &> /dev/null; then
    sudo dnf makecache
elif command -v yum &> /dev/null; then
    sudo yum makecache
fi

echo ""
echo "RawrXD YUM/DNF repository configured successfully!"
echo ""
echo "To install RawrXD:"
if command -v dnf &> /dev/null; then
    echo "  sudo dnf install rawrxd"
else
    echo "  sudo yum install rawrxd"
fi
echo ""
echo "To install with GPU support:"
if command -v dnf &> /dev/null; then
    echo "  sudo dnf install rawrxd-rocm"
else
    echo "  sudo yum install rawrxd-rocm"
fi
echo ""
