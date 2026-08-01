#!/bin/bash
# Force Fix Node.js Package Conflicts
# Aggressively removes all Node.js packages and installs fresh

echo "Force Fixing Node.js Package Conflicts..."
echo "========================================"

# Stop any running Node.js processes
echo "Stopping any running Node.js processes..."
pkill -f node || true
systemctl stop rawrz.service 2>/dev/null || true

# Remove all Node.js related packages aggressively
echo "Removing all Node.js packages..."
apt-get remove -y --purge nodejs nodejs-doc libnode72 javascript-common libc-ares2 libjs-highlight.js
apt-get autoremove -y
apt-get autoclean
apt-get clean

# Force remove any remaining files
echo "Force removing remaining Node.js files..."
rm -rf /usr/share/systemtap/tapset/node.stp
rm -rf /usr/lib/node_modules
rm -rf /usr/share/nodejs
rm -rf /var/lib/nodejs

# Update package list
echo "Updating package list..."
apt-get update

# Install prerequisites
echo "Installing prerequisites..."
apt-get install -y \
    apt-transport-https \
    ca-certificates \
    curl \
    gnupg \
    lsb-release

# Add NodeSource repository
echo "Adding NodeSource repository..."
curl -fsSL https://deb.nodesource.com/setup_18.x | bash -

# Update package list again
echo "Updating package list with NodeSource..."
apt-get update

# Install Node.js and npm with force
echo "Installing Node.js 18 and npm..."
apt-get install -y nodejs --fix-missing

# Verify installation
echo "Verifying Node.js installation..."
node --version
npm --version

echo "Node.js installation completed successfully!"
