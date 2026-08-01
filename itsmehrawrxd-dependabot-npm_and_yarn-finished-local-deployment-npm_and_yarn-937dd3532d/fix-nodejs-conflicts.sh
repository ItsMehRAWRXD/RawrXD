#!/bin/bash
# Fix Node.js Package Conflicts on Ubuntu
# Resolves conflicts between old and new Node.js packages

echo "Fixing Node.js Package Conflicts..."
echo "==================================="

# Remove conflicting packages
echo "Removing conflicting Node.js packages..."
apt-get remove -y nodejs nodejs-doc libnode72 javascript-common
apt-get purge -y nodejs nodejs-doc libnode72 javascript-common

# Clean up
echo "Cleaning up package cache..."
apt-get autoremove -y
apt-get autoclean
apt-get clean

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

# Install Node.js and npm
echo "Installing Node.js 18 and npm..."
apt-get install -y nodejs

# Verify installation
echo "Verifying Node.js installation..."
node --version
npm --version

echo "Node.js installation completed successfully!"
