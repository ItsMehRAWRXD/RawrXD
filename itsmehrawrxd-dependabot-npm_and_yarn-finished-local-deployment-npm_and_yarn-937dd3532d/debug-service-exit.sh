#!/bin/bash
set -e

echo "🔍 Debugging RawrZ Service Exit Issue"
echo "====================================="

# Stop the current service
echo "Stopping current service..."
systemctl stop rawrz.service || true

# Check the logs to see what's happening
echo "Checking recent service logs..."
journalctl -u rawrz.service --no-pager -n 20

echo ""
echo "Testing the Node.js server manually..."
cd /root/RawrZApp

# Check if the file exists and is readable
echo "Checking api-server-no-cli.js..."
ls -la api-server-no-cli.js

# Try running it manually to see what happens
echo "Running Node.js server manually (will timeout after 10 seconds)..."
timeout 10s node api-server-no-cli.js || echo "Manual run completed or timed out"

echo ""
echo "Checking if there are any syntax errors..."
node -c api-server-no-cli.js && echo "✅ Syntax is valid" || echo "❌ Syntax error found"

echo ""
echo "Checking Node.js and npm versions..."
node --version
npm --version

echo ""
echo "Checking if all dependencies are installed..."
npm list --depth=0 2>/dev/null || echo "Some dependencies may be missing"

echo ""
echo "🔍 Debug complete. Check the output above for issues."
