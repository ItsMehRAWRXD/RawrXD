#!/bin/bash
set -e

echo "🔧 Fixing RawrZ Service Directory Issue"
echo "======================================="

# Stop the current service
echo "Stopping current service..."
systemctl stop rawrz.service || true

# Check if directory exists and create if needed
echo "Checking directory structure..."
if [ ! -d "/root/RawrZApp" ]; then
    echo "Creating /root/RawrZApp directory..."
    mkdir -p /root/RawrZApp
fi

# Ensure we're in the right directory
cd /root/RawrZApp

# Check if the no-CLI server file exists
if [ ! -f "api-server-no-cli.js" ]; then
    echo "api-server-no-cli.js not found, pulling latest changes..."
    git pull origin main
fi

# Update the systemd service file with correct paths
echo "Updating systemd service configuration..."
cat <<EOF > /etc/systemd/system/rawrz.service
[Unit]
Description=RawrZ Security Platform
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node api-server-no-cli.js
WorkingDirectory=/root/RawrZApp
Restart=always
RestartSec=5
User=root
Environment=PORT=3000
Environment=NODE_ENV=production

# Security settings
NoNewPrivileges=false
PrivateTmp=false
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start the service
echo "Reloading systemd configuration..."
systemctl daemon-reload

echo "Starting RawrZ service..."
systemctl start rawrz.service

# Wait a moment and check status
sleep 3
echo "Checking service status..."
systemctl status rawrz.service --no-pager

echo "✅ Service directory issue fixed!"
echo "🌐 RawrZ Security Platform should now be accessible at: http://$(hostname -I | awk '{print $1}'):3000"
