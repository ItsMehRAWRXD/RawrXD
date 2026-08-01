#!/bin/bash
set -e

echo "🔧 Fixing RawrZ Service Restart Loop"
echo "===================================="

# Stop the current service
echo "Stopping current service..."
systemctl stop rawrz.service || true

# Update the systemd service file to use the no-CLI version
echo "Updating systemd service configuration..."
cat <<EOF > /etc/systemd/system/rawrz.service
[Unit]
Description=RawrZ Security Platform
After=network.target

[Service]
Type=simple
ExecStart=/usr/bin/node /root/RawrZApp/api-server-no-cli.js
WorkingDirectory=/root/RawrZApp
Restart=always
RestartSec=5
User=root
Environment=PORT=3000
Environment=NODE_ENV=production

# Security settings
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/root/RawrZApp /app

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

echo "✅ Service restart loop fixed!"
echo "🌐 RawrZ Security Platform should now be accessible at: http://$(hostname -I | awk '{print $1}'):3000"
