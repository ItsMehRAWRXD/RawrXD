#!/bin/bash
set -e

echo "🔧 Comprehensive RawrZ Service Fix"
echo "=================================="

# Stop the service
echo "1. Stopping current service..."
systemctl stop rawrz.service || true

# Check and install dependencies
echo ""
echo "2. Checking Node.js installation..."
if ! command -v node &> /dev/null; then
    echo "Node.js not found, installing..."
    curl -fsSL https://deb.nodesource.com/setup_18.x | sudo -E bash -
    apt-get install -y nodejs
fi

echo "Node.js version: $(node --version)"
echo "NPM version: $(npm --version)"

# Navigate to the application directory
cd /root/RawrZApp

echo ""
echo "3. Installing/updating dependencies..."
if [ -f "package.json" ]; then
    npm install --production
else
    echo "No package.json found, installing basic dependencies..."
    npm init -y
    npm install express cors multer
fi

echo ""
echo "4. Checking application file..."
if [ ! -f "api-server-no-cli.js" ]; then
    echo "Application file not found!"
    exit 1
fi

# Create a more robust startup script
echo ""
echo "5. Creating robust startup script..."
cat <<'EOF' > /root/RawrZApp/start-rawrz-robust.sh
#!/bin/bash

# Set working directory
cd /root/RawrZApp

# Set environment variables
export PORT=3000
export NODE_ENV=production
export NODE_OPTIONS="--max-old-space-size=4096"

# Create necessary directories
mkdir -p /app/uploads /app/processed 2>/dev/null || true
mkdir -p uploads processed 2>/dev/null || true

# Start the application with error handling
echo "Starting RawrZ Security Platform..."
exec /usr/bin/node api-server-no-cli.js
EOF

chmod +x /root/RawrZApp/start-rawrz-robust.sh

# Create an improved systemd service
echo ""
echo "6. Creating improved systemd service..."
cat <<EOF > /etc/systemd/system/rawrz.service
[Unit]
Description=RawrZ Security Platform
After=network.target
Wants=network.target

[Service]
Type=exec
ExecStart=/root/RawrZApp/start-rawrz-robust.sh
WorkingDirectory=/root/RawrZApp
Restart=always
RestartSec=10
User=root
Group=root

# Environment
Environment=PORT=3000
Environment=NODE_ENV=production
Environment=NODE_OPTIONS="--max-old-space-size=4096"

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rawrz

# Process management
KillMode=mixed
KillSignal=SIGTERM
TimeoutStopSec=30
TimeoutStartSec=60

# Security (relaxed for development)
NoNewPrivileges=false
PrivateTmp=false
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF

# Reload systemd and start service
echo ""
echo "7. Reloading systemd and starting service..."
systemctl daemon-reload
systemctl enable rawrz.service
systemctl start rawrz.service

# Wait for service to start
echo ""
echo "8. Waiting for service to start..."
sleep 15

# Check service status
echo ""
echo "9. Checking service status..."
systemctl status rawrz.service --no-pager

# Test the service
echo ""
echo "10. Testing service functionality..."
sleep 5

# Check if service is active
if systemctl is-active --quiet rawrz.service; then
    echo "✅ Service is running!"
    
    # Test health endpoint
    echo "Testing health endpoint..."
    curl -s http://localhost:3000/api/health | head -c 200 || echo "Health check failed"
    
    echo ""
    echo "🌐 RawrZ Security Platform is accessible at:"
    echo "   http://$(hostname -I | awk '{print $1}'):3000"
    echo "   http://localhost:3000"
    
else
    echo "❌ Service failed to start"
    echo "Recent logs:"
    journalctl -u rawrz.service --no-pager -n 20
fi

echo ""
echo "✅ Comprehensive fix completed!"
