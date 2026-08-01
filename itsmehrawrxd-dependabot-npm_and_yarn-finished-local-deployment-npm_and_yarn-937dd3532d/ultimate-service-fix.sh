#!/bin/bash
set -e

echo "🚀 Ultimate RawrZ Service Fix"
echo "============================="

# Stop the service
systemctl stop rawrz.service || true

echo "1. Creating a simple, reliable systemd service..."
cd /root/RawrZApp

# Create a simple startup script
cat <<'EOF' > start-rawrz.sh
#!/bin/bash
cd /root/RawrZApp
export PORT=3000
export NODE_ENV=production
mkdir -p uploads processed 2>/dev/null || true
exec node api-server-no-cli.js
EOF

chmod +x start-rawrz.sh

echo "2. Creating the most reliable systemd service configuration..."
# Use Type=simple with proper process management
cat <<EOF > /etc/systemd/system/rawrz.service
[Unit]
Description=RawrZ Security Platform
After=network.target

[Service]
Type=simple
ExecStart=/root/RawrZApp/start-rawrz.sh
WorkingDirectory=/root/RawrZApp
Restart=always
RestartSec=5
User=root
Group=root

# Environment
Environment=PORT=3000
Environment=NODE_ENV=production

# Logging
StandardOutput=journal
StandardError=journal
SyslogIdentifier=rawrz

# Process management - this is the key fix
KillMode=process
KillSignal=SIGTERM
TimeoutStopSec=30
TimeoutStartSec=60

# Don't kill the process on restart
RemainAfterExit=no

# Security (relaxed for development)
NoNewPrivileges=false
PrivateTmp=false
ProtectSystem=false
ProtectHome=false

[Install]
WantedBy=multi-user.target
EOF

echo "3. Reloading systemd and starting service..."
systemctl daemon-reload
systemctl start rawrz.service

echo "4. Waiting for service to start..."
sleep 10

echo "5. Checking service status..."
systemctl status rawrz.service --no-pager

echo ""
echo "6. Testing service functionality..."
sleep 5

if systemctl is-active --quiet rawrz.service; then
    echo "✅ Service is running!"
    echo "Testing health endpoint..."
    curl -s http://localhost:3000/api/health | head -c 200 || echo "Health check failed"
    
    echo ""
    echo "🌐 RawrZ Security Platform is accessible at:"
    echo "   http://$(hostname -I | awk '{print $1}'):3000"
    echo "   http://localhost:3000"
    
    echo ""
    echo "Final service status:"
    systemctl is-active rawrz.service
    systemctl is-enabled rawrz.service
else
    echo "❌ Service is still not running"
    echo "Recent logs:"
    journalctl -u rawrz.service --no-pager -n 10
    
    echo ""
    echo "Trying alternative approach with Type=exec..."
    systemctl stop rawrz.service
    
    # Try Type=exec as fallback
    sed -i 's/Type=simple/Type=exec/' /etc/systemd/system/rawrz.service
    systemctl daemon-reload
    systemctl start rawrz.service
    
    sleep 10
    echo "Checking Type=exec status..."
    systemctl status rawrz.service --no-pager
    
    if systemctl is-active --quiet rawrz.service; then
        echo "✅ Type=exec worked! Service is running."
        curl -s http://localhost:3000/api/health | head -c 200 || echo "Health check failed"
    else
        echo "❌ Both approaches failed. Checking logs..."
        journalctl -u rawrz.service --no-pager -n 20
    fi
fi

echo ""
echo "✅ Ultimate fix completed!"
