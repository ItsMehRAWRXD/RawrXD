#!/bin/bash
# RawrZ Security Platform - Droplet Deployment Script
# Run this script on your DigitalOcean droplet to deploy the latest version

echo "RawrZ Security Platform - Droplet Deployment"
echo "============================================="

# Update system packages
echo "Updating system packages..."
apt update && apt upgrade -y

# Install required dependencies
echo "Installing dependencies..."
apt install -y nodejs npm git docker.io docker-compose curl wget build-essential

# Clone or update the repository
if [ -d "/root/RawrZApp" ]; then
    echo "Updating existing repository..."
    cd /root/RawrZApp
    git pull origin main
else
    echo "Cloning repository..."
    git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git /root/RawrZApp
    cd /root/RawrZApp
fi

# Install Node.js dependencies
echo "Installing Node.js dependencies..."
npm install

# Build Docker image
echo "Building Docker image..."
docker build -t rawrz-security-platform .

# Stop existing containers
echo "Stopping existing containers..."
docker stop rawrz-app 2>/dev/null || true
docker rm rawrz-app 2>/dev/null || true

# Run new container
echo "Starting RawrZ Security Platform..."
docker run -d \
    --name rawrz-app \
    --restart unless-stopped \
    -p 3000:3000 \
    -p 80:3000 \
    -v /root/RawrZApp/data:/app/data \
    -v /root/RawrZApp/logs:/app/logs \
    rawrz-security-platform

# Configure firewall
echo "Configuring firewall..."
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 3000/tcp
ufw --force enable

# Set up systemd service for auto-start
echo "Setting up systemd service..."
cat > /etc/systemd/system/rawrz.service << EOF
[Unit]
Description=RawrZ Security Platform
After=docker.service
Requires=docker.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/bin/docker start rawrz-app
ExecStop=/usr/bin/docker stop rawrz-app
TimeoutStartSec=0

[Install]
WantedBy=multi-user.target
EOF

systemctl daemon-reload
systemctl enable rawrz.service

# Check deployment status
echo "Checking deployment status..."
sleep 10
if docker ps | grep -q rawrz-app; then
    echo "✅ RawrZ Security Platform deployed successfully!"
    echo "🌐 Access the platform at: http://$(curl -s ifconfig.me):3000"
    echo "📊 Container status:"
    docker ps | grep rawrz-app
else
    echo "❌ Deployment failed. Checking logs..."
    docker logs rawrz-app
fi

echo "Deployment complete!"
