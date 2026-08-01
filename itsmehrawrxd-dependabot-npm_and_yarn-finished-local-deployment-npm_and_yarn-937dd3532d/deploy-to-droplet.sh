#!/bin/bash

# RawrZ Security Platform - Droplet Deployment Script
echo "=== RawrZ Security Platform - Droplet Deployment ==="

# Update system
echo "📦 Updating system packages..."
apt update && apt upgrade -y

# Install Docker
echo "🐳 Installing Docker..."
curl -fsSL https://get.docker.com -o get-docker.sh
sh get-docker.sh
usermod -aG docker $USER
systemctl enable docker
systemctl start docker

# Install Docker Compose
echo "🐳 Installing Docker Compose..."
curl -L "https://github.com/docker/compose/releases/latest/download/docker-compose-$(uname -s)-$(uname -m)" -o /usr/local/bin/docker-compose
chmod +x /usr/local/bin/docker-compose

# Create app directory
echo "📁 Creating application directory..."
mkdir -p /opt/rawrz-platform
cd /opt/rawrz-platform

# Clone repository
echo "📥 Cloning repository..."
git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git .

# Build and run
echo "🔨 Building Docker image..."
docker build -t rawrz-security-platform:latest .

# Stop existing container
echo "🛑 Stopping existing container..."
docker stop rawrz-app 2>/dev/null || true
docker rm rawrz-app 2>/dev/null || true

# Run application
echo "🚀 Starting application..."
docker run -d \
    --name rawrz-app \
    --restart unless-stopped \
    -p 3000:3000 \
    -v /opt/rawrz-platform/logs:/app/logs \
    rawrz-security-platform:latest

# Configure firewall
echo "🔥 Configuring firewall..."
ufw allow 3000/tcp
ufw allow ssh
ufw --force enable

# Get public IP
PUBLIC_IP=$(curl -s http://checkip.amazonaws.com/)
echo ""
echo "🎉 Deployment completed successfully!"
echo "🌐 Your RawrZ Security Platform is available at:"
echo "   http://$PUBLIC_IP:3000"
echo "📊 Health check: http://$PUBLIC_IP:3000/health"
echo "🧪 API test: http://$PUBLIC_IP:3000/api/simple-test"
echo ""
echo "📝 Useful commands:"
echo "  View logs: docker logs rawrz-app"
echo "  Stop app: docker stop rawrz-app"
echo "  Restart app: docker restart rawrz-app"
echo "  Remove app: docker rm -f rawrz-app"
echo ""
echo "🔒 Security Note: Make sure to configure SSL/TLS for production use!"
