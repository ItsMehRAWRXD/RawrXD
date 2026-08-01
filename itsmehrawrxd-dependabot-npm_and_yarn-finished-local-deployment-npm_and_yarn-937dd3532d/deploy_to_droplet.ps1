# RawrZ Security Platform - Droplet Deployment Script (Windows)
# Use this script to deploy to your DigitalOcean droplet from Windows

param(
    [Parameter(Mandatory=$true)]
    [string]$DropletIP,
    
    [Parameter(Mandatory=$false)]
    [string]$Username = "root"
)

Write-Host "RawrZ Security Platform - Droplet Deployment" -ForegroundColor Cyan
Write-Host "=============================================" -ForegroundColor Cyan

# Check if SSH is available
try {
    $null = Get-Command ssh -ErrorAction Stop
    Write-Host "SSH client found" -ForegroundColor Green
} catch {
    Write-Host "SSH client not found. Please install OpenSSH or use WSL." -ForegroundColor Red
    exit 1
}

Write-Host "Deploying to droplet: $DropletIP" -ForegroundColor Yellow

# Create deployment commands
$deployCommands = @"
#!/bin/bash
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
cat > /etc/systemd/system/rawrz.service << 'EOF'
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
    echo "🌐 Access the platform at: http://\$(curl -s ifconfig.me):3000"
    echo "📊 Container status:"
    docker ps | grep rawrz-app
else
    echo "❌ Deployment failed. Checking logs..."
    docker logs rawrz-app
fi

echo "Deployment complete!"
"@

# Write deployment script to temporary file
$tempScript = "deploy_temp.sh"
$deployCommands | Out-File -FilePath $tempScript -Encoding UTF8

try {
    Write-Host "Uploading deployment script to droplet..." -ForegroundColor Yellow
    scp $tempScript "${Username}@${DropletIP}:/tmp/deploy.sh"
    
    Write-Host "Executing deployment on droplet..." -ForegroundColor Yellow
    ssh "${Username}@${DropletIP}" "chmod +x /tmp/deploy.sh && /tmp/deploy.sh"
    
    Write-Host "✅ Deployment completed successfully!" -ForegroundColor Green
    Write-Host "🌐 Access your RawrZ Security Platform at: http://${DropletIP}:3000" -ForegroundColor Cyan
    
} catch {
    Write-Host "❌ Deployment failed: $_" -ForegroundColor Red
} finally {
    # Clean up temporary file
    if (Test-Path $tempScript) {
        Remove-Item $tempScript -Force
    }
}

Write-Host "Deployment script execution complete!" -ForegroundColor Cyan
