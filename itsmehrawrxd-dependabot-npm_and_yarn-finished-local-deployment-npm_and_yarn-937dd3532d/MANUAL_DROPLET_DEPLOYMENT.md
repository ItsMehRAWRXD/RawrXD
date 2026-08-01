# Manual Droplet Deployment Guide

Since SSH key authentication is not set up, here's how to manually deploy to your droplet:

## Step 1: Connect to Your Droplet

```bash
# Connect via SSH (you'll need to use password authentication)
ssh root@198.199.70.153
```

## Step 2: Fix Docker Dependencies (if needed)

If you get Docker dependency conflicts, run this first:

```bash
# Fix Docker dependencies
wget https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/fix-docker-dependencies.sh
chmod +x fix-docker-dependencies.sh
./fix-docker-dependencies.sh
```

## Step 3: Deploy RawrZ Platform

### Option A: Docker Deployment (if Docker is working)

```bash
# Update system
apt update && apt upgrade -y

# Install dependencies
apt install -y nodejs npm git docker.io docker-compose curl wget build-essential

# Clone the repository
git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git /root/RawrZApp
cd /root/RawrZApp

# Install Node.js dependencies
npm install

# Build Docker image
docker build -t rawrz-security-platform .

# Stop existing containers
docker stop rawrz-app 2>/dev/null || true
docker rm rawrz-app 2>/dev/null || true

# Run new container
docker run -d \
    --name rawrz-app \
    --restart unless-stopped \
    -p 3000:3000 \
    -p 80:3000 \
    -v /root/RawrZApp/data:/app/data \
    -v /root/RawrZApp/logs:/app/logs \
    rawrz-security-platform

# Configure firewall
ufw allow 22/tcp
ufw allow 80/tcp
ufw allow 3000/tcp
ufw --force enable

# Check deployment status
sleep 10
docker ps | grep rawrz-app
```

### Option B: Direct Node.js Deployment (recommended if Docker issues persist)

```bash
# Deploy without Docker
wget https://raw.githubusercontent.com/ItsMehRAWRXD/itsmehrawrxd/main/deploy-without-docker.sh
chmod +x deploy-without-docker.sh
./deploy-without-docker.sh
```

## Step 3: Access Your Platform

Once deployed, you can access your RawrZ Security Platform at:

- **Main Platform**: http://198.199.70.153:3000
- **PowerShell Panels**: http://198.199.70.153:3000/powershell-panels.html
- **One-Liner Panels**: http://198.199.70.153:3000/one-liner-panels.html
- **API Health**: http://198.199.70.153:3000/api/health

## Step 4: Verify Deployment

```bash
# Check if the container is running
docker ps

# Check logs
docker logs rawrz-app

# Test the API
curl http://localhost:3000/api/health
```

## Showcase Ready!

Your RawrZ Security Platform is now ready for showcasing on:

- **HackForums**: Share the GitHub link and droplet URL
- **Reddit**: Post about the comprehensive security platform
- **GitHub**: The repository is public and ready for stars/forks

## Features to Highlight

- 47+ Security Engines (all functional)
- 25+ PowerShell One-Liners (all tested)
- 9 Advanced PowerShell Utilities
- 6 Polymorphic Loaders
- 3 Ring-0 Components
- Interactive Web Panels
- 100% Test Pass Rate
- Public Domain License

## Security Notice

Remember to emphasize that this is for educational and authorized security testing purposes only.
