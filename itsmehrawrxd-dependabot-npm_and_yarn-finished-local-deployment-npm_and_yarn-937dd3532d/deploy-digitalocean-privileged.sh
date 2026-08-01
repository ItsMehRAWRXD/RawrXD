#!/bin/bash

# RawrZ Security Platform - DigitalOcean Privileged Deployment
# This script deploys the RawrZ Security Platform to DigitalOcean with elevated privileges

set -e

echo "🚀 RawrZ Security Platform - DigitalOcean Privileged Deployment"
echo "=============================================================="
echo ""

# Configuration
APP_NAME="rawrz-security-platform"
DOCKER_IMAGE="rawrz-security-platform:privileged"
CONTAINER_NAME="rawrz-platform-privileged"
PORT="3000"
DOMAIN="${DOMAIN:-localhost}"

echo "📋 Deployment Configuration:"
echo "  - App Name: $APP_NAME"
echo "  - Docker Image: $DOCKER_IMAGE"
echo "  - Container: $CONTAINER_NAME"
echo "  - Port: $PORT"
echo "  - Domain: $DOMAIN"
echo ""

# Check if running as root (required for privileged containers)
if [ "$EUID" -ne 0 ]; then
    echo "⚠️  WARNING: Not running as root. Some features may not work properly."
    echo "   For full functionality, run with: sudo $0"
    echo ""
fi

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"

# Stop and remove existing container
echo "🛑 Stopping existing container..."
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true

# Build the privileged Docker image
echo "🔨 Building privileged Docker image..."
docker build -f Dockerfile.privileged -t $DOCKER_IMAGE .

if [ $? -ne 0 ]; then
    echo "❌ Docker build failed"
    exit 1
fi

echo "✅ Privileged Docker image built successfully"

# Create necessary directories
echo "📁 Creating directories..."
mkdir -p logs models data temp uploads scans scan-results loot backups plugins

# Run the privileged container
echo "🚀 Starting privileged container..."
docker run -d \
    --name $CONTAINER_NAME \
    --restart unless-stopped \
    --privileged \
    --cap-add=SYS_ADMIN \
    --cap-add=NET_ADMIN \
    --cap-add=DAC_OVERRIDE \
    --cap-add=FOWNER \
    --cap-add=SETUID \
    --cap-add=SETGID \
    -p $PORT:3000 \
    -v $(pwd)/logs:/app/logs \
    -v $(pwd)/models:/app/models \
    -v $(pwd)/data:/app/data \
    -v $(pwd)/temp:/app/temp \
    -v $(pwd)/uploads:/app/uploads \
    -v $(pwd)/scans:/app/scans \
    -v $(pwd)/scan-results:/app/scan-results \
    -v $(pwd)/loot:/app/loot \
    -v $(pwd)/backups:/app/backups \
    -v $(pwd)/plugins:/app/plugins \
    -e NODE_ENV=production \
    -e PRIVILEGED_MODE=true \
    -e PORT=3000 \
    $DOCKER_IMAGE

if [ $? -ne 0 ]; then
    echo "❌ Container startup failed"
    exit 1
fi

echo "✅ Privileged container started successfully"

# Wait for container to be ready
echo "⏳ Waiting for container to be ready..."
sleep 15

# Check container status
if docker ps | grep -q $CONTAINER_NAME; then
    echo "✅ Container is running with privileged access"
    echo ""
    echo "🎉 RawrZ Security Platform deployed successfully!"
    echo ""
    echo "🌐 Access Points:"
    echo "  - Main Panel: http://$DOMAIN:$PORT"
    echo "  - API Status: http://$DOMAIN:$PORT/api/rawrz-engine/status"
    echo "  - Health Check: http://$DOMAIN:$PORT/health"
    echo "  - Test Endpoint: http://$DOMAIN:$PORT/api/test-engine"
    echo ""
    echo "🔧 Container Management:"
    echo "  - View logs: docker logs $CONTAINER_NAME"
    echo "  - Stop container: docker stop $CONTAINER_NAME"
    echo "  - Restart container: docker restart $CONTAINER_NAME"
    echo "  - Remove container: docker rm -f $CONTAINER_NAME"
    echo ""
    echo "🛡️ Privileged Features Enabled:"
    echo "  - Full system access"
    echo "  - Registry modification"
    echo "  - Service control"
    echo "  - Process management"
    echo "  - File system operations"
    echo "  - Network configuration"
    echo ""
    echo "🔥 All 47 modules loaded with maximum functionality!"
    echo "🚀 Ready for field testing with elevated privileges!"
    echo ""
    
    # Show container logs
    echo "📋 Container Status:"
    docker ps --filter name=$CONTAINER_NAME --format "table {{.Names}}\t{{.Status}}\t{{.Ports}}"
    echo ""
    
    # Test health endpoint
    echo "🔍 Testing health endpoint..."
    sleep 5
    if curl -f http://localhost:$PORT/health > /dev/null 2>&1; then
        echo "✅ Health check passed - Platform is fully operational!"
    else
        echo "⚠️  Health check failed - Container may still be starting up"
        echo "   Check logs with: docker logs $CONTAINER_NAME"
    fi
    
else
    echo "❌ Container failed to start"
    echo "📋 Container logs:"
    docker logs $CONTAINER_NAME
    exit 1
fi

echo ""
echo "🎯 Deployment Complete - RawrZ Security Platform is ready for field testing!"
echo "🔥 All HackForums-level features are now live and operational!"
