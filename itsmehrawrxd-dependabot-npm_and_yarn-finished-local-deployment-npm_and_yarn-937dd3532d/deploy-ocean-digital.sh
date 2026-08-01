#!/bin/bash

# RawrZ Security Platform - Ocean Digital Deployment Script
# This script deploys the RawrZ Security Platform to Ocean Digital

echo "=== RawrZ Security Platform - Ocean Digital Deployment ==="
echo "Starting deployment process..."

# Set deployment variables
APP_NAME="rawrz-security-platform"
DOCKER_IMAGE="rawrz-security-platform:latest"
CONTAINER_NAME="rawrz-app"
PORT="3000"

# Check if Docker is running
if ! docker info > /dev/null 2>&1; then
    echo "❌ Docker is not running. Please start Docker and try again."
    exit 1
fi

echo "✅ Docker is running"

# Build the Docker image
echo "🔨 Building Docker image..."
docker build -t $DOCKER_IMAGE .

if [ $? -ne 0 ]; then
    echo "❌ Docker build failed"
    exit 1
fi

echo "✅ Docker image built successfully"

# Stop and remove existing container if it exists
echo "🛑 Stopping existing container..."
docker stop $CONTAINER_NAME 2>/dev/null || true
docker rm $CONTAINER_NAME 2>/dev/null || true

# Run the new container
echo "🚀 Starting new container..."
docker run -d \
    --name $CONTAINER_NAME \
    --restart unless-stopped \
    -p $PORT:3000 \
    -e NODE_ENV=production \
    -e PORT=3000 \
    $DOCKER_IMAGE

if [ $? -ne 0 ]; then
    echo "❌ Container startup failed"
    exit 1
fi

echo "✅ Container started successfully"

# Wait for the application to start
echo "⏳ Waiting for application to start..."
sleep 10

# Health check
echo "🔍 Performing health check..."
HEALTH_RESPONSE=$(curl -s -o /dev/null -w "%{http_code}" http://localhost:$PORT/health)

if [ "$HEALTH_RESPONSE" = "200" ]; then
    echo "✅ Application is healthy and responding"
    echo "🌐 Application is available at: http://localhost:$PORT"
    echo "📊 Health check: http://localhost:$PORT/health"
    echo "🧪 API test: http://localhost:$PORT/api/simple-test"
else
    echo "❌ Health check failed (HTTP $HEALTH_RESPONSE)"
    echo "📋 Container logs:"
    docker logs $CONTAINER_NAME
    exit 1
fi

# Show container status
echo "📋 Container status:"
docker ps | grep $CONTAINER_NAME

echo ""
echo "🎉 Deployment completed successfully!"
echo "🔗 Access your RawrZ Security Platform at: http://localhost:$PORT"
echo "📚 API Documentation: http://localhost:$PORT/API-TESTING-GUIDE.md"
echo ""
echo "📝 Useful commands:"
echo "  View logs: docker logs $CONTAINER_NAME"
echo "  Stop app: docker stop $CONTAINER_NAME"
echo "  Restart app: docker restart $CONTAINER_NAME"
echo "  Remove app: docker rm -f $CONTAINER_NAME"
