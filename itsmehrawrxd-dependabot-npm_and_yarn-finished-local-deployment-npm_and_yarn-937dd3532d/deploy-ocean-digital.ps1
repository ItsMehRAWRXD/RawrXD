# RawrZ Security Platform - Ocean Digital Deployment Script (PowerShell)
# This script deploys the RawrZ Security Platform to Ocean Digital

Write-Host "=== RawrZ Security Platform - Ocean Digital Deployment ===" -ForegroundColor Green
Write-Host "Starting deployment process..." -ForegroundColor Yellow

# Set deployment variables
$APP_NAME = "rawrz-security-platform"
$DOCKER_IMAGE = "rawrz-security-platform:latest"
$CONTAINER_NAME = "rawrz-app"
$PORT = "3000"

# Check if Docker is running
try {
    docker info | Out-Null
    Write-Host "✅ Docker is running" -ForegroundColor Green
} catch {
    Write-Host "❌ Docker is not running. Please start Docker and try again." -ForegroundColor Red
    exit 1
}

# Build the Docker image
Write-Host "🔨 Building Docker image..." -ForegroundColor Yellow
docker build -t $DOCKER_IMAGE .

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Docker build failed" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Docker image built successfully" -ForegroundColor Green

# Stop and remove existing container if it exists
Write-Host "🛑 Stopping existing container..." -ForegroundColor Yellow
docker stop $CONTAINER_NAME 2>$null
docker rm $CONTAINER_NAME 2>$null

# Run the new container
Write-Host "🚀 Starting new container..." -ForegroundColor Yellow
docker run -d `
    --name $CONTAINER_NAME `
    --restart unless-stopped `
    -p "${PORT}:3000" `
    -e NODE_ENV=production `
    -e PORT=3000 `
    $DOCKER_IMAGE

if ($LASTEXITCODE -ne 0) {
    Write-Host "❌ Container startup failed" -ForegroundColor Red
    exit 1
}

Write-Host "✅ Container started successfully" -ForegroundColor Green

# Wait for the application to start
Write-Host "⏳ Waiting for application to start..." -ForegroundColor Yellow
Start-Sleep -Seconds 10

# Health check
Write-Host "🔍 Performing health check..." -ForegroundColor Yellow
try {
    $response = Invoke-WebRequest -Uri "http://localhost:$PORT/health" -UseBasicParsing
    if ($response.StatusCode -eq 200) {
        Write-Host "✅ Application is healthy and responding" -ForegroundColor Green
        Write-Host "🌐 Application is available at: http://localhost:$PORT" -ForegroundColor Cyan
        Write-Host "📊 Health check: http://localhost:$PORT/health" -ForegroundColor Cyan
        Write-Host "🧪 API test: http://localhost:$PORT/api/simple-test" -ForegroundColor Cyan
    } else {
        Write-Host "❌ Health check failed (HTTP $($response.StatusCode))" -ForegroundColor Red
        Write-Host "📋 Container logs:" -ForegroundColor Yellow
        docker logs $CONTAINER_NAME
        exit 1
    }
} catch {
    Write-Host "❌ Health check failed: $($_.Exception.Message)" -ForegroundColor Red
    Write-Host "📋 Container logs:" -ForegroundColor Yellow
    docker logs $CONTAINER_NAME
    exit 1
}

# Show container status
Write-Host "📋 Container status:" -ForegroundColor Yellow
docker ps | Select-String $CONTAINER_NAME

Write-Host ""
Write-Host "🎉 Deployment completed successfully!" -ForegroundColor Green
Write-Host "🔗 Access your RawrZ Security Platform at: http://localhost:$PORT" -ForegroundColor Cyan
Write-Host "📚 API Documentation: http://localhost:$PORT/API-TESTING-GUIDE.md" -ForegroundColor Cyan
Write-Host ""
Write-Host "📝 Useful commands:" -ForegroundColor Yellow
Write-Host "  View logs: docker logs $CONTAINER_NAME" -ForegroundColor White
Write-Host "  Stop app: docker stop $CONTAINER_NAME" -ForegroundColor White
Write-Host "  Restart app: docker restart $CONTAINER_NAME" -ForegroundColor White
Write-Host "  Remove app: docker rm -f $CONTAINER_NAME" -ForegroundColor White
