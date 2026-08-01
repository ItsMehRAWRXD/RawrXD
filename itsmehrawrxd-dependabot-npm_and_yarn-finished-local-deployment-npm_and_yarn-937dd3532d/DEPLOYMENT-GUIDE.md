# RawrZ Security Platform - Deployment Guide

This guide provides comprehensive instructions for deploying the RawrZ Security Platform to Ocean Digital or any other cloud provider.

## Prerequisites

- Docker installed and running
- Git access to the repository
- Basic knowledge of Docker and containerization

## Quick Deployment

### Option 1: Using the Deployment Script (Recommended)

#### For Linux/macOS:
```bash
chmod +x deploy-ocean-digital.sh
./deploy-ocean-digital.sh
```

#### For Windows PowerShell:
```powershell
.\deploy-ocean-digital.ps1
```

### Option 2: Manual Deployment

#### Step 1: Clone the Repository
```bash
git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git
cd itsmehrawrxd
```

#### Step 2: Build the Docker Image
```bash
docker build -t rawrz-security-platform:latest .
```

#### Step 3: Run the Container
```bash
docker run -d \
    --name rawrz-app \
    --restart unless-stopped \
    -p 3000:3000 \
    -e NODE_ENV=production \
    -e PORT=3000 \
    rawrz-security-platform:latest
```

#### Step 4: Verify Deployment
```bash
# Health check
curl http://localhost:3000/health

# API test
curl http://localhost:3000/api/simple-test
```

## Ocean Digital Specific Deployment

### Using Ocean Digital App Platform

1. **Connect your GitHub repository** to Ocean Digital
2. **Configure the app** with the following settings:
   - **Build Command**: `docker build -t rawrz-security-platform .`
   - **Run Command**: `docker run -p 3000:3000 rawrz-security-platform`
   - **Port**: `3000`
   - **Environment Variables**:
     - `NODE_ENV=production`
     - `PORT=3000`

### Using Ocean Digital Droplets

1. **Create a new droplet** with Docker pre-installed
2. **SSH into the droplet**:
   ```bash
   ssh root@your-droplet-ip
   ```

3. **Clone and deploy**:
   ```bash
   git clone https://github.com/ItsMehRAWRXD/itsmehrawrxd.git
   cd itsmehrawrxd
   chmod +x deploy-ocean-digital.sh
   ./deploy-ocean-digital.sh
   ```

## Environment Configuration

### Required Environment Variables

- `NODE_ENV=production` - Sets the application to production mode
- `PORT=3000` - Sets the port the application runs on

### Optional Environment Variables

- `NPM_CONFIG_AUDIT_LEVEL=moderate` - Sets npm audit level
- `NODE_OPTIONS=--max-old-space-size=512` - Limits memory usage

## Security Considerations

The Dockerfile includes several security measures:

- **Non-root user**: Application runs as `rawrz` user (UID 1001)
- **Security updates**: All packages are updated during build
- **Minimal attack surface**: Only necessary packages are installed
- **Health checks**: Built-in health monitoring
- **Resource limits**: Memory and CPU limits configured

### Privilege Requirements

Some engines require elevated privileges for full functionality:

- **Red Killer**: Requires Administrator privileges for registry modification, service control, and file deletion
- **Private Virus Scanner**: Some engines may require elevated privileges for deep system scanning
- **Advanced Anti-Analysis**: May require elevated privileges for kernel-level operations

**Note**: The application will run with limited privileges by default for security. Some features may show warnings but will still function with reduced capabilities.

## Running with Elevated Privileges

For full functionality of all engines, run the application with elevated privileges:

### Windows - Local Development

#### Option 1: Batch Script (Recommended)
```bash
# Run as Administrator
start-elevated.bat
```

#### Option 2: PowerShell Script
```powershell
# Run PowerShell as Administrator, then:
.\start-elevated.ps1
```

#### Option 3: Manual Administrator Start
1. Right-click on Command Prompt or PowerShell
2. Select "Run as administrator"
3. Navigate to the project directory
4. Run: `node api-server.js`

### Docker - Privileged Container

#### Option 1: Docker Compose (Recommended)
```bash
# Linux/macOS
sudo ./deploy-privileged.sh

# Windows PowerShell (as Administrator)
.\deploy-privileged.ps1
```

#### Option 2: Manual Docker Commands
```bash
# Build privileged container
docker build -f Dockerfile.privileged -t rawrz-platform-privileged .

# Run with full privileges
docker run --privileged --cap-add=SYS_ADMIN --cap-add=NET_ADMIN \
  --network=host -p 3000:3000 rawrz-platform-privileged
```

### Benefits of Elevated Privileges

When running with elevated privileges, you get:

#### Red Killer Engine
- ✅ Full registry access and modification
- ✅ Complete service control and management
- ✅ File system operations and deletion
- ✅ Process termination capabilities
- ✅ WiFi credential extraction
- ✅ Complete system analysis

#### Private Virus Scanner
- ✅ Full system scanning capabilities
- ✅ Registry analysis
- ✅ Memory scanning
- ✅ Network analysis
- ✅ Complete threat detection

#### AI Threat Detector
- ✅ Full model training and saving
- ✅ Complete feature extraction
- ✅ Advanced threat analysis
- ✅ Behavior profiling

#### All Other Engines
- ✅ Maximum functionality
- ✅ Complete system integration
- ✅ Full API capabilities
- ✅ Advanced features enabled

## Monitoring and Maintenance

### Health Monitoring

The application includes built-in health checks:

- **Health endpoint**: `GET /health`
- **API status**: `GET /api/rawrz-engine/status`
- **Simple test**: `GET /api/simple-test`

### Log Management

```bash
# View application logs
docker logs rawrz-app

# Follow logs in real-time
docker logs -f rawrz-app

# View logs with timestamps
docker logs -t rawrz-app
```

### Container Management

```bash
# Stop the application
docker stop rawrz-app

# Start the application
docker start rawrz-app

# Restart the application
docker restart rawrz-app

# Remove the application
docker rm -f rawrz-app
```

### Updates and Maintenance

```bash
# Pull latest changes
git pull origin master

# Rebuild and redeploy
./deploy-ocean-digital.sh
```

## API Testing

Once deployed, you can test the API using the provided test files:

```bash
# Test basic functionality
curl http://your-domain:3000/health

# Test engine status
curl -X POST -H "Content-Type: application/json" \
  -d @test-engine-request.json \
  http://your-domain:3000/api/rawrz-engine/execute

# Test all engines
./test-api.sh
```

## Troubleshooting

### Common Issues

1. **Port already in use**:
   ```bash
   # Find process using port 3000
   lsof -i :3000
   # Kill the process
   kill -9 <PID>
   ```

2. **Docker build fails**:
   ```bash
   # Check Docker daemon
   docker info
   # Clean up Docker cache
   docker system prune -a
   ```

3. **Application not responding**:
   ```bash
   # Check container status
   docker ps
   # Check logs
   docker logs rawrz-app
   # Restart container
   docker restart rawrz-app
   ```

4. **Engine warnings in logs**:
   - **Private Virus Scanner**: Some engines (ClamAV, YARA, etc.) may not be available in the container environment
   - **Red Killer**: Privilege warnings are expected when not running as Administrator
   - **AI Threat Detector**: ML model training warnings are normal during initialization
   - These warnings don't affect core functionality

### Performance Optimization

1. **Resource limits**:
   ```bash
   docker run -d \
     --name rawrz-app \
     --memory=1g \
     --cpus=1 \
     -p 3000:3000 \
     rawrz-security-platform:latest
   ```

2. **Load balancing** (for multiple instances):
   ```bash
   # Run multiple instances
   docker run -d --name rawrz-app-1 -p 3001:3000 rawrz-security-platform:latest
   docker run -d --name rawrz-app-2 -p 3002:3000 rawrz-security-platform:latest
   ```

## Production Checklist

- [ ] Docker image built successfully
- [ ] Container running without errors
- [ ] Health check endpoint responding
- [ ] API endpoints functional
- [ ] Environment variables configured
- [ ] Security measures in place
- [ ] Monitoring configured
- [ ] Backup strategy implemented
- [ ] SSL/TLS configured (if needed)
- [ ] Domain configured (if needed)

## Support

For deployment issues or questions:

1. Check the application logs: `docker logs rawrz-app`
2. Verify health status: `curl http://localhost:3000/health`
3. Review the API documentation: `http://localhost:3000/API-TESTING-GUIDE.md`
4. Check GitHub issues for known problems

## Security Notice

This application is designed for legitimate security testing and research purposes only. Ensure you have proper authorization before deploying and testing on any systems.
