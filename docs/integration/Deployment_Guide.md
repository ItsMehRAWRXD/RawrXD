# Sovereign IDE - Deployment Guide
## Installation, Configuration, and Maintenance

**Version:** 1.0.0  
**Date:** 2026-07-11  
**Status:** ✅ Complete

---

## Table of Contents

1. [Overview](#overview)
2. [System Requirements](#system-requirements)
3. [Installation](#installation)
4. [Configuration](#configuration)
5. [Maintenance](#maintenance)
6. [Troubleshooting](#troubleshooting)
7. [Upgrade Procedures](#upgrade-procedures)

---

## Overview

This guide covers the deployment of the Sovereign IDE, including installation on various platforms, configuration for different use cases, and ongoing maintenance procedures.

### Deployment Options

- **Desktop Installation**: Single-user workstation
- **Enterprise Deployment**: Multi-user organization
- **Container Deployment**: Docker/Kubernetes
- **Cloud Deployment**: AWS, Azure, GCP

---

## System Requirements

### Minimum Requirements

| Component | Requirement |
|-----------|-------------|
| OS | Windows 10/11, Ubuntu 20.04+, macOS 12+ |
| CPU | x64, 4 cores |
| RAM | 8 GB |
| Storage | 10 GB free space |
| GPU | Optional (for AI acceleration) |

### Recommended Requirements

| Component | Requirement |
|-----------|-------------|
| CPU | x64, 8+ cores |
| RAM | 32 GB |
| Storage | 50 GB SSD |
| GPU | NVIDIA RTX 3060+ or equivalent |

### Enterprise Requirements

| Component | Requirement |
|-----------|-------------|
| Servers | 3+ nodes for HA |
| Load Balancer | Required |
| Database | PostgreSQL 13+ |
| Cache | Redis 6+ |
| Storage | 500 GB+ shared storage |

---

## Installation

### Windows Installation

```powershell
# Download installer
Invoke-WebRequest -Uri "https://sovereign-ide.com/download/SovereignIDE-Setup.exe" -OutFile "SovereignIDE-Setup.exe"

# Run installer
.\SovereignIDE-Setup.exe /SILENT /NORESTART

# Verify installation
& "C:\Program Files\SovereignIDE\bin\sovereign.exe" --version
```

### Linux Installation

```bash
# Download package
wget https://sovereign-ide.com/download/sovereign-ide_1.0.0_amd64.deb

# Install
sudo dpkg -i sovereign-ide_1.0.0_amd64.deb
sudo apt-get install -f  # Fix dependencies

# Or using apt repository
sudo add-apt-repository ppa:sovereign/ide
sudo apt-get update
sudo apt-get install sovereign-ide

# Verify installation
sovereign --version
```

### macOS Installation

```bash
# Using Homebrew
brew tap sovereign/tap
brew install sovereign-ide

# Or download DMG
curl -O https://sovereign-ide.com/download/SovereignIDE-1.0.0.dmg
hdiutil attach SovereignIDE-1.0.0.dmg
cp -R /Volumes/SovereignIDE/SovereignIDE.app /Applications
hdiutil detach /Volumes/SovereignIDE

# Verify installation
/Applications/SovereignIDE.app/Contents/MacOS/sovereign --version
```

### Docker Deployment

```dockerfile
# Dockerfile
FROM ubuntu:22.04

# Install dependencies
RUN apt-get update && apt-get install -y \
    libgtk-3-0 \
    libwebkit2gtk-4.0-37 \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Copy Sovereign IDE
COPY sovereign-ide_1.0.0_amd64.deb /tmp/
RUN dpkg -i /tmp/sovereign-ide_1.0.0_amd64.deb || apt-get install -f -y

# Create user
RUN useradd -m -s /bin/bash sovereign
USER sovereign

# Set entrypoint
ENTRYPOINT ["/usr/bin/sovereign"]
```

```yaml
# docker-compose.yml
version: '3.8'

services:
  sovereign-ide:
    build: .
    container_name: sovereign-ide
    volumes:
      - ./workspace:/home/sovereign/workspace
      - ./config:/home/sovereign/.config/sovereign
    ports:
      - "8080:8080"  # API port
    environment:
      - SOVEREIGN_MODE=headless
      - SOVEREIGN_API_KEY=${API_KEY}
    restart: unless-stopped
```

### Kubernetes Deployment

```yaml
# sovereign-deployment.yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: sovereign-ide
  labels:
    app: sovereign-ide
spec:
  replicas: 3
  selector:
    matchLabels:
      app: sovereign-ide
  template:
    metadata:
      labels:
        app: sovereign-ide
    spec:
      containers:
      - name: sovereign-ide
        image: sovereign/ide:1.0.0
        ports:
        - containerPort: 8080
        env:
        - name: SOVEREIGN_MODE
          value: "server"
        - name: SOVEREIGN_DATABASE_URL
          valueFrom:
            secretKeyRef:
              name: sovereign-secrets
              key: database-url
        resources:
          requests:
            memory: "4Gi"
            cpu: "2"
          limits:
            memory: "16Gi"
            cpu: "8"
        volumeMounts:
        - name: workspace
          mountPath: /workspace
      volumes:
      - name: workspace
        persistentVolumeClaim:
          claimName: sovereign-workspace
---
apiVersion: v1
kind: Service
metadata:
  name: sovereign-ide
spec:
  selector:
    app: sovereign-ide
  ports:
  - port: 80
    targetPort: 8080
  type: LoadBalancer
```

---

## Configuration

### Configuration Files

```json
// ~/.config/sovereign/settings.json
{
  "version": "1.0.0",
  "ui": {
    "theme": "dark",
    "fontSize": 14,
    "fontFamily": "Fira Code",
    "showLineNumbers": true,
    "wordWrap": true
  },
  "editor": {
    "tabSize": 4,
    "insertSpaces": true,
    "autoSave": true,
    "autoSaveDelay": 1000
  },
  "ai": {
    "defaultModel": "llama-7b",
    "contextSize": 4096,
    "temperature": 0.7,
    "gpuLayers": 33
  },
  "security": {
    "enableSandbox": true,
    "maxFileSize": 104857600,
    "allowedExtensions": [".c", ".cpp", ".h", ".hpp", ".py", ".js"]
  },
  "network": {
    "proxy": {
      "enabled": false,
      "host": "",
      "port": 0
    }
  }
}
```

### Environment Variables

```bash
# Core settings
export SOVEREIGN_HOME="/opt/sovereign"
export SOVEREIGN_CONFIG="/etc/sovereign"
export SOVEREIGN_DATA="/var/lib/sovereign"

# Mode settings
export SOVEREIGN_MODE="desktop"  # desktop, server, headless

# AI settings
export SOVEREIGN_AI_BACKEND="llama.cpp"
export SOVEREIGN_MODEL_PATH="/opt/models"
export SOVEREIGN_GPU_ENABLED="true"

# Security settings
export SOVEREIGN_API_KEY="your-api-key-here"
export SOVEREIGN_JWT_SECRET="your-jwt-secret-here"

# Database settings (enterprise)
export SOVEREIGN_DATABASE_URL="postgresql://user:pass@localhost/sovereign"
export SOVEREIGN_REDIS_URL="redis://localhost:6379"
```

### Enterprise Configuration

```yaml
# /etc/sovereign/enterprise.yml
server:
  port: 8080
  host: "0.0.0.0"
  ssl:
    enabled: true
    cert: "/etc/sovereign/ssl/cert.pem"
    key: "/etc/sovereign/ssl/key.pem"

authentication:
  method: "ldap"
  ldap:
    url: "ldap://ldap.company.com:389"
    base_dn: "dc=company,dc=com"
    bind_dn: "cn=admin,dc=company,dc=com"
    bind_password: "${LDAP_PASSWORD}"

authorization:
  method: "rbac"
  roles:
    - name: "admin"
      permissions: ["*"]
    - name: "developer"
      permissions: ["read", "write", "build"]
    - name: "analyst"
      permissions: ["read", "analyze"]

logging:
  level: "info"
  output: "/var/log/sovereign/app.log"
  rotation:
    enabled: true
    maxSize: "100MB"
    maxAge: "30d"
    maxBackups: 10

monitoring:
  enabled: true
  prometheus:
    enabled: true
    port: 9090
  grafana:
    enabled: true
    dashboard: "/etc/sovereign/grafana/dashboards"
```

---

## Maintenance

### Backup Procedures

```bash
#!/bin/bash
# backup.sh

BACKUP_DIR="/backup/sovereign/$(date +%Y%m%d)"
mkdir -p "$BACKUP_DIR"

# Backup configuration
cp -r ~/.config/sovereign "$BACKUP_DIR/config"

# Backup workspaces
cp -r ~/SovereignWorkspaces "$BACKUP_DIR/workspaces"

# Backup database (if using external DB)
pg_dump -h localhost -U sovereign sovereign_db > "$BACKUP_DIR/database.sql"

# Create archive
tar -czf "$BACKUP_DIR.tar.gz" "$BACKUP_DIR"
rm -rf "$BACKUP_DIR"

echo "Backup completed: $BACKUP_DIR.tar.gz"
```

### Log Rotation

```bash
# /etc/logrotate.d/sovereign
/var/log/sovereign/*.log {
    daily
    rotate 30
    compress
    delaycompress
    missingok
    notifempty
    create 0644 sovereign sovereign
    sharedscripts
    postrotate
        /bin/kill -HUP $(cat /var/run/sovereign.pid 2>/dev/null) 2>/dev/null || true
    endscript
}
```

### Health Checks

```bash
#!/bin/bash
# health-check.sh

# Check process
if ! pgrep -x "sovereign" > /dev/null; then
    echo "ERROR: Sovereign IDE process not running"
    exit 1
fi

# Check API
if ! curl -sf http://localhost:8080/api/v1/health > /dev/null; then
    echo "ERROR: API not responding"
    exit 1
fi

# Check disk space
DISK_USAGE=$(df /var/lib/sovereign | awk 'NR==2 {print $5}' | sed 's/%//')
if [ "$DISK_USAGE" -gt 90 ]; then
    echo "WARNING: Disk usage at ${DISK_USAGE}%"
fi

# Check memory
MEMORY_USAGE=$(free | awk 'NR==2{printf "%.0f", $3*100/$2}')
if [ "$MEMORY_USAGE" -gt 90 ]; then
    echo "WARNING: Memory usage at ${MEMORY_USAGE}%"
fi

echo "Health check passed"
```

### Performance Monitoring

```python
# monitor.py
import psutil
import requests
import time
import json

def monitor_system():
    metrics = {
        "timestamp": time.time(),
        "cpu_percent": psutil.cpu_percent(interval=1),
        "memory_percent": psutil.virtual_memory().percent,
        "disk_usage": psutil.disk_usage('/').percent,
        "sovereign_process": None
    }
    
    # Find Sovereign process
    for proc in psutil.process_iter(['pid', 'name', 'memory_info']):
        if proc.info['name'] == 'sovereign':
            metrics["sovereign_process"] = {
                "pid": proc.info['pid'],
                "memory_mb": proc.info['memory_info'].rss / 1024 / 1024
            }
            break
    
    # Check API
    try:
        response = requests.get('http://localhost:8080/api/v1/metrics', timeout=5)
        metrics["api_status"] = "healthy" if response.status_code == 200 else "degraded"
        metrics["api_response_time_ms"] = response.elapsed.total_seconds() * 1000
    except:
        metrics["api_status"] = "unhealthy"
    
    return metrics

if __name__ == "__main__":
    while True:
        metrics = monitor_system()
        print(json.dumps(metrics))
        time.sleep(60)
```

---

## Troubleshooting

### Common Issues

#### Issue 1: Application Won't Start

**Symptoms:**
- Double-clicking icon does nothing
- Process immediately exits

**Solutions:**
```bash
# Check logs
tail -f ~/.config/sovereign/logs/app.log

# Check for missing dependencies
ldd /usr/bin/sovereign  # Linux
otool -L /Applications/SovereignIDE.app/Contents/MacOS/sovereign  # macOS

# Reset configuration
mv ~/.config/sovereign ~/.config/sovereign.backup

# Reinstall
sudo apt-get remove --purge sovereign-ide
sudo apt-get install sovereign-ide
```

#### Issue 2: AI Features Not Working

**Symptoms:**
- Chat returns errors
- Model loading fails

**Solutions:**
```bash
# Check model files
ls -la /opt/sovereign/models/

# Verify GPU support
nvidia-smi  # NVIDIA
clinfo      # OpenCL

# Check AI backend logs
tail -f ~/.config/sovereign/logs/ai.log

# Re-download models
sovereign --download-models
```

#### Issue 3: Performance Issues

**Symptoms:**
- Slow response times
- High CPU/memory usage

**Solutions:**
```bash
# Check resource usage
top -p $(pgrep sovereign)

# Enable performance profiling
sovereign --enable-profiling

# Reduce AI context size
# Edit ~/.config/sovereign/settings.json
# Set ai.contextSize to 2048

# Disable GPU acceleration if problematic
# Set ai.gpuLayers to 0
```

### Diagnostic Commands

```bash
# Get version info
sovereign --version
sovereign --version-full

# Verify installation
sovereign --verify

# Check configuration
sovereign --config-check

# Run diagnostics
sovereign --diagnose

# Reset to defaults
sovereign --reset-config

# Safe mode (disable plugins)
sovereign --safe-mode

# Verbose logging
sovereign --verbose
```

### Log Analysis

```bash
# View recent errors
grep -i "error" ~/.config/sovereign/logs/app.log | tail -20

# View crash dumps
ls -la ~/.config/sovereign/crashes/

# Analyze performance
sovereign --analyze-performance

# Generate diagnostic report
sovereign --generate-report > diagnostic-report.txt
```

---

## Upgrade Procedures

### Minor Version Upgrade

```bash
# Backup current installation
sudo cp -r /opt/sovereign /opt/sovereign.backup

# Download new version
wget https://sovereign-ide.com/download/sovereign-ide_1.0.1_amd64.deb

# Upgrade
sudo dpkg -i sovereign-ide_1.0.1_amd64.deb

# Verify
sovereign --version

# Test basic functionality
sovereign --test
```

### Major Version Upgrade

```bash
#!/bin/bash
# upgrade-major.sh

echo "Starting major version upgrade..."

# 1. Full backup
./backup.sh

# 2. Export settings
sovereign --export-config > config-backup.json

# 3. Stop service
sudo systemctl stop sovereign-ide

# 4. Uninstall old version
sudo apt-get remove sovereign-ide

# 5. Install new version
sudo dpkg -i sovereign-ide_2.0.0_amd64.deb

# 6. Migrate configuration
sovereign --migrate-config config-backup.json

# 7. Start service
sudo systemctl start sovereign-ide

# 8. Verify
sleep 5
sovereign --health-check

echo "Upgrade complete!"
```

### Rollback Procedure

```bash
#!/bin/bash
# rollback.sh

echo "Rolling back to previous version..."

# Stop service
sudo systemctl stop sovereign-ide

# Restore from backup
sudo rm -rf /opt/sovereign
sudo cp -r /opt/sovereign.backup /opt/sovereign

# Restore configuration
cp ~/.config/sovereign.backup/settings.json ~/.config/sovereign/

# Start service
sudo systemctl start sovereign-ide

# Verify
sovereign --version
sovereign --health-check

echo "Rollback complete!"
```

### Database Migration

```bash
#!/bin/bash
# migrate-database.sh

# Backup database
pg_dump -h localhost -U sovereign sovereign_db > db-backup.sql

# Run migration scripts
sovereign --migrate-database --from=1.0 --to=2.0

# Verify migration
sovereign --verify-database

# If failed, restore
# psql -h localhost -U sovereign sovereign_db < db-backup.sql
```

---

## Summary

The Deployment Guide provides:

- ✅ **Platform-specific installation** (Windows, Linux, macOS)
- ✅ **Container deployment** (Docker, Kubernetes)
- ✅ **Configuration management** (files, environment variables)
- ✅ **Maintenance procedures** (backup, monitoring, health checks)
- ✅ **Troubleshooting guide** (common issues, diagnostic commands)
- ✅ **Upgrade procedures** (minor, major, rollback)

**Status:** ✅ Complete

---

*End of Deployment Guide*
