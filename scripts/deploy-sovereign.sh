#!/bin/bash
#
# Sovereign Substrate Deployment Script
# Usage: ./deploy-sovereign.sh [environment] [version]
# Example: ./deploy-sovereign.sh production 1.0.0

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Configuration
ENVIRONMENT=${1:-staging}
VERSION=${2:-latest}
DEPLOY_DIR="/opt/sovereign"
BACKUP_DIR="/opt/sovereign-backups"
LOG_FILE="/var/log/sovereign-deploy.log"

# Logging function
log() {
    echo -e "${GREEN}[$(date +'%Y-%m-%d %H:%M:%S')] $1${NC}" | tee -a "$LOG_FILE"
}

warn() {
    echo -e "${YELLOW}[$(date +'%Y-%m-%d %H:%M:%S')] WARNING: $1${NC}" | tee -a "$LOG_FILE"
}

error() {
    echo -e "${RED}[$(date +'%Y-%m-%d %H:%M:%S')] ERROR: $1${NC}" | tee -a "$LOG_FILE"
    exit 1
}

# Pre-deployment checks
check_prerequisites() {
    log "Checking prerequisites..."
    
    # Check if running as root
    if [[ $EUID -ne 0 ]]; then
        error "This script must be run as root"
    fi
    
    # Check required tools
    command -v docker >/dev/null 2>&1 || error "Docker is required but not installed"
    command -v docker-compose >/dev/null 2>&1 || error "Docker Compose is required but not installed"
    
    # Check disk space
    AVAILABLE_SPACE=$(df /opt | tail -1 | awk '{print $4}')
    if [[ $AVAILABLE_SPACE -lt 1048576 ]]; then  # 1GB in KB
        error "Insufficient disk space. At least 1GB required"
    fi
    
    log "Prerequisites check passed"
}

# Create backup
create_backup() {
    log "Creating backup..."
    
    if [[ -d "$DEPLOY_DIR" ]]; then
        BACKUP_NAME="sovereign-$(date +%Y%m%d-%H%M%S)"
        mkdir -p "$BACKUP_DIR"
        
        # Stop current instance
        if [[ -f "$DEPLOY_DIR/docker-compose.yml" ]]; then
            (cd "$DEPLOY_DIR" && docker-compose down) || warn "Failed to stop current instance"
        fi
        
        # Create backup
        tar -czf "$BACKUP_DIR/$BACKUP_NAME.tar.gz" -C "$DEPLOY_DIR" . || error "Failed to create backup"
        log "Backup created: $BACKUP_DIR/$BACKUP_NAME.tar.gz"
    fi
}

# Deploy new version
deploy() {
    log "Deploying Sovereign Substrate v$VERSION to $ENVIRONMENT..."
    
    # Create deployment directory
    mkdir -p "$DEPLOY_DIR"
    
    # Copy configuration
    cp "config/sovereign.$ENVIRONMENT.json" "$DEPLOY_DIR/config.json" || error "Failed to copy configuration"
    
    # Copy Docker Compose file
    cp "docker/docker-compose.$ENVIRONMENT.yml" "$DEPLOY_DIR/docker-compose.yml" || error "Failed to copy Docker Compose file"
    
    # Pull latest image
    (cd "$DEPLOY_DIR" && docker-compose pull) || error "Failed to pull Docker image"
    
    # Start services
    (cd "$DEPLOY_DIR" && docker-compose up -d) || error "Failed to start services"
    
    log "Deployment completed successfully"
}

# Health check
health_check() {
    log "Running health checks..."
    
    # Wait for services to start
    sleep 10
    
    # Check if container is running
    if ! docker ps | grep -q "sovereign"; then
        error "Sovereign container is not running"
    fi
    
    # Check HTTP endpoint
    if ! curl -sf http://localhost:8080/health >/dev/null 2>&1; then
        error "Health check failed"
    fi
    
    # Check metrics endpoint
    if ! curl -sf http://localhost:8081/metrics >/dev/null 2>&1; then
        warn "Metrics endpoint not responding"
    fi
    
    log "Health checks passed"
}

# Cleanup old backups
cleanup_backups() {
    log "Cleaning up old backups..."
    
    # Keep only last 10 backups
    ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | tail -n +11 | xargs -r rm -f
    
    log "Cleanup completed"
}

# Rollback function
rollback() {
    error "Deployment failed. Rolling back..."
    
    # Find latest backup
    LATEST_BACKUP=$(ls -t "$BACKUP_DIR"/*.tar.gz 2>/dev/null | head -1)
    
    if [[ -n "$LATEST_BACKUP" ]]; then
        # Stop current instance
        (cd "$DEPLOY_DIR" && docker-compose down) || true
        
        # Restore backup
        rm -rf "$DEPLOY_DIR"/*
        tar -xzf "$LATEST_BACKUP" -C "$DEPLOY_DIR"
        
        # Restart services
        (cd "$DEPLOY_DIR" && docker-compose up -d)
        
        log "Rollback completed"
    else
        error "No backup found for rollback"
    fi
}

# Main deployment flow
main() {
    log "Starting Sovereign Substrate deployment"
    log "Environment: $ENVIRONMENT"
    log "Version: $VERSION"
    
    check_prerequisites
    create_backup
    deploy
    health_check
    cleanup_backups
    
    log "Deployment completed successfully!"
    log "Sovereign Substrate is now running on $ENVIRONMENT"
    log ""
    log "Access points:"
    log "  - API: http://localhost:8080"
    log "  - Metrics: http://localhost:8081"
    log "  - Logs: docker-compose logs -f"
}

# Trap errors for rollback
trap 'rollback' ERR

# Run main function
main
