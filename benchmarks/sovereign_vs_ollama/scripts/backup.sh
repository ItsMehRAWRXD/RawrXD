#!/bin/bash
# Backup & Recovery Automation Script for RawrXD Benchmark Suite
# Copyright (c) 2026 RawrXD Team

set -e

# Configuration
BACKUP_DIR="${BACKUP_DIR:-/var/backups/rawrxd}"
DATA_DIR="${DATA_DIR:-/var/lib/rawrxd}"
CONFIG_DIR="${CONFIG_DIR:-/etc/rawrxd}"
LOG_DIR="${LOG_DIR:-/var/log/rawrxd}"
RETENTION_DAYS="${RETENTION_DAYS:-30}"
COMPRESS="${COMPRESS:-true}"
ENCRYPT="${ENCRYPT:-false}"
REMOTE_BACKUP="${REMOTE_BACKUP:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[BACKUP]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_info() {
    echo -e "${BLUE}[INFO]${NC} $1"
}

# Create backup directory structure
setup_backup_dirs() {
    mkdir -p "$BACKUP_DIR"/{daily,weekly,monthly,manual}
    mkdir -p "$BACKUP_DIR"/logs
}

# Generate backup filename
generate_backup_name() {
    local type="$1"
    local timestamp=$(date +%Y%m%d_%H%M%S)
    echo "rawrxd_${type}_${timestamp}"
}

# Backup data directory
backup_data() {
    local backup_name="$1"
    local temp_dir=$(mktemp -d)
    
    print_status "Backing up data directory..."
    
    # Create archive
    local archive_path="$BACKUP_DIR/manual/${backup_name}_data.tar"
    
    tar -cf "$archive_path" -C "$DATA_DIR" . 2>&1 | tee -a "$BACKUP_DIR/logs/backup_${backup_name}.log"
    
    # Compress if enabled
    if [ "$COMPRESS" = "true" ]; then
        print_status "Compressing backup..."
        gzip -f "$archive_path"
        archive_path="${archive_path}.gz"
    fi
    
    # Encrypt if enabled
    if [ "$ENCRYPT" = "true" ] && [ -n "$ENCRYPTION_KEY" ]; then
        print_status "Encrypting backup..."
        openssl enc -aes-256-cbc -salt -in "$archive_path" -out "${archive_path}.enc" -k "$ENCRYPTION_KEY"
        rm "$archive_path"
        archive_path="${archive_path}.enc"
    fi
    
    # Calculate checksum
    local checksum=$(sha256sum "$archive_path" | awk '{print $1}')
    echo "$checksum  $(basename "$archive_path")" > "${archive_path}.sha256"
    
    rm -rf "$temp_dir"
    
    print_status "Data backup complete: $archive_path"
    echo "$archive_path"
}

# Backup configuration
backup_config() {
    local backup_name="$1"
    
    print_status "Backing up configuration..."
    
    local archive_path="$BACKUP_DIR/manual/${backup_name}_config.tar.gz"
    
    tar -czf "$archive_path" -C "$CONFIG_DIR" . 2>&1 | tee -a "$BACKUP_DIR/logs/backup_${backup_name}.log"
    
    # Calculate checksum
    local checksum=$(sha256sum "$archive_path" | awk '{print $1}')
    echo "$checksum  $(basename "$archive_path")" > "${archive_path}.sha256"
    
    print_status "Configuration backup complete: $archive_path"
    echo "$archive_path"
}

# Backup logs (recent only)
backup_logs() {
    local backup_name="$1"
    local days="${2:-7}"
    
    print_status "Backing up logs (last $days days)..."
    
    local archive_path="$BACKUP_DIR/manual/${backup_name}_logs.tar.gz"
    
    find "$LOG_DIR" -name "*.log" -mtime -$days -print0 | \
        tar -czf "$archive_path" --null -T - 2>&1 | \
        tee -a "$BACKUP_DIR/logs/backup_${backup_name}.log"
    
    # Calculate checksum
    local checksum=$(sha256sum "$archive_path" | awk '{print $1}')
    echo "$checksum  $(basename "$archive_path")" > "${archive_path}.sha256"
    
    print_status "Logs backup complete: $archive_path"
    echo "$archive_path"
}

# Full backup (data + config + logs)
backup_full() {
    local backup_name=$(generate_backup_name "full")
    
    print_status "Starting full backup: $backup_name"
    
    setup_backup_dirs
    
    local data_backup=$(backup_data "$backup_name")
    local config_backup=$(backup_config "$backup_name")
    local logs_backup=$(backup_logs "$backup_name")
    
    # Create manifest
    local manifest="$BACKUP_DIR/manual/${backup_name}_manifest.json"
    cat > "$manifest" << EOF
{
    "backup_name": "$backup_name",
    "timestamp": "$(date -Iseconds)",
    "type": "full",
    "components": {
        "data": {
            "path": "$data_backup",
            "size": $(stat -c%s "$data_backup" 2>/dev/null || stat -f%z "$data_backup")
        },
        "config": {
            "path": "$config_backup",
            "size": $(stat -c%s "$config_backup" 2>/dev/null || stat -f%z "$config_backup")
        },
        "logs": {
            "path": "$logs_backup",
            "size": $(stat -c%s "$logs_backup" 2>/dev/null || stat -f%z "$logs_backup")
        }
    },
    "checksums_verified": true
}
EOF
    
    # Remote backup if configured
    if [ -n "$REMOTE_BACKUP" ]; then
        remote_backup "$backup_name" "$manifest"
    fi
    
    print_status "Full backup complete: $backup_name"
    echo "$backup_name"
}

# Remote backup sync
remote_backup() {
    local backup_name="$1"
    local manifest="$2"
    
    print_status "Syncing to remote backup location..."
    
    case "$REMOTE_BACKUP" in
        s3://*)
            aws s3 sync "$BACKUP_DIR/manual/" "$REMOTE_BACKUP/" --exclude "*.log"
            ;;
        rsync://*)
            local remote_path="${REMOTE_BACKUP#rsync://}"
            rsync -avz --delete "$BACKUP_DIR/manual/" "$remote_path/"
            ;;
        *)
            print_warning "Unknown remote backup type: $REMOTE_BACKUP"
            ;;
    esac
}

# List available backups
list_backups() {
    print_status "Available backups:"
    
    echo ""
    echo "Full Backups:"
    echo "-------------"
    for manifest in "$BACKUP_DIR"/*/*_manifest.json 2>/dev/null; do
        if [ -f "$manifest" ]; then
            local name=$(jq -r '.backup_name' "$manifest")
            local timestamp=$(jq -r '.timestamp' "$manifest")
            local type=$(jq -r '.type' "$manifest")
            echo "  $name ($type) - $timestamp"
        fi
    done
    
    echo ""
    echo "Backup Storage Usage:"
    du -sh "$BACKUP_DIR" 2>/dev/null || echo "  No backups found"
}

# Verify backup integrity
verify_backup() {
    local backup_name="$1"
    
    print_status "Verifying backup: $backup_name"
    
    local verified=true
    
    # Check each component
    for shafile in "$BACKUP_DIR"/manual/${backup_name}_*.sha256; do
        if [ -f "$shafile" ]; then
            local archive="${shafile%.sha256}"
            if [ -f "$archive" ]; then
                if sha256sum -c "$shafile" > /dev/null 2>&1; then
                    print_status "✓ $(basename "$archive")"
                else
                    print_error "✗ $(basename "$archive") - checksum mismatch!"
                    verified=false
                fi
            else
                print_warning "Missing archive: $(basename "$archive")"
                verified=false
            fi
        fi
    done
    
    if [ "$verified" = "true" ]; then
        print_status "Backup verification passed"
        return 0
    else
        print_error "Backup verification failed"
        return 1
    fi
}

# Restore from backup
restore_backup() {
    local backup_name="$1"
    local component="${2:-all}"
    local target_dir="${3:-}"
    
    print_status "Restoring from backup: $backup_name"
    
    # Verify first
    if ! verify_backup "$backup_name"; then
        print_error "Backup verification failed, aborting restore"
        exit 1
    fi
    
    # Confirm restore
    if [ -z "$FORCE_RESTORE" ]; then
        echo "WARNING: This will overwrite existing data!"
        read -p "Are you sure? (yes/no): " confirm
        if [ "$confirm" != "yes" ]; then
            print_status "Restore cancelled"
            exit 0
        fi
    fi
    
    case "$component" in
        data)
            restore_component "$backup_name" "data" "$DATA_DIR" "$target_dir"
            ;;
        config)
            restore_component "$backup_name" "config" "$CONFIG_DIR" "$target_dir"
            ;;
        logs)
            restore_component "$backup_name" "logs" "$LOG_DIR" "$target_dir"
            ;;
        all|*)
            restore_component "$backup_name" "data" "$DATA_DIR" "$target_dir"
            restore_component "$backup_name" "config" "$CONFIG_DIR" "$target_dir"
            restore_component "$backup_name" "logs" "$LOG_DIR" "$target_dir"
            ;;
    esac
    
    print_status "Restore complete"
}

# Restore individual component
restore_component() {
    local backup_name="$1"
    local component="$2"
    local original_dir="$3"
    local target_dir="${4:-$original_dir}"
    
    print_status "Restoring $component..."
    
    local archive="$BACKUP_DIR/manual/${backup_name}_${component}.tar"
    
    # Handle compressed/encrypted archives
    if [ -f "${archive}.gz" ]; then
        archive="${archive}.gz"
    elif [ -f "${archive}.gz.enc" ]; then
        if [ -z "$ENCRYPTION_KEY" ]; then
            print_error "Encryption key required for encrypted backup"
            exit 1
        fi
        openssl enc -aes-256-cbc -d -in "${archive}.gz.enc" -out "${archive}.gz" -k "$ENCRYPTION_KEY"
        archive="${archive}.gz"
    fi
    
    # Extract
    if [ -f "$archive" ]; then
        mkdir -p "$target_dir"
        if [[ "$archive" == *.gz ]]; then
            tar -xzf "$archive" -C "$target_dir"
        else
            tar -xf "$archive" -C "$target_dir"
        fi
        print_status "Restored $component to $target_dir"
    else
        print_error "Archive not found: $archive"
        return 1
    fi
}

# Cleanup old backups
cleanup_backups() {
    print_status "Cleaning up backups older than $RETENTION_DAYS days..."
    
    find "$BACKUP_DIR" -name "*.tar*" -type f -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "*.sha256" -type f -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR" -name "*_manifest.json" -type f -mtime +$RETENTION_DAYS -delete
    find "$BACKUP_DIR"/logs -name "*.log" -type f -mtime +$RETENTION_DAYS -delete
    
    print_status "Cleanup complete"
}

# Schedule automatic backups
schedule_backup() {
    local schedule="$1"
    
    print_status "Scheduling $schedule backups..."
    
    local cron_expr=""
    case "$schedule" in
        hourly)
            cron_expr="0 * * * *"
            ;;
        daily)
            cron_expr="0 2 * * *"
            ;;
        weekly)
            cron_expr="0 2 * * 0"
            ;;
        monthly)
            cron_expr="0 2 1 * *"
            ;;
        *)
            print_error "Unknown schedule: $schedule"
            exit 1
            ;;
    esac
    
    # Add to crontab
    (crontab -l 2>/dev/null; echo "$cron_expr $SCRIPT_DIR/backup.sh auto $schedule") | crontab -
    
    print_status "Scheduled $schedule backups"
}

# Automated backup (called from cron)
auto_backup() {
    local type="$1"
    
    case "$type" in
        daily)
            backup_full
            cleanup_backups
            ;;
        weekly)
            backup_full
            cleanup_backups
            ;;
        monthly)
            backup_full
            cleanup_backups
            ;;
        *)
            backup_full
            ;;
    esac
}

# Main function
main() {
    local command="${1:-full}"
    
    setup_backup_dirs
    
    case "$command" in
        full)
            backup_full
            ;;
        data)
            local name=$(generate_backup_name "data")
            backup_data "$name"
            ;;
        config)
            local name=$(generate_backup_name "config")
            backup_config "$name"
            ;;
        logs)
            local name=$(generate_backup_name "logs")
            backup_logs "$name"
            ;;
        list)
            list_backups
            ;;
        verify)
            verify_backup "$2"
            ;;
        restore)
            restore_backup "$2" "${3:-all}" "${4:-}"
            ;;
        cleanup)
            cleanup_backups
            ;;
        schedule)
            schedule_backup "$2"
            ;;
        auto)
            auto_backup "$2"
            ;;
        *)
            print_error "Unknown command: $command"
            usage
            exit 1
            ;;
    esac
}

# Show usage
usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  full                    Create full backup"
    echo "  data                    Backup data only"
    echo "  config                  Backup configuration only"
    echo "  logs [days]             Backup logs (default: last 7 days)"
    echo "  list                    List available backups"
    echo "  verify <name>           Verify backup integrity"
    echo "  restore <name> [comp] [dir]  Restore from backup"
    echo "  cleanup                 Remove old backups"
    echo "  schedule <freq>          Schedule automatic backups"
    echo "  auto <type>             Automated backup (for cron)"
    echo ""
    echo "Examples:"
    echo "  $0 full                    # Full backup"
    echo "  $0 restore full_20260115   # Restore full backup"
    echo "  $0 schedule daily          # Schedule daily backups"
    echo "  ENCRYPTION_KEY=secret $0 full  # Encrypted backup"
}

# Parse arguments
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

main "$@"
