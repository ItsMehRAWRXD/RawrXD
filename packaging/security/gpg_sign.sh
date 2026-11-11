#!/bin/bash
# gpg_sign.sh
# Phase F.1 Batch 3/5: GPG signing for Linux/macOS releases

set -e

# Configuration
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
RELEASE_DIR="${1:-./release}"
GPG_KEY_ID="${GPG_KEY_ID:-}"  # Set via environment or argument
OUTPUT_DIR="${2:-./signed}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m' # No Color

# Logging functions
log_status() {
    echo -e "${CYAN}[SIGN]${NC} $1"
}

log_success() {
    echo -e "${GREEN}[SUCCESS]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

# Check dependencies
check_dependencies() {
    log_status "Checking dependencies..."
    
    if ! command -v gpg &> /dev/null; then
        log_error "GPG not found. Please install GnuPG."
        exit 1
    fi
    
    if ! command -v sha256sum &> /dev/null; then
        log_error "sha256sum not found. Please install coreutils."
        exit 1
    fi
    
    log_success "Dependencies OK"
}

# List available keys
list_keys() {
    log_status "Available GPG keys:"
    gpg --list-secret-keys --keyid-format LONG
}

# Sign a file
sign_file() {
    local file="$1"
    local key_id="$2"
    
    log_status "Signing: $(basename "$file")"
    
    if [ -z "$key_id" ]; then
        # Detached signature without specific key
        gpg --armor --detach-sign "$file"
    else
        # Detached signature with specific key
        gpg --armor --detach-sign --local-user "$key_id" "$file"
    fi
    
    log_success "Created: ${file}.asc"
}

# Generate checksums
generate_checksums() {
    local target_dir="$1"
    local output_file="$2"
    
    log_status "Generating checksums..."
    
    (
        cd "$target_dir" || exit 1
        sha256sum * > "$output_file"
    )
    
    log_success "Checksums written to: $output_file"
}

# Sign checksums file
sign_checksums() {
    local checksums_file="$1"
    local key_id="$2"
    
    log_status "Signing checksums file..."
    
    if [ -z "$key_id" ]; then
        gpg --armor --detach-sign "$checksums_file"
    else
        gpg --armor --detach-sign --local-user "$key_id" "$checksums_file"
    fi
    
    log_success "Signed checksums: ${checksums_file}.asc"
}

# Verify signature
verify_signature() {
    local file="$1"
    local sig_file="${file}.asc"
    
    if [ ! -f "$sig_file" ]; then
        log_warn "Signature file not found: $sig_file"
        return 1
    fi
    
    log_status "Verifying: $(basename "$file")"
    
    if gpg --verify "$sig_file" "$file" 2>/dev/null; then
        log_success "Signature valid"
        return 0
    else
        log_error "Signature verification failed"
        return 1
    fi
}

# Verify checksums
verify_checksums() {
    local checksums_file="$1"
    
    log_status "Verifying checksums..."
    
    if [ ! -f "$checksums_file" ]; then
        log_error "Checksums file not found: $checksums_file"
        return 1
    fi
    
    local dir=$(dirname "$checksums_file")
    
    (
        cd "$dir" || exit 1
        if sha256sum -c "$(basename "$checksums_file")" 2>/dev/null | grep -q "FAILED"; then
            log_error "Checksum verification failed"
            return 1
        else
            log_success "All checksums valid"
            return 0
        fi
    )
}

# Create signed release package
create_signed_package() {
    local input_dir="$1"
    local output_dir="$2"
    local key_id="$3"
    
    log_status "Creating signed release package..."
    
    # Create output directory
    mkdir -p "$output_dir"
    
    # Copy files
    cp -r "$input_dir"/* "$output_dir/"
    
    # Sign each executable and archive
    for file in "$output_dir"/*; do
        if [ -f "$file" ]; then
            case "${file##*.}" in
                exe|dll|so|dylib|tar|gz|bz2|xz|zip|rpm|deb|AppImage)
                    sign_file "$file" "$key_id"
                    ;;
            esac
        fi
    done
    
    # Generate checksums
    local checksums_file="$output_dir/SHA256SUMS"
    generate_checksums "$output_dir" "$checksums_file"
    
    # Sign checksums
    sign_checksums "$checksums_file" "$key_id"
    
    # Create manifest
    create_manifest "$output_dir" "$key_id"
    
    log_success "Signed package created in: $output_dir"
}

# Create manifest
create_manifest() {
    local dir="$1"
    local key_id="$2"
    
    log_status "Creating manifest..."
    
    local manifest_file="$dir/manifest.json"
    local timestamp=$(date -u +"%Y-%m-%dT%H:%M:%SZ")
    
    # Get GPG key fingerprint
    local fingerprint=""
    if [ -n "$key_id" ]; then
        fingerprint=$(gpg --list-keys --with-colons "$key_id" 2>/dev/null | grep fpr | head -1 | cut -d: -f10)
    fi
    
    cat > "$manifest_file" << EOF
{
    "product": "RawrXD Sovereign",
    "version": "1.0.0",
    "timestamp": "$timestamp",
    "signed_by": {
        "key_id": "$key_id",
        "fingerprint": "$fingerprint"
    },
    "files": [
EOF
    
    # Add file entries
    local first=true
    for file in "$dir"/*; do
        if [ -f "$file" ] && [[ "$(basename "$file")" != "manifest.json" ]]; then
            local filename=$(basename "$file")
            local hash=$(sha256sum "$file" | cut -d' ' -f1)
            local size=$(stat -f%z "$file" 2>/dev/null || stat -c%s "$file" 2>/dev/null)
            
            if [ "$first" = true ]; then
                first=false
            else
                echo "," >> "$manifest_file"
            fi
            
            cat >> "$manifest_file" << EOF
        {
            "name": "$filename",
            "sha256": "$hash",
            "size": $size
        }
EOF
        fi
    done
    
    cat >> "$manifest_file" << EOF

    ]
}
EOF
    
    log_success "Manifest created: $manifest_file"
}

# Main function
main() {
    echo ""
    echo "=== RawrXD GPG Signing Tool ==="
    echo ""
    
    # Parse arguments
    local command="${1:-sign}"
    local target="${2:-$RELEASE_DIR}"
    
    check_dependencies
    
    case "$command" in
        sign)
            if [ -z "$GPG_KEY_ID" ]; then
                log_warn "No GPG_KEY_ID set, using default key"
                list_keys
            fi
            create_signed_package "$target" "$OUTPUT_DIR" "$GPG_KEY_ID"
            ;;
        verify)
            if [ -f "$target" ]; then
                verify_signature "$target"
            elif [ -d "$target" ]; then
                for sig in "$target"/*.asc; do
                    if [ -f "$sig" ]; then
                        local original="${sig%.asc}"
                        verify_signature "$original"
                    fi
                done
                
                # Verify checksums
                if [ -f "$target/SHA256SUMS" ]; then
                    verify_checksums "$target/SHA256SUMS"
                fi
            fi
            ;;
        list-keys)
            list_keys
            ;;
        *)
            echo "Usage: $0 [sign|verify|list-keys] [target]"
            echo ""
            echo "Commands:"
            echo "  sign       Sign all files in target directory"
            echo "  verify     Verify signatures in target directory"
            echo "  list-keys  List available GPG keys"
            echo ""
            echo "Environment variables:"
            echo "  GPG_KEY_ID    GPG key ID to use for signing"
            exit 1
            ;;
    esac
    
    echo ""
    log_success "Done!"
    echo ""
}

# Run main
main "$@"
