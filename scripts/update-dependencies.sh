#!/bin/bash
# RawrXD Dependency Update Script
# Usage: ./scripts/update-dependencies.sh [check|update|audit]

set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
SERVICES_DIR="$PROJECT_ROOT/services"

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

# Check if pip-audit is installed
check_pip_audit() {
    if ! command -v pip-audit &> /dev/null; then
        log_warn "pip-audit not found. Installing..."
        pip install pip-audit
    fi
}

# Check current dependencies for vulnerabilities
check_dependencies() {
    log_info "Checking Python dependencies for vulnerabilities..."
    check_pip_audit
    
    cd "$SERVICES_DIR"
    
    # Generate requirements from current environment if needed
    if [ ! -f "requirements.txt" ]; then
        log_error "requirements.txt not found in $SERVICES_DIR"
        exit 1
    fi
    
    # Run pip-audit
    pip-audit --desc --format=markdown -r requirements.txt || true
    
    log_info "Check complete. Review the output above for vulnerabilities."
}

# Update dependencies to latest secure versions
update_dependencies() {
    log_info "Updating Python dependencies..."
    
    cd "$SERVICES_DIR"
    
    # Create backup
    cp requirements.txt requirements.txt.backup.$(date +%Y%m%d-%H%M%S)
    log_info "Backup created: requirements.txt.backup.*"
    
    # Update pip first
    pip install --upgrade pip
    
    # Install pip-tools for better dependency management
    pip install pip-tools
    
    # Generate new requirements with latest versions
    # This will resolve dependencies and find compatible versions
    pip-compile --upgrade --output-file=requirements.txt requirements.in 2>/dev/null || {
        log_warn "No requirements.in found. Using direct update method..."
        
        # Update each package to latest version
        while IFS= read -r line || [[ -n "$line" ]]; do
            # Skip comments and empty lines
            [[ "$line" =~ ^#.*$ ]] && continue
            [[ -z "$line" ]] && continue
            
            # Extract package name (handle ==, >=, <=, ~= operators)
            pkg=$(echo "$line" | sed -E 's/([a-zA-Z0-9_-]+).*/\1/')
            
            if [ -n "$pkg" ]; then
                log_info "Updating $pkg..."
                pip install --upgrade "$pkg" 2>/dev/null || log_warn "Could not update $pkg"
            fi
        done < requirements.txt
        
        # Freeze current versions
        pip freeze | grep -f <(grep -oE '^[a-zA-Z0-9_-]+' requirements.txt) > requirements.new.txt
        mv requirements.new.txt requirements.txt
    }
    
    log_info "Dependencies updated. Review changes and test before committing."
}

# Run full security audit
run_audit() {
    log_info "Running full security audit..."
    
    check_pip_audit
    
    cd "$SERVICES_DIR"
    
    # Generate audit report
    local report_file="../SECURITY_AUDIT_$(date +%Y%m%d).md"
    
    cat > "$report_file" << EOF
# RawrXD Security Audit Report

**Date:** $(date +%Y-%m-%d)  
**Version:** $(git describe --tags --always 2>/dev/null || echo "unknown")  
**Commit:** $(git rev-parse --short HEAD 2>/dev/null || echo "unknown")

## Python Dependencies

EOF
    
    # Add pip-audit results
    pip-audit --desc --format=markdown -r requirements.txt >> "$report_file" 2>/dev/null || true
    
    cat >> "$report_file" << EOF

## Recommendations

1. Review all HIGH and CRITICAL vulnerabilities immediately
2. Update dependencies using: ./scripts/update-dependencies.sh update
3. Run tests after updating: ./scripts/run-tests.sh
4. Create a PR with the updated requirements.txt

## Next Steps

- [ ] Review and approve dependency updates
- [ ] Run full test suite
- [ ] Update CHANGELOG.md
- [ ] Tag new release if needed

EOF
    
    log_info "Audit report generated: $report_file"
}

# Main command handler
case "${1:-check}" in
    check)
        check_dependencies
        ;;
    update)
        update_dependencies
        ;;
    audit)
        run_audit
        ;;
    *)
        echo "Usage: $0 [check|update|audit]"
        echo ""
        echo "Commands:"
        echo "  check  - Check for vulnerable dependencies (default)"
        echo "  update - Update dependencies to latest secure versions"
        echo "  audit  - Generate full security audit report"
        exit 1
        ;;
esac
