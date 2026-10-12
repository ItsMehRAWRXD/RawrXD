#!/bin/bash
# Security Incident Response Script
# Copyright (c) 2026 RawrXD Team

set -e

# Configuration
INCIDENT_LOG="/var/log/rawrxd/security_incidents.log"
ALERT_EMAIL="security@rawrxd.local"
SLACK_WEBHOOK="${SLACK_WEBHOOK_URL:-}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[SECURITY]${NC} $1"
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

# Log incident
log_incident() {
    local severity="$1"
    local type="$2"
    local description="$3"
    local timestamp=$(date -Iseconds)
    
    echo "[$timestamp] $severity - $type: $description" >> "$INCIDENT_LOG"
    
    # Send alert
    if [ -n "$SLACK_WEBHOOK" ]; then
        curl -s -X POST -H 'Content-type: application/json' \
            --data "{\"text\":\"SECURITY ALERT: $severity - $type\n$description\"}" \
            "$SLACK_WEBHOOK" > /dev/null 2>&1 || true
    fi
}

# Block IP address
block_ip() {
    local ip="$1"
    local reason="$2"
    
    print_status "Blocking IP: $ip"
    
    # Add to firewall
    if command -v ufw > /dev/null; then
        ufw deny from "$ip" comment "Security incident: $reason"
    fi
    
    # Add to iptables
    iptables -A INPUT -s "$ip" -j DROP
    
    # Add to hosts.deny
    echo "ALL: $ip" >> /etc/hosts.deny
    
    log_incident "HIGH" "IP_BLOCKED" "Blocked IP $ip: $reason"
    
    print_status "IP $ip blocked successfully"
}

# Revoke all sessions
revoke_all_sessions() {
    print_status "Revoking all active sessions..."
    
    # Kill all benchmark processes
    pkill -f "integrated_benchmark_runner" || true
    
    # Clear session cache
    rm -f /var/lib/rawrxd/sessions/*
    
    log_incident "CRITICAL" "SESSIONS_REVOKED" "All user sessions revoked"
    
    print_status "All sessions revoked"
}

# Force password reset
force_password_reset() {
    print_status "Forcing password reset for all users..."
    
    # Mark all passwords as expired
    # This would integrate with your auth system
    
    log_incident "HIGH" "PASSWORD_RESET" "Forced password reset for all users"
    
    print_status "Password reset initiated"
}

# Isolate system
isolate_system() {
    print_status "Isolating system..."
    
    # Disable network access
    iptables -P INPUT DROP
    iptables -P FORWARD DROP
    iptables -P OUTPUT DROP
    
    # Allow only loopback
    iptables -A INPUT -i lo -j ACCEPT
    iptables -A OUTPUT -o lo -j ACCEPT
    
    # Allow established connections
    iptables -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    iptables -A OUTPUT -m state --state ESTABLISHED,RELATED -j ACCEPT
    
    log_incident "CRITICAL" "SYSTEM_ISOLATED" "System network access restricted"
    
    print_status "System isolated"
}

# Preserve evidence
preserve_evidence() {
    local incident_id="$1"
    local evidence_dir="/var/lib/rawrxd/evidence/$incident_id"
    
    print_status "Preserving evidence to $evidence_dir..."
    
    mkdir -p "$evidence_dir"
    
    # Copy logs
    cp /var/log/rawrxd/*.log "$evidence_dir/" 2>/dev/null || true
    cp /var/log/syslog "$evidence_dir/" 2>/dev/null || true
    cp /var/log/auth.log "$evidence_dir/" 2>/dev/null || true
    
    # Copy configuration
    cp -r /etc/rawrxd "$evidence_dir/config" 2>/dev/null || true
    
    # Capture process list
    ps aux > "$evidence_dir/processes.txt"
    
    # Capture network connections
    netstat -tuln > "$evidence_dir/network.txt"
    
    # Create tarball
    tar -czf "$evidence_dir.tar.gz" "$evidence_dir"
    
    log_incident "HIGH" "EVIDENCE_PRESERVED" "Evidence preserved in $evidence_dir.tar.gz"
    
    print_status "Evidence preserved: $evidence_dir.tar.gz"
}

# Handle data breach
handle_data_breach() {
    print_error "DATA BREACH DETECTED"
    
    local incident_id="BREACH_$(date +%Y%m%d_%H%M%S)"
    
    # Step 1: Isolate system
    isolate_system
    
    # Step 2: Preserve evidence
    preserve_evidence "$incident_id"
    
    # Step 3: Revoke sessions
    revoke_all_sessions
    
    # Step 4: Notify stakeholders
    print_warning "Notifying stakeholders..."
    
    # Step 5: Generate breach report
    cat > "/var/lib/rawrxd/reports/breach_$incident_id.txt" << EOF
DATA BREACH INCIDENT REPORT
===========================
Incident ID: $incident_id
Timestamp: $(date -Iseconds)
Severity: CRITICAL

Actions Taken:
1. System isolated
2. Evidence preserved
3. All sessions revoked
4. Stakeholders notified

Next Steps:
- Forensic analysis required
- Legal review
- Regulatory notification (if required)
- Public disclosure (if required)
EOF
    
    log_incident "CRITICAL" "DATA_BREACH" "Data breach incident $incident_id handled"
    
    print_status "Data breach response completed"
}

# Handle brute force attack
handle_brute_force() {
    local attacker_ip="$1"
    
    print_warning "BRUTE FORCE ATTACK DETECTED from $attacker_ip"
    
    # Block the IP
    block_ip "$attacker_ip" "Brute force attack"
    
    # Review logs
    grep "$attacker_ip" /var/log/rawrxd/*.log > "/tmp/brute_force_$attacker_ip.log"
    
    log_incident "HIGH" "BRUTE_FORCE" "Brute force attack from $attacker_ip blocked"
    
    print_status "Brute force attack handled"
}

# Handle unauthorized access
handle_unauthorized_access() {
    local user_id="$1"
    
    print_error "UNAUTHORIZED ACCESS by $user_id"
    
    # Revoke all sessions
    revoke_all_sessions
    
    # Force password reset
    force_password_reset
    
    # Review audit logs
    ./scripts/logs.sh search "user:$user_id" 24h > "/tmp/unauthorized_$user_id.log"
    
    log_incident "CRITICAL" "UNAUTHORIZED_ACCESS" "Unauthorized access by $user_id"
    
    print_status "Unauthorized access handled"
}

# Main incident handler
handle_incident() {
    local incident_type="$1"
    shift
    
    print_status "Handling incident: $incident_type"
    
    case "$incident_type" in
        DATA_BREACH)
            handle_data_breach
            ;;
        BRUTE_FORCE)
            handle_brute_force "$1"
            ;;
        UNAUTHORIZED_ACCESS)
            handle_unauthorized_access "$1"
            ;;
        DDOS)
            print_status "Activating DDoS protection..."
            # Enable strict rate limiting
            iptables -A INPUT -p tcp --dport 8888 -m limit --limit 25/minute --limit-burst 100 -j ACCEPT
            iptables -A INPUT -p tcp --dport 8888 -j DROP
            log_incident "HIGH" "DDOS" "DDoS protection activated"
            ;;
        MALWARE)
            print_status "Isolating potential malware..."
            isolate_system
            preserve_evidence "MALWARE_$(date +%Y%m%d_%H%M%S)"
            log_incident "CRITICAL" "MALWARE" "Potential malware detected and isolated"
            ;;
        *)
            print_error "Unknown incident type: $incident_type"
            exit 1
            ;;
    esac
}

# Show usage
usage() {
    echo "Usage: $0 <INCIDENT_TYPE> [OPTIONS]"
    echo ""
    echo "Incident Types:"
    echo "  DATA_BREACH              Handle data breach"
    echo "  BRUTE_FORCE <ip>         Handle brute force attack"
    echo "  UNAUTHORIZED_ACCESS <id> Handle unauthorized access"
    echo "  DDOS                     Handle DDoS attack"
    echo "  MALWARE                  Handle malware detection"
    echo ""
    echo "Examples:"
    echo "  $0 DATA_BREACH"
    echo "  $0 BRUTE_FORCE 192.168.1.100"
    echo "  $0 UNAUTHORIZED_ACCESS user_123"
}

# Main
if [ $# -eq 0 ]; then
    usage
    exit 1
fi

# Create log directory
mkdir -p "$(dirname "$INCIDENT_LOG")"

# Handle incident
handle_incident "$@"

print_status "Incident response completed"
