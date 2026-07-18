#!/bin/bash
# Monitoring & Metrics Collection Script for RawrXD Benchmark Suite
# Copyright (c) 2026 RawrXD Team

set -e

# Configuration
METRICS_INTERVAL="${METRICS_INTERVAL:-60}"
METRICS_RETENTION_DAYS="${METRICS_RETENTION_DAYS:-30}"
METRICS_DIR="${METRICS_DIR:-/var/lib/rawrxd/metrics}"
PROMETHEUS_PORT="${PROMETHEUS_PORT:-9090}"
GRAFANA_PORT="${GRAFANA_PORT:-3000}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[MONITOR]${NC} $1"
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

# Collect system metrics
collect_system_metrics() {
    local timestamp=$(date +%s)
    local output_file="$METRICS_DIR/system_${timestamp}.json"
    
    # CPU usage
    local cpu_usage=$(top -bn1 | grep "Cpu(s)" | awk '{print $2}' | cut -d'%' -f1)
    
    # Memory usage
    local mem_info=$(free -m | awk 'NR==2{printf "%.2f", $3*100/$2}')
    
    # Disk usage
    local disk_usage=$(df -h / | awk 'NR==2{print $5}' | cut -d'%' -f1)
    
    # Load average
    local load_avg=$(uptime | awk -F'load average:' '{print $2}' | awk '{print $1}' | tr -d ',')
    
    # Network stats
    local net_rx=$(cat /proc/net/dev | grep eth0 | awk '{print $2}')
    local net_tx=$(cat /proc/net/dev | grep eth0 | awk '{print $10}')
    
    # Create JSON output
    cat > "$output_file" << EOF
{
    "timestamp": $timestamp,
    "type": "system",
    "metrics": {
        "cpu_usage_percent": ${cpu_usage:-0},
        "memory_usage_percent": ${mem_info:-0},
        "disk_usage_percent": ${disk_usage:-0},
        "load_average_1m": ${load_avg:-0},
        "network_rx_bytes": ${net_rx:-0},
        "network_tx_bytes": ${net_tx:-0}
    }
}
EOF
    
    print_status "Collected system metrics: CPU=${cpu_usage}%, MEM=${mem_info}%"
}

# Collect benchmark metrics
collect_benchmark_metrics() {
    local timestamp=$(date +%s)
    local output_file="$METRICS_DIR/benchmark_${timestamp}.json"
    
    # Check if benchmark process is running
    local benchmark_pid=$(pgrep -f "integrated_benchmark_runner" | head -1)
    
    if [ -n "$benchmark_pid" ]; then
        # Process metrics
        local proc_cpu=$(ps -p "$benchmark_pid" -o %cpu= 2>/dev/null || echo "0")
        local proc_mem=$(ps -p "$benchmark_pid" -o %mem= 2>/dev/null || echo "0")
        local proc_rss=$(ps -p "$benchmark_pid" -o rss= 2>/dev/null || echo "0")
        
        # Open file descriptors
        local open_fds=$(ls /proc/$benchmark_pid/fd 2>/dev/null | wc -l)
        
        # Thread count
        local thread_count=$(ls /proc/$benchmark_pid/task 2>/dev/null | wc -l)
        
        cat > "$output_file" << EOF
{
    "timestamp": $timestamp,
    "type": "benchmark",
    "pid": $benchmark_pid,
    "metrics": {
        "cpu_percent": ${proc_cpu:-0},
        "memory_percent": ${proc_mem:-0},
        "rss_kb": ${proc_rss:-0},
        "open_file_descriptors": ${open_fds:-0},
        "thread_count": ${thread_count:-0}
    }
}
EOF
        print_status "Collected benchmark metrics: PID=$benchmark_pid, CPU=${proc_cpu}%"
    else
        print_warning "Benchmark process not running"
    fi
}

# Collect backend health metrics
collect_backend_health() {
    local timestamp=$(date +%s)
    local output_file="$METRICS_DIR/backend_${timestamp}.json"
    
    # Check Sovereign health
    local sovereign_status="unknown"
    local sovereign_response_time="0"
    
    if curl -sf -o /dev/null -w "%{http_code}" \
            --max-time 5 \
            "http://localhost:8080/api/health" 2>/dev/null | grep -q "200"; then
        sovereign_status="healthy"
        sovereign_response_time=$(curl -sf -o /dev/null -w "%{time_total}" \
            --max-time 5 "http://localhost:8080/api/health" 2>/dev/null || echo "0")
    else
        sovereign_status="unhealthy"
    fi
    
    # Check Ollama health
    local ollama_status="unknown"
    local ollama_response_time="0"
    
    if curl -sf -o /dev/null -w "%{http_code}" \
            --max-time 5 \
            "http://localhost:11434/api/tags" 2>/dev/null | grep -q "200"; then
        ollama_status="healthy"
        ollama_response_time=$(curl -sf -o /dev/null -w "%{time_total}" \
            --max-time 5 "http://localhost:11434/api/tags" 2>/dev/null || echo "0")
    else
        ollama_status="unhealthy"
    fi
    
    cat > "$output_file" << EOF
{
    "timestamp": $timestamp,
    "type": "backend_health",
    "metrics": {
        "sovereign": {
            "status": "$sovereign_status",
            "response_time_ms": $(echo "$sovereign_response_time * 1000" | bc | cut -d'.' -f1)
        },
        "ollama": {
            "status": "$ollama_status",
            "response_time_ms": $(echo "$ollama_response_time * 1000" | bc | cut -d'.' -f1)
        }
    }
}
EOF
    
    print_status "Backend health: Sovereign=$sovereign_status, Ollama=$ollama_status"
}

# Generate Prometheus metrics endpoint
generate_prometheus_metrics() {
    local output_file="$METRICS_DIR/prometheus.metrics"
    
    {
        echo "# HELP rawrxd_benchmark_cpu_usage CPU usage percentage"
        echo "# TYPE rawrxd_benchmark_cpu_usage gauge"
        
        echo "# HELP rawrxd_benchmark_memory_usage Memory usage percentage"
        echo "# TYPE rawrxd_benchmark_memory_usage gauge"
        
        echo "# HELP rawrxd_backend_health Backend health status (1=healthy, 0=unhealthy)"
        echo "# TYPE rawrxd_backend_health gauge"
        
        echo "# HELP rawrxd_backend_response_time Backend response time in milliseconds"
        echo "# TYPE rawrxd_backend_response_time gauge"
        
        # Add latest metrics
        local latest_system=$(ls -t "$METRICS_DIR"/system_*.json 2>/dev/null | head -1)
        if [ -n "$latest_system" ]; then
            local cpu=$(jq -r '.metrics.cpu_usage_percent // 0' "$latest_system")
            local mem=$(jq -r '.metrics.memory_usage_percent // 0' "$latest_system")
            echo "rawrxd_benchmark_cpu_usage $cpu"
            echo "rawrxd_benchmark_memory_usage $mem"
        fi
        
        local latest_backend=$(ls -t "$METRICS_DIR"/backend_*.json 2>/dev/null | head -1)
        if [ -n "$latest_backend" ]; then
            local sovereign_status=$(jq -r '.metrics.sovereign.status' "$latest_backend")
            local ollama_status=$(jq -r '.metrics.ollama.status' "$latest_backend")
            local sovereign_time=$(jq -r '.metrics.sovereign.response_time_ms // 0' "$latest_backend")
            local ollama_time=$(jq -r '.metrics.ollama.response_time_ms // 0' "$latest_backend")
            
            [ "$sovereign_status" = "healthy" ] && echo "rawrxd_backend_health{backend=\"sovereign\"} 1" || echo "rawrxd_backend_health{backend=\"sovereign\"} 0"
            [ "$ollama_status" = "healthy" ] && echo "rawrxd_backend_health{backend=\"ollama\"} 1" || echo "rawrxd_backend_health{backend=\"ollama\"} 0"
            
            echo "rawrxd_backend_response_time{backend=\"sovereign\"} $sovereign_time"
            echo "rawrxd_backend_response_time{backend=\"ollama\"} $ollama_time"
        fi
        
    } > "$output_file"
    
    print_status "Generated Prometheus metrics at $output_file"
}

# Cleanup old metrics
cleanup_old_metrics() {
    print_status "Cleaning up metrics older than $METRICS_RETENTION_DAYS days..."
    
    find "$METRICS_DIR" -name "*.json" -type f -mtime +$METRICS_RETENTION_DAYS -delete
    
    local remaining=$(find "$METRICS_DIR" -name "*.json" | wc -l)
    print_status "Cleanup complete. $remaining metric files remaining."
}

# Start metrics collection daemon
start_daemon() {
    print_status "Starting metrics collection daemon..."
    
    mkdir -p "$METRICS_DIR"
    
    while true; do
        collect_system_metrics
        collect_benchmark_metrics
        collect_backend_health
        generate_prometheus_metrics
        
        # Cleanup once per day (at midnight)
        if [ "$(date +%H:%M)" = "00:00" ]; then
            cleanup_old_metrics
        fi
        
        sleep "$METRICS_INTERVAL"
    done
}

# Export metrics for external systems
export_metrics() {
    local format="${1:-json}"
    local since="${2:-1h}"
    
    local since_timestamp=$(date -d "-$since" +%s 2>/dev/null || date -v "-${since}" +%s)
    
    case "$format" in
        json)
            echo "["
            local first=true
            for file in "$METRICS_DIR"/*.json; do
                if [ -f "$file" ]; then
                    local file_ts=$(echo "$file" | grep -o '[0-9]\+' | head -1)
                    if [ "$file_ts" -ge "$since_timestamp" ]; then
                        $first || echo ","
                        first=false
                        cat "$file"
                    fi
                fi
            done
            echo "]"
            ;;
        csv)
            echo "timestamp,type,metric,value"
            for file in "$METRICS_DIR"/system_*.json; do
                if [ -f "$file" ]; then
                    local ts=$(jq -r '.timestamp' "$file")
                    jq -r '.metrics | to_entries[] | ["'$ts'", "system", .key, .value] | @csv' "$file"
                fi
            done
            ;;
        prometheus)
            generate_prometheus_metrics
            cat "$METRICS_DIR/prometheus.metrics"
            ;;
        *)
            print_error "Unknown format: $format"
            exit 1
            ;;
    esac
}

# Show current status
show_status() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              RawrXD Metrics Status                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    # Count metrics files
    local system_count=$(find "$METRICS_DIR" -name "system_*.json" | wc -l)
    local benchmark_count=$(find "$METRICS_DIR" -name "benchmark_*.json" | wc -l)
    local backend_count=$(find "$METRICS_DIR" -name "backend_*.json" | wc -l)
    
    print_info "Metrics Collection Status:"
    echo "  System metrics:     $system_count files"
    echo "  Benchmark metrics:  $benchmark_count files"
    echo "  Backend health:     $backend_count files"
    echo ""
    
    # Show latest values
    local latest_system=$(ls -t "$METRICS_DIR"/system_*.json 2>/dev/null | head -1)
    if [ -n "$latest_system" ]; then
        print_info "Latest System Metrics:"
        jq -r '.metrics | to_entries[] | "  \(.key): \(.value)"' "$latest_system"
    fi
    
    echo ""
    
    # Show backend status
    local latest_backend=$(ls -t "$METRICS_DIR"/backend_*.json 2>/dev/null | head -1)
    if [ -n "$latest_backend" ]; then
        print_info "Backend Health:"
        jq -r '.metrics | to_entries[] | "  \(.key): \(.value.status) (\(.value.response_time_ms)ms)"' "$latest_backend"
    fi
}

# Main function
main() {
    local command="${1:-status}"
    
    mkdir -p "$METRICS_DIR"
    
    case "$command" in
        collect)
            collect_system_metrics
            collect_benchmark_metrics
            collect_backend_health
            generate_prometheus_metrics
            ;;
        daemon)
            start_daemon
            ;;
        export)
            export_metrics "${2:-json}" "${3:-1h}"
            ;;
        cleanup)
            cleanup_old_metrics
            ;;
        status|*)
            show_status
            ;;
    esac
}

# Show usage
usage() {
    echo "Usage: $0 [COMMAND] [OPTIONS]"
    echo ""
    echo "Commands:"
    echo "  collect              Collect metrics once"
    echo "  daemon               Start metrics collection daemon"
    echo "  export [fmt] [time]  Export metrics (json|csv|prometheus)"
    echo "  cleanup              Remove old metrics"
    echo "  status               Show current status (default)"
    echo ""
    echo "Examples:"
    echo "  $0 collect                    # Collect metrics once"
    echo "  $0 daemon                     # Start daemon"
    echo "  $0 export json 24h            # Export last 24h as JSON"
    echo "  $0 export prometheus          # Export Prometheus format"
}

# Parse arguments
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

main "$@"
