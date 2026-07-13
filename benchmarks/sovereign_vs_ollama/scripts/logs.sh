#!/bin/bash
# Log Aggregation & Analysis Script for RawrXD Benchmark Suite
# Copyright (c) 2026 RawrXD Team

set -e

# Configuration
LOG_DIR="${LOG_DIR:-/var/log/rawrxd}"
ARCHIVE_DIR="${ARCHIVE_DIR:-/var/log/rawrxd/archive}"
ANALYSIS_DIR="${ANALYSIS_DIR:-/var/lib/rawrxd/analysis}"
RETENTION_DAYS="${RETENTION_DAYS:-90}"
ALERT_THRESHOLD_ERROR="${ALERT_THRESHOLD_ERROR:-100}"
ALERT_THRESHOLD_WARNING="${ALERT_THRESHOLD_WARNING:-500}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[LOGS]${NC} $1"
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

# Rotate and archive logs
rotate_logs() {
    print_status "Rotating logs..."
    
    mkdir -p "$ARCHIVE_DIR"
    
    # Find logs older than 7 days
    find "$LOG_DIR" -name "*.log" -type f -mtime +7 | while read -r logfile; do
        local basename=$(basename "$logfile")
        local archive_name="${basename%.log}_$(date +%Y%m%d).log.gz"
        
        # Compress and move to archive
        gzip -c "$logfile" > "$ARCHIVE_DIR/$archive_name"
        rm "$logfile"
        
        print_status "Archived: $basename -> $archive_name"
    done
    
    # Remove old archives
    find "$ARCHIVE_DIR" -name "*.gz" -type f -mtime +$RETENTION_DAYS -delete
    
    print_status "Log rotation complete"
}

# Analyze log patterns
analyze_patterns() {
    print_status "Analyzing log patterns..."
    
    mkdir -p "$ANALYSIS_DIR"
    local analysis_file="$ANALYSIS_DIR/pattern_analysis_$(date +%Y%m%d).json"
    
    # Count error patterns
    local error_count=$(grep -r "ERROR" "$LOG_DIR"/*.log 2>/dev/null | wc -l)
    local warning_count=$(grep -r "WARN" "$LOG_DIR"/*.log 2>/dev/null | wc -l)
    local fatal_count=$(grep -r "FATAL" "$LOG_DIR"/*.log 2>/dev/null | wc -l)
    
    # Count specific patterns
    local timeout_count=$(grep -r "timeout\|Timeout" "$LOG_DIR"/*.log 2>/dev/null | wc -l)
    local connection_count=$(grep -r "connection\|Connection" "$LOG_DIR"/*.log 2>/dev/null | wc -l)
    local benchmark_count=$(grep -r "benchmark\|Benchmark" "$LOG_DIR"/*.log 2>/dev/null | wc -l)
    
    # Generate analysis report
    cat > "$analysis_file" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "analysis_type": "pattern",
    "counts": {
        "errors": $error_count,
        "warnings": $warning_count,
        "fatal": $fatal_count,
        "timeouts": $timeout_count,
        "connection_issues": $connection_count,
        "benchmark_runs": $benchmark_count
    },
    "alerts": []
}
EOF
    
    # Check thresholds and add alerts
    if [ "$error_count" -gt "$ALERT_THRESHOLD_ERROR" ]; then
        print_warning "High error count detected: $error_count errors"
        jq '.alerts += [{"level": "error", "message": "High error count: '"$error_count"'", "threshold": '"$ALERT_THRESHOLD_ERROR"'}]' "$analysis_file" > "$analysis_file.tmp" && mv "$analysis_file.tmp" "$analysis_file"
    fi
    
    if [ "$warning_count" -gt "$ALERT_THRESHOLD_WARNING" ]; then
        print_warning "High warning count detected: $warning_count warnings"
        jq '.alerts += [{"level": "warning", "message": "High warning count: '"$warning_count"'", "threshold": '"$ALERT_THRESHOLD_WARNING"'}]' "$analysis_file" > "$analysis_file.tmp" && mv "$analysis_file.tmp" "$analysis_file"
    fi
    
    print_status "Pattern analysis complete: $analysis_file"
    
    # Return alert count for monitoring
    jq '.alerts | length' "$analysis_file"
}

# Search logs with filters
search_logs() {
    local pattern="$1"
    local since="${2:-24h}"
    local level="${3:-all}"
    
    print_status "Searching logs for: $pattern (since: $since, level: $level)"
    
    # Calculate cutoff time
    local cutoff=$(date -d "-$since" +%s 2>/dev/null || date -v "-${since}" +%s)
    
    # Search in current logs
    for logfile in "$LOG_DIR"/*.log; do
        if [ -f "$logfile" ]; then
            local file_time=$(stat -c %Y "$logfile" 2>/dev/null || stat -f %m "$logfile")
            if [ "$file_time" -ge "$cutoff" ]; then
                case "$level" in
                    error)
                        grep -n "ERROR.*$pattern\|$pattern.*ERROR" "$logfile" 2>/dev/null || true
                        ;;
                    warning)
                        grep -n "WARN.*$pattern\|$pattern.*WARN" "$logfile" 2>/dev/null || true
                        ;;
                    info)
                        grep -n "INFO.*$pattern\|$pattern.*INFO" "$logfile" 2>/dev/null || true
                        ;;
                    all|*)
                        grep -n "$pattern" "$logfile" 2>/dev/null || true
                        ;;
                esac
            fi
        fi
    done
    
    # Search in archived logs if needed
    if [ "$since" = "all" ] || [ "$since" = "30d" ] || [ "$since" = "90d" ]; then
        for archive in "$ARCHIVE_DIR"/*.gz; do
            if [ -f "$archive" ]; then
                zgrep -H -n "$pattern" "$archive" 2>/dev/null || true
            fi
        done
    fi
}

# Generate log summary report
generate_summary() {
    local output_file="${1:-$ANALYSIS_DIR/summary_$(date +%Y%m%d).txt}"
    
    print_status "Generating log summary report..."
    
    mkdir -p "$(dirname "$output_file")"
    
    {
        echo "RawrXD Benchmark Suite - Log Summary Report"
        echo "=========================================="
        echo "Generated: $(date)"
        echo ""
        
        echo "Log Files:"
        echo "----------"
        ls -lh "$LOG_DIR"/*.log 2>/dev/null | awk '{print "  " $9 ": " $5}' || echo "  No log files found"
        echo ""
        
        echo "Archive Files:"
        echo "--------------"
        ls -lh "$ARCHIVE_DIR"/*.gz 2>/dev/null | wc -l | xargs echo "  Total archives:"
        du -sh "$ARCHIVE_DIR" 2>/dev/null | awk '{print "  Total size: " $1}' || echo "  No archives"
        echo ""
        
        echo "Recent Activity (last 24h):"
        echo "---------------------------"
        local recent_errors=$(find "$LOG_DIR" -name "*.log" -mtime -1 -exec grep -c "ERROR" {} \; 2>/dev/null | awk '{sum+=$1} END {print sum}')
        local recent_warnings=$(find "$LOG_DIR" -name "*.log" -mtime -1 -exec grep -c "WARN" {} \; 2>/dev/null | awk '{sum+=$1} END {print sum}')
        echo "  Errors:   ${recent_errors:-0}"
        echo "  Warnings: ${recent_warnings:-0}"
        echo ""
        
        echo "Top Error Patterns:"
        echo "-------------------"
        grep -h "ERROR" "$LOG_DIR"/*.log 2>/dev/null | \
            sed 's/.*ERROR //' | \
            sort | uniq -c | \
            sort -rn | head -10 | \
            while read -r count pattern; do
                echo "  $count: $pattern"
            done || echo "  No errors found"
        
    } > "$output_file"
    
    print_status "Summary report generated: $output_file"
    cat "$output_file"
}

# Real-time log tail with filtering
tail_logs() {
    local lines="${1:-50}"
    local follow="${2:-false}"
    local filter="${3:-}"
    
    print_status "Tailing last $lines lines..."
    
    # Combine all log files and sort by timestamp
    local cmd="find $LOG_DIR -name '*.log' -type f -exec cat {} \; | sort"
    
    if [ -n "$filter" ]; then
        cmd="$cmd | grep '$filter'"
    fi
    
    cmd="$cmd | tail -n $lines"
    
    if [ "$follow" = "true" ]; then
        # Use tail -f on the most recent log file
        local latest_log=$(ls -t "$LOG_DIR"/*.log 2>/dev/null | head -1)
        if [ -n "$latest_log" ]; then
            if [ -n "$filter" ]; then
                tail -f "$latest_log" | grep --line-buffered "$filter"
            else
                tail -f "$latest_log"
            fi
        else
            print_error "No log files found"
        fi
    else
        eval "$cmd"
    fi
}

# Export logs in various formats
export_logs() {
    local format="${1:-json}"
    local since="${2:-24h}"
    local output="${3:-$ANALYSIS_DIR/export_$(date +%Y%m%d).$format}"
    
    print_status "Exporting logs to $format format..."
    
    mkdir -p "$(dirname "$output")"
    
    case "$format" in
        json)
            echo "[" > "$output"
            local first=true
            for logfile in "$LOG_DIR"/*.log; do
                if [ -f "$logfile" ]; then
                    while IFS= read -r line; do
                        $first || echo "," >> "$output"
                        first=false
                        # Parse log line and convert to JSON
                        local timestamp=$(echo "$line" | grep -oP '^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}' || echo "null")
                        local level=$(echo "$line" | grep -oP '\b(ERROR|WARN|INFO|DEBUG)\b' || echo "UNKNOWN")
                        local message=$(echo "$line" | sed 's/.*\b(ERROR|WARN|INFO|DEBUG)\b\s*//' | sed 's/"/\\"/g')
                        
                        echo "  {\"timestamp\": \"$timestamp\", \"level\": \"$level\", \"message\": \"$message\"}" >> "$output"
                    done < "$logfile"
                fi
            done
            echo "" >> "$output"
            echo "]" >> "$output"
            ;;
        csv)
            echo "timestamp,level,message" > "$output"
            for logfile in "$LOG_DIR"/*.log; do
                if [ -f "$logfile" ]; then
                    while IFS= read -r line; do
                        local timestamp=$(echo "$line" | grep -oP '^\d{4}-\d{2}-\d{2}[ T]\d{2}:\d{2}:\d{2}' || echo "")
                        local level=$(echo "$line" | grep -oP '\b(ERROR|WARN|INFO|DEBUG)\b' || echo "UNKNOWN")
                        local message=$(echo "$line" | sed 's/.*\b(ERROR|WARN|INFO|DEBUG)\b\s*//' | sed 's/,/;/g')
                        echo "$timestamp,$level,$message" >> "$output"
                    done < "$logfile"
                fi
            done
            ;;
        *)
            print_error "Unknown format: $format (supported: json, csv)"
            exit 1
            ;;
    esac
    
    print_status "Logs exported to: $output"
}

# Cleanup old logs and analysis
cleanup() {
    print_status "Cleaning up old logs and analysis files..."
    
    # Remove old log files
    find "$LOG_DIR" -name "*.log" -type f -mtime +$RETENTION_DAYS -delete
    
    # Remove old archives
    find "$ARCHIVE_DIR" -name "*.gz" -type f -mtime +$RETENTION_DAYS -delete
    
    # Remove old analysis files
    find "$ANALYSIS_DIR" -name "*.json" -type f -mtime +30 -delete
    
    print_status "Cleanup complete"
}

# Main function
main() {
    local command="${1:-summary}"
    
    mkdir -p "$LOG_DIR" "$ARCHIVE_DIR" "$ANALYSIS_DIR"
    
    case "$command" in
        rotate)
            rotate_logs
            ;;
        analyze)
            analyze_patterns
            ;;
        search)
            search_logs "${2:-}" "${3:-24h}" "${4:-all}"
            ;;
        summary)
            generate_summary "${2:-}"
            ;;
        tail)
            tail_logs "${2:-50}" "${3:-false}" "${4:-}"
            ;;
        export)
            export_logs "${2:-json}" "${3:-24h}" "${4:-}"
            ;;
        cleanup)
            cleanup
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
    echo "  rotate              Rotate and archive old logs"
    echo "  analyze             Analyze log patterns"
    echo "  search <pattern> [since] [level]  Search logs"
    echo "  summary [output]    Generate summary report"
    echo "  tail [lines] [follow] [filter]    Tail logs"
    echo "  export [fmt] [since] [output]     Export logs"
    echo "  cleanup             Remove old logs"
    echo ""
    echo "Examples:"
    echo "  $0 rotate                    # Rotate logs"
    echo "  $0 analyze                   # Analyze patterns"
    echo "  $0 search 'timeout' 24h      # Search for timeouts in last 24h"
    echo "  $0 tail 100 true error         # Follow errors in real-time"
    echo "  $0 export json 7d              # Export last 7 days as JSON"
}

# Parse arguments
if [ "$1" = "-h" ] || [ "$1" = "--help" ]; then
    usage
    exit 0
fi

main "$@"
