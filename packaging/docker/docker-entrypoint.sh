#!/bin/bash
# docker-entrypoint.sh
# Phase F.1 Batch 5/5: Docker entrypoint with benchmark execution

set -e

# Configuration
BENCHMARK_DIR="/opt/rawrxd/benchmarks"
RESULTS_DIR="/opt/rawrxd/results"
CONFIG_FILE="/etc/rawrxd/config.yaml"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# Logging
log() { echo -e "${CYAN}[ENTRYPOINT]${NC} $1"; }
success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }
error() { echo -e "${RED}[ERROR]${NC} $1"; }
warn() { echo -e "${YELLOW}[WARN]${NC} $1"; }

# Show usage
show_usage() {
    cat << EOF
RawrXD Sovereign Docker Container

Usage:
  docker run rawrxd/sovereign [COMMAND] [OPTIONS]

Commands:
  serve           Start the runtime server (default)
  benchmark       Run benchmark suite
  validate        Validate installation
  shell           Start interactive shell
  help            Show this help

Benchmark Options:
  --quick         Run quick benchmark (5 runs)
  --full          Run full benchmark (50 runs)
  --stress        Include stress tests
  --compare       Compare with Ollama

Environment Variables:
  RWRXD_THREADS   Number of threads (default: auto)
  RWRXD_GPU       Enable GPU (default: true)
  RWRXD_MODEL     Default model path
  RWRXD_LOG_LEVEL Log level (debug, info, warn, error)

Examples:
  # Start server
  docker run -p 8080:8080 rawrxd/sovereign serve

  # Run quick benchmark
  docker run rawrxd/sovereign benchmark --quick

  # Run with custom config
  docker run -v /path/to/config:/etc/rawrxd rawrxd/sovereign serve

EOF
}

# Validate installation
validate_installation() {
    log "Validating RawrXD installation..."
    
    if ! command -v rawrxd &> /dev/null; then
        error "rawrxd not found in PATH"
        exit 1
    fi
    
    if ! command -v rawrxd-benchmark &> /dev/null; then
        warn "rawrxd-benchmark not found"
    fi
    
    # Test version
    local version
    version=$(rawrxd --version 2>/dev/null || echo "unknown")
    success "RawrXD version: $version"
    
    # Test GPU availability
    if rawrxd validate --quick &> /dev/null; then
        success "Validation passed"
    else
        warn "Validation had warnings (check logs)"
    fi
}

# Run benchmark
run_benchmark() {
    local args=("$@")
    
    log "Starting benchmark suite..."
    
    # Create results directory
    mkdir -p "$RESULTS_DIR"
    
    # Set default output
    local output_file="$RESULTS_DIR/benchmark_$(date +%Y%m%d_%H%M%S).json"
    
    # Build benchmark arguments
    local benchmark_args=()
    
    if [[ " ${args[*]} " =~ " --quick " ]]; then
        benchmark_args+=("--quick")
    fi
    
    if [[ " ${args[*]} " =~ " --full " ]]; then
        benchmark_args+=("--runs" "50")
    fi
    
    if [[ " ${args[*]} " =~ " --stress " ]]; then
        benchmark_args+=("--stress")
    fi
    
    if [[ " ${args[*]} " =~ " --compare " ]]; then
        benchmark_args+=("--backend" "both")
    fi
    
    benchmark_args+=("--output" "$output_file")
    
    # Run benchmark
    log "Running: rawrxd-benchmark ${benchmark_args[*]}"
    
    if rawrxd-benchmark "${benchmark_args[@]}"; then
        success "Benchmark complete: $output_file"
        
        # Display summary if available
        if [[ -f "$output_file" ]]; then
            log "Results summary:"
            if command -v jq &> /dev/null; then
                jq -r '.benchmarks[] | "  \(.name): \(.mean // "N/A") \(.unit // "")"' "$output_file" 2>/dev/null || true
            fi
        fi
    else
        error "Benchmark failed"
        exit 1
    fi
}

# Start server
start_server() {
    log "Starting RawrXD Sovereign server..."
    
    local args=("$@")
    
    # Add config if exists and not specified
    if [[ -f "$CONFIG_FILE" ]] && [[ ! " ${args[*]} " =~ " --config " ]]; then
        args+=("--config" "$CONFIG_FILE")
    fi
    
    # Set log level from environment
    if [[ -n "${RWRXD_LOG_LEVEL:-}" ]]; then
        args+=("--log-level" "$RWRXD_LOG_LEVEL")
    fi
    
    log "Executing: rawrxd serve ${args[*]}"
    
    # Use exec to replace shell process
    exec rawrxd serve "${args[@]}"
}

# Main entrypoint
main() {
    local command="${1:-serve}"
    shift || true
    
    case "$command" in
        serve|server)
            validate_installation
            start_server "$@"
            ;;
        benchmark|bench)
            validate_installation
            run_benchmark "$@"
            ;;
        validate|check)
            validate_installation
            ;;
        shell|bash|sh)
            log "Starting interactive shell..."
            exec /bin/bash
            ;;
        help|--help|-h)
            show_usage
            exit 0
            ;;
        *)
            # If it's a rawrxd subcommand, pass through
            if rawrxd "$command" --help &> /dev/null; then
                exec rawrxd "$command" "$@"
            fi
            
            error "Unknown command: $command"
            show_usage
            exit 1
            ;;
    esac
}

# Run main
main "$@"
