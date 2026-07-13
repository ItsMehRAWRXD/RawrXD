#!/bin/bash
# run_benchmarks.sh
# Batch 6: Benchmark Execution Script
# Usage: ./run_benchmarks.sh [options]

set -euo pipefail

# =============================================================================
# Configuration
# =============================================================================
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PROJECT_ROOT="$(dirname "$SCRIPT_DIR")"
RESULTS_DIR="${PROJECT_ROOT}/results"
TIMESTAMP=$(date +%Y%m%d_%H%M%S)
RUN_ID="run_${TIMESTAMP}"

# Default values
BACKEND="sovereign"
BACKEND_URL=""
TIERS=("tier1")
VERBOSE=false
OUTPUT_FORMAT="json"
PARALLEL=false
MAX_WORKERS=4
TIMEOUT=3600
ENABLE_PROFILING=false
COMPARE_BASELINE=false
BASELINE_FILE=""
UPLOAD_RESULTS=false
NOTIFY_ON_FAILURE=false

# =============================================================================
# Help Message
# =============================================================================
show_help() {
    cat << EOF
RawrXD Benchmark Runner Script

Usage: $(basename "$0") [OPTIONS]

Options:
    -b, --backend BACKEND       Backend to test (sovereign|ollama) [default: sovereign]
    -u, --backend-url URL       Backend URL (auto-detected if not specified)
    -t, --tier TIER             Benchmark tier to run (can be repeated)
                                tier1, tier2, tier3, tier4, workflow, stress, all
    -v, --verbose               Enable verbose output
    -f, --format FORMAT         Output format (json|html|markdown|console) [default: json]
    -p, --parallel              Run benchmarks in parallel
    -w, --workers N             Number of parallel workers [default: 4]
    -T, --timeout SECONDS       Timeout per benchmark [default: 3600]
    --profile                   Enable CPU/memory profiling
    --compare BASELINE          Compare against baseline results
    --upload                    Upload results to S3/dashboard
    --notify                    Send notification on failure
    -h, --help                  Show this help message

Examples:
    # Run Tier 1 benchmarks
    $(basename "$0") -t tier1

    # Run all benchmarks with comparison
    $(basename "$0") -t all --compare results/baseline.json

    # Run stress tests with Ollama backend
    $(basename "$0") -b ollama -t stress --verbose

    # Parallel execution
    $(basename "$0") -t tier1 -t tier2 -p -w 4

EOF
}

# =============================================================================
# Logging
# =============================================================================
log_info() {
    echo "[INFO] $(date '+%Y-%m-%d %H:%M:%S') - $*"
}

log_warn() {
    echo "[WARN] $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

log_error() {
    echo "[ERROR] $(date '+%Y-%m-%d %H:%M:%S') - $*" >&2
}

# =============================================================================
# Argument Parsing
# =============================================================================
parse_args() {
    while [[ $# -gt 0 ]]; do
        case $1 in
            -b|--backend)
                BACKEND="$2"
                shift 2
                ;;
            -u|--backend-url)
                BACKEND_URL="$2"
                shift 2
                ;;
            -t|--tier)
                if [[ "$2" == "all" ]]; then
                    TIERS=("tier1" "tier2" "tier3" "tier4" "workflow" "stress")
                else
                    TIERS+=("$2")
                fi
                shift 2
                ;;
            -v|--verbose)
                VERBOSE=true
                shift
                ;;
            -f|--format)
                OUTPUT_FORMAT="$2"
                shift 2
                ;;
            -p|--parallel)
                PARALLEL=true
                shift
                ;;
            -w|--workers)
                MAX_WORKERS="$2"
                shift 2
                ;;
            -T|--timeout)
                TIMEOUT="$2"
                shift 2
                ;;
            --profile)
                ENABLE_PROFILING=true
                shift
                ;;
            --compare)
                COMPARE_BASELINE=true
                BASELINE_FILE="$2"
                shift 2
                ;;
            --upload)
                UPLOAD_RESULTS=true
                shift
                ;;
            --notify)
                NOTIFY_ON_FAILURE=true
                shift
                ;;
            -h|--help)
                show_help
                exit 0
                ;;
            *)
                log_error "Unknown option: $1"
                show_help
                exit 1
                ;;
        esac
    done
}

# =============================================================================
# Environment Setup
# =============================================================================
setup_environment() {
    log_info "Setting up environment..."
    
    # Create results directory
    mkdir -p "${RESULTS_DIR}/${RUN_ID}"
    
    # Auto-detect backend URL if not specified
    if [[ -z "$BACKEND_URL" ]]; then
        case "$BACKEND" in
            sovereign)
                BACKEND_URL="http://localhost:8080"
                ;;
            ollama)
                BACKEND_URL="http://localhost:11434"
                ;;
            *)
                log_error "Unknown backend: $BACKEND"
                exit 1
                ;;
        esac
    fi
    
    # Verify backend is accessible
    log_info "Checking backend at $BACKEND_URL..."
    if ! curl -sf "${BACKEND_URL}/health" > /dev/null 2>&1; then
        if ! curl -sf "${BACKEND_URL}/api/tags" > /dev/null 2>&1; then
            log_error "Backend is not accessible at $BACKEND_URL"
            log_info "Please ensure the backend is running:"
            log_info "  Sovereign: docker-compose up sovereign"
            log_info "  Ollama: ollama serve"
            exit 1
        fi
    fi
    
    log_info "Backend is ready"
    
    # Set environment variables for benchmark runner
    export BENCHMARK_BACKEND="$BACKEND"
    export BENCHMARK_BACKEND_URL="$BACKEND_URL"
    export BENCHMARK_RESULTS_DIR="${RESULTS_DIR}/${RUN_ID}"
    export BENCHMARK_VERBOSE="$VERBOSE"
    export BENCHMARK_TIMEOUT="$TIMEOUT"
    
    log_info "Run ID: $RUN_ID"
    log_info "Results directory: ${RESULTS_DIR}/${RUN_ID}"
}

# =============================================================================
# Build Benchmark Runner
# =============================================================================
build_runner() {
    log_info "Building benchmark runner..."
    
    cd "$PROJECT_ROOT"
    
    if [[ ! -d "build" ]]; then
        cmake -B build -DCMAKE_BUILD_TYPE=Release
    fi
    
    cmake --build build --parallel "$(nproc)"
    
    if [[ ! -f "build/benchmark_runner" ]]; then
        log_error "Failed to build benchmark_runner"
        exit 1
    fi
    
    log_info "Build complete"
}

# =============================================================================
# Run Single Benchmark
# =============================================================================
run_benchmark() {
    local tier="$1"
    local output_file="${RESULTS_DIR}/${RUN_ID}/${tier}_results.json"
    
    log_info "Running $tier benchmarks..."
    
    local args=(
        "--backend" "$BACKEND"
        "--tier" "$tier"
        "--format" "$OUTPUT_FORMAT"
        "--output" "$output_file"
    )
    
    if [[ "$VERBOSE" == true ]]; then
        args+=("--verbose")
    fi
    
    # Run with timeout
    if timeout "$TIMEOUT" "${PROJECT_ROOT}/build/benchmark_runner" "${args[@]}"; then
        log_info "$tier benchmarks completed successfully"
        return 0
    else
        log_error "$tier benchmarks failed or timed out"
        return 1
    fi
}

# =============================================================================
# Run Benchmarks in Parallel
# =============================================================================
run_parallel() {
    log_info "Running benchmarks in parallel with $MAX_WORKERS workers..."
    
    local pids=()
    local failed=()
    
    for tier in "${TIERS[@]}"; do
        # Wait if we've hit max workers
        while [[ $(jobs -r | wc -l) -ge $MAX_WORKERS ]]; do
            sleep 1
        done
        
        run_benchmark "$tier" &
        pids+=($!)
    done
    
    # Wait for all jobs
    for i in "${!pids[@]}"; do
        if ! wait "${pids[$i]}"; then
            failed+=("${TIERS[$i]}")
        fi
    done
    
    if [[ ${#failed[@]} -gt 0 ]]; then
        log_error "Failed tiers: ${failed[*]}"
        return 1
    fi
    
    return 0
}

# =============================================================================
# Run Benchmarks Sequentially
# =============================================================================
run_sequential() {
    log_info "Running benchmarks sequentially..."
    
    local failed=()
    
    for tier in "${TIERS[@]}"; do
        if ! run_benchmark "$tier"; then
            failed+=("$tier")
            if [[ "$NOTIFY_ON_FAILURE" == true ]]; then
                send_notification "Benchmark $tier failed"
            fi
        fi
    done
    
    if [[ ${#failed[@]} -gt 0 ]]; then
        log_error "Failed tiers: ${#failed[@]}"
        return 1
    fi
    
    return 0
}

# =============================================================================
# Generate Reports
# =============================================================================
generate_reports() {
    log_info "Generating reports..."
    
    local report_dir="${RESULTS_DIR}/${RUN_ID}"
    
    # Aggregate results
    if command -v python3 &> /dev/null; then
        python3 "${SCRIPT_DIR}/aggregate_results.py" \
            --input-dir "$report_dir" \
            --output "${report_dir}/aggregated_report.json"
        
        # Generate HTML report
        python3 "${SCRIPT_DIR}/generate_html_report.py" \
            --input "${report_dir}/aggregated_report.json" \
            --output "${report_dir}/report.html"
        
        # Compare with baseline if requested
        if [[ "$COMPARE_BASELINE" == true && -f "$BASELINE_FILE" ]]; then
            python3 "${SCRIPT_DIR}/compare_results.py" \
                --baseline "$BASELINE_FILE" \
                --current "${report_dir}/aggregated_report.json" \
                --output "${report_dir}/comparison.md"
        fi
    fi
    
    # Create summary
    cat > "${report_dir}/SUMMARY.txt" << EOF
Benchmark Run Summary
=====================
Run ID: $RUN_ID
Timestamp: $(date)
Backend: $BACKEND ($BACKEND_URL)
Tiers: ${TIERS[*]}

Results Location: $report_dir
EOF
    
    log_info "Reports generated in: $report_dir"
}

# =============================================================================
# Upload Results
# =============================================================================
upload_results() {
    [[ "$UPLOAD_RESULTS" != true ]] && return 0
    
    log_info "Uploading results..."
    
    local report_dir="${RESULTS_DIR}/${RUN_ID}"
    
    # Upload to S3 if configured
    if [[ -n "${AWS_ACCESS_KEY_ID:-}" && -n "${BENCHMARK_S3_BUCKET:-}" ]]; then
        aws s3 sync "$report_dir" "s3://${BENCHMARK_S3_BUCKET}/results/${RUN_ID}/"
        log_info "Results uploaded to S3"
    fi
    
    # Trigger dashboard update
    if [[ -n "${DASHBOARD_WEBHOOK_URL:-}" ]]; then
        curl -X POST "$DASHBOARD_WEBHOOK_URL" \
            -H "Content-Type: application/json" \
            -d "{\"run_id\": \"$RUN_ID\", \"timestamp\": \"$(date -Iseconds)\"}"
        log_info "Dashboard update triggered"
    fi
}

# =============================================================================
# Send Notification
# =============================================================================
send_notification() {
    local message="$1"
    
    # Slack notification
    if [[ -n "${SLACK_WEBHOOK_URL:-}" ]]; then
        curl -X POST "$SLACK_WEBHOOK_URL" \
            -H 'Content-Type: application/json' \
            -d "{\"text\": \"$message\"}" \
            > /dev/null 2>&1
    fi
    
    # Email notification (if mail is configured)
    if [[ -n "${NOTIFICATION_EMAIL:-}" ]]; then
        echo "$message" | mail -s "Benchmark Alert" "$NOTIFICATION_EMAIL"
    fi
}

# =============================================================================
# Cleanup
# =============================================================================
cleanup() {
    log_info "Cleaning up..."
    # Cleanup is minimal since we want to keep results
    # Could add temp file cleanup here if needed
}

# =============================================================================
# Main
# =============================================================================
main() {
    parse_args "$@"
    
    log_info "RawrXD Benchmark Suite"
    log_info "====================="
    
    setup_environment
    build_runner
    
    # Run benchmarks
    if [[ "$PARALLEL" == true ]]; then
        run_parallel
    else
        run_sequential
    fi
    
    local exit_code=$?
    
    generate_reports
    upload_results
    
    if [[ $exit_code -eq 0 ]]; then
        log_info "All benchmarks completed successfully!"
        log_info "Results available at: ${RESULTS_DIR}/${RUN_ID}"
    else
        log_error "Some benchmarks failed!"
        if [[ "$NOTIFY_ON_FAILURE" == true ]]; then
            send_notification "Benchmark run $RUN_ID failed!"
        fi
    fi
    
    cleanup
    
    return $exit_code
}

# Run main function
trap cleanup EXIT
main "$@"
