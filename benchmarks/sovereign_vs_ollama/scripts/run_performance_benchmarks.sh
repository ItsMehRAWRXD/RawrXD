#!/bin/bash
# Performance Benchmark Automation Script
# Copyright (c) 2026 RawrXD Team

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     RawrXD Benchmark Suite - Performance Automation         ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
BUILD_DIR="${BUILD_DIR:-build}"
RESULTS_DIR="${RESULTS_DIR:-results/$(date +%Y%m%d_%H%M%S)}"
BACKEND="${BACKEND:-sovereign}"
MODEL="${MODEL:-default}"
ITERATIONS="${ITERATIONS:-100}"
WARMUP="${WARMUP:-10}"
PARALLEL="${PARALLEL:-$(nproc)}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

print_section() {
    echo -e "${BLUE}[BENCH]${NC} $1"
}

# Create results directory
setup_results() {
    mkdir -p "$RESULTS_DIR"
    print_status "Results will be saved to: $RESULTS_DIR"
}

# Check prerequisites
check_prerequisites() {
    if [ ! -d "$BUILD_DIR" ]; then
        print_error "Build directory not found. Run build_verification.sh first."
        exit 1
    fi
    
    if [ ! -f "$BUILD_DIR/integrated_benchmark_runner" ]; then
        print_error "integrated_benchmark_runner not found."
        exit 1
    fi
}

# Run core performance benchmarks
run_core_benchmarks() {
    print_section "Running Core Performance Benchmarks"
    
    cd "$BUILD_DIR"
    
    # Batch 1: Core Performance
    print_status "Batch 1: Core Performance"
    ./integrated_benchmark_runner \
        --backend "$BACKEND" \
        --model "$MODEL" \
        --category core \
        --iterations "$ITERATIONS" \
        --warmup "$WARMUP" \
        --parallel "$PARALLEL" \
        --output "$RESULTS_DIR/core_performance.json" \
        --format json
    
    # Batch 2: Agentic Capabilities
    print_status "Batch 2: Agentic Capabilities"
    ./integrated_benchmark_runner \
        --backend "$BACKEND" \
        --model "$MODEL" \
        --category agentic \
        --iterations "$ITERATIONS" \
        --warmup "$WARMUP" \
        --parallel "$PARALLEL" \
        --output "$RESULTS_DIR/agentic_capabilities.json" \
        --format json
    
    # Batch 3: Infrastructure
    print_status "Batch 3: Infrastructure"
    ./integrated_benchmark_runner \
        --backend "$BACKEND" \
        --model "$MODEL" \
        --category infrastructure \
        --iterations "$ITERATIONS" \
        --warmup "$WARMUP" \
        --parallel "$PARALLEL" \
        --output "$RESULTS_DIR/infrastructure.json" \
        --format json
    
    # Batch 4: Chaos & Stress
    print_status "Batch 4: Chaos & Stress"
    ./integrated_benchmark_runner \
        --backend "$BACKEND" \
        --model "$MODEL" \
        --category chaos \
        --iterations "$ITERATIONS" \
        --warmup "$WARMUP" \
        --parallel "$PARALLEL" \
        --output "$RESULTS_DIR/chaos_stress.json" \
        --format json
    
    cd ..
}

# Run Phase E statistical validation
run_phase_e() {
    print_section "Running Phase E Statistical Validation"
    
    cd "$BUILD_DIR"
    
    if [ -f "phase_e_benchmark" ]; then
        ./phase_e_benchmark \
            --backend "$BACKEND" \
            --model "$MODEL" \
            --iterations "$ITERATIONS" \
            --output "$RESULTS_DIR/phase_e_validation.json" \
            --format json
    else
        print_warning "phase_e_benchmark not found, skipping Phase E"
    fi
    
    cd ..
}

# Run comparison benchmarks
run_comparison() {
    print_section "Running Sovereign vs Ollama Comparison"
    
    cd "$BUILD_DIR"
    
    # Run with Sovereign
    print_status "Benchmarking Sovereign..."
    ./integrated_benchmark_runner \
        --backend sovereign \
        --model "$MODEL" \
        --iterations "$ITERATIONS" \
        --warmup "$WARMUP" \
        --output "$RESULTS_DIR/sovereign_results.json" \
        --format json
    
    # Run with Ollama
    print_status "Benchmarking Ollama..."
    ./integrated_benchmark_runner \
        --backend ollama \
        --model "$MODEL" \
        --iterations "$ITERATIONS" \
        --warmup "$WARMUP" \
        --output "$RESULTS_DIR/ollama_results.json" \
        --format json
    
    cd ..
}

# Generate reports
generate_reports() {
    print_section "Generating Reports"
    
    # JSON summary
    cat > "$RESULTS_DIR/summary.json" << EOF
{
    "timestamp": "$(date -Iseconds)",
    "backend": "$BACKEND",
    "model": "$MODEL",
    "iterations": $ITERATIONS,
    "warmup": $WARMUP,
    "parallel": $PARALLEL,
    "results_directory": "$RESULTS_DIR"
}
EOF
    
    # HTML report
    cat > "$RESULTS_DIR/report.html" << 'HTMLEOF'
<!DOCTYPE html>
<html>
<head>
    <title>RawrXD Benchmark Results</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 40px; }
        h1 { color: #333; }
        .summary { background: #f5f5f5; padding: 20px; border-radius: 5px; }
        .metric { margin: 10px 0; }
        .metric-label { font-weight: bold; }
    </style>
</head>
<body>
    <h1>RawrXD Benchmark Results</h1>
    <div class="summary">
        <h2>Summary</h2>
        <div class="metric"><span class="metric-label">Timestamp:</span> $(date)</div>
        <div class="metric"><span class="metric-label">Backend:</span> $BACKEND</div>
        <div class="metric"><span class="metric-label">Model:</span> $MODEL</div>
        <div class="metric"><span class="metric-label">Iterations:</span> $ITERATIONS</div>
    </div>
</body>
</html>
HTMLEOF
    
    print_status "Reports generated in $RESULTS_DIR"
}

# Upload results (if configured)
upload_results() {
    print_section "Uploading Results"
    
    if [ -n "$UPLOAD_URL" ]; then
        print_status "Uploading to $UPLOAD_URL..."
        curl -X POST \
            -H "Content-Type: application/json" \
            -d "@$RESULTS_DIR/summary.json" \
            "$UPLOAD_URL" || print_warning "Upload failed"
    else
        print_status "No upload URL configured, skipping upload"
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Performance Benchmark Complete!                 ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    print_status "Results saved to: $RESULTS_DIR"
    print_status "View HTML report: file://$(realpath $RESULTS_DIR)/report.html"
    
    # List result files
    echo ""
    echo "Generated files:"
    ls -lh "$RESULTS_DIR"
}

# Main execution
main() {
    print_status "Starting performance benchmark automation..."
    
    check_prerequisites
    setup_results
    
    # Run benchmarks based on mode
    case "${MODE:-full}" in
        core)
            run_core_benchmarks
            ;;
        phase-e)
            run_phase_e
            ;;
        comparison)
            run_comparison
            ;;
        quick)
            ITERATIONS=10
            WARMUP=2
            run_core_benchmarks
            ;;
        full|*)
            run_core_benchmarks
            run_phase_e
            run_comparison
            ;;
    esac
    
    generate_reports
    upload_results
    print_summary
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -b, --backend <name>      Backend to benchmark (sovereign|ollama)"
    echo "  -m, --model <name>        Model name"
    echo "  -i, --iterations <n>      Number of iterations (default: 100)"
    echo "  -w, --warmup <n>          Warmup iterations (default: 10)"
    echo "  -p, --parallel <n>        Parallel workers (default: nproc)"
    echo "  --mode <mode>             Benchmark mode (full|core|phase-e|comparison|quick)"
    echo "  --upload-url <url>        URL to upload results"
    echo "  -h, --help                 Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                           # Run full benchmark suite"
    echo "  $0 --mode quick              # Quick benchmark (10 iterations)"
    echo "  $0 --backend ollama          # Benchmark Ollama only"
    echo "  $0 --mode comparison         # Run comparison between backends"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -b|--backend)
            BACKEND="$2"
            shift 2
            ;;
        -m|--model)
            MODEL="$2"
            shift 2
            ;;
        -i|--iterations)
            ITERATIONS="$2"
            shift 2
            ;;
        -w|--warmup)
            WARMUP="$2"
            shift 2
            ;;
        -p|--parallel)
            PARALLEL="$2"
            shift 2
            ;;
        --mode)
            MODE="$2"
            shift 2
            ;;
        --upload-url)
            UPLOAD_URL="$2"
            shift 2
            ;;
        -h|--help)
            usage
            exit 0
            ;;
        *)
            print_error "Unknown option: $1"
            usage
            exit 1
            ;;
    esac
done

# Run main
main
