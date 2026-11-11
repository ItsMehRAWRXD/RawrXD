#!/bin/bash
# Quick Start Script for RawrXD Benchmark Suite
# One-command setup and execution

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     RawrXD Benchmark Suite - Quick Start                    ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_status() {
    echo -e "${GREEN}[SETUP]${NC} $1"
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

# Check prerequisites
check_prerequisites() {
    print_status "Checking prerequisites..."
    
    local missing=()
    
    if ! command -v cmake &> /dev/null; then
        missing+=("cmake")
    fi
    
    if ! command -v python3 &> /dev/null; then
        missing+=("python3")
    fi
    
    if ! command -v g++ &> /dev/null && ! command -v clang++ &> /dev/null; then
        missing+=("C++ compiler")
    fi
    
    if [ ${#missing[@]} -gt 0 ]; then
        print_error "Missing prerequisites: ${missing[*]}"
        echo ""
        echo "Install with:"
        echo "  Ubuntu/Debian: sudo apt-get install cmake python3 build-essential"
        echo "  CentOS/RHEL:   sudo yum install cmake python3 gcc-c++"
        echo "  macOS:         brew install cmake python3"
        exit 1
    fi
    
    print_status "Prerequisites check passed"
}

# Setup Python environment
setup_python() {
    print_status "Setting up Python environment..."
    
    if [ ! -d "venv" ]; then
        python3 -m venv venv
    fi
    
    source venv/bin/activate
    
    # Install dependencies
    pip install -q aiohttp aiohttp-cors click jinja2 numpy scipy
    
    print_status "Python environment ready"
}

# Build project
build_project() {
    print_status "Building project..."
    
    if [ ! -d "build" ]; then
        mkdir build
    fi
    
    cd build
    cmake .. -DCMAKE_BUILD_TYPE=Release
    cmake --build . --parallel $(nproc)
    cd ..
    
    print_status "Build complete"
}

# Run quick benchmark
run_quick_benchmark() {
    print_status "Running quick benchmark..."
    
    print_info "Testing Sovereign backend..."
    ./build/integrated_benchmark_runner \
        --backend sovereign \
        --iterations 10 \
        --warmup 2 \
        --output results/quick_sovereign.json \
        2>&1 | tail -20
    
    print_info "Testing Ollama backend..."
    ./build/integrated_benchmark_runner \
        --backend ollama \
        --iterations 10 \
        --warmup 2 \
        --output results/quick_ollama.json \
        2>&1 | tail -20
    
    print_status "Quick benchmark complete"
}

# Generate report
generate_report() {
    print_status "Generating report..."
    
    mkdir -p results
    
    # Combine results
    python3 -c "
import json
import glob

results = []
for f in glob.glob('results/quick_*.json'):
    with open(f) as fp:
        results.append(json.load(fp))

with open('results/combined.json', 'w') as fp:
    json.dump(results, fp, indent=2)
"
    
    # Generate HTML report
    python3 tools/report_generator.py html -r results/combined.json -o results/report.html
    
    print_status "Report generated: results/report.html"
}

# Print summary
print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║              Quick Start Complete!                           ║"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    print_info "Next steps:"
    echo "  1. View report:     open results/report.html"
    echo "  2. Run full suite: ./scripts/run_performance_benchmarks.sh"
    echo "  3. Start API:      python3 api/server.py"
    echo "  4. View dashboard: open dashboard/index.html"
    echo ""
    print_info "Documentation:"
    echo "  - README.md"
    echo "  - docs/performance_tuning.md"
    echo "  - docs/troubleshooting.md"
    echo ""
}

# Main
main() {
    check_prerequisites
    setup_python
    build_project
    run_quick_benchmark
    generate_report
    print_summary
}

# Run
main
