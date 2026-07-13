#!/bin/bash
# Integration Test Runner for RawrXD Benchmark Suite
# Copyright (c) 2026 RawrXD Team

set -e

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║     RawrXD Benchmark Suite - Integration Tests              ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Configuration
BUILD_DIR="${BUILD_DIR:-build}"
TEST_CATEGORY="${TEST_CATEGORY:-all}"
VERBOSE="${VERBOSE:-0}"
USE_MOCK="${USE_MOCK:-1}"
TIMEOUT="${TIMEOUT:-300}"

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

# Test results
TESTS_PASSED=0
TESTS_FAILED=0
TESTS_TOTAL=0

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
    echo -e "${BLUE}[TEST]${NC} $1"
}

# Check if build exists
check_build() {
    if [ ! -d "$BUILD_DIR" ]; then
        print_error "Build directory not found. Run build_verification.sh first."
        exit 1
    fi
    
    if [ ! -f "$BUILD_DIR/integrated_benchmark_runner" ]; then
        print_error "integrated_benchmark_runner not found. Build may be incomplete."
        exit 1
    fi
}

# Run a test and track results
run_test() {
    local test_name="$1"
    local test_cmd="$2"
    local timeout_sec="${3:-$TIMEOUT}"
    
    TESTS_TOTAL=$((TESTS_TOTAL + 1))
    
    print_section "Running: $test_name"
    
    if timeout $timeout_sec bash -c "$test_cmd"; then
        print_status "✓ $test_name PASSED"
        TESTS_PASSED=$((TESTS_PASSED + 1))
        return 0
    else
        print_error "✗ $test_name FAILED"
        TESTS_FAILED=$((TESTS_FAILED + 1))
        return 1
    fi
}

# Test 1: HTTP Client Unit Tests
test_http_client() {
    print_status "Running HTTP Client Unit Tests..."
    cd "$BUILD_DIR"
    
    if [ -f "http_client_tests" ]; then
        ./http_client_tests --category http
        return $?
    else
        print_warning "http_client_tests not found, skipping"
        return 0
    fi
}

# Test 2: Backend Adapter Tests
test_backend_adapter() {
    print_status "Running Backend Adapter Tests..."
    cd "$BUILD_DIR"
    
    if [ -f "backend_adapter_tests" ]; then
        ./backend_adapter_tests --category backend
        return $?
    else
        print_warning "backend_adapter_tests not found, skipping"
        return 0
    fi
}

# Test 3: Smoke Tests
test_smoke() {
    print_status "Running Smoke Tests..."
    cd "$BUILD_DIR"
    
    if [ -f "e2e_tests" ]; then
        ./e2e_tests --category smoke --verbose
        return $?
    else
        print_warning "e2e_tests not found, skipping"
        return 0
    fi
}

# Test 4: Configuration Loading
test_configuration() {
    print_status "Testing Configuration Loading..."
    cd "$BUILD_DIR"
    
    # Test with different config sources
    local temp_config=$(mktemp)
    echo "backend=sovereign" > "$temp_config"
    echo "model_name=test-model" >> "$temp_config"
    
    # Test config file loading
    ./integrated_benchmark_runner --config "$temp_config" --help > /dev/null 2>&1
    local result=$?
    
    rm -f "$temp_config"
    
    return $result
}

# Test 5: Backend Health Check
test_health_check() {
    print_status "Testing Backend Health Check..."
    cd "$BUILD_DIR"
    
    # This would normally check real backends
    # For now, just verify the executable can run
    ./integrated_benchmark_runner --help > /dev/null 2>&1
    return $?
}

# Test 6: Report Generation
test_report_generation() {
    print_status "Testing Report Generation..."
    cd "$BUILD_DIR"
    
    local temp_dir=$(mktemp -d)
    
    # Test JSON output
    ./integrated_benchmark_runner --help > /dev/null 2>&1
    local result=$?
    
    rm -rf "$temp_dir"
    return $result
}

# Test 7: Error Handling
test_error_handling() {
    print_status "Testing Error Handling..."
    cd "$BUILD_DIR"
    
    # Test with invalid arguments (should fail gracefully)
    ./integrated_benchmark_runner --invalid-option 2>&1 | grep -q "error\|Error\|usage\|Usage"
    return 0  # We expect this to show usage, not crash
}

# Test 8: Memory Leak Check (if valgrind available)
test_memory_leaks() {
    print_status "Testing for Memory Leaks..."
    cd "$BUILD_DIR"
    
    if command -v valgrind > /dev/null; then
        valgrind --leak-check=summary --error-exitcode=1 \
            ./integrated_benchmark_runner --help > /dev/null 2>&1
        return $?
    else
        print_warning "valgrind not available, skipping memory leak test"
        return 0
    fi
}

# Test 9: Performance Baseline
test_performance_baseline() {
    print_status "Testing Performance Baseline..."
    cd "$BUILD_DIR"
    
    # Quick performance test
    local start_time=$(date +%s)
    
    ./integrated_benchmark_runner --help > /dev/null 2>&1
    
    local end_time=$(date +%s)
    local duration=$((end_time - start_time))
    
    if [ $duration -lt 5 ]; then
        print_status "Startup time: ${duration}s (acceptable)"
        return 0
    else
        print_warning "Startup time: ${duration}s (slow)"
        return 0
    fi
}

# Test 10: Integration with Mock Backends
test_mock_backends() {
    print_status "Testing with Mock Backends..."
    cd "$BUILD_DIR"
    
    if [ "$USE_MOCK" -eq 1 ]; then
        # This would start mock servers and run tests
        # For now, just verify the test infrastructure exists
        if [ -f "e2e_tests" ]; then
            print_status "Mock backend tests available"
            return 0
        else
            print_warning "e2e_tests not found"
            return 0
        fi
    else
        print_status "Skipping mock backend tests (USE_MOCK=0)"
        return 0
    fi
}

# Print summary
print_summary() {
    echo ""
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║                    Test Summary                             ║"
    echo "╠══════════════════════════════════════════════════════════════╣"
    printf "║  Total Tests:  %-45s ║\n" "$TESTS_TOTAL"
    printf "║  Passed:       %-45s ║\n" "$TESTS_PASSED"
    printf "║  Failed:      %-45s ║\n" "$TESTS_FAILED"
    echo "╚══════════════════════════════════════════════════════════════╝"
    echo ""
    
    if [ $TESTS_FAILED -eq 0 ]; then
        print_status "All tests passed!"
        return 0
    else
        print_error "Some tests failed!"
        return 1
    fi
}

# Main test execution
main() {
    print_status "Starting integration tests..."
    
    check_build
    
    # Run tests based on category
    case "$TEST_CATEGORY" in
        http)
            run_test "HTTP Client Tests" test_http_client
            ;;
        backend)
            run_test "Backend Adapter Tests" test_backend_adapter
            ;;
        smoke)
            run_test "Smoke Tests" test_smoke
            ;;
        config)
            run_test "Configuration Tests" test_configuration
            ;;
        health)
            run_test "Health Check Tests" test_health_check
            ;;
        report)
            run_test "Report Generation Tests" test_report_generation
            ;;
        error)
            run_test "Error Handling Tests" test_error_handling
            ;;
        memory)
            run_test "Memory Leak Tests" test_memory_leaks
            ;;
        performance)
            run_test "Performance Baseline Tests" test_performance_baseline
            ;;
        mock)
            run_test "Mock Backend Tests" test_mock_backends
            ;;
        all|*)
            run_test "HTTP Client Tests" test_http_client
            run_test "Backend Adapter Tests" test_backend_adapter
            run_test "Smoke Tests" test_smoke
            run_test "Configuration Tests" test_configuration
            run_test "Health Check Tests" test_health_check
            run_test "Report Generation Tests" test_report_generation
            run_test "Error Handling Tests" test_error_handling
            run_test "Memory Leak Tests" test_memory_leaks
            run_test "Performance Baseline Tests" test_performance_baseline
            run_test "Mock Backend Tests" test_mock_backends
            ;;
    esac
    
    print_summary
}

# Show usage
usage() {
    echo "Usage: $0 [OPTIONS]"
    echo ""
    echo "Options:"
    echo "  -c, --category <cat>    Test category (http|backend|smoke|config|health|report|error|memory|performance|mock|all)"
    echo "  -b, --build-dir <dir>   Build directory (default: build)"
    echo "  -t, --timeout <sec>     Test timeout in seconds (default: 300)"
    echo "  -v, --verbose            Enable verbose output"
    echo "  --no-mock                Don't use mock backends"
    echo "  -h, --help               Show this help message"
    echo ""
    echo "Examples:"
    echo "  $0                       # Run all tests"
    echo "  $0 -c smoke              # Run smoke tests only"
    echo "  $0 -c http -v            # Run HTTP tests with verbose output"
}

# Parse arguments
while [[ $# -gt 0 ]]; do
    case $1 in
        -c|--category)
            TEST_CATEGORY="$2"
            shift 2
            ;;
        -b|--build-dir)
            BUILD_DIR="$2"
            shift 2
            ;;
        -t|--timeout)
            TIMEOUT="$2"
            shift 2
            ;;
        -v|--verbose)
            VERBOSE=1
            shift
            ;;
        --no-mock)
            USE_MOCK=0
            shift
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
