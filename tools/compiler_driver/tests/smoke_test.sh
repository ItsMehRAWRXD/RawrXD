#!/bin/bash
# RAWRXD Compiler Driver - Smoke Test Suite (Unix)
# Cross-platform smoke tests

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m'

# Counters
TESTS_PASSED=0
TESTS_FAILED=0

# Functions
log_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

log_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

log_warn() {
    echo -e "${YELLOW}[WARN]${NC} $1"
}

run_test() {
    local test_name="$1"
    local test_cmd="$2"
    
    echo ""
    echo "Running: $test_name"
    echo "Command: $test_cmd"
    
    if eval "$test_cmd"; then
        echo -e "${GREEN}PASSED${NC}: $test_name"
        ((TESTS_PASSED++))
    else
        echo -e "${RED}FAILED${NC}: $test_name"
        ((TESTS_FAILED++))
    fi
}

# Main
echo "=========================================="
echo "RAWRXD Compiler Driver - Smoke Tests"
echo "=========================================="
echo ""

# Check if compiler exists
if [ ! -f "../bin/rawrxd-compiler" ]; then
    log_error "Compiler not found! Build first with: make"
    exit 1
fi

RAWRXD="../bin/rawrxd-compiler"

# Run tests
run_test "C Compilation" "$RAWRXD compile test_c.c -o test_c"
run_test "Assembly Compilation" "$RAWRXD compile test_asm.asm -o test_asm"
run_test "C# Compilation" "$RAWRXD compile test_cs.cs -o test_cs"
run_test "Help Command" "$RAWRXD --help"
run_test "Version Command" "$RAWRXD --version"
run_test "Config Command" "$RAWRXD config"

# Summary
echo ""
echo "=========================================="
echo "Test Summary"
echo "=========================================="
echo "Tests Passed: $TESTS_PASSED"
echo "Tests Failed: $TESTS_FAILED"
echo ""

if [ $TESTS_FAILED -eq 0 ]; then
    echo -e "${GREEN}All tests passed!${NC}"
    exit 0
else
    echo -e "${RED}Some tests failed!${NC}"
    exit 1
fi
