#!/bin/bash
#
# Sovereign Substrate - Benchmark Script
# Usage: ./benchmark.sh [output_file]

set -e

OUTPUT_FILE=${1:-benchmark_results.json}
BUILD_DIR="build"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║           Sovereign Substrate Benchmark                      ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""

# Check if build exists
if [ ! -d "$BUILD_DIR" ]; then
    echo "Build directory not found. Building first..."
    mkdir -p "$BUILD_DIR"
    cd "$BUILD_DIR"
    cmake .. -DCMAKE_BUILD_TYPE=Release
    cmake --build . --parallel
    cd ..
fi

cd "$BUILD_DIR"

# Initialize results
RESULTS='{"timestamp":"'$(date -u +"%Y-%m-%dT%H:%M:%SZ")'","benchmarks":[]}'

# Function to run benchmark
run_benchmark() {
    local name=$1
    local command=$2
    
    echo "Running: $name"
    
    # Run benchmark 5 times and calculate average
    local total_time=0
    local min_time=999999
    local max_time=0
    
    for i in {1..5}; do
        start_time=$(date +%s%N)
        eval "$command" > /dev/null 2>&1
        end_time=$(date +%s%N)
        
        duration=$(( (end_time - start_time) / 1000000 ))  # Convert to ms
        total_time=$((total_time + duration))
        
        if [ $duration -lt $min_time ]; then
            min_time=$duration
        fi
        
        if [ $duration -gt $max_time ]; then
            max_time=$duration
        fi
    done
    
    avg_time=$((total_time / 5))
    
    echo "  Average: ${avg_time}ms"
    echo "  Min: ${min_time}ms"
    echo "  Max: ${max_time}ms"
    echo ""
    
    # Add to results
    RESULTS=$(echo "$RESULTS" | jq ".benchmarks += [{\"name\":\"$name\",\"avg_ms\":$avg_time,\"min_ms\":$min_time,\"max_ms\":$max_time}]")
}

# Run benchmarks
echo "Running benchmarks..."
echo ""

# Intent parsing benchmark
run_benchmark "intent_parse" "./tests/test_intent_guardrails --gtest_filter='*Parse*'"

# Security validation benchmark
run_benchmark "security_validate" "./tests/test_security_hardening --gtest_filter='*Validate*'"

# Tool execution benchmark
run_benchmark "tool_execute" "./tests/test_tool_system --gtest_filter='*Execute*'"

# Memory graph query benchmark
run_benchmark "memory_query" "./tests/test_repository_memory --gtest_filter='*Query*'"

# Model adapter benchmark
run_benchmark "model_adapter" "./tests/test_model_adapter --gtest_filter='*Convert*'"

# End-to-end benchmark
run_benchmark "e2e" "./tests/test_sovereign_substrate_e2e"

# Save results
echo "$RESULTS" > "$OUTPUT_FILE"

echo "╔══════════════════════════════════════════════════════════════╗"
echo "║                    Benchmark Complete                        ║"
echo "╚══════════════════════════════════════════════════════════════╝"
echo ""
echo "Results saved to: $OUTPUT_FILE"
echo ""
echo "Summary:"
echo "$RESULTS" | jq '.benchmarks[] | "\(.name): \(.avg_ms)ms"' -r
