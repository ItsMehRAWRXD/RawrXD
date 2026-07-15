// ============================================================================
// RawrXD-Script VM Test Harness (Phase 0)
// C++ interface to validate MASM interpreter core
// ============================================================================

#include <cstdint>
#include <cstdio>
#include <cstring>

// ============================================================================
// External MASM Functions
// ============================================================================
extern "C" {
    // Main interpreter entry point
    // Input:  rcx = bytecode pointer, rdx = bytecode size
    // Output: rax = return value
    int64_t JsInterpreter_Run(const uint8_t* bytecode, size_t size);
}

// ============================================================================
// Phase 0 Bytecode Definitions
// ============================================================================

// Opcode constants (must match MASM definitions)
constexpr uint8_t OP_LOAD_INT     = 0x01;
constexpr uint8_t OP_LOAD_CONST   = 0x02;
constexpr uint8_t OP_ADD          = 0x03;
constexpr uint8_t OP_RETURN       = 0x07;

// Virtual register indices
constexpr uint8_t REG_V0 = 0x08;  // Maps to r8
constexpr uint8_t REG_V1 = 0x09;  // Maps to r9
constexpr uint8_t REG_V2 = 0x0A;  // Maps to r10
constexpr uint8_t REG_V3 = 0x0B;  // Maps to r11

// Helper to emit OP_LOAD_INT: load 32-bit immediate into register
void emit_load_int(uint8_t* bytecode, size_t& offset, uint8_t reg, int32_t value) {
    bytecode[offset++] = OP_LOAD_INT;
    bytecode[offset++] = reg;
    memcpy(&bytecode[offset], &value, sizeof(value));
    offset += 4;
}

// Helper to emit OP_ADD: dest = src_a + src_b
void emit_add(uint8_t* bytecode, size_t& offset, uint8_t dest, uint8_t src_a, uint8_t src_b) {
    bytecode[offset++] = OP_ADD;
    bytecode[offset++] = dest;
    bytecode[offset++] = src_a;
    bytecode[offset++] = src_b;
}

// Helper to emit OP_RETURN: return value from register
void emit_return(uint8_t* bytecode, size_t& offset, uint8_t reg) {
    bytecode[offset++] = OP_RETURN;
    bytecode[offset++] = reg;
}

// ============================================================================
// Test Cases
// ============================================================================

bool test_load_and_return() {
    printf("Test 1: Load immediate and return...\n");
    
    uint8_t bytecode[32];
    size_t offset = 0;
    
    // Load 42 into V0, return V0
    emit_load_int(bytecode, offset, REG_V0, 42);
    emit_return(bytecode, offset, REG_V0);
    
    int64_t result = JsInterpreter_Run(bytecode, offset);
    
    printf("  Expected: 42, Got: %lld\n", result);
    return result == 42;
}

bool test_add_simple() {
    printf("Test 2: Simple addition (42 + 8)...\n");
    
    uint8_t bytecode[64];
    size_t offset = 0;
    
    // Load 42 into V0
    emit_load_int(bytecode, offset, REG_V0, 42);
    // Load 8 into V1
    emit_load_int(bytecode, offset, REG_V1, 8);
    // V2 = V0 + V1
    emit_add(bytecode, offset, REG_V2, REG_V0, REG_V1);
    // Return V2
    emit_return(bytecode, offset, REG_V2);
    
    int64_t result = JsInterpreter_Run(bytecode, offset);
    
    printf("  Expected: 50, Got: %lld\n", result);
    return result == 50;
}

bool test_add_negative() {
    printf("Test 3: Addition with negative numbers...\n");
    
    uint8_t bytecode[64];
    size_t offset = 0;
    
    // Load -100 into V0
    emit_load_int(bytecode, offset, REG_V0, -100);
    // Load 50 into V1
    emit_load_int(bytecode, offset, REG_V1, 50);
    // V2 = V0 + V1
    emit_add(bytecode, offset, REG_V2, REG_V0, REG_V1);
    // Return V2
    emit_return(bytecode, offset, REG_V2);
    
    int64_t result = JsInterpreter_Run(bytecode, offset);
    
    printf("  Expected: -50, Got: %lld\n", result);
    return result == -50;
}

bool test_chained_add() {
    printf("Test 4: Chained addition...\n");
    
    uint8_t bytecode[128];
    size_t offset = 0;
    
    // Load values
    emit_load_int(bytecode, offset, REG_V0, 10);
    emit_load_int(bytecode, offset, REG_V1, 20);
    emit_load_int(bytecode, offset, REG_V2, 30);
    
    // V3 = V0 + V1 (10 + 20 = 30)
    emit_add(bytecode, offset, REG_V3, REG_V0, REG_V1);
    // V0 = V3 + V2 (30 + 30 = 60)
    emit_add(bytecode, offset, REG_V0, REG_V3, REG_V2);
    
    emit_return(bytecode, offset, REG_V0);
    
    int64_t result = JsInterpreter_Run(bytecode, offset);
    
    printf("  Expected: 60, Got: %lld\n", result);
    return result == 60;
}

bool test_large_values() {
    printf("Test 5: Large 32-bit values...\n");
    
    uint8_t bytecode[64];
    size_t offset = 0;
    
    // Load large values
    emit_load_int(bytecode, offset, REG_V0, 1000000);
    emit_load_int(bytecode, offset, REG_V1, 2000000);
    emit_add(bytecode, offset, REG_V2, REG_V0, REG_V1);
    emit_return(bytecode, offset, REG_V2);
    
    int64_t result = JsInterpreter_Run(bytecode, offset);
    
    printf("  Expected: 3000000, Got: %lld\n", result);
    return result == 3000000;
}

// ============================================================================
// Benchmark
// ============================================================================

void benchmark_dispatch_loop() {
    printf("\nBenchmark: Dispatch loop throughput...\n");
    
    // Create a loop that does many additions
    constexpr size_t ITERATIONS = 10000000;  // 10 million
    constexpr size_t BYTECODE_SIZE = 6 + (ITERATIONS * 6) + 2;
    
    uint8_t* bytecode = new uint8_t[BYTECODE_SIZE];
    size_t offset = 0;
    
    // Initialize V0 = 0
    emit_load_int(bytecode, offset, REG_V0, 0);
    // Initialize V1 = 1
    emit_load_int(bytecode, offset, REG_V1, 1);
    
    // Loop: V0 = V0 + V1 (10 million times)
    for (size_t i = 0; i < ITERATIONS; i++) {
        emit_add(bytecode, offset, REG_V0, REG_V0, REG_V1);
    }
    
    emit_return(bytecode, offset, REG_V0);
    
    printf("  Bytecode size: %zu bytes\n", offset);
    printf("  Iterations: %zu\n", ITERATIONS);
    
    // Run benchmark
    auto start = __rdtsc();
    int64_t result = JsInterpreter_Run(bytecode, offset);
    auto end = __rdtsc();
    
    double cycles = static_cast<double>(end - start);
    double cycles_per_iteration = cycles / ITERATIONS;
    
    printf("  Result: %lld (expected: %zu)\n", result, ITERATIONS);
    printf("  Total cycles: %.0f\n", cycles);
    printf("  Cycles per dispatch: %.2f\n", cycles_per_iteration);
    
    delete[] bytecode;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    printf("================================================================================\n");
    printf("RawrXD-Script VM Phase 0 Test Harness\n");
    printf("================================================================================\n\n");
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (test_load_and_return()) passed++; else failed++;
    if (test_add_simple()) passed++; else failed++;
    if (test_add_negative()) passed++; else failed++;
    if (test_chained_add()) passed++; else failed++;
    if (test_large_values()) passed++; else failed++;
    
    printf("\n================================================================================\n");
    printf("Results: %d passed, %d failed\n", passed, failed);
    printf("================================================================================\n");
    
    // Run benchmark if all tests passed
    if (failed == 0) {
        benchmark_dispatch_loop();
    }
    
    return failed > 0 ? 1 : 0;
}
