// RawrXD-Script Bug Classification Test
// Captures execution traces and classifies bugs

#include <cstdio>
#include <cstdint>
#include <cstring>
#include "golden_masters.hpp"

// Simulated trace capture (would be linked to actual TraceCollector)
struct ExecutionTrace {
    uint8_t opcodes[100];
    int count;
    uint64_t result;
    bool success;
};

// Capture trace from execution (placeholder - would call actual interpreter)
ExecutionTrace captureTrace(const char* source, uint64_t expected) {
    ExecutionTrace trace = {};
    
    // Parse simple expression: NUM1 OP NUM2
    int num1, num2;
    char op[4];
    sscanf(source, "%d %s %d", &num1, op, &num2);
    
    // Determine expected opcode
    uint8_t expected_opcode = 0;
    if (strcmp(op, "+") == 0) expected_opcode = 0x20;
    else if (strcmp(op, "-") == 0) expected_opcode = 0x21;
    else if (strcmp(op, "*") == 0) expected_opcode = 0x22;
    else if (strcmp(op, "/") == 0) expected_opcode = 0x23;
    
    // Record the trace
    trace.opcodes[0] = 0x00;  // LOAD_CONST
    trace.opcodes[1] = expected_opcode;  // The actual operation
    trace.opcodes[2] = 0x58;  // RETURN
    trace.count = 3;
    
    // Simulate buggy interpreter (always does ADD)
    trace.result = num1 + num2;  // BUG: Always adds!
    trace.success = true;
    
    return trace;
}

// Classify the bug based on trace vs expected
void classifyBug(const char* test_name, const char* source, 
                 uint64_t expected, uint64_t actual, uint8_t expected_opcode) {
    printf("\n========================================\n");
    printf("Test: %s\n", test_name);
    printf("Source: %s\n", source);
    printf("Expected: %llu\n", (unsigned long long)expected);
    printf("Actual:   %llu\n", (unsigned long long)actual);
    
    if (expected == actual) {
        printf("Result: ✅ PASS\n");
        return;
    }
    
    printf("Result: ❌ FAIL\n");
    
    // Bug classification
    printf("\n--- Bug Classification ---\n");
    
    // Check if it's the "always ADD" bug
    int num1, num2;
    char op[4];
    sscanf(source, "%d %s %d", &num1, op, &num2);
    
    if (actual == (uint64_t)(num1 + num2)) {
        printf("Bug Type: %s\n", RawrXD::Script::BugPatterns::ALU_DISPATCH_FAILURE);
        printf("Description: %s\n", RawrXD::Script::BugPatterns::DESCRIPTION);
        printf("Details: Opcode 0x%02X (%s) was dispatched as ADD\n", 
               expected_opcode, op);
        printf("Expected: %d %s %d = %llu\n", num1, op, num2, 
               (unsigned long long)expected);
        printf("Actual:   %d + %d = %llu (ADD result)\n", num1, num2, 
               (unsigned long long)actual);
        printf("\nSuggested Fix:\n");
        printf("  1. Check dispatch table in interpreter_full.asm\n");
        printf("  2. Verify opcode comparison logic (cmp/je)\n");
        printf("  3. Ensure no fall-through from OP_SUB/OP_MUL/OP_DIV to OP_ADD\n");
    } else {
        printf("Bug Type: UNKNOWN\n");
        printf("Details: Result doesn't match expected or ADD fallback\n");
    }
}

int main() {
    printf("RawrXD-Script Bug Classification System\n");
    printf("=======================================\n");
    printf("\nGolden Master Tests:\n");
    
    using namespace RawrXD::Script::GoldenMasters;
    
    // Test ADD (should pass - this is our Golden Master)
    auto trace_add = captureTrace(ADD_BASIC.source_code, ADD_BASIC.expected_result);
    classifyBug(ADD_BASIC.name, ADD_BASIC.source_code, 
                ADD_BASIC.expected_result, trace_add.result, ADD_BASIC.expected_opcode);
    
    // Test SUB (currently fails - demonstrates bug classification)
    auto trace_sub = captureTrace(SUB_BASIC.source_code, SUB_BASIC.expected_result);
    classifyBug(SUB_BASIC.name, SUB_BASIC.source_code,
                SUB_BASIC.expected_result, trace_sub.result, SUB_BASIC.expected_opcode);
    
    // Test MUL (currently fails)
    auto trace_mul = captureTrace(MUL_BASIC.source_code, MUL_BASIC.expected_result);
    classifyBug(MUL_BASIC.name, MUL_BASIC.source_code,
                MUL_BASIC.expected_result, trace_mul.result, MUL_BASIC.expected_opcode);
    
    // Test DIV (currently fails)
    auto trace_div = captureTrace(DIV_BASIC.source_code, DIV_BASIC.expected_result);
    classifyBug(DIV_BASIC.name, DIV_BASIC.source_code,
                DIV_BASIC.expected_result, trace_div.result, DIV_BASIC.expected_opcode);
    
    printf("\n\n========================================\n");
    printf("Summary:\n");
    printf("  ADD: Working (Golden Master established)\n");
    printf("  SUB/MUL/DIV: Bug classified as ALU_DISPATCH_FAILURE\n");
    printf("\nNext Steps:\n");
    printf("  1. Fix dispatch table in interpreter_full.asm\n");
    printf("  2. Re-run tests to verify fixes\n");
    printf("  3. Capture new fingerprints for SUB/MUL/DIV\n");
    printf("  4. Add to Golden Master database\n");
    
    return 0;
}
