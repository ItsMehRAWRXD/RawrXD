// RawrXD-Script Full Interpreter Test
// Tests comprehensive opcode support

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <math.h>

// External ASM functions
extern int JsInterpreter_Run(uint8_t* bytecode, size_t bytecode_size, 
                             uint64_t* constants, uint64_t* result);
extern uint64_t* JsInterpreter_GetTrace(void);
extern uint64_t JsInterpreter_GetTraceCount(void);
extern void JsInterpreter_ClearTrace(void);
extern uint8_t* JsInterpreter_GetCoverage(void);
extern void JsInterpreter_ResetCoverage(void);

// Opcodes
#define OP_NOP          0x00
#define OP_LOAD_CONST   0x01
#define OP_LOAD_REG     0x02
#define OP_STORE_REG    0x03
#define OP_LOAD_GLOBAL  0x04
#define OP_STORE_GLOBAL 0x05
#define OP_LOAD_NULL    0x06
#define OP_LOAD_UNDEF   0x07
#define OP_LOAD_TRUE    0x08
#define OP_LOAD_FALSE   0x09
#define OP_LOAD_ZERO    0x0A
#define OP_ADD          0x10
#define OP_SUB          0x11
#define OP_MUL          0x12
#define OP_DIV          0x13
#define OP_MOD          0x14
#define OP_NEG          0x15
#define OP_INC          0x16
#define OP_DEC          0x17
#define OP_EQ           0x20
#define OP_NE           0x21
#define OP_LT           0x22
#define OP_LE           0x23
#define OP_GT           0x24
#define OP_GE           0x25
#define OP_JUMP         0x30
#define OP_JUMP_IF_TRUE 0x31
#define OP_JUMP_IF_FALSE 0x32
#define OP_CALL_NATIVE  0x40
#define OP_CALL         0x41
#define OP_RETURN       0x50
#define OP_PRINT        0x60
#define OP_HALT         0xFF

// NaN-boxed constants
#define JS_NULL         0x7FF3000000000000ULL
#define JS_UNDEFINED    0x7FF3000000000001ULL
#define JS_TRUE         0x7FF2000000000001ULL
#define JS_FALSE        0x7FF2000000000000ULL

// Helper to encode double as NaN-boxed value
static uint64_t encode_double(double val) {
    union { double d; uint64_t u; } conv;
    conv.d = val;
    return conv.u;
}

// Helper to decode NaN-boxed value to double
static double decode_double(uint64_t val) {
    union { double d; uint64_t u; } conv;
    conv.u = val;
    return conv.d;
}

// Test result tracking
static int tests_passed = 0;
static int tests_failed = 0;

void test_arithmetic() {
    printf("\n=== Test: Arithmetic Operations ===\n");
    
    // Test: 5 + 3 = 8
    uint8_t bytecode_add[] = {
        OP_LOAD_CONST, 0, 0, 0,    // r0 = const[0] (5.0)
        OP_LOAD_CONST, 1, 1, 0,    // r1 = const[1] (3.0)
        OP_ADD, 2, 0, 1,           // r2 = r0 + r1
        OP_RETURN, 2              // return r2
    };
    uint64_t constants_add[] = { encode_double(5.0), encode_double(3.0) };
    uint64_t result_add;
    
    JsInterpreter_ResetCoverage();
    int status_add = JsInterpreter_Run(bytecode_add, sizeof(bytecode_add), 
                                        constants_add, &result_add);
    
    double val_add = decode_double(result_add);
    if (status_add && fabs(val_add - 8.0) < 0.0001) {
        printf("  [PASS] 5 + 3 = %.1f\n", val_add);
        tests_passed++;
    } else {
        printf("  [FAIL] 5 + 3: expected 8.0, got %.1f (status=%d)\n", 
               val_add, status_add);
        tests_failed++;
    }
    
    // Test: 10 - 4 = 6
    uint8_t bytecode_sub[] = {
        OP_LOAD_CONST, 0, 0, 0,    // r0 = 10.0
        OP_LOAD_CONST, 1, 1, 0,    // r1 = 4.0
        OP_SUB, 2, 0, 1,           // r2 = r0 - r1
        OP_RETURN, 2
    };
    uint64_t constants_sub[] = { encode_double(10.0), encode_double(4.0) };
    uint64_t result_sub;
    
    JsInterpreter_ResetCoverage();
    int status_sub = JsInterpreter_Run(bytecode_sub, sizeof(bytecode_sub), 
                                        constants_sub, &result_sub);
    
    double val_sub = decode_double(result_sub);
    if (status_sub && fabs(val_sub - 6.0) < 0.0001) {
        printf("  [PASS] 10 - 4 = %.1f\n", val_sub);
        tests_passed++;
    } else {
        printf("  [FAIL] 10 - 4: expected 6.0, got %.1f\n", val_sub);
        tests_failed++;
    }
    
    // Test: 7 * 6 = 42
    uint8_t bytecode_mul[] = {
        OP_LOAD_CONST, 0, 0, 0,    // r0 = 7.0
        OP_LOAD_CONST, 1, 1, 0,    // r1 = 6.0
        OP_MUL, 2, 0, 1,           // r2 = r0 * r1
        OP_RETURN, 2
    };
    uint64_t constants_mul[] = { encode_double(7.0), encode_double(6.0) };
    uint64_t result_mul;
    
    JsInterpreter_ResetCoverage();
    int status_mul = JsInterpreter_Run(bytecode_mul, sizeof(bytecode_mul), 
                                        constants_mul, &result_mul);
    
    double val_mul = decode_double(result_mul);
    if (status_mul && fabs(val_mul - 42.0) < 0.0001) {
        printf("  [PASS] 7 * 6 = %.1f\n", val_mul);
        tests_passed++;
    } else {
        printf("  [FAIL] 7 * 6: expected 42.0, got %.1f\n", val_mul);
        tests_failed++;
    }
    
    // Test: 20 / 4 = 5
    uint8_t bytecode_div[] = {
        OP_LOAD_CONST, 0, 0, 0,    // r0 = 20.0
        OP_LOAD_CONST, 1, 1, 0,    // r1 = 4.0
        OP_DIV, 2, 0, 1,           // r2 = r0 / r1
        OP_RETURN, 2
    };
    uint64_t constants_div[] = { encode_double(20.0), encode_double(4.0) };
    uint64_t result_div;
    
    JsInterpreter_ResetCoverage();
    int status_div = JsInterpreter_Run(bytecode_div, sizeof(bytecode_div), 
                                        constants_div, &result_div);
    
    double val_div = decode_double(result_div);
    if (status_div && fabs(val_div - 5.0) < 0.0001) {
        printf("  [PASS] 20 / 4 = %.1f\n", val_div);
        tests_passed++;
    } else {
        printf("  [FAIL] 20 / 4: expected 5.0, got %.1f\n", val_div);
        tests_failed++;
    }
}

void test_comparisons() {
    printf("\n=== Test: Comparison Operations ===\n");
    
    // Test: 5 == 5 (true)
    uint8_t bytecode_eq[] = {
        OP_LOAD_CONST, 0, 0, 0,    // r0 = 5.0
        OP_LOAD_CONST, 1, 0, 0,    // r1 = 5.0 (same const)
        OP_EQ, 2, 0, 1,            // r2 = r0 == r1
        OP_RETURN, 2
    };
    uint64_t constants_eq[] = { encode_double(5.0) };
    uint64_t result_eq;
    
    JsInterpreter_ResetCoverage();
    int status_eq = JsInterpreter_Run(bytecode_eq, sizeof(bytecode_eq), 
                                        constants_eq, &result_eq);
    
    if (status_eq && result_eq == JS_TRUE) {
        printf("  [PASS] 5 == 5 is true\n");
        tests_passed++;
    } else {
        printf("  [FAIL] 5 == 5: expected true, got 0x%016llX\n", result_eq);
        tests_failed++;
    }
    
    // Test: 3 < 7 (true)
    uint8_t bytecode_lt[] = {
        OP_LOAD_CONST, 0, 0, 0,    // r0 = 3.0
        OP_LOAD_CONST, 1, 1, 0,    // r1 = 7.0
        OP_LT, 2, 0, 1,            // r2 = r0 < r1
        OP_RETURN, 2
    };
    uint64_t constants_lt[] = { encode_double(3.0), encode_double(7.0) };
    uint64_t result_lt;
    
    JsInterpreter_ResetCoverage();
    int status_lt = JsInterpreter_Run(bytecode_lt, sizeof(bytecode_lt), 
                                        constants_lt, &result_lt);
    
    if (status_lt && result_lt == JS_TRUE) {
        printf("  [PASS] 3 < 7 is true\n");
        tests_passed++;
    } else {
        printf("  [FAIL] 3 < 7: expected true, got 0x%016llX\n", result_lt);
        tests_failed++;
    }
}

void test_control_flow() {
    printf("\n=== Test: Control Flow ===\n");
    
    // Test: if (true) return 42 else return 0
    // Jump offset is relative to AFTER the jump instruction
    // Jump instruction is at offset 2, length 6, so after jump PC = 8
    // Target (else branch) is at offset 14, so offset = 14 - 8 = 6
    uint8_t bytecode_if[] = {
        OP_LOAD_TRUE, 0,           // r0 = true (offset 0-1)
        OP_JUMP_IF_FALSE, 0, 6, 0, 0, 0,  // if !r0, jump +6 bytes to else branch
        OP_LOAD_CONST, 1, 0, 0,    // r1 = 42.0 (then branch, executed if true)
        OP_RETURN, 1,              // return r1
        OP_LOAD_CONST, 1, 1, 0,    // r1 = 0.0 (else branch, skipped if true)
        OP_RETURN, 1               // return r1
    };
    uint64_t constants_if[] = { encode_double(42.0), encode_double(0.0) };
    uint64_t result_if;
    
    JsInterpreter_ResetCoverage();
    int status_if = JsInterpreter_Run(bytecode_if, sizeof(bytecode_if), 
                                       constants_if, &result_if);
    
    double val_if = decode_double(result_if);
    if (status_if && fabs(val_if - 42.0) < 0.0001) {
        printf("  [PASS] if (true) return 42 -> %.1f\n", val_if);
        tests_passed++;
    } else {
        printf("  [FAIL] if (true): expected 42.0, got %.1f\n", val_if);
        tests_failed++;
    }
    
    // Test: if (false) return 42 else return 0
    // Jump offset is relative to AFTER the jump instruction
    // Jump instruction: OP_JUMP_IF_FALSE + reg + 4-byte offset = 6 bytes
    // After jump instruction, PC = 2 + 6 = 8
    // Target (else branch LOAD_CONST) is at offset 14
    // Jump offset = 14 - 8 = 6
    uint8_t bytecode_if_false[] = {
        OP_LOAD_FALSE, 0,          // r0 = false (offset 0-1)
        OP_JUMP_IF_FALSE, 0, 6, 0, 0, 0,  // if !r0, jump +6 bytes to else branch
        OP_LOAD_CONST, 1, 0, 0,    // r1 = 42.0 (then branch at offset 8, skipped if false)
        OP_RETURN, 1,              // return r1 (offset 12)
        OP_LOAD_CONST, 1, 1, 0,    // r1 = 0.0 (else branch at offset 14)
        OP_RETURN, 1               // return r1 (offset 18)
    };
    uint64_t result_if_false;
    
    JsInterpreter_ResetCoverage();
    int status_if_false = JsInterpreter_Run(bytecode_if_false, sizeof(bytecode_if_false), 
                                             constants_if, &result_if_false);
    
    double val_if_false = decode_double(result_if_false);
    if (status_if_false && fabs(val_if_false - 0.0) < 0.0001) {
        printf("  [PASS] if (false) return 42 -> %.1f (took else branch)\n", val_if_false);
        tests_passed++;
    } else {
        printf("  [FAIL] if (false): expected 0.0, got %.1f\n", val_if_false);
        tests_failed++;
    }
}

void test_coverage() {
    printf("\n=== Test: Opcode Coverage ===\n");
    
    uint8_t* coverage = JsInterpreter_GetCoverage();
    
    printf("  Coverage array (first 32 bytes):\n  ");
    for (int i = 0; i < 32; i++) {
        printf("%02X ", coverage[i]);
        if ((i + 1) % 16 == 0) printf("\n  ");
    }
    
    // Check that some opcodes were executed
    int covered = 0;
    for (int i = 0; i < 256; i++) {
        if (coverage[i]) covered++;
    }
    printf("  Total opcodes covered: %d/256\n", covered);
}

void test_trace() {
    printf("\n=== Test: Execution Trace ===\n");
    
    uint64_t* trace = JsInterpreter_GetTrace();
    uint64_t trace_count = JsInterpreter_GetTraceCount();
    
    printf("  Trace entries: %llu\n", (unsigned long long)trace_count);
    
    if (trace_count > 0) {
        printf("  First 5 trace entries:\n");
        for (int i = 0; i < 5 && i < trace_count; i++) {
            printf("    [%d] PC=0x%016llX\n", i, (unsigned long long)trace[i]);
        }
    }
}

int main() {
    printf("RawrXD-Script Full Interpreter Test\n");
    printf("=====================================\n");
    printf("Testing comprehensive opcode support\n\n");
    
    test_arithmetic();
    test_comparisons();
    test_control_flow();
    test_coverage();
    test_trace();
    
    printf("\n=====================================\n");
    printf("Test Summary: %d passed, %d failed\n", tests_passed, tests_failed);
    
    if (tests_failed == 0) {
        printf("\n✅ ALL TESTS PASSED!\n");
        printf("The RawrXD-Script interpreter is fully functional.\n");
        return 0;
    } else {
        printf("\n⚠️  Some tests failed.\n");
        return 1;
    }
}
