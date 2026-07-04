// RawrXD-Script Integration Test - Milestone 1
// First end-to-end: Hard-coded bytecode → MASM interpreter → JsValue
//
// GOAL: Prove C++ → MASM → return value works
// NO parser, NO lexer, NO emitter - just raw bytecode

#include "../../runtime/runtime_minimal.hpp"
#include <iostream>
#include <cstring>

using namespace RawrXD::Script;

// ============================================================================
// Bytecode Opcodes (minimal subset)
// ============================================================================

enum MinimalOpcode : uint8_t {
    OP_LOAD_CONST = 0x00,   // OP_LOAD_CONST <const_idx> <dst_reg>
    OP_LOAD_INT   = 0x01,   // OP_LOAD_INT <int32> <dst_reg>
    OP_RETURN     = 0x50,   // OP_RETURN <src_reg>
};

// ============================================================================
// Test: return 42;
// ============================================================================

bool Test_Return42() {
    std::cout << "[Test] return 42;" << std::endl;
    
    // Hard-coded bytecode for: return 42;
    // LOAD_INT 42, r0
    // RETURN r0
    const uint8_t bytecode[] = {
        OP_LOAD_INT, 0x2A, 0x00, 0x00, 0x00,  // 42 in little-endian
        0x00,                                     // dst register r0
        OP_RETURN, 0x00                         // return r0
    };
    
    // Create runtime
    Runtime* rt = CreateRuntime();
    if (!rt) {
        std::cerr << "  FAIL: Could not create runtime" << std::endl;
        return false;
    }
    
    // Execute
    JsValue result;
    bool success = ExecuteBytecode(rt, bytecode, sizeof(bytecode), &result);
    
    // Verify
    bool passed = false;
    if (!success) {
        std::cerr << "  FAIL: Execution failed" << std::endl;
        const char* err = GetExceptionString(rt);
        if (err) {
            std::cerr << "  Error: " << err << std::endl;
        }
    } else if (!result.IsInt32() && !result.IsNumber()) {
        std::cerr << "  FAIL: Result is not a number" << std::endl;
    } else {
        int32_t value = result.IsInt32() ? result.GetInt32() : static_cast<int32_t>(result.GetNumber());
        if (value == 42) {
            std::cout << "  PASS: Result = " << value << std::endl;
            passed = true;
        } else {
            std::cerr << "  FAIL: Expected 42, got " << value << std::endl;
        }
    }
    
    DestroyRuntime(rt);
    return passed;
}

// ============================================================================
// Test: return 0;
// ============================================================================

bool Test_ReturnZero() {
    std::cout << "[Test] return 0;" << std::endl;
    
    const uint8_t bytecode[] = {
        OP_LOAD_INT, 0x00, 0x00, 0x00, 0x00,  // 0
        0x00,                                     // r0
        OP_RETURN, 0x00                         // return r0
    };
    
    Runtime* rt = CreateRuntime();
    JsValue result;
    bool success = ExecuteBytecode(rt, bytecode, sizeof(bytecode), &result);
    
    bool passed = false;
    if (success) {
        int32_t value = result.IsInt32() ? result.GetInt32() : 0;
        if (value == 0) {
            std::cout << "  PASS: Result = " << value << std::endl;
            passed = true;
        } else {
            std::cerr << "  FAIL: Expected 0, got " << value << std::endl;
        }
    } else {
        std::cerr << "  FAIL: Execution failed" << std::endl;
    }
    
    DestroyRuntime(rt);
    return passed;
}

// ============================================================================
// Test: return -1;
// ============================================================================

bool Test_ReturnNegative() {
    std::cout << "[Test] return -1;" << std::endl;
    
    const uint8_t bytecode[] = {
        OP_LOAD_INT, 0xFF, 0xFF, 0xFF, 0xFF,  // -1 in two's complement
        0x00,                                     // r0
        OP_RETURN, 0x00                         // return r0
    };
    
    Runtime* rt = CreateRuntime();
    JsValue result;
    bool success = ExecuteBytecode(rt, bytecode, sizeof(bytecode), &result);
    
    bool passed = false;
    if (success) {
        int32_t value = result.IsInt32() ? result.GetInt32() : 0;
        if (value == -1) {
            std::cout << "  PASS: Result = " << value << std::endl;
            passed = true;
        } else {
            std::cerr << "  FAIL: Expected -1, got " << value << std::endl;
        }
    } else {
        std::cerr << "  FAIL: Execution failed" << std::endl;
    }
    
    DestroyRuntime(rt);
    return passed;
}

// ============================================================================
// Test: Runtime lifecycle
// ============================================================================

bool Test_RuntimeLifecycle() {
    std::cout << "[Test] Runtime lifecycle" << std::endl;
    
    bool passed = true;
    
    // Create
    Runtime* rt = CreateRuntime();
    if (!rt) {
        std::cerr << "  FAIL: CreateRuntime returned null" << std::endl;
        return false;
    }
    std::cout << "  Create: OK" << std::endl;
    
    // Reset
    ResetRuntime(rt);
    std::cout << "  Reset: OK" << std::endl;
    
    // Destroy
    DestroyRuntime(rt);
    std::cout << "  Destroy: OK" << std::endl;
    
    std::cout << "  PASS" << std::endl;
    return passed;
}

// ============================================================================
// Test: Multiple executions
// ============================================================================

bool Test_MultipleExecutions() {
    std::cout << "[Test] Multiple executions on same runtime" << std::endl;
    
    const uint8_t bytecode[] = {
        OP_LOAD_INT, 0x01, 0x00, 0x00, 0x00,  // 1
        0x00,                                     // r0
        OP_RETURN, 0x00                         // return r0
    };
    
    Runtime* rt = CreateRuntime();
    bool passed = true;
    
    for (int i = 0; i < 5; i++) {
        JsValue result;
        bool success = ExecuteBytecode(rt, bytecode, sizeof(bytecode), &result);
        
        if (!success) {
            std::cerr << "  FAIL: Execution " << i << " failed" << std::endl;
            passed = false;
            break;
        }
        
        int32_t value = result.IsInt32() ? result.GetInt32() : 0;
        if (value != 1) {
            std::cerr << "  FAIL: Execution " << i << " returned " << value << " instead of 1" << std::endl;
            passed = false;
            break;
        }
        
        ResetRuntime(rt);
    }
    
    if (passed) {
        std::cout << "  PASS: 5 executions completed" << std::endl;
    }
    
    DestroyRuntime(rt);
    return passed;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char** argv) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD-Script Milestone 1 Tests" << std::endl;
    std::cout << "C++ → MASM → JsValue Integration" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    // Run tests
    if (Test_RuntimeLifecycle()) passed++; else failed++;
    if (Test_ReturnZero()) passed++; else failed++;
    if (Test_Return42()) passed++; else failed++;
    if (Test_ReturnNegative()) passed++; else failed++;
    if (Test_MultipleExecutions()) passed++; else failed++;
    
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Results: " << passed << " passed, " << failed << " failed" << std::endl;
    std::cout << "========================================" << std::endl;
    
    if (failed == 0) {
        std::cout << std::endl;
        std::cout << "MILESTONE 1 ACHIEVED" << std::endl;
        std::cout << "C++ → MASM → JsValue pipeline operational" << std::endl;
        return 0;
    } else {
        std::cout << std::endl;
        std::cout << "MILESTONE 1 NOT YET ACHIEVED" << std::endl;
        std::cout << "Check MASM interpreter linkage" << std::endl;
        return 1;
    }
}
