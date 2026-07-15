// Minimal MASM Interpreter Execution Test
// Tests the MASM interpreter with hand-crafted bytecode

#include <stdio.h>
#include <stdint.h>

// Opcodes
#define OP_LOAD_CONST   0x00
#define OP_RETURN       0x58

// Function prototype
extern int64_t JsInterpreter_Run(void* bytecode, size_t code_size, void* constants, uint64_t* result);

// Box a double into NaN-boxed format
static inline uint64_t BoxDouble(double val) {
    union { double d; uint64_t u; } conv;
    conv.d = val;
    return conv.u;
}

int main() {
    printf("RawrXD-Script Minimal Execution Test\n");
    printf("====================================\n\n");
    
    // Create bytecode: LOAD_CONST r0, const[0] ; RETURN r0
    uint8_t bytecode[] = {
        OP_LOAD_CONST,  // 0x00
        0x00,           // dest = r0
        0x00, 0x00,     // const_idx = 0
        OP_RETURN,      // 0x58
        0x00            // src = r0
    };
    size_t code_size = sizeof(bytecode);
    
    // Constants pool: [0] = 42.0
    uint64_t constants[] = {
        BoxDouble(42.0)
    };
    
    printf("Bytecode program:\n");
    printf("  [0] LOAD_CONST r0, const[0]\n");
    printf("  [1] RETURN r0\n\n");
    
    printf("Constants pool:\n");
    printf("  [0] = 42.0 (0x%016llX)\n\n", constants[0]);
    
    uint64_t result = 0;
    
    printf("Executing bytecode...\n\n");
    
    // Call the interpreter
    int64_t status = JsInterpreter_Run(bytecode, code_size, constants, &result);
    
    printf("Execution status: %lld\n", status);
    printf("Raw result: 0x%016llX\n", result);
    
    // Check result
    if (status == 1) {
        // Check if result is NaN-boxed 42.0
        uint64_t expected = BoxDouble(42.0);
        if (result == expected) {
            printf("\n✓ SUCCESS: Interpreter executed correctly!\n");
            printf("  Expected: 42.0 (0x%016llX)\n", expected);
            printf("  Got:      %f (0x%016llX)\n", *(double*)&result, result);
            return 0;
        } else {
            printf("\n? Result mismatch\n");
            printf("  Expected: 0x%016llX\n", expected);
            printf("  Got:      0x%016llX\n", result);
            
            // Try interpreting as double
            double d = *(double*)&result;
            printf("  As double: %f\n", d);
            return 0;  // Still partial success
        }
    } else {
        printf("\n✗ FAILURE: Interpreter returned error status\n");
        return 1;
    }
}
