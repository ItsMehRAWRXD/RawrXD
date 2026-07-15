// Minimal JavaScript Execution Test
// Directly tests the MASM interpreter without full parser

#include <cstdio>
#include <cstdint>
#include <cstring>
#include <windows.h>

// Bytecode opcodes (must match bytecode.hpp)
enum class Opcode : uint8_t {
    NOP = 0,
    LOAD_CONST = 1,
    ADD = 2,
    SUB = 3,
    MUL = 4,
    DIV = 5,
    RETURN = 6,
};

// 4-byte instruction format
#pragma pack(push, 1)
struct Instruction {
    uint8_t opcode;
    uint8_t dest_reg : 4;
    uint8_t src_a : 4;
    uint8_t src_b : 4;
    uint16_t reserved : 12;
};
#pragma pack(pop)

static_assert(sizeof(Instruction) == 4, "Instruction must be 4 bytes");

// NaN-boxed value (64-bit)
union Value {
    uint64_t bits;
    double number;
    
    static Value Number(double n) {
        Value v;
        v.number = n;
        return v;
    }
};

// Simple bytecode program: return 42
// LOAD_CONST r0, 42
// RETURN r0

extern "C" {
    // MASM interpreter entry point
    // int ExecuteBytecode(Instruction* code, size_t count, Value* constants, size_t const_count);
    int RawrXD_ExecuteBytecode(void* code, size_t count, void* constants, size_t const_count);
}

int main() {
    printf("RawrXD-Script Minimal Execution Test\n");
    printf("=====================================\n\n");
    
    // Create simple bytecode: load constant 42 into r0, then return
    Instruction program[] = {
        { static_cast<uint8_t>(Opcode::LOAD_CONST), 0, 0, 0, 0 },  // LOAD_CONST r0, const[0]
        { static_cast<uint8_t>(Opcode::RETURN), 0, 0, 0, 0 },      // RETURN r0
    };
    
    Value constants[] = {
        Value::Number(42.0)
    };
    
    printf("Bytecode program:\n");
    printf("  [0] LOAD_CONST r0, 42.0\n");
    printf("  [1] RETURN r0\n\n");
    
    // Check if interpreter is available
    HMODULE hModule = GetModuleHandle(NULL);
    FARPROC proc = GetProcAddress(hModule, "RawrXD_ExecuteBytecode");
    
    if (!proc) {
        printf("ERROR: RawrXD_ExecuteBytecode not found in executable\n");
        printf("The interpreter may not be linked or exported correctly.\n");
        return 1;
    }
    
    printf("Interpreter found at: %p\n", proc);
    
    // Execute the bytecode
    printf("\nExecuting bytecode...\n");
    
    typedef int (*ExecuteFunc)(void*, size_t, void*, size_t);
    ExecuteFunc execute = (ExecuteFunc)proc;
    
    int result = execute(program, 2, constants, 1);
    
    printf("\nExecution result: %d\n", result);
    
    if (result == 42) {
        printf("\n✓ SUCCESS: JavaScript engine executes correctly!\n");
        printf("  Expected: 42, Got: %d\n", result);
        return 0;
    } else {
        printf("\n✗ FAILURE: Unexpected result\n");
        printf("  Expected: 42, Got: %d\n", result);
        return 1;
    }
}
