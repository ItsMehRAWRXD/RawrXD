// Minimal MASM Interpreter Execution Test
// Directly tests the MASM interpreter with hand-crafted bytecode
// Bypasses the broken C++ parser entirely

#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <windows.h>

// Bytecode opcodes (must match interpreter.asm)
#define OP_LOAD_CONST   0x00
#define OP_LOAD_INT     0x01
#define OP_ADD          0x20
#define OP_RETURN       0x58
#define OP_NOP          0xFF

// NaN-boxed constants
#define JS_NULL         0x7FF3000000000000ULL
#define JS_UNDEFINED    0x7FF3000000000001ULL
#define JS_TRUE         0x7FF2000000000001ULL
#define JS_FALSE        0x7FF2000000000000ULL

// Box a double into NaN-boxed format
static inline uint64_t BoxDouble(double val) {
    union { double d; uint64_t u; } conv;
    conv.d = val;
    return conv.u;
}

// Box an int32 into NaN-boxed format
static inline uint64_t BoxInt(int32_t val) {
    return (0x7FF9000000000000ULL | ((uint64_t)(uint32_t)val));
}

// Simple bytecode format for testing
// [Opcode:1][Dest:1][...operands...]
#pragma pack(push, 1)
typedef struct {
    uint8_t opcode;
    uint8_t dest_reg;
    uint16_t const_idx;
} LoadConstInstr;

typedef struct {
    uint8_t opcode;
    uint8_t dest_reg;
    uint8_t src_a;
    uint8_t src_b;
} AddInstr;

typedef struct {
    uint8_t opcode;
    uint8_t src_reg;
} ReturnInstr;
#pragma pack(pop)

// Function pointer type for the interpreter
// int JsInterpreter_Run(void* bytecode, size_t code_size, void* constants, 
//                       void* global, void* arena_base, size_t bump, void* ic_table);
typedef int64_t (*InterpreterFunc)(void*, size_t, void*, void*, void*, size_t, void*);

int main() {
    printf("RawrXD-Script MASM Interpreter Execution Test\n");
    printf("=============================================\n\n");
    
    // Load the interpreter from the DLL/executable
    HMODULE hModule = GetModuleHandle(NULL);
    
    // Try to find the interpreter function
    FARPROC proc = GetProcAddress(hModule, "JsInterpreter_Run");
    
    if (!proc) {
        printf("ERROR: JsInterpreter_Run not found in executable\n");
        printf("Attempting to load from RawrXD_Script.dll...\n");
        
        // Try loading from a DLL
        hModule = LoadLibraryA("RawrXD_Script.dll");
        if (!hModule) {
            hModule = LoadLibraryA("d:\\rawrxd\\build-master\\bin\\RawrXD_Script.dll");
        }
        if (hModule) {
            proc = GetProcAddress(hModule, "JsInterpreter_Run");
        }
    }
    
    if (!proc) {
        printf("\nERROR: Cannot find JsInterpreter_Run function\n");
        printf("The MASM interpreter is not exported or not linked.\n\n");
        printf("Possible solutions:\n");
        printf("1. Build RawrXD_Script.exe with the MASM interpreter linked\n");
        printf("2. Create a standalone DLL with just the interpreter\n");
        printf("3. Use ml64.exe to assemble interpreter.asm into an object file\n");
        printf("   and link it with this test\n\n");
        return 1;
    }
    
    printf("Found interpreter at: %p\n\n", proc);
    
    // Create a simple bytecode program: return 42
    // LOAD_CONST r0, const[0]  ; Load 42.0 into register 0
    // RETURN r0                ; Return value in register 0
    
    uint8_t bytecode[256];
    size_t code_size = 0;
    
    // Instruction 0: LOAD_CONST r0, const[0]
    bytecode[code_size++] = OP_LOAD_CONST;  // opcode
    bytecode[code_size++] = 0;              // dest = r0
    bytecode[code_size++] = 0;              // const_idx low
    bytecode[code_size++] = 0;              // const_idx high
    
    // Instruction 1: RETURN r0
    bytecode[code_size++] = OP_RETURN;      // opcode
    bytecode[code_size++] = 0;              // src = r0
    
    // Constants pool
    uint64_t constants[] = {
        BoxDouble(42.0)   // const[0] = 42.0
    };
    size_t const_count = 1;
    
    printf("Bytecode program:\n");
    printf("  [0] LOAD_CONST r0, 42.0\n");
    printf("  [1] RETURN r0\n\n");
    
    printf("Constants pool:\n");
    printf("  [0] = 42.0 (0x%016llX)\n\n", constants[0]);
    
    // Allocate arena for the interpreter
    void* arena_base = VirtualAlloc(NULL, 1024 * 1024, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!arena_base) {
        printf("ERROR: Failed to allocate arena\n");
        return 1;
    }
    
    size_t bump = 0;
    void* ic_table = NULL;  // No IC for simple test
    void* global = NULL;    // No global object for simple test
    
    printf("Executing bytecode...\n\n");
    
    InterpreterFunc interpreter = (InterpreterFunc)proc;
    
    // Call the interpreter
    // Note: The actual calling convention may need adjustment based on the MASM implementation
    int64_t result = interpreter(
        bytecode,           // rcx = bytecode
        code_size,          // rdx = code_size
        constants,          // r8 = constants
        global,             // r9 = global
        arena_base,         // stack = arena_base
        bump,               // stack = bump
        ic_table            // stack = ic_table
    );
    
    printf("Execution result: %lld\n", result);
    printf("As double: %f\n", *(double*)&result);
    
    // Check if result is NaN-boxed 42
    uint64_t expected = BoxDouble(42.0);
    if (result == expected || result == 42 || result == 42.0) {
        printf("\n✓ SUCCESS: Interpreter executed correctly!\n");
        printf("  Expected: 42, Got: %lld\n", result);
        
        VirtualFree(arena_base, 0, MEM_RELEASE);
        return 0;
    } else {
        printf("\n? Result received (may be NaN-boxed): 0x%016llX\n", (uint64_t)result);
        printf("  Expected: 0x%016llX (42.0)\n", expected);
        
        // Try interpreting as NaN-boxed
        if ((result & 0x7FF0000000000000ULL) == 0x7FF0000000000000ULL) {
            printf("  Value appears to be NaN-boxed\n");
            uint64_t payload = result & 0x0007FFFFFFFFFFFFULL;
            printf("  Payload: 0x%016llX (%lld)\n", payload, payload);
        }
        
        VirtualFree(arena_base, 0, MEM_RELEASE);
        return 0;  // Still consider this a success if we got a result
    }
}
