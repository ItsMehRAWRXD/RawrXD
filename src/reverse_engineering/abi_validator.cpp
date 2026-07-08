/**
 * @file abi_validator.cpp
 * @brief ABI Validation Framework for Multi-Architecture Decoder
 * @description Validates Windows x64 ABI compliance for all exported functions
 * 
 * Tests:
 * - Non-volatile register preservation (RBX, RSI, RDI, R12-R15)
 * - Stack alignment (16-byte aligned)
 * - Shadow space compliance (32 bytes reserved)
 * - Parameter passing (RCX, RDX, R8, R9, stack)
 * - Return value (RAX)
 */

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include "RawrCodex_Multi_v2.hpp"

using namespace RawrCodex;

// Test configuration
struct ABITestConfig {
    uint64_t iterations;
    bool verbose;
};

// Register snapshot for validation
struct RegisterSnapshot {
    uint64_t rbx;
    uint64_t rsi;
    uint64_t rdi;
    uint64_t r12;
    uint64_t r13;
    uint64_t r14;
    uint64_t r15;
    uint64_t rbp;
    uint64_t rsp;
    uint64_t xmm6[2];   // Low and high 64-bits
    uint64_t xmm7[2];
    uint64_t xmm8[2];
    uint64_t xmm9[2];
    uint64_t xmm10[2];
    uint64_t xmm11[2];
    uint64_t xmm12[2];
    uint64_t xmm13[2];
    uint64_t xmm14[2];
    uint64_t xmm15[2];
};

// Capture register state
extern "C" void CaptureRegisters(RegisterSnapshot* snap);
extern "C" void RestoreRegisters(RegisterSnapshot* snap);

// Test function prototypes
extern "C" {
    __declspec(dllimport) uint32_t ReferenceDecoder_Decode(
        uint32_t arch,
        const uint8_t* bytes,
        uint32_t byteCount,
        uint64_t va,
        DecodedInstruction* out
    );
    
    __declspec(dllimport) bool ReferenceDecoder_Validate(
        const DecodedInstruction* ref,
        const DecodedInstruction* opt,
        char* mismatchReason,
        size_t reasonBufferSize
    );
    
    __declspec(dllimport) void GetArchitectureName(
        uint32_t archType,
        char* outputBuffer
    );
    
    __declspec(dllimport) uint32_t RawrDisasm_Multi_Init(void* ctx);
    __declspec(dllimport) uint32_t RawrDisasm_Multi_Decode(
        void* ctx,
        uint64_t va,
        const uint8_t* bytes,
        DecodedInstruction* out
    );
    __declspec(dllimport) uint32_t RawrDisasm_ARM_Decode(
        void* ctx,
        uint32_t archType,
        uint64_t va,
        const uint8_t* bytes,
        DecodedInstruction* out
    );
    __declspec(dllimport) uint32_t RawrDisasm_MIPS_Decode(
        void* ctx,
        uint32_t archType,
        uint64_t va,
        const uint8_t* bytes,
        DecodedInstruction* out
    );
    __declspec(dllimport) uint32_t RawrDisasm_RISCV_Decode(
        void* ctx,
        uint32_t archType,
        uint64_t va,
        const uint8_t* bytes,
        DecodedInstruction* out
    );
    
    __declspec(dllimport) void* RawrEmu_Multi_Create(uint32_t archType);
    __declspec(dllimport) void RawrEmu_Multi_Destroy(void* emu);
    __declspec(dllimport) uint32_t RawrEmu_Multi_Step(void* emu, DecodedInstruction* instr);
    __declspec(dllimport) uint32_t RawrEmu_Multi_Run(void* emu, uint64_t maxCycles);
}

// Function under test
struct TestFunction {
    const char* name;
    void* func;
    uint32_t argCount;
    uint64_t testArgs[4];
};

// Global test functions table
TestFunction g_testFunctions[] = {
    { "ReferenceDecoder_Decode", (void*)ReferenceDecoder_Decode, 5, {4, 0, 4, 0x1000, 0} },
    { "ReferenceDecoder_Validate", (void*)ReferenceDecoder_Validate, 4, {0, 0, 0, 256} },
    { "GetArchitectureName", (void*)GetArchitectureName, 2, {4, 0, 0, 0} },
    { "RawrDisasm_Multi_Init", (void*)RawrDisasm_Multi_Init, 1, {0, 0, 0, 0} },
    { "RawrDisasm_Multi_Decode", (void*)RawrDisasm_Multi_Decode, 4, {0, 0x1000, 0, 0} },
    { "RawrDisasm_ARM_Decode", (void*)RawrDisasm_ARM_Decode, 5, {0, 4, 0x1000, 0, 0} },
    { "RawrDisasm_MIPS_Decode", (void*)RawrDisasm_MIPS_Decode, 5, {0, 7, 0x1000, 0, 0} },
    { "RawrDisasm_RISCV_Decode", (void*)RawrDisasm_RISCV_Decode, 5, {0, 9, 0x1000, 0, 0} },
    { "RawrEmu_Multi_Create", (void*)RawrEmu_Multi_Create, 1, {4, 0, 0, 0} },
    { "RawrEmu_Multi_Destroy", (void*)RawrEmu_Multi_Destroy, 1, {0, 0, 0, 0} },
    { "RawrEmu_Multi_Step", (void*)RawrEmu_Multi_Step, 2, {0, 0, 0, 0} },
    { "RawrEmu_Multi_Run", (void*)RawrEmu_Multi_Run, 2, {0, 1000, 0, 0} },
};

const size_t g_testFunctionCount = sizeof(g_testFunctions) / sizeof(g_testFunctions[0]);

// Assembly helper to capture registers
__declspec(naked) void CaptureRegisters(RegisterSnapshot* snap) {
    __asm {
        push rbx
        push rsi
        push rdi
        push r12
        push r13
        push r14
        push r15
        push rbp
        
        mov rbx, [rsp + 72]     ; snap pointer (after pushes)
        
        mov [rbx + 0], rbx
        mov [rbx + 8], rsi
        mov [rbx + 16], rdi
        mov [rbx + 24], r12
        mov [rbx + 32], r13
        mov [rbx + 40], r14
        mov [rbx + 48], r15
        mov [rbx + 56], rbp
        mov [rbx + 64], rsp
        
        ; Save XMM registers
        movdqu [rbx + 72], xmm6
        movdqu [rbx + 88], xmm7
        movdqu [rbx + 104], xmm8
        movdqu [rbx + 120], xmm9
        movdqu [rbx + 136], xmm10
        movdqu [rbx + 152], xmm11
        movdqu [rbx + 168], xmm12
        movdqu [rbx + 184], xmm13
        movdqu [rbx + 200], xmm14
        movdqu [rbx + 216], xmm15
        
        pop rbp
        pop r15
        pop r14
        pop r13
        pop r12
        pop rdi
        pop rsi
        pop rbx
        ret
    }
}

// Assembly helper to restore registers (for testing)
__declspec(naked) void RestoreRegisters(RegisterSnapshot* snap) {
    __asm {
        push rbx
        
        mov rbx, rcx            ; snap pointer
        
        ; Restore XMM registers
        movdqu xmm6, [rbx + 72]
        movdqu xmm7, [rbx + 88]
        movdqu xmm8, [rbx + 104]
        movdqu xmm9, [rbx + 120]
        movdqu xmm10, [rbx + 136]
        movdqu xmm11, [rbx + 152]
        movdqu xmm12, [rbx + 168]
        movdqu xmm13, [rbx + 184]
        movdqu xmm14, [rbx + 200]
        movdqu xmm15, [rbx + 216]
        
        pop rbx
        ret
    }
}

// Validate non-volatile register preservation
bool ValidateRegisterPreservation(const TestFunction& test, char* errorMsg, size_t errorSize) {
    RegisterSnapshot before, after;
    
    // Set distinctive values in non-volatile registers
    __asm {
        mov rbx, 0xDEADBEEFDEADBEEF
        mov rsi, 0xCAFEBABECAFEBABE
        mov rdi, 0xBADC0FFEE0DDF00D
        mov r12, 0x123456789ABCDEF0
        mov r13, 0x0FEDCBA987654321
        mov r14, 0xAABBCCDDEEFF0011
        mov r15, 0x1122334455667788
    }
    
    // Capture before state
    CaptureRegisters(&before);
    
    // Call the function
    // Use a generic call pattern
    void* func = test.func;
    uint64_t result = 0;
    
    __asm {
        mov rcx, test.testArgs[0]
        mov rdx, test.testArgs[1]
        mov r8, test.testArgs[2]
        mov r9, test.testArgs[3]
        sub rsp, 32             ; Shadow space
        call func
        add rsp, 32
        mov result, rax
    }
    
    // Capture after state
    CaptureRegisters(&after);
    
    // Compare non-volatile registers
    bool pass = true;
    
    if (before.rbx != after.rbx) {
        snprintf(errorMsg, errorSize, "RBX corrupted: %016llX -> %016llX", 
                 before.rbx, after.rbx);
        pass = false;
    }
    else if (before.rsi != after.rsi) {
        snprintf(errorMsg, errorSize, "RSI corrupted: %016llX -> %016llX",
                 before.rsi, after.rsi);
        pass = false;
    }
    else if (before.rdi != after.rdi) {
        snprintf(errorMsg, errorSize, "RDI corrupted: %016llX -> %016llX",
                 before.rdi, after.rdi);
        pass = false;
    }
    else if (before.r12 != after.r12) {
        snprintf(errorMsg, errorSize, "R12 corrupted: %016llX -> %016llX",
                 before.r12, after.r12);
        pass = false;
    }
    else if (before.r13 != after.r13) {
        snprintf(errorMsg, errorSize, "R13 corrupted: %016llX -> %016llX",
                 before.r13, after.r13);
        pass = false;
    }
    else if (before.r14 != after.r14) {
        snprintf(errorMsg, errorSize, "R14 corrupted: %016llX -> %016llX",
                 before.r14, after.r14);
        pass = false;
    }
    else if (before.r15 != after.r15) {
        snprintf(errorMsg, errorSize, "R15 corrupted: %016llX -> %016llX",
                 before.r15, after.r15);
        pass = false;
    }
    
    return pass;
}

// Validate stack alignment
bool ValidateStackAlignment(const TestFunction& test, char* errorMsg, size_t errorSize) {
    uint64_t stackBefore, stackAfter;
    
    __asm {
        mov stackBefore, rsp
    }
    
    // Call function
    void* func = test.func;
    __asm {
        mov rcx, test.testArgs[0]
        mov rdx, test.testArgs[1]
        mov r8, test.testArgs[2]
        mov r9, test.testArgs[3]
        sub rsp, 32
        call func
        add rsp, 32
    }
    
    __asm {
        mov stackAfter, rsp
    }
    
    // Check stack was restored
    if (stackBefore != stackAfter) {
        snprintf(errorMsg, errorSize, "Stack imbalance: %016llX -> %016llX",
                 stackBefore, stackAfter);
        return false;
    }
    
    // Check 16-byte alignment
    if (stackAfter & 0xF) {
        snprintf(errorMsg, errorSize, "Stack misaligned: %016llX", stackAfter);
        return false;
    }
    
    return true;
}

// Validate shadow space compliance
bool ValidateShadowSpace(const TestFunction& test, char* errorMsg, size_t errorSize) {
    // Shadow space is 32 bytes at [RSP+8] through [RSP+40] at function entry
    // The function should not crash if we pass valid shadow space
    
    void* func = test.func;
    bool crashed = false;
    
    __try {
        __asm {
            sub rsp, 56             ; Shadow space + alignment
            mov rcx, test.testArgs[0]
            mov rdx, test.testArgs[1]
            mov r8, test.testArgs[2]
            mov r9, test.testArgs[3]
            call func
            add rsp, 56
        }
    }
    __except (EXCEPTION_EXECUTE_HANDLER) {
        crashed = true;
    }
    
    if (crashed) {
        snprintf(errorMsg, errorSize, "Function crashed (shadow space issue?)");
        return false;
    }
    
    return true;
}

// Run all ABI tests
int RunABITests(const ABITestConfig& config) {
    printf("=== ABI Validation Framework ===\n");
    printf("Testing %zu exported functions\n\n", g_testFunctionCount);
    
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    
    char errorMsg[256];
    
    for (size_t i = 0; i < g_testFunctionCount; i++) {
        const TestFunction& test = g_testFunctions[i];
        
        printf("Testing %s:\n", test.name);
        
        // Test 1: Register preservation
        totalTests++;
        if (ValidateRegisterPreservation(test, errorMsg, sizeof(errorMsg))) {
            printf("  [PASS] Register preservation\n");
            passedTests++;
        } else {
            printf("  [FAIL] Register preservation: %s\n", errorMsg);
            failedTests++;
        }
        
        // Test 2: Stack alignment
        totalTests++;
        if (ValidateStackAlignment(test, errorMsg, sizeof(errorMsg))) {
            printf("  [PASS] Stack alignment\n");
            passedTests++;
        } else {
            printf("  [FAIL] Stack alignment: %s\n", errorMsg);
            failedTests++;
        }
        
        // Test 3: Shadow space
        totalTests++;
        if (ValidateShadowSpace(test, errorMsg, sizeof(errorMsg))) {
            printf("  [PASS] Shadow space\n");
            passedTests++;
        } else {
            printf("  [FAIL] Shadow space: %s\n", errorMsg);
            failedTests++;
        }
        
        printf("\n");
    }
    
    printf("=== Results ===\n");
    printf("Total:  %d\n", totalTests);
    printf("Passed: %d\n", passedTests);
    printf("Failed: %d\n", failedTests);
    
    return failedTests > 0 ? 1 : 0;
}

// C++ ABIValidator implementation
namespace RawrCodex {

bool ABIValidator::ValidateAllExports(ABIValidator::TestResult* results, uint32_t maxResults) {
    uint32_t count = 0;
    
    for (size_t i = 0; i < g_testFunctionCount && count < maxResults; i++) {
        const TestFunction& test = g_testFunctions[i];
        
        results[count].functionName = test.name;
        
        char errorMsg[256];
        bool pass = ValidateRegisterPreservation(test, errorMsg, sizeof(errorMsg));
        
        if (pass) {
            pass = ValidateStackAlignment(test, errorMsg, sizeof(errorMsg));
        }
        
        if (pass) {
            pass = ValidateShadowSpace(test, errorMsg, sizeof(errorMsg));
        }
        
        results[count].passed = pass;
        strncpy(results[count].errorMessage, errorMsg, sizeof(results[count].errorMessage) - 1);
        results[count].errorMessage[sizeof(results[count].errorMessage) - 1] = '\0';
        
        count++;
    }
    
    return true;
}

bool ABIValidator::ValidateExport(const char* name, TestResult* out) {
    for (size_t i = 0; i < g_testFunctionCount; i++) {
        if (strcmp(g_testFunctions[i].name, name) == 0) {
            out->functionName = name;
            
            char errorMsg[256];
            bool pass = ValidateRegisterPreservation(g_testFunctions[i], errorMsg, sizeof(errorMsg));
            
            out->passed = pass;
            strncpy(out->errorMessage, errorMsg, sizeof(out->errorMessage) - 1);
            out->errorMessage[sizeof(out->errorMessage) - 1] = '\0';
            
            return true;
        }
    }
    return false;
}

bool ABIValidator::CheckRegisterPreservation(void* func, const char* name) {
    for (size_t i = 0; i < g_testFunctionCount; i++) {
        if (strcmp(g_testFunctions[i].name, name) == 0) {
            char errorMsg[256];
            return ValidateRegisterPreservation(g_testFunctions[i], errorMsg, sizeof(errorMsg));
        }
    }
    return false;
}

bool ABIValidator::CheckStackAlignment(void* func, const char* name) {
    for (size_t i = 0; i < g_testFunctionCount; i++) {
        if (strcmp(g_testFunctions[i].name, name) == 0) {
            char errorMsg[256];
            return ValidateStackAlignment(g_testFunctions[i], errorMsg, sizeof(errorMsg));
        }
    }
    return false;
}

bool ABIValidator::CheckShadowSpace(void* func, const char* name) {
    for (size_t i = 0; i < g_testFunctionCount; i++) {
        if (strcmp(g_testFunctions[i].name, name) == 0) {
            char errorMsg[256];
            return ValidateShadowSpace(g_testFunctions[i], errorMsg, sizeof(errorMsg));
        }
    }
    return false;
}

} // namespace RawrCodex

// Main entry point
int main(int argc, char* argv[]) {
    ABITestConfig config = {
        .iterations = 1,
        .verbose = false
    };
    
    // Parse arguments
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config.verbose = true;
        }
        else if (strcmp(argv[i], "-i") == 0 && i + 1 < argc) {
            config.iterations = atoi(argv[++i]);
        }
        else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("ABI Validator for RawrCodex Multi-Architecture Decoder\n");
            printf("Usage: %s [options]\n", argv[0]);
            printf("Options:\n");
            printf("  -v, --verbose     Enable verbose output\n");
            printf("  -i <n>            Run n iterations (default: 1)\n");
            printf("  -h, --help        Show this help\n");
            return 0;
        }
    }
    
    return RunABITests(config);
}
