// Test_CodeEmitter.cpp - Standalone code emitter test
#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <cstdio>
#include <vector>
#include <cstdint>

class CodeEmitter {
    std::vector<uint8_t> code;

public:
    void EmitU8(uint8_t val) { code.push_back(val); }
    void EmitU32(uint32_t val) {
        code.push_back(val & 0xFF);
        code.push_back((val >> 8) & 0xFF);
        code.push_back((val >> 16) & 0xFF);
        code.push_back((val >> 24) & 0xFF);
    }

    void EmitPushReg(int reg) { EmitU8(0x50 + (reg & 7)); }
    void EmitPopReg(int reg) { EmitU8(0x58 + (reg & 7)); }
    void EmitRet() { EmitU8(0xC3); }

    void EmitMovRegReg(int dst, int src) {
        EmitU8(0x48 + ((dst >= 8) ? 1 : 0) + ((src >= 8) ? 4 : 0));
        EmitU8(0x89);
        EmitU8(0xC0 + ((src & 7) << 3) + (dst & 7));
    }

    void EmitAddRegImm32(int reg, uint32_t imm) {
        EmitU8(0x48 + (reg >= 8 ? 1 : 0));
        EmitU8(0x81);
        EmitU8(0xC0 + (reg & 7));
        EmitU32(imm);
    }

    void EmitFunctionPrologue() {
        EmitPushReg(5);
        EmitMovRegReg(5, 4);
    }

    void EmitFunctionEpilogue() {
        EmitPopReg(5);
        EmitRet();
    }

    void* AllocateExecutable() {
        void* mem = VirtualAlloc(nullptr, code.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (mem) {
            memcpy(mem, code.data(), code.size());
            DWORD oldProtect;
            VirtualProtect(mem, code.size(), PAGE_EXECUTE_READ, &oldProtect);
        }
        return mem;
    }

    void Clear() { code.clear(); }
    size_t GetSize() const { return code.size(); }
};

int main() {
    printf("RawrXD Code Emitter Test\n");
    printf("========================\n\n");

    CodeEmitter emitter;

    // Test 1: Emit simple function - int add(int a, int b) { return a + b; }
    printf("Test 1: Emitting add(5, 3) function...\n");
    emitter.Clear();
    emitter.EmitFunctionPrologue();
    emitter.EmitMovRegReg(0, 2);  // mov rax, rdx (arg2 = b)
    emitter.EmitAddRegImm32(0, 8); // add rax, [rbp+8] (arg1 = a)
    emitter.EmitFunctionEpilogue();

    printf("  Generated %zu bytes of x64 code\n", emitter.GetSize());

    void* func = emitter.AllocateExecutable();
    if (!func) {
        printf("  FAILED: Could not allocate executable memory\n");
        return 1;
    }

    typedef int (*AddFunc)(int, int);
    AddFunc add = (AddFunc)func;
    int result = add(5, 3);

    printf("  Result: 5 + 3 = %d\n", result);
    printf("  Status: %s\n\n", (result == 8) ? "PASS" : "FAIL");

    VirtualFree(func, 0, MEM_RELEASE);

    // Test 2: Emit function that returns constant
    printf("Test 2: Emitting constant return function...\n");
    emitter.Clear();
    emitter.EmitFunctionPrologue();
    // mov rax, 42
    emitter.EmitU8(0x48);
    emitter.EmitU8(0xC7);
    emitter.EmitU8(0xC0);
    emitter.EmitU32(42);
    emitter.EmitFunctionEpilogue();

    void* func2 = emitter.AllocateExecutable();
    if (func2) {
        typedef int (*ConstFunc)();
        ConstFunc getConst = (ConstFunc)func2;
        int result2 = getConst();
        printf("  Result: getConst() = %d\n", result2);
        printf("  Status: %s\n\n", (result2 == 42) ? "PASS" : "FAIL");
        VirtualFree(func2, 0, MEM_RELEASE);
    }

    printf("Code Emitter: All tests complete.\n");
    return 0;
}
