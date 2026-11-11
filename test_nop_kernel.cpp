// Nop-Kernel ABI Test Harness
// Tests basic MASM/C++ interop without complex logic

#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// External MASM functions
extern "C" {
    uint64_t NopKernel_Test(uint64_t param1, uint64_t param2, uint64_t param3, uint64_t param4);
    uint16_t NopKernel_Simple();
}

int main() {
    printf("========================================\n");
    printf("Nop-Kernel ABI Test Harness\n");
    printf("========================================\n\n");
    
    // Test 1: Simplest possible call
    printf("[Test 1] NopKernel_Simple()...\n");
    uint16_t result1 = NopKernel_Simple();
    printf("  Result: 0x%04X (expected: 0xBEEF)\n", result1);
    if (result1 == 0xBEEF) {
        printf("  Status: PASS ✓\n\n");
    } else {
        printf("  Status: FAIL ✗\n\n");
        return 1;
    }
    
    // Test 2: Full calling convention test
    printf("[Test 2] NopKernel_Test(RCX, RDX, R8, R9)...\n");
    uint64_t result2 = NopKernel_Test(0x1111, 0x2222, 0x3333, 0x4444);
    printf("  Result: 0x%llX (expected: 0xDEADBEEF)\n", result2);
    if (result2 == 0xDEADBEEF) {
        printf("  Status: PASS ✓\n\n");
    } else {
        printf("  Status: FAIL ✗\n\n");
        return 1;
    }
    
    printf("========================================\n");
    printf("All ABI Tests PASSED\n");
    printf("========================================\n");
    
    return 0;
}
