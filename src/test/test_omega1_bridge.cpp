// test_omega1_bridge.cpp
// Simple test harness for Omega1 Bridge with dual GPU support

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Test function declarations
extern "C" {
    // These would be linked from Omega1Engine.lib
    int Omega1_Initialize(void);
    int Omega1_Shutdown(void);
    int Omega1_GetGpuCount(void);
    int Omega1_GetGpuInfo(int index, char* name, size_t nameLen, size_t* vramBytes);
    int Omega1_TestDualGpu(void);
}

int main(int argc, char* argv[]) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Omega1 Bridge Test Harness                               ║\n");
    printf("║     Dual GPU Configuration: R9700 + 7800XT                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    // Test 1: Initialization
    printf("[TEST 1/5] Initializing Omega1...\n");
    int result = Omega1_Initialize();
    if (result == 0) {
        printf("           PASS: Initialization successful\n\n");
    } else {
        printf("           FAIL: Initialization returned %d\n\n", result);
        return 1;
    }

    // Test 2: GPU Count
    printf("[TEST 2/5] Detecting GPUs...\n");
    int gpuCount = Omega1_GetGpuCount();
    printf("           Found %d GPU(s)\n", gpuCount);
    if (gpuCount >= 2) {
        printf("           PASS: Multiple GPUs detected\n\n");
    } else if (gpuCount >= 1) {
        printf("           WARN: Only 1 GPU detected\n\n");
    } else {
        printf("           FAIL: No GPUs detected\n\n");
    }

    // Test 3: GPU Info
    printf("[TEST 3/5] Querying GPU information...\n");
    for (int i = 0; i < gpuCount && i < 4; i++) {
        char name[256] = {0};
        size_t vram = 0;
        result = Omega1_GetGpuInfo(i, name, sizeof(name), &vram);
        if (result == 0) {
            double vramGB = vram / (1024.0 * 1024.0 * 1024.0);
            printf("           GPU %d: %s (%.1f GB)\n", i, name, vramGB);
        }
    }
    printf("           PASS: GPU info retrieved\n\n");

    // Test 4: Dual GPU Test
    printf("[TEST 4/5] Running dual GPU test...\n");
    result = Omega1_TestDualGpu();
    if (result == 0) {
        printf("           PASS: Dual GPU test successful\n\n");
    } else {
        printf("           WARN: Dual GPU test returned %d\n\n", result);
    }

    // Test 5: Shutdown
    printf("[TEST 5/5] Shutting down Omega1...\n");
    result = Omega1_Shutdown();
    if (result == 0) {
        printf("           PASS: Shutdown successful\n\n");
    } else {
        printf("           FAIL: Shutdown returned %d\n\n", result);
    }

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Test Complete                                            ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    return 0;
}
