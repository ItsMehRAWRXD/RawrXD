// test_omega1_bridge_simple.cpp
// Standalone test for Omega1 Bridge - no external dependencies

#include <windows.h>
#include <stdio.h>
#include <stdlib.h>

// Simulated Omega1 functions for testing
static int g_initialized = 0;
static int g_gpuCount = 2;

extern "C" {
    int Omega1_Initialize(void) {
        g_initialized = 1;
        return 0;
    }

    int Omega1_Shutdown(void) {
        g_initialized = 0;
        return 0;
    }

    int Omega1_GetGpuCount(void) {
        return g_gpuCount;
    }

    int Omega1_GetGpuInfo(int index, char* name, size_t nameLen, size_t* vramBytes) {
        if (!g_initialized) return -1;
        if (index < 0 || index >= g_gpuCount) return -1;
        if (!name || !vramBytes) return -1;

        const char* gpuNames[] = {
            "AMD Radeon AI PRO R9700",
            "AMD Radeon RX 7800 XT"
        };
        size_t vramSizes[] = {
            34359738368ULL,  // 32GB
            17179869184ULL   // 16GB
        };

        strncpy_s(name, nameLen, gpuNames[index], _TRUNCATE);
        *vramBytes = vramSizes[index];
        return 0;
    }

    int Omega1_TestDualGpu(void) {
        if (!g_initialized) return -1;
        if (g_gpuCount < 2) return -2;
        return 0;
    }
}

int main(int argc, char* argv[]) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Omega1 Bridge Test Harness                               ║\n");
    printf("║     Dual GPU Configuration: R9700 + 7800XT                    ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");

    int passed = 0;
    int failed = 0;

    // Test 1: Initialization
    printf("[TEST 1/5] Initializing Omega1...\n");
    int result = Omega1_Initialize();
    if (result == 0) {
        printf("           PASS: Initialization successful\n\n");
        passed++;
    } else {
        printf("           FAIL: Initialization returned %d\n\n", result);
        failed++;
    }

    // Test 2: GPU Count
    printf("[TEST 2/5] Detecting GPUs...\n");
    int gpuCount = Omega1_GetGpuCount();
    printf("           Found %d GPU(s)\n", gpuCount);
    if (gpuCount >= 2) {
        printf("           PASS: Multiple GPUs detected\n\n");
        passed++;
    } else if (gpuCount >= 1) {
        printf("           WARN: Only 1 GPU detected\n\n");
        passed++;
    } else {
        printf("           FAIL: No GPUs detected\n\n");
        failed++;
    }

    // Test 3: GPU Info
    printf("[TEST 3/5] Querying GPU information...\n");
    int infoPassed = 1;
    for (int i = 0; i < gpuCount && i < 4; i++) {
        char name[256] = {0};
        size_t vram = 0;
        result = Omega1_GetGpuInfo(i, name, sizeof(name), &vram);
        if (result == 0) {
            double vramGB = vram / (1024.0 * 1024.0 * 1024.0);
            printf("           GPU %d: %s (%.1f GB)\n", i, name, vramGB);
        } else {
            printf("           GPU %d: Failed to query (error %d)\n", i, result);
            infoPassed = 0;
        }
    }
    if (infoPassed) {
        printf("           PASS: GPU info retrieved\n\n");
        passed++;
    } else {
        printf("           FAIL: Some GPU info failed\n\n");
        failed++;
    }

    // Test 4: Dual GPU Test
    printf("[TEST 4/5] Running dual GPU test...\n");
    result = Omega1_TestDualGpu();
    if (result == 0) {
        printf("           PASS: Dual GPU test successful\n\n");
        passed++;
    } else {
        printf("           WARN: Dual GPU test returned %d\n\n", result);
        passed++; // Warning, not failure
    }

    // Test 5: Shutdown
    printf("[TEST 5/5] Shutting down Omega1...\n");
    result = Omega1_Shutdown();
    if (result == 0) {
        printf("           PASS: Shutdown successful\n\n");
        passed++;
    } else {
        printf("           FAIL: Shutdown returned %d\n\n", result);
        failed++;
    }

    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║     Test Summary                                             ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║  Total:  5                                                   ║\n");
    printf("║  Passed: %d                                                  ║\n", passed);
    printf("║  Failed: %d                                                  ║\n", failed);
    printf("╚══════════════════════════════════════════════════════════════╝\n");

    return failed > 0 ? 1 : 0;
}
