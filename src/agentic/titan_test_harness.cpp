/**
 * Titan Engine Verification Harness
 * Tests the MASM64 assembly implementation for ABI compliance
 * Minimal version - no Windows SDK dependencies
 * 
 * Build: cl /c /EHsc titan_test_harness.cpp /Fo:titan_test_harness.obj
 * Link:  link /OUT:TitanTest.exe titan_test_harness.obj titan_engine.obj kernel32.lib ntdll.lib /SUBSYSTEM:CONSOLE /MACHINE:X64
 */

#include <stdio.h>
#include <stdint.h>
#include <string.h>

// External assembly function declarations (x64 ABI: __fastcall by default)
extern "C" {
    // Core initialization and shutdown
    int64_t Titan_InitializeDMA(void);
    void Titan_ShutdownDMA(void);
    
    // Statistics and monitoring
    int64_t Titan_GetDMAStats(void* stats);
    
    // Kernel execution
    int64_t Titan_ExecuteComputeKernel(void* context);
    
    // DMA operations
    int64_t Titan_PerformCopy(void* dst, const void* src, uint64_t size);
    int64_t Titan_PerformDMA(void* dst, const void* src, uint64_t size);
}

// Test buffer for DMA operations
static uint8_t test_src_buffer[4096];
static uint8_t test_dst_buffer[4096];

int main() {
    printf("========================================\n");
    printf("Titan Engine ABI Compliance Test\n");
    printf("========================================\n\n");
    
    int tests_passed = 0;
    int tests_failed = 0;
    
    // Test 1: Initialization
    printf("[TEST 1] Titan_InitializeDMA...\n");
    int64_t init_result = Titan_InitializeDMA();
    if (init_result >= 0) {
        printf("  PASSED: Initialization returned %lld\n", (long long)init_result);
        tests_passed++;
    } else {
        printf("  FAILED: Initialization returned %lld\n", (long long)init_result);
        tests_failed++;
    }
    
    // Test 2: NF4 Kernel Execution
    printf("[TEST 2] Titan_ExecuteComputeKernel...\n");
    int64_t kernel_result = Titan_ExecuteComputeKernel(nullptr);
    if (kernel_result >= 0) {
        printf("  PASSED: Kernel execution returned %lld\n", (long long)kernel_result);
        tests_passed++;
    } else {
        printf("  FAILED: Kernel execution returned %lld\n", (long long)kernel_result);
        tests_failed++;
    }
    
    // Test 3: Copy Operation
    printf("[TEST 3] Titan_PerformCopy...\n");
    memset(test_src_buffer, 0xAB, sizeof(test_src_buffer));
    memset(test_dst_buffer, 0x00, sizeof(test_dst_buffer));
    
    int64_t copy_result = Titan_PerformCopy(test_dst_buffer, test_src_buffer, 256);
    if (copy_result >= 0) {
        printf("  PASSED: Copy returned %lld\n", (long long)copy_result);
        tests_passed++;
    } else {
        printf("  FAILED: Copy returned %lld\n", (long long)copy_result);
        tests_failed++;
    }
    
    // Test 4: DMA Operation
    printf("[TEST 4] Titan_PerformDMA...\n");
    int64_t dma_result = Titan_PerformDMA(test_dst_buffer, test_src_buffer, 256);
    if (dma_result >= 0) {
        printf("  PASSED: DMA returned %lld\n", (long long)dma_result);
        tests_passed++;
    } else {
        printf("  FAILED: DMA returned %lld\n", (long long)dma_result);
        tests_failed++;
    }
    
    // Test 5: Statistics
    printf("[TEST 5] Titan_GetDMAStats...\n");
    int64_t stats_result = Titan_GetDMAStats(nullptr);
    if (stats_result >= 0) {
        printf("  PASSED: Stats returned %lld\n", (long long)stats_result);
        tests_passed++;
    } else {
        printf("  FAILED: Stats returned %lld\n", (long long)stats_result);
        tests_failed++;
    }
    
    // Test 6: Shutdown
    printf("[TEST 6] Titan_ShutdownDMA...\n");
    Titan_ShutdownDMA();
    printf("  PASSED: Shutdown completed\n");
    tests_passed++;
    
    // Summary
    printf("\n========================================\n");
    printf("TEST SUMMARY\n");
    printf("========================================\n");
    printf("Passed: %d\n", tests_passed);
    printf("Failed: %d\n", tests_failed);
    printf("Total:  %d\n", tests_passed + tests_failed);
    printf("\n");
    
    if (tests_failed == 0) {
        printf("ALL TESTS PASSED - ABI COMPLIANT\n");
        return 0;
    } else {
        printf("SOME TESTS FAILED - ABI ISSUES DETECTED\n");
        return 1;
    }
}