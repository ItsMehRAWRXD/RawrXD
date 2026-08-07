// ============================================================================
// test_gpu.cpp — GPU Backend Unit Tests
// ============================================================================

#include <cstdio>
#include <cstring>
#include "../src/gpu/GpuManager.hpp"

static int g_passed = 0;
static int g_failed = 0;

#define TEST(name, expr) do { \
    printf("  [TEST] %-45s ... ", name); \
    if (expr) { printf("PASSED\n"); g_passed++; } \
    else { printf("FAILED\n"); g_failed++; } \
} while(0)

int main() {
    printf("========================================\n");
    printf("  RawrXD GPU Test Suite\n");
    printf("========================================\n\n");

    auto& gpu = rawr::GpuManager::Get();

    TEST("GPU manager initialize", gpu.Initialize());
    TEST("GPU device count > 0", gpu.GetDeviceCount() > 0);

    // Test device enumeration
    auto* firstDev = gpu.GetDevice(0);
    TEST("First device exists", firstDev != nullptr);
    if (firstDev) {
        TEST("Device has name", strlen(firstDev->name.c_str()) > 0);
        TEST("Device is available", firstDev->available);
    }

    // Test best device selection
    int bestIdx = gpu.GetBestDevice();
    TEST("Best device index valid", bestIdx >= 0);

    // Test memory allocation
    auto* block = gpu.Allocate(1024 * 1024, true);  // 1 MB
    TEST("Memory allocation", block != nullptr && block->devicePtr != nullptr);
    TEST("Allocation size", block ? block->size == 1024 * 1024 : false);

    // Test copy operations
    if (block) {
        char testData[] = "RawrXD GPU Test";
        TEST("Copy to device", gpu.CopyToDevice(block, testData, sizeof(testData)));

        char readback[64] = {0};
        TEST("Copy from device", gpu.CopyFromDevice(readback, block, sizeof(testData)));
        TEST("Data integrity", strcmp(readback, testData) == 0);
    }

    // Test stats
    auto stats = gpu.GetStats();
    TEST("Stats device count", stats.deviceCount > 0);
    TEST("Stats allocations", stats.allocations > 0);

    // Test backend detection
    TEST("Has CPU backend", gpu.HasBackend(rawr::GpuBackend::CPU));
    TEST("Set CPU backend", gpu.SetActiveBackend(rawr::GpuBackend::CPU));

    // Cleanup
    if (block) gpu.Free(block);

    printf("\n========================================\n");
    printf("  Results: %d passed, %d failed out of %d\n", g_passed, g_failed, g_passed + g_failed);
    printf("========================================\n");

    gpu.Shutdown();
    return g_failed > 0 ? 1 : 0;
}
