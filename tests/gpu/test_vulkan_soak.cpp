// ============================================================================
// test_vulkan_soak.cpp
// Soak harness for VulkanCompute KMT import/release lifecycle.
//
// Build:
//   cmake --build d:\rawrxd\build_win32ide --config Release --target RawrXD-VulkanKMTSoak
// Run:
//   d:\rawrxd\build_win32ide\tests\RawrXD-VulkanKMTSoak.exe [iterations]
// ============================================================================

#include "../../src/vulkan_compute.h"

#include <windows.h>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <limits>
#include <string>

static void fail(const char* message) {
    std::fprintf(stderr, "FATAL: %s\n", message);
    std::exit(1);
}

int main(int argc, char** argv) {
    int iterations = 1000;
    if (argc > 1) {
        iterations = std::atoi(argv[1]);
        if (iterations <= 0) {
            fail("iterations must be positive");
        }
    }

    std::printf("=================================================================\n");
    std::printf("Vulkan KMT Soak Harness\n");
    std::printf("iterations=%d\n", iterations);
    std::printf("=================================================================\n");

    VulkanCompute engine;
    if (!engine.Initialize()) {
        fail("failed to initialize VulkanCompute");
    }

    uint32_t source_buffer_idx = UINT32_MAX;
    size_t memory_size = 0;
    if (!engine.AllocateBuffer(1024, source_buffer_idx, memory_size, true)) {
        fail("failed to allocate exportable source buffer");
    }

    HANDLE exported_handle = nullptr;
    if (!engine.ExportBufferKMT(source_buffer_idx, exported_handle)) {
        fail("failed to export KMT handle");
    }

    int64_t high_water_mark = 0;
    for (int iteration = 0; iteration < iterations; ++iteration) {
        uint32_t imported_buffer_idx = UINT32_MAX;
        if (!engine.ImportBufferKMT(exported_handle, 1024, imported_buffer_idx)) {
            std::fprintf(stderr, "ImportBufferKMT failed on iteration %d\n", iteration);
            return 1;
        }

        const int64_t active_after_import = engine.GetActiveImportCount();
        if (active_after_import > high_water_mark) {
            high_water_mark = active_after_import;
        }
        if (active_after_import <= 0) {
            fail("active import count did not increase after import");
        }

        if (!engine.ReleaseImportedBufferKMT(imported_buffer_idx)) {
            std::fprintf(stderr, "ReleaseImportedBufferKMT failed on iteration %d\n", iteration);
            return 1;
        }

        const int64_t active_after_release = engine.GetActiveImportCount();
        if (active_after_release != 0) {
            std::fprintf(stderr, "active import count not zero after iteration %d: %lld\n",
                         iteration, static_cast<long long>(active_after_release));
            return 1;
        }
    }

    std::printf("High-water mark: %lld active import(s)\n", static_cast<long long>(high_water_mark));
    std::printf("Final active import count: %lld\n", static_cast<long long>(engine.GetActiveImportCount()));
    std::printf("Soak test passed: net-zero import lifecycle confirmed.\n");
    return 0;
}
