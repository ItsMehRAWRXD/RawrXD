// ============================================================================
// test_vulkan_validation_tax.cpp
// Benchmark the overhead of the KMT import/release validation guards.
//
// Build:
//   cmake --build d:\rawrxd\build_win32ide --config Release --target RawrXD-VulkanValidationTax
// Run:
//   d:\rawrxd\build_win32ide\tests\RawrXD-VulkanValidationTax.exe [iterations]
// ============================================================================

#include "../../src/vulkan_compute.h"

#include <windows.h>
#include <chrono>
#include <cstdio>
#include <cstdlib>
#include <cstdint>
#include <string>

static void setGuardMode(bool enabled) {
    if (enabled) {
        SetEnvironmentVariableA("RAWRXD_VULKAN_IMPORT_GUARDS_OFF", nullptr);
    } else {
        SetEnvironmentVariableA("RAWRXD_VULKAN_IMPORT_GUARDS_OFF", "1");
    }
}

struct PhaseResult {
    const char* label;
    double total_ms = 0.0;
    double per_iter_us = 0.0;
    int64_t active_imports = 0;
};

static void printBreadcrumbState(const char* label) {
    const volatile uint32_t* breadcrumb_addr = RawrXD_GetVulkanTraceBreadcrumbAddress();
    const uint32_t breadcrumb_value = RawrXD_GetVulkanTraceBreadcrumb();
    const unsigned long long breadcrumb_addr_hex =
        static_cast<unsigned long long>(reinterpret_cast<std::uintptr_t>(breadcrumb_addr));
    std::printf("[%s] breadcrumb_addr=0x%llX breadcrumb_value=0x%08X\n",
                label,
                breadcrumb_addr_hex,
                breadcrumb_value);
}

static PhaseResult runPhase(const char* label, bool guardsEnabled, int iterations) {
    setGuardMode(guardsEnabled);
    RawrXD_SetVulkanTraceBreadcrumb(0);

    std::printf("[%s] begin\n", label);
    std::fflush(stdout);

    PhaseResult result{};
    VulkanCompute* engine = new VulkanCompute();
    if (!engine->Initialize()) {
        std::fprintf(stderr, "FATAL: failed to initialize VulkanCompute for %s phase\n", label);
        std::exit(1);
    }
    RawrXD_SetVulkanTraceBreadcrumb(0x110);

    uint32_t source_buffer_idx = UINT32_MAX;
    size_t memory_size = 0;
    if (!engine->AllocateBuffer(1024, source_buffer_idx, memory_size, true)) {
        std::fprintf(stderr, "FATAL: failed to allocate exportable source buffer for %s phase\n", label);
        std::exit(1);
    }
    RawrXD_SetVulkanTraceBreadcrumb(0x120);

    HANDLE exported_handle = nullptr;
    if (!engine->ExportBufferKMT(source_buffer_idx, exported_handle)) {
        std::fprintf(stderr, "FATAL: failed to export KMT handle for %s phase\n", label);
        std::exit(1);
    }
    RawrXD_SetVulkanTraceBreadcrumb(0x130);

    auto start = std::chrono::steady_clock::now();
    for (int iteration = 0; iteration < iterations; ++iteration) {
        if (iteration == 0) {
            RawrXD_SetVulkanTraceBreadcrumb(0x200);
        } else if (iteration < 8) {
            RawrXD_SetVulkanTraceBreadcrumb(0x200 + static_cast<uint32_t>(iteration));
            std::printf("[%s] iter=%d breadcrumb=0x%08X\n",
                        label,
                        iteration,
                        RawrXD_GetVulkanTraceBreadcrumb());
            std::fflush(stdout);
        } else if ((iteration % 1000) == 0) {
            RawrXD_SetVulkanTraceBreadcrumb(0x300 + static_cast<uint32_t>(iteration / 1000));
            std::printf("[%s] progress=%d breadcrumb=0x%08X\n",
                        label,
                        iteration,
                        RawrXD_GetVulkanTraceBreadcrumb());
            std::fflush(stdout);
        }
        RawrXD_SetVulkanTraceBreadcrumb(0x210);
        std::fprintf(stderr, "[TRACE] %s iteration=%d before ImportBufferKMT breadcrumb=0x%08X\n",
                     label,
                     iteration,
                     RawrXD_GetVulkanTraceBreadcrumb());
        std::fflush(stderr);
        uint32_t imported_buffer_idx = UINT32_MAX;
        if (!engine->ImportBufferKMT(exported_handle, 1024, imported_buffer_idx)) {
            std::fprintf(stderr, "FATAL: ImportBufferKMT failed during %s phase at iteration %d\n", label, iteration);
            std::exit(1);
        }
        RawrXD_SetVulkanTraceBreadcrumb(0x220);
        std::fprintf(stderr, "[TRACE] %s iteration=%d before ReleaseImportedBufferKMT breadcrumb=0x%08X\n",
                     label,
                     iteration,
                     RawrXD_GetVulkanTraceBreadcrumb());
        std::fflush(stderr);
        if (!engine->ReleaseImportedBufferKMT(imported_buffer_idx)) {
            std::fprintf(stderr, "FATAL: ReleaseImportedBufferKMT failed during %s phase at iteration %d\n", label, iteration);
            std::exit(1);
        }
        RawrXD_SetVulkanTraceBreadcrumb(0x230);
    }
    auto end = std::chrono::steady_clock::now();
    RawrXD_SetVulkanTraceBreadcrumb(0x2F);

    const double total_ms = std::chrono::duration_cast<std::chrono::duration<double, std::milli>>(end - start).count();
    result.label = label;
    result.total_ms = total_ms;
    result.per_iter_us = (total_ms * 1000.0) / static_cast<double>(iterations);
    result.active_imports = engine->GetActiveImportCount();

    // Emit the completed phase summary before Cleanup() runs so a late teardown fault
    // does not hide the timing and breadcrumb state.
    RawrXD_SetVulkanTraceBreadcrumb(0x2F);
    std::printf("[%s] end\n", label);
    printBreadcrumbState(label);
    std::printf("%s:  total=%.3f ms  per-iter=%.3f us  active-imports=%lld\n",
                result.label, result.total_ms, result.per_iter_us,
                static_cast<long long>(result.active_imports));
    std::fflush(stdout);
    std::fflush(stderr);
    // Intentionally leak the VulkanCompute instance here. The benchmark is only
    // interested in the import/release path cost; teardown noise is measured separately.
    (void)engine;
    return result;
}

int main(int argc, char** argv) {
    int iterations = 1000;
    const char* mode = "full";

    for (int i = 1; i < argc; ++i) {
        const char* arg = argv[i];
        if (std::strcmp(arg, "--iterations") == 0 && i + 1 < argc) {
            iterations = std::atoi(argv[++i]);
            continue;
        }
        if (std::strncmp(arg, "--iterations=", 13) == 0) {
            iterations = std::atoi(arg + 13);
            continue;
        }
        if (std::strncmp(arg, "--mode=", 7) == 0) {
            mode = arg + 7;
            continue;
        }
        if (std::strcmp(arg, "--mode") == 0 && i + 1 < argc) {
            mode = argv[++i];
            continue;
        }
        if (arg[0] != '-' && i == 1) {
            iterations = std::atoi(arg);
            continue;
        }
        std::fprintf(stderr, "FATAL: unknown argument: %s\n", arg);
        return 1;
    }

    if (iterations <= 0) {
        std::fprintf(stderr, "FATAL: iterations must be positive\n");
        return 1;
    }

    if (std::strcmp(mode, "full") != 0 && std::strcmp(mode, "guards-on") != 0 && std::strcmp(mode, "guards-off") != 0) {
        std::fprintf(stderr, "FATAL: unsupported mode: %s\n", mode);
        return 1;
    }

    std::printf("=================================================================\n");
    std::printf("Vulkan KMT Validation Tax Benchmark\n");
    std::printf("iterations=%d\n", iterations);
    std::printf("mode=%s\n", mode);
    std::printf("=================================================================\n");

    if (std::strcmp(mode, "guards-on") == 0) {
        (void)runPhase("guards-on", true, iterations);
        std::printf("===============================================================\n");
        std::fflush(stdout);
        std::fflush(stderr);
        return 0;
    }

    if (std::strcmp(mode, "guards-off") == 0) {
        (void)runPhase("guards-off", false, iterations);
        std::printf("===============================================================\n");
        std::fflush(stdout);
        std::fflush(stderr);
        return 0;
    }

    PhaseResult enabled = runPhase("guards-on", true, iterations);
    PhaseResult disabled = runPhase("guards-off", false, iterations);

    const double delta_us = enabled.per_iter_us - disabled.per_iter_us;
    const double delta_pct = disabled.per_iter_us > 0.0 ? (delta_us / disabled.per_iter_us) * 100.0 : 0.0;

    std::printf("Validation tax: %.3f us/iter (%.2f%% vs guards-off)\n", delta_us, delta_pct);
    std::printf("===============================================================\n");
    std::fflush(stdout);
    std::fflush(stderr);

    return 0;
}
