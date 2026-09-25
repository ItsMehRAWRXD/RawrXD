// ============================================================================
// test_device_fault_recovery.cpp
// Exercises VulkanCompute device-lost recovery via cleanup()+initialize().
//
// Recovery model in Deep2:
//   VulkanCompute::cleanup()    — destroys all Vulkan handles
//   VulkanCompute::initialize() — re-creates instance, device, pipelines
//
// There is no synthetic fault injection API in VulkanCompute; the test
// simulates the recovery sequence directly by calling cleanup() then
// initialize() and verifying the pipeline is operational afterwards via
// RunComputeProbe.
// ============================================================================
#include <iostream>
#include <vector>
#include <cstdlib>

#include "../src/deep2/vulkan_compute.h"

static bool run_probe(Deep2::VulkanCompute& gpu, const char* label)
{
    constexpr size_t kElements = 256;
    std::vector<float> out(kElements, 0.0f);
    const bool ok = gpu.RunComputeProbe(kElements, 1.0f, 0.0f, &out);
    std::cout << "[" << label << "] RunComputeProbe(" << kElements
              << " elems): " << (ok ? "PASS" : "FAIL") << "\n";
    return ok;
}

int main()
{
    std::cout << "=========================================================\n"
              << "   RAWRXD VULKAN DEVICE LOST RECOVERY TEST HARNESS\n"
              << "=========================================================\n";

    // ---- Phase 1: initial init ----
    Deep2::VulkanCompute gpu(0);
    if (!gpu.initialize()) {
        std::cerr << "[FAIL] VulkanCompute::initialize() failed on first call.\n";
        return 1;
    }
    std::cout << "[+] Phase 1: VulkanCompute initialized.\n"
              << "    Device : " << gpu.physicalInfo().name << "\n"
              << "    VRAM   : " << gpu.deviceLocalBytes() / (1024*1024) << " MB\n"
              << "    Compute: " << (gpu.computeReady()     ? "YES" : "NO") << "\n"
              << "    Quant  : " << (gpu.quantComputeReady()? "YES" : "NO") << "\n";

    if (!run_probe(gpu, "pre-recovery"))
        return 1;

    // ---- Phase 2: simulate device lost via cleanup() ----
    std::cout << "\n[*] Phase 2: Simulating device lost (cleanup)...\n";
    gpu.cleanup();
    std::cout << "    initialized() after cleanup: "
              << (gpu.initialized() ? "true (unexpected)" : "false (correct)") << "\n";
    if (gpu.initialized()) {
        std::cerr << "[FAIL] initialized() should be false after cleanup().\n";
        return 1;
    }

    // ---- Phase 3: recovery — re-initialize ----
    std::cout << "\n[*] Phase 3: Executing recovery (re-initialize)...\n";
    if (!gpu.initialize()) {
        std::cerr << "[FAIL] VulkanCompute::initialize() failed on recovery call.\n";
        return 1;
    }
    std::cout << "[+] Phase 3: VulkanCompute re-initialized.\n"
              << "    Compute: " << (gpu.computeReady()     ? "YES" : "NO") << "\n"
              << "    Quant  : " << (gpu.quantComputeReady()? "YES" : "NO") << "\n";

    if (!gpu.computeReady()) {
        std::cerr << "[FAIL] Compute pipeline not ready after recovery.\n";
        return 1;
    }

    // ---- Phase 4: post-recovery verification ----
    std::cout << "\n[*] Phase 4: Post-recovery compute verification...\n";
    if (!run_probe(gpu, "post-recovery"))
        return 1;

    // ---- Phase 5: second cleanup/reinit cycle ----
    std::cout << "\n[*] Phase 5: Second cleanup/reinit cycle (stability check)...\n";
    gpu.cleanup();
    if (!gpu.initialize()) {
        std::cerr << "[FAIL] VulkanCompute::initialize() failed on second recovery.\n";
        return 1;
    }
    if (!run_probe(gpu, "second-recovery"))
        return 1;

    gpu.cleanup();

    std::cout << "\n=========================================================\n"
              << "  VERDICT: PASS — device recovery sequence stable\n"
              << "=========================================================\n";
    return 0;
}
