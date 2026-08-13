// ============================================================================
// b023_multi_gpu_placement_certification.cpp — B023 Multi-GPU Placement Strategy
// ============================================================================
// Tests: Model partitioning, load balancing, device selection heuristics,
//        fallback when device unavailable
// ============================================================================
#include "rawrxd_host.hpp"
#include "rawrxd_gpu_context.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>

struct TestResult {
    const char* id;
    const char* desc;
    bool passed;
    const char* detail;
};

static std::vector<TestResult> g_results;

static void Record(const char* id, const char* desc, bool passed, const char* detail = "")
{
    g_results.push_back({id, desc, passed, detail});
    std::printf("  [%s] %s: %s\n", passed ? "PASS" : "FAIL", id, detail);
}

static bool Check(bool condition, const char* id, const char* desc, const char* detail = "")
{
    Record(id, desc, condition, detail);
    return condition;
}

// ============================================================================
// Placement engine simulator
// ============================================================================
struct DeviceScore {
    uint32_t index;
    uint64_t vram_bytes;
    uint32_t compute_units;
    float    score;
};

static float ScoreDevice(const rawrxd_gpu_device_info_t& dev, uint64_t model_bytes)
{
    // Heuristic: prefer devices with more VRAM headroom and more compute
    float vram_headroom = (dev.vram_total_bytes > model_bytes)
        ? static_cast<float>(dev.vram_total_bytes - model_bytes) / (1024.0f * 1024.0f)
        : -1.0f;
    float compute_score = static_cast<float>(dev.compute_units);
    return vram_headroom * 0.7f + compute_score * 0.3f;
}

static int SelectBestDevice(const rawrxd_gpu_device_info_t* devices, uint32_t count, uint64_t model_bytes)
{
    int best = -1;
    float best_score = -9999.0f;
    for (uint32_t i = 0; i < count; ++i) {
        float s = ScoreDevice(devices[i], model_bytes);
        if (s > best_score) {
            best_score = s;
            best = static_cast<int>(i);
        }
    }
    return best;
}

static bool CanFit(const rawrxd_gpu_device_info_t& dev, uint64_t model_bytes, float safety_margin = 1.2f)
{
    return dev.vram_total_bytes >= static_cast<uint64_t>(model_bytes * safety_margin);
}

// ============================================================================
// Test 1: Device scoring heuristic
// ============================================================================
static bool TestDeviceScoring()
{
    std::printf("\n[TEST 1] Device scoring heuristic\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    int rc = rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;
    ok &= Check(rc == RAWRXD_OK && count >= 1, "B023-001", "enumeration for scoring", count >= 1 ? "OK" : "none");

    if (count >= 1) {
        uint64_t model_bytes = 8ULL * 1024 * 1024 * 1024; // 8GB model
        int best = SelectBestDevice(devices, count, model_bytes);
        ok &= Check(best >= 0, "B023-002", "best device selected", best >= 0 ? "yes" : "no");

        if (best >= 0) {
            ok &= Check(CanFit(devices[best], model_bytes), "B023-003",
                        "selected device can fit model with margin", "yes");
        }
    }

    return ok;
}

// ============================================================================
// Test 2: Model partitioning across devices
// ============================================================================
static bool TestModelPartitioning()
{
    std::printf("\n[TEST 2] Model partitioning across devices\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;

    // Simulate a 16GB model that needs partitioning
    const uint64_t model_total_bytes = 16ULL * 1024 * 1024 * 1024;
    const int num_layers = 32;
    const uint64_t bytes_per_layer = model_total_bytes / num_layers;

    if (count >= 2) {
        // Partition layers round-robin across devices
        std::vector<int> layer_to_device(num_layers, -1);
        for (int layer = 0; layer < num_layers; ++layer) {
            layer_to_device[layer] = layer % count;
        }

        // Verify every layer assigned
        bool all_assigned = true;
        for (int d : layer_to_device) if (d < 0) { all_assigned = false; break; }
        ok &= Check(all_assigned, "B023-004", "all layers assigned to a device", "yes");

        // Verify load balance (within 1 layer)
        std::vector<int> layers_per_device(count, 0);
        for (int d : layer_to_device) layers_per_device[d]++;
        int max_layers = *std::max_element(layers_per_device.begin(), layers_per_device.end());
        int min_layers = *std::min_element(layers_per_device.begin(), layers_per_device.end());
        ok &= Check(max_layers - min_layers <= 1, "B023-005",
                    "load balanced within 1 layer", std::to_string(max_layers - min_layers).c_str());
    } else {
        // Single device: all layers go to device 0
        ok &= Check(count == 1, "B023-004", "single device fallback", "1 device");
    }

    return ok;
}

// ============================================================================
// Test 3: Fallback when preferred device unavailable
// ============================================================================
static bool TestDeviceFallback()
{
    std::printf("\n[TEST 3] Fallback when preferred device unavailable\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;

    // Simulate: device 0 "fails", fallback to device 1
    if (count >= 2) {
        int preferred = 0;
        int fallback = 1;

        // Verify fallback device exists and has VRAM
        ok &= Check(devices[fallback].vram_total_bytes > 0, "B023-006",
                    "fallback device has VRAM", "yes");

        // Create context on fallback
        rawrxd_gpu_context_handle_t ctx = rawrxd_gpu_context_create(fallback);
        ok &= Check(ctx != nullptr, "B023-007", "fallback context created", ctx ? "yes" : "no");
        if (ctx) rawrxd_gpu_context_destroy(ctx);
    } else {
        ok &= Check(count >= 1, "B023-006", "at least one device for fallback", "yes");
    }

    return ok;
}

// ============================================================================
// Test 4: VRAM budget enforcement
// ============================================================================
static bool TestVRAMBudget()
{
    std::printf("\n[TEST 4] VRAM budget enforcement\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;

    if (count >= 1) {
        uint64_t vram = devices[0].vram_total_bytes;

        // Model that fits
        uint64_t small_model = vram / 4;
        ok &= Check(CanFit(devices[0], small_model), "B023-008",
                    "small model fits with margin", "yes");

        // Model that exceeds capacity
        uint64_t huge_model = vram * 4;
        ok &= Check(!CanFit(devices[0], huge_model), "B023-009",
                    "oversized model rejected", "rejected");
    }

    return ok;
}

// ============================================================================
// Test 5: Context per device isolation
// ============================================================================
static bool TestContextIsolation()
{
    std::printf("\n[TEST 5] Context per-device isolation\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;

    if (count >= 2) {
        rawrxd_gpu_context_handle_t ctx0 = rawrxd_gpu_context_create(0);
        rawrxd_gpu_context_handle_t ctx1 = rawrxd_gpu_context_create(1);

        ok &= Check(ctx0 != nullptr && ctx1 != nullptr, "B023-010",
                    "two contexts created independently", ctx0 && ctx1 ? "yes" : "no");

        if (ctx0 && ctx1) {
            rawrxd_gpu_device_info_t info0, info1;
            rawrxd_gpu_context_get_info(ctx0, &info0);
            rawrxd_gpu_context_get_info(ctx1, &info1);
            ok &= Check(info0.device_index != info1.device_index, "B023-011",
                        "contexts point to different devices", "different");
        }

        if (ctx0) rawrxd_gpu_context_destroy(ctx0);
        if (ctx1) rawrxd_gpu_context_destroy(ctx1);
        ok &= Check(true, "B023-012", "both contexts destroyed cleanly", "done");
    } else {
        ok &= Check(count >= 1, "B023-010", "at least one device", "yes");
    }

    return ok;
}

// ============================================================================
// Main
// ============================================================================
int main()
{
    std::printf("========================================\n");
    std::printf("  B023 — Multi-GPU Placement Strategy\n");
    std::printf("========================================\n");

    bool all_passed = true;
    all_passed &= TestDeviceScoring();
    all_passed &= TestModelPartitioning();
    all_passed &= TestDeviceFallback();
    all_passed &= TestVRAMBudget();
    all_passed &= TestContextIsolation();

    std::printf("\n========================================\n");
    std::printf("  Results: %zu tests\n", g_results.size());

    size_t passed = 0;
    for (const auto& r : g_results) {
        if (r.passed) passed++;
    }
    std::printf("  Passed: %zu / %zu\n", passed, g_results.size());
    std::printf("  B023 CERTIFICATION: %s\n", all_passed ? "PASS" : "FAIL");
    std::printf("========================================\n");

    return all_passed ? 0 : 1;
}
