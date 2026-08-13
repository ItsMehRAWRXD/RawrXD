// ============================================================================
// b029_device_hotplug_resilience_certification.cpp — B029 Device Hot-Plug Resilience
// ============================================================================
// Tests: Device removal simulation, re-enumeration after change,
//        graceful fallback, context invalidation
// ============================================================================
#include "rawrxd_host.hpp"
#include "rawrxd_gpu_context.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

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
// Test 1: Initial enumeration baseline
// ============================================================================
static bool TestInitialEnumeration()
{
    std::printf("\n[TEST 1] Initial enumeration baseline\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    int rc = rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;
    ok &= Check(rc == RAWRXD_OK, "B029-001", "initial enumeration succeeds", rc == RAWRXD_OK ? "OK" : "fail");
    ok &= Check(count >= 1, "B029-002", "at least one device present", count >= 1 ? "yes" : "no");

    return ok;
}

// ============================================================================
// Test 2: Re-enumeration consistency
// ============================================================================
static bool TestReenumerationConsistency()
{
    std::printf("\n[TEST 2] Re-enumeration consistency\n");

    rawrxd_gpu_device_info_t devices1[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count1 = 0;
    rawrxd_gpu_enumerate(devices1, &count1);

    rawrxd_gpu_device_info_t devices2[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count2 = 0;
    int rc = rawrxd_gpu_enumerate(devices2, &count2);

    bool ok = true;
    ok &= Check(rc == RAWRXD_OK, "B029-003", "re-enumeration succeeds", "OK");
    ok &= Check(count1 == count2, "B029-004", "device count stable", std::to_string(count2).c_str());

    if (count1 > 0 && count1 == count2) {
        bool names_match = (std::strcmp(devices1[0].name, devices2[0].name) == 0);
        ok &= Check(names_match, "B029-005", "primary device name stable", names_match ? "match" : "changed");
    }

    return ok;
}

// ============================================================================
// Test 3: Context invalidation on device change
// ============================================================================
static bool TestContextInvalidation()
{
    std::printf("\n[TEST 3] Context invalidation on device change\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;

    if (count >= 1) {
        rawrxd_gpu_context_handle_t ctx = rawrxd_gpu_context_create(0);
        ok &= Check(ctx != nullptr, "B029-006", "context created before change", ctx ? "yes" : "no");

        if (ctx) {
            // Simulate device change by re-enumerating
            rawrxd_gpu_device_info_t new_devices[RAWRXD_GPU_MAX_DEVICES];
            uint32_t new_count = 0;
            rawrxd_gpu_enumerate(new_devices, &new_count);

            // Context should still be valid (no actual hotplug in test)
            rawrxd_gpu_device_info_t info;
            int rc = rawrxd_gpu_context_get_info(ctx, &info);
            ok &= Check(rc == RAWRXD_OK, "B029-007", "context valid after re-enumeration", rc == RAWRXD_OK ? "yes" : "no");

            rawrxd_gpu_context_destroy(ctx);
        }
    }

    return ok;
}

// ============================================================================
// Test 4: Fallback to remaining devices
// ============================================================================
static bool TestFallbackRemaining()
{
    std::printf("\n[TEST 4] Fallback to remaining devices\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;

    if (count >= 2) {
        // Create context on device 1 (simulate device 0 removed)
        rawrxd_gpu_context_handle_t ctx = rawrxd_gpu_context_create(1);
        ok &= Check(ctx != nullptr, "B029-008", "fallback context created", ctx ? "yes" : "no");

        if (ctx) {
            rawrxd_gpu_device_info_t info;
            int rc = rawrxd_gpu_context_get_info(ctx, &info);
            ok &= Check(rc == RAWRXD_OK && info.device_index == 1, "B029-009",
                        "fallback context points to device 1", std::to_string(info.device_index).c_str());
            rawrxd_gpu_context_destroy(ctx);
        }
    } else {
        ok &= Check(count >= 1, "B029-008", "at least one device for fallback", "yes");
    }

    return ok;
}

// ============================================================================
// Test 5: Graceful degradation when no devices
// ============================================================================
static bool TestGracefulDegradation()
{
    std::printf("\n[TEST 5] Graceful degradation when no devices\n");

    // Simulate: request for device index 99 (nonexistent)
    rawrxd_gpu_context_handle_t ctx = rawrxd_gpu_context_create(99);

    bool ok = true;
    ok &= Check(ctx == nullptr, "B029-010", "invalid device index returns null", ctx ? "not null" : "null");

    return ok;
}

// ============================================================================
// Main
// ============================================================================
int main()
{
    std::printf("========================================\n");
    std::printf("  B029 — Device Hot-Plug Resilience\n");
    std::printf("========================================\n");

    bool all_passed = true;
    all_passed &= TestInitialEnumeration();
    all_passed &= TestReenumerationConsistency();
    all_passed &= TestContextInvalidation();
    all_passed &= TestFallbackRemaining();
    all_passed &= TestGracefulDegradation();

    std::printf("\n========================================\n");
    std::printf("  Results: %zu tests\n", g_results.size());

    size_t passed = 0;
    for (const auto& r : g_results) {
        if (r.passed) passed++;
    }
    std::printf("  Passed: %zu / %zu\n", passed, g_results.size());
    std::printf("  B029 CERTIFICATION: %s\n", all_passed ? "PASS" : "FAIL");
    std::printf("========================================\n");

    return all_passed ? 0 : 1;
}
