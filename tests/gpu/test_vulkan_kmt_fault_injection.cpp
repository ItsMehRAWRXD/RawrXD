// ============================================================================
// test_vulkan_kmt_fault_injection.cpp
// Negative-test harness for VulkanCompute::ImportBufferKMT guards.
//
// Goals:
//   1. Initialize a VulkanCompute context on the default GPU.
//   2. Feed ImportBufferKMT a series of malformed / adversarial inputs.
//   3. Verify every bad input returns false without crashing, TDR, or AV.
//   4. (Optional) Run a valid export→import round-trip to prove the path
//      still works when given correct inputs.
//
// Build (inside d:\rawrxd\tests\gpu):
//   cmake --build . --target vulkan_kmt_fault_injection
// Run:
//   .\vulkan_kmt_fault_injection.exe
// ============================================================================

#include <vulkan/vulkan.h>
#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <string>

// Pull in the production implementation we want to harden.
#include "../../src/vulkan_compute.h"

// ---------------------------------------------------------------------------
// Minimal test scaffolding (no external test framework)
// ---------------------------------------------------------------------------
static int g_pass = 0;
static int g_fail = 0;

static void check(bool condition, const char* expr, const char* file, int line) {
    if (condition) {
        ++g_pass;
        std::printf("  [PASS] %s (%s:%d)\n", expr, file, line);
    } else {
        ++g_fail;
        std::printf("  [FAIL] %s (%s:%d)\n", expr, file, line);
    }
}
#define REQUIRE(expr) check((expr), #expr, __FILE__, __LINE__)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static HANDLE createDummyFileHandle() {
    // Create a real kernel handle, but of the wrong type (file instead of KMT).
    HANDLE h = CreateFileA(
        "NUL", GENERIC_READ, FILE_SHARE_READ, nullptr,
        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr);
    return h; // may be INVALID_HANDLE_VALUE, which is fine for the test
}

// ---------------------------------------------------------------------------
// Test cases
// ---------------------------------------------------------------------------
static void test_null_device() {
    std::printf("\n[TEST] ImportBufferKMT with null device\n");
    // A default-constructed VulkanCompute has device_ == nullptr.
    VulkanCompute vc;
    uint32_t idx = UINT32_MAX;
    HANDLE dummy = reinterpret_cast<HANDLE>(0x1234);
    bool rc = vc.ImportBufferKMT(dummy, 1024, idx);
    REQUIRE(rc == false);
    REQUIRE(idx == UINT32_MAX);
}

static void test_null_handle() {
    std::printf("\n[TEST] ImportBufferKMT with null handle (after init)\n");
    VulkanCompute vc;
    if (!vc.Initialize()) {
        std::printf("  [SKIP] No Vulkan device available\n");
        return;
    }
    uint32_t idx = UINT32_MAX;
    bool rc = vc.ImportBufferKMT(nullptr, 1024, idx);
    REQUIRE(rc == false);
    REQUIRE(idx == UINT32_MAX);
}

static void test_invalid_handle_value() {
    std::printf("\n[TEST] ImportBufferKMT with INVALID_HANDLE_VALUE\n");
    VulkanCompute vc;
    if (!vc.Initialize()) {
        std::printf("  [SKIP] No Vulkan device available\n");
        return;
    }
    uint32_t idx = UINT32_MAX;
    bool rc = vc.ImportBufferKMT(INVALID_HANDLE_VALUE, 1024, idx);
    REQUIRE(rc == false);
    REQUIRE(idx == UINT32_MAX);
}

static void test_zero_size() {
    std::printf("\n[TEST] ImportBufferKMT with size == 0\n");
    VulkanCompute vc;
    if (!vc.Initialize()) {
        std::printf("  [SKIP] No Vulkan device available\n");
        return;
    }
    uint32_t idx = UINT32_MAX;
    HANDLE dummy = reinterpret_cast<HANDLE>(0x1234);
    bool rc = vc.ImportBufferKMT(dummy, 0, idx);
    REQUIRE(rc == false);
    REQUIRE(idx == UINT32_MAX);
}

static void test_wrong_handle_type() {
    std::printf("\n[TEST] ImportBufferKMT with wrong handle type (file handle)\n");
    VulkanCompute vc;
    if (!vc.Initialize()) {
        std::printf("  [SKIP] No Vulkan device available\n");
        return;
    }
    HANDLE hFile = createDummyFileHandle();
    if (hFile == INVALID_HANDLE_VALUE) {
        std::printf("  [SKIP] Could not create dummy file handle\n");
        return;
    }
    uint32_t idx = UINT32_MAX;
    bool rc = vc.ImportBufferKMT(hFile, 1024, idx);
    CloseHandle(hFile);
    REQUIRE(rc == false);
    REQUIRE(idx == UINT32_MAX);
}

static void test_valid_round_trip() {
    std::printf("\n[TEST] Valid export→import round-trip\n");
    VulkanCompute vc;
    if (!vc.Initialize()) {
        std::printf("  [SKIP] No Vulkan device available\n");
        return;
    }

    // Create an exportable buffer.
    uint32_t src_idx = UINT32_MAX;
    size_t mem_size = 0;
    if (!vc.AllocateBuffer(1024, src_idx, mem_size, true)) {
        std::printf("  [SKIP] Failed to create source buffer\n");
        return;
    }

    HANDLE kmt = nullptr;
    if (!vc.ExportBufferKMT(src_idx, kmt)) {
        std::printf("  [SKIP] Failed to export KMT handle\n");
        return;
    }

    uint32_t dst_idx = UINT32_MAX;
    bool rc = vc.ImportBufferKMT(kmt, 1024, dst_idx);
    REQUIRE(rc == true);
    REQUIRE(dst_idx != UINT32_MAX);
    REQUIRE(dst_idx != src_idx);

    REQUIRE(vc.GetActiveImportCount() == 1);
    REQUIRE(vc.ReleaseImportedBufferKMT(dst_idx) == true);
    REQUIRE(vc.GetActiveImportCount() == 0);

    // Cleanup is handled by VulkanCompute destructor.
}

// ---------------------------------------------------------------------------
// Entry point
// ---------------------------------------------------------------------------
int main(int, char**) {
    std::printf("=================================================================\n");
    std::printf("Vulkan KMT Fault-Injection Harness\n");
    std::printf("=================================================================\n");

    test_null_device();
    test_null_handle();
    test_invalid_handle_value();
    test_zero_size();
    test_wrong_handle_type();
    test_valid_round_trip();

    std::printf("\n=================================================================\n");
    std::printf("Results: %d passed, %d failed\n", g_pass, g_fail);
    std::printf("=================================================================\n");

    return g_fail > 0 ? 1 : 0;
}
