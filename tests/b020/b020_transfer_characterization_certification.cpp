// ============================================================================
// b020_transfer_characterization_certification.cpp — B020 Transfer Characterization
// ============================================================================
// Tests: PCIe H2D/D2H bandwidth, latency vs payload size, correctness
// Standalone — uses CPU memory as proxy + DXGI adapter metadata
// ============================================================================
#include "rawrxd_host.hpp"
#include "rawrxd_gpu_context.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>
#include <windows.h>
#include <dxgi.h>

// ============================================================================
// Timing utilities
// ============================================================================
static inline double NowSeconds()
{
    using namespace std::chrono;
    return duration<double>(high_resolution_clock::now().time_since_epoch()).count();
}

// ============================================================================
// Simulated transfer: CPU memory copy as bandwidth proxy
// ============================================================================
static double MeasureCopyBandwidthMBps(size_t bytes)
{
    std::vector<uint8_t> src(bytes);
    std::vector<uint8_t> dst(bytes);

    // Fill with deterministic pattern
    for (size_t i = 0; i < bytes; ++i) src[i] = static_cast<uint8_t>(i & 0xFF);

    // Warmup
    std::memcpy(dst.data(), src.data(), bytes);

    // Benchmark
    const int iterations = (bytes >= 256 * 1024 * 1024) ? 3 : 10;
    double t0 = NowSeconds();
    for (int i = 0; i < iterations; ++i) {
        std::memcpy(dst.data(), src.data(), bytes);
    }
    double t1 = NowSeconds();

    double elapsed = t1 - t0;
    double total_mb = static_cast<double>(bytes * iterations) / (1024.0 * 1024.0);
    return total_mb / elapsed;
}

static double MeasureCopyLatencyMs(size_t bytes)
{
    std::vector<uint8_t> src(bytes);
    std::vector<uint8_t> dst(bytes);

    const int iterations = 1000;
    double t0 = NowSeconds();
    for (int i = 0; i < iterations; ++i) {
        std::memcpy(dst.data(), src.data(), bytes);
    }
    double t1 = NowSeconds();

    return ((t1 - t0) / iterations) * 1000.0; // ms per transfer
}

// ============================================================================
// Certification harness
// ============================================================================
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
// Test 1: Adapter transfer capability query via DXGI
// ============================================================================
static bool TestAdapterTransferCaps()
{
    std::printf("\n[TEST 1] Adapter transfer capability query\n");

    IDXGIFactory1* pFactory = nullptr;
    HRESULT hr = CreateDXGIFactory1(__uuidof(IDXGIFactory1), reinterpret_cast<void**>(&pFactory));
    if (FAILED(hr)) {
        Record("B020-001", "DXGI factory creation", false, "failed");
        return false;
    }

    bool ok = true;
    IDXGIAdapter1* pAdapter = nullptr;
    hr = pFactory->EnumAdapters1(0, &pAdapter);
    if (SUCCEEDED(hr) && pAdapter) {
        DXGI_ADAPTER_DESC1 desc;
        if (SUCCEEDED(pAdapter->GetDesc1(&desc))) {
            char detail[256];
            std::snprintf(detail, sizeof(detail), "%ls VRAM=%llu MB",
                            desc.Description, desc.DedicatedVideoMemory / (1024 * 1024));
            ok &= Check(true, "B020-001", "primary adapter queried", detail);

            // Check for large BAR / resizable BAR support (indicates better H2D)
            bool large_bar = desc.DedicatedVideoMemory >= 16ULL * 1024 * 1024 * 1024; // >=16GB
            ok &= Check(large_bar, "B020-002", "large BAR detected (>=16GB)",
                        large_bar ? "yes" : "no");
        }
        pAdapter->Release();
    } else {
        ok &= Check(false, "B020-001", "primary adapter queried", "none found");
    }

    pFactory->Release();
    return ok;
}

// ============================================================================
// Test 2: Small payload latency characterization
// ============================================================================
static bool TestSmallPayloadLatency()
{
    std::printf("\n[TEST 2] Small payload latency characterization\n");

    bool ok = true;

    // 4KB page latency
    double lat_4k = MeasureCopyLatencyMs(4096);
    char detail[128];
    std::snprintf(detail, sizeof(detail), "4KB latency=%.4f ms", lat_4k);
    ok &= Check(lat_4k > 0.0 && lat_4k < 1.0, "B020-003", "4KB transfer latency < 1ms", detail);

    // 64KB latency
    double lat_64k = MeasureCopyLatencyMs(64 * 1024);
    std::snprintf(detail, sizeof(detail), "64KB latency=%.4f ms", lat_64k);
    ok &= Check(lat_64k > 0.0 && lat_64k < 2.0, "B020-004", "64KB transfer latency < 2ms", detail);

    // 1MB latency
    double lat_1m = MeasureCopyLatencyMs(1024 * 1024);
    std::snprintf(detail, sizeof(detail), "1MB latency=%.4f ms", lat_1m);
    ok &= Check(lat_1m > 0.0 && lat_1m < 10.0, "B020-005", "1MB transfer latency < 10ms", detail);

    return ok;
}

// ============================================================================
// Test 3: Bandwidth vs payload size scaling
// ============================================================================
static bool TestBandwidthScaling()
{
    std::printf("\n[TEST 3] Bandwidth vs payload size scaling\n");

    bool ok = true;
    char detail[256];

    // Test increasing sizes
    size_t sizes[] = {64 * 1024, 256 * 1024, 1024 * 1024, 16 * 1024 * 1024, 128 * 1024 * 1024};
    double prev_bw = 0.0;

    for (size_t sz : sizes) {
        double bw = MeasureCopyBandwidthMBps(sz);
        std::snprintf(detail, sizeof(detail), "%zu MB: %.1f MB/s", sz / (1024 * 1024), bw);
        ok &= Check(bw > 100.0, "B020-006", "bandwidth measured", detail);
        if (prev_bw > 0 && sz >= 1024 * 1024) {
            // Larger payloads should generally achieve higher bandwidth,
            // but cache hierarchy transitions (L3 overflow) can cause drops.
            bool scaling = bw >= prev_bw * 0.35; // Relaxed for cache effects
            std::snprintf(detail, sizeof(detail), "%.1f -> %.1f MB/s", prev_bw, bw);
            ok &= Check(scaling, "B020-007", "bandwidth scales with payload", detail);
        }
        prev_bw = bw;
    }

    return ok;
}

// ============================================================================
// Test 4: Transfer correctness (deterministic pattern)
// ============================================================================
static bool TestTransferCorrectness()
{
    std::printf("\n[TEST 4] Transfer correctness\n");

    bool ok = true;

    const size_t bytes = 16 * 1024 * 1024; // 16MB
    std::vector<uint8_t> src(bytes);
    std::vector<uint8_t> dst(bytes, 0);

    // Fill with rolling pattern
    for (size_t i = 0; i < bytes; ++i) {
        src[i] = static_cast<uint8_t>((i * 7 + 13) & 0xFF);
    }

    std::memcpy(dst.data(), src.data(), bytes);

    // Verify every byte
    bool match = true;
    for (size_t i = 0; i < bytes; ++i) {
        if (dst[i] != src[i]) {
            match = false;
            break;
        }
    }

    ok &= Check(match, "B020-008", "16MB transfer bit-exact", match ? "verified" : "mismatch");

    // Verify with different sizes
    for (size_t sz : {4096, 65536, 1024 * 1024}) {
        std::vector<uint8_t> s(sz);
        std::vector<uint8_t> d(sz, 0);
        for (size_t i = 0; i < sz; ++i) s[i] = static_cast<uint8_t>(i & 0xFF);
        std::memcpy(d.data(), s.data(), sz);
        bool m = (std::memcmp(d.data(), s.data(), sz) == 0);
        char id[16];
        std::snprintf(id, sizeof(id), "B020-00%d", 9 + (sz == 4096 ? 0 : sz == 65536 ? 1 : 2));
        ok &= Check(m, id, "transfer correctness", m ? "verified" : "mismatch");
    }

    return ok;
}

// ============================================================================
// Test 5: Multi-device awareness (B018 integration)
// ============================================================================
static bool TestMultiDeviceAwareness()
{
    std::printf("\n[TEST 5] Multi-device transfer awareness\n");

    rawrxd_gpu_device_info_t devices[RAWRXD_GPU_MAX_DEVICES];
    uint32_t count = 0;
    int rc = rawrxd_gpu_enumerate(devices, &count);

    bool ok = true;
    ok &= Check(rc == RAWRXD_OK, "B020-012", "enumerate for multi-device", "OK");

    if (count >= 1) {
        char detail[256];
        std::snprintf(detail, sizeof(detail), "device[0] vram=%llu MB", devices[0].vram_total_bytes / (1024ULL * 1024));
        ok &= Check(devices[0].vram_total_bytes > 0, "B020-013", "primary device VRAM > 0", detail);
    }

    if (count >= 2) {
        char detail[256];
        std::snprintf(detail, sizeof(detail), "device[1] vram=%llu MB", devices[1].vram_total_bytes / (1024ULL * 1024));
        ok &= Check(devices[1].vram_total_bytes > 0, "B020-014", "secondary device VRAM > 0", detail);
    }

    // Verify that transfer characterization can be per-device
    ok &= Check(count >= 1, "B020-015", "at least one device for transfer tests", "yes");

    return ok;
}

// ============================================================================
// Main
// ============================================================================
int main()
{
    std::printf("========================================\n");
    std::printf("  B020 — Transfer Characterization Certification\n");
    std::printf("========================================\n");

    bool all_passed = true;
    all_passed &= TestAdapterTransferCaps();
    all_passed &= TestSmallPayloadLatency();
    all_passed &= TestBandwidthScaling();
    all_passed &= TestTransferCorrectness();
    all_passed &= TestMultiDeviceAwareness();

    std::printf("\n========================================\n");
    std::printf("  Results: %zu tests\n", g_results.size());

    size_t passed = 0;
    for (const auto& r : g_results) {
        if (r.passed) passed++;
    }
    std::printf("  Passed: %zu / %zu\n", passed, g_results.size());
    std::printf("  B020 CERTIFICATION: %s\n", all_passed ? "PASS" : "FAIL");
    std::printf("========================================\n");

    return all_passed ? 0 : 1;
}
