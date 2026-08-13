// ============================================================================
// b033_cross_device_telemetry_aggregation_certification.cpp — B033 Telemetry Aggregation
// ============================================================================
// Tests: Per-device telemetry collection, cross-device aggregation,
//        telemetry correctness, peak/average across devices
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <algorithm>
#include <cstdint>

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
// Telemetry structures
// ============================================================================
struct DeviceTelemetry {
    uint32_t device_index;
    uint64_t tokens_generated;
    uint64_t tokens_processed;
    double avg_latency_ms;
    double peak_tps;
    uint64_t residency_hits;
    uint64_t residency_misses;
};

struct AggregatedTelemetry {
    uint64_t total_tokens_generated;
    uint64_t total_tokens_processed;
    double avg_latency_ms;
    double peak_tps;
    uint64_t total_residency_hits;
    uint64_t total_residency_misses;
    double overall_hit_rate;
};

static AggregatedTelemetry Aggregate(const std::vector<DeviceTelemetry>& devices)
{
    AggregatedTelemetry agg{};
    double latency_sum = 0;
    double peak_tps_max = 0;

    for (const auto& dev : devices) {
        agg.total_tokens_generated += dev.tokens_generated;
        agg.total_tokens_processed += dev.tokens_processed;
        latency_sum += dev.avg_latency_ms;
        if (dev.peak_tps > peak_tps_max) peak_tps_max = dev.peak_tps;
        agg.total_residency_hits += dev.residency_hits;
        agg.total_residency_misses += dev.residency_misses;
    }

    agg.avg_latency_ms = devices.empty() ? 0.0 : latency_sum / devices.size();
    agg.peak_tps = peak_tps_max;

    uint64_t total_accesses = agg.total_residency_hits + agg.total_residency_misses;
    agg.overall_hit_rate = (total_accesses > 0) ? static_cast<double>(agg.total_residency_hits) / total_accesses : 0.0;

    return agg;
}

// ============================================================================
// Test 1: Single device aggregation
// ============================================================================
static bool TestSingleDeviceAggregation()
{
    std::printf("\n[TEST 1] Single device aggregation\n");

    std::vector<DeviceTelemetry> devices;
    devices.push_back({0, 100, 50, 10.0, 50.0, 90, 10});

    AggregatedTelemetry agg = Aggregate(devices);

    bool ok = true;
    ok &= Check(agg.total_tokens_generated == 100, "B033-001", "tokens generated aggregated", std::to_string(agg.total_tokens_generated).c_str());
    ok &= Check(agg.total_tokens_processed == 50, "B033-002", "tokens processed aggregated", std::to_string(agg.total_tokens_processed).c_str());
    ok &= Check(agg.avg_latency_ms == 10.0, "B033-003", "avg latency correct", std::to_string(agg.avg_latency_ms).c_str());

    return ok;
}

// ============================================================================
// Test 2: Multi-device aggregation
// ============================================================================
static bool TestMultiDeviceAggregation()
{
    std::printf("\n[TEST 2] Multi-device aggregation\n");

    std::vector<DeviceTelemetry> devices;
    devices.push_back({0, 100, 50, 10.0, 50.0, 90, 10});
    devices.push_back({1, 200, 100, 15.0, 60.0, 180, 20});

    AggregatedTelemetry agg = Aggregate(devices);

    bool ok = true;
    ok &= Check(agg.total_tokens_generated == 300, "B033-004", "total tokens across devices", std::to_string(agg.total_tokens_generated).c_str());
    ok &= Check(agg.total_tokens_processed == 150, "B033-005", "total processed across devices", std::to_string(agg.total_tokens_processed).c_str());
    ok &= Check(agg.avg_latency_ms == 12.5, "B033-006", "average latency correct", std::to_string(agg.avg_latency_ms).c_str());
    ok &= Check(agg.peak_tps == 60.0, "B033-007", "peak TPS is max across devices", std::to_string(agg.peak_tps).c_str());

    return ok;
}

// ============================================================================
// Test 3: Hit rate calculation
// ============================================================================
static bool TestHitRateCalculation()
{
    std::printf("\n[TEST 3] Hit rate calculation\n");

    std::vector<DeviceTelemetry> devices;
    devices.push_back({0, 0, 0, 0.0, 0.0, 80, 20}); // 80% hit rate
    devices.push_back({1, 0, 0, 0.0, 0.0, 90, 10}); // 90% hit rate

    AggregatedTelemetry agg = Aggregate(devices);

    bool ok = true;
    // Overall: (80+90) / (100+100) = 170/200 = 85%
    ok &= Check(agg.overall_hit_rate == 0.85, "B033-008", "overall hit rate correct", std::to_string(agg.overall_hit_rate).c_str());

    return ok;
}

// ============================================================================
// Test 4: Empty aggregation
// ============================================================================
static bool TestEmptyAggregation()
{
    std::printf("\n[TEST 4] Empty aggregation\n");

    std::vector<DeviceTelemetry> devices;
    AggregatedTelemetry agg = Aggregate(devices);

    bool ok = true;
    ok &= Check(agg.total_tokens_generated == 0, "B033-009", "empty aggregation tokens=0", std::to_string(agg.total_tokens_generated).c_str());
    ok &= Check(agg.avg_latency_ms == 0.0, "B033-010", "empty aggregation latency=0", std::to_string(agg.avg_latency_ms).c_str());
    ok &= Check(agg.overall_hit_rate == 0.0, "B033-011", "empty aggregation hit_rate=0", std::to_string(agg.overall_hit_rate).c_str());

    return ok;
}

// ============================================================================
// Test 5: Peak detection across devices
// ============================================================================
static bool TestPeakDetection()
{
    std::printf("\n[TEST 5] Peak detection across devices\n");

    std::vector<DeviceTelemetry> devices;
    devices.push_back({0, 1000, 500, 20.0, 100.0, 100, 0});
    devices.push_back({1, 500, 250, 30.0, 150.0, 50, 0}); // higher peak
    devices.push_back({2, 200, 100, 25.0, 80.0, 20, 0});

    AggregatedTelemetry agg = Aggregate(devices);

    bool ok = true;
    ok &= Check(agg.peak_tps == 150.0, "B033-012", "peak TPS detected correctly", std::to_string(agg.peak_tps).c_str());
    ok &= Check(agg.total_tokens_generated == 1700, "B033-013", "total tokens summed", std::to_string(agg.total_tokens_generated).c_str());

    return ok;
}

// ============================================================================
// Main
// ============================================================================
int main()
{
    std::printf("========================================\n");
    std::printf("  B033 — Cross-Device Telemetry Aggregation\n");
    std::printf("========================================\n");

    bool all_passed = true;
    all_passed &= TestSingleDeviceAggregation();
    all_passed &= TestMultiDeviceAggregation();
    all_passed &= TestHitRateCalculation();
    all_passed &= TestEmptyAggregation();
    all_passed &= TestPeakDetection();

    std::printf("\n========================================\n");
    std::printf("  Results: %zu tests\n", g_results.size());

    size_t passed = 0;
    for (const auto& r : g_results) {
        if (r.passed) passed++;
    }
    std::printf("  Passed: %zu / %zu\n", passed, g_results.size());
    std::printf("  B033 CERTIFICATION: %s\n", all_passed ? "PASS" : "FAIL");
    std::printf("========================================\n");

    return all_passed ? 0 : 1;
}
