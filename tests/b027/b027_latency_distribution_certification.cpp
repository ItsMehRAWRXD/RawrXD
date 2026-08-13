// ============================================================================
// b027_latency_distribution_certification.cpp — B027 Latency Distribution
// ============================================================================
// Tests: P50/P90/P99 latency percentiles, tail latency detection,
//        jitter measurement, latency histogram correctness
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <chrono>
#include <algorithm>
#include <cmath>
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

static inline double NowMs()
{
    using namespace std::chrono;
    return duration<double, std::milli>(high_resolution_clock::now().time_since_epoch()).count();
}

// ============================================================================
// Latency statistics calculator
// ============================================================================
struct LatencyStats {
    double p50;
    double p90;
    double p99;
    double min_val;
    double max_val;
    double mean;
    double stddev;
};

static LatencyStats CalculateStats(std::vector<double> latencies)
{
    std::sort(latencies.begin(), latencies.end());
    LatencyStats stats{};
    stats.min_val = latencies.front();
    stats.max_val = latencies.back();

    double sum = 0;
    for (double v : latencies) sum += v;
    stats.mean = sum / latencies.size();

    double sq_sum = 0;
    for (double v : latencies) sq_sum += (v - stats.mean) * (v - stats.mean);
    stats.stddev = std::sqrt(sq_sum / latencies.size());

    auto percentile = [&](double p) {
        size_t idx = static_cast<size_t>(std::ceil(p / 100.0 * latencies.size()) - 1);
        if (idx >= latencies.size()) idx = latencies.size() - 1;
        return latencies[idx];
    };

    stats.p50 = percentile(50.0);
    stats.p90 = percentile(90.0);
    stats.p99 = percentile(99.0);

    return stats;
}

// ============================================================================
// Test 1: Percentile ordering
// ============================================================================
static bool TestPercentileOrdering()
{
    std::printf("\n[TEST 1] Percentile ordering\n");

    std::vector<double> latencies;
    for (int i = 0; i < 100; ++i) latencies.push_back(static_cast<double>(i)); // 0..99

    LatencyStats stats = CalculateStats(latencies);

    bool ok = true;
    ok &= Check(stats.p50 >= stats.min_val && stats.p50 <= stats.max_val, "B027-001",
                "P50 in range", std::to_string(stats.p50).c_str());
    ok &= Check(stats.p90 >= stats.p50, "B027-002", "P90 >= P50", std::to_string(stats.p90).c_str());
    ok &= Check(stats.p99 >= stats.p90, "B027-003", "P99 >= P90", std::to_string(stats.p99).c_str());

    return ok;
}

// ============================================================================
// Test 2: Tail latency detection
// ============================================================================
static bool TestTailLatencyDetection()
{
    std::printf("\n[TEST 2] Tail latency detection\n");

    std::vector<double> latencies;
    // Mostly fast
    for (int i = 0; i < 80; ++i) latencies.push_back(10.0);
    // Some slow tail
    for (int i = 0; i < 20; ++i) latencies.push_back(100.0);

    LatencyStats stats = CalculateStats(latencies);

    bool ok = true;
    ok &= Check(stats.p90 >= 50.0, "B027-004", "P90 detects tail", std::to_string(stats.p90).c_str());
    ok &= Check(stats.p99 >= 90.0, "B027-005", "P99 captures worst tail", std::to_string(stats.p99).c_str());

    return ok;
}

// ============================================================================
// Test 3: Jitter measurement
// ============================================================================
static bool TestJitterMeasurement()
{
    std::printf("\n[TEST 3] Jitter measurement\n");

    std::vector<double> latencies;
    // Variable latencies
    for (int i = 0; i < 50; ++i) latencies.push_back(10.0 + (i % 5) * 2.0);

    LatencyStats stats = CalculateStats(latencies);

    bool ok = true;
    ok &= Check(stats.stddev > 0, "B027-006", "stddev positive", std::to_string(stats.stddev).c_str());

    // Low jitter set
    std::vector<double> low_jitter(50, 10.0);
    LatencyStats low_stats = CalculateStats(low_jitter);
    ok &= Check(low_stats.stddev < stats.stddev, "B027-007",
                "low jitter has lower stddev", std::to_string(low_stats.stddev).c_str());

    return ok;
}

// ============================================================================
// Test 4: Histogram correctness
// ============================================================================
static bool TestHistogramCorrectness()
{
    std::printf("\n[TEST 4] Histogram correctness\n");

    std::vector<double> latencies;
    for (int i = 0; i < 100; ++i) latencies.push_back(static_cast<double>(i * 10)); // 0..990

    // Bucket into 10 bins
    std::vector<int> bins(10, 0);
    double max_val = 1000.0;
    for (double v : latencies) {
        int bin = static_cast<int>(v / max_val * bins.size());
        if (bin >= static_cast<int>(bins.size())) bin = bins.size() - 1;
        bins[bin]++;
    }

    bool ok = true;
    int total = 0;
    for (int b : bins) total += b;
    ok &= Check(total == 100, "B027-008", "histogram counts all samples", std::to_string(total).c_str());

    // First bin should have most samples (0-99)
    ok &= Check(bins[0] > 0, "B027-009", "first bin populated", std::to_string(bins[0]).c_str());

    return ok;
}

// ============================================================================
// Test 5: Latency regression detection
// ============================================================================
static bool TestLatencyRegression()
{
    std::printf("\n[TEST 5] Latency regression detection\n");

    // Baseline: P50 = 10ms
    std::vector<double> baseline;
    for (int i = 0; i < 100; ++i) baseline.push_back(10.0);
    LatencyStats base_stats = CalculateStats(baseline);

    // Regression: P50 = 20ms
    std::vector<double> regression;
    for (int i = 0; i < 100; ++i) regression.push_back(20.0);
    LatencyStats reg_stats = CalculateStats(regression);

    bool ok = true;
    ok &= Check(reg_stats.p50 > base_stats.p50, "B027-010",
                "regression P50 higher than baseline", std::to_string(reg_stats.p50).c_str());
    ok &= Check(reg_stats.mean > base_stats.mean * 1.5, "B027-011",
                "regression mean significantly higher", std::to_string(reg_stats.mean).c_str());

    return ok;
}

// ============================================================================
// Main
// ============================================================================
int main()
{
    std::printf("========================================\n");
    std::printf("  B027 — Latency Distribution Certification\n");
    std::printf("========================================\n");

    bool all_passed = true;
    all_passed &= TestPercentileOrdering();
    all_passed &= TestTailLatencyDetection();
    all_passed &= TestJitterMeasurement();
    all_passed &= TestHistogramCorrectness();
    all_passed &= TestLatencyRegression();

    std::printf("\n========================================\n");
    std::printf("  Results: %zu tests\n", g_results.size());

    size_t passed = 0;
    for (const auto& r : g_results) {
        if (r.passed) passed++;
    }
    std::printf("  Passed: %zu / %zu\n", passed, g_results.size());
    std::printf("  B027 CERTIFICATION: %s\n", all_passed ? "PASS" : "FAIL");
    std::printf("========================================\n");

    return all_passed ? 0 : 1;
}
