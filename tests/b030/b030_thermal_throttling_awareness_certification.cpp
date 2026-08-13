// ============================================================================
// b030_thermal_throttling_awareness_certification.cpp — B030 Thermal Throttling
// ============================================================================
// Tests: Thermal state simulation, throttling detection, performance degradation
//        under heat, graceful slowdown, recovery after cooling
// ============================================================================
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <cmath>
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
// Thermal simulator
// ============================================================================
struct ThermalState {
    double temperature_c;
    double throttle_threshold;
    double critical_threshold;
    bool   throttling;
    bool   critical;
    double performance_factor; // 1.0 = full, 0.5 = half

    void Update(double temp)
    {
        temperature_c = temp;
        throttling = temp >= throttle_threshold;
        critical = temp >= critical_threshold;
        performance_factor = throttling ? std::max(0.5, 1.0 - (temp - throttle_threshold) / 50.0) : 1.0;
    }
};

// ============================================================================
// Test 1: Thermal state tracking
// ============================================================================
static bool TestThermalStateTracking()
{
    std::printf("\n[TEST 1] Thermal state tracking\n");

    ThermalState state;
    state.throttle_threshold = 80.0;
    state.critical_threshold = 95.0;

    bool ok = true;

    state.Update(70.0);
    ok &= Check(!state.throttling && !state.critical, "B030-001",
                "normal temperature no throttle", "70C OK");

    state.Update(85.0);
    ok &= Check(state.throttling && !state.critical, "B030-002",
                "throttle threshold crossed", "85C throttling");

    state.Update(98.0);
    ok &= Check(state.throttling && state.critical, "B030-003",
                "critical threshold crossed", "98C critical");

    return ok;
}

// ============================================================================
// Test 2: Performance degradation under heat
// ============================================================================
static bool TestPerformanceDegradation()
{
    std::printf("\n[TEST 2] Performance degradation under heat\n");

    ThermalState state;
    state.throttle_threshold = 80.0;
    state.critical_threshold = 95.0;

    bool ok = true;

    state.Update(70.0);
    ok &= Check(state.performance_factor == 1.0, "B030-004",
                "full performance at normal temp", std::to_string(state.performance_factor).c_str());

    state.Update(85.0);
    ok &= Check(state.performance_factor < 1.0 && state.performance_factor > 0.0, "B030-005",
                "reduced performance under throttle", std::to_string(state.performance_factor).c_str());

    state.Update(100.0);
    ok &= Check(state.performance_factor <= 0.7, "B030-006",
                "severe degradation at critical", std::to_string(state.performance_factor).c_str());

    return ok;
}

// ============================================================================
// Test 3: Throttling detection latency
// ============================================================================
static bool TestThrottlingDetectionLatency()
{
    std::printf("\n[TEST 3] Throttling detection latency\n");

    ThermalState state;
    state.throttle_threshold = 80.0;
    state.critical_threshold = 95.0;

    bool ok = true;

    // Rapid temperature spike
    std::vector<double> temps = {70.0, 75.0, 82.0, 88.0, 92.0};
    bool detected = false;
    for (double t : temps) {
        state.Update(t);
        if (state.throttling) {
            detected = true;
            break;
        }
    }

    ok &= Check(detected, "B030-007", "throttle detected within spike", detected ? "yes" : "no");

    return ok;
}

// ============================================================================
// Test 4: Recovery after cooling
// ============================================================================
static bool TestRecoveryAfterCooling()
{
    std::printf("\n[TEST 4] Recovery after cooling\n");

    ThermalState state;
    state.throttle_threshold = 80.0;
    state.critical_threshold = 95.0;

    bool ok = true;

    // Heat up
    state.Update(90.0);
    ok &= Check(state.throttling, "B030-008", "throttling active", "yes");

    // Cool down
    state.Update(75.0);
    ok &= Check(!state.throttling, "B030-009", "throttle released after cooling", "yes");
    ok &= Check(state.performance_factor == 1.0, "B030-010",
                "performance restored", std::to_string(state.performance_factor).c_str());

    return ok;
}

// ============================================================================
// Test 5: Graceful slowdown behavior
// ============================================================================
static bool TestGracefulSlowdown()
{
    std::printf("\n[TEST 5] Graceful slowdown behavior\n");

    ThermalState state;
    state.throttle_threshold = 80.0;
    state.critical_threshold = 95.0;

    bool ok = true;

    // Simulate workload at different temperatures
    std::vector<double> temps = {60.0, 70.0, 80.0, 85.0, 90.0};
    std::vector<double> factors;
    for (double t : temps) {
        state.Update(t);
        factors.push_back(state.performance_factor);
    }

    // Factors should decrease monotonically
    bool monotonic = true;
    for (size_t i = 1; i < factors.size(); ++i) {
        if (factors[i] > factors[i-1]) { monotonic = false; break; }
    }

    ok &= Check(monotonic, "B030-011", "performance degrades monotonically", monotonic ? "yes" : "no");

    // Never goes below minimum
    double min_factor = *std::min_element(factors.begin(), factors.end());
    ok &= Check(min_factor >= 0.5, "B030-012", "minimum performance factor maintained",
                std::to_string(min_factor).c_str());

    return ok;
}

// ============================================================================
// Main
// ============================================================================
int main()
{
    std::printf("========================================\n");
    std::printf("  B030 — Thermal Throttling Awareness\n");
    std::printf("========================================\n");

    bool all_passed = true;
    all_passed &= TestThermalStateTracking();
    all_passed &= TestPerformanceDegradation();
    all_passed &= TestThrottlingDetectionLatency();
    all_passed &= TestRecoveryAfterCooling();
    all_passed &= TestGracefulSlowdown();

    std::printf("\n========================================\n");
    std::printf("  Results: %zu tests\n", g_results.size());

    size_t passed = 0;
    for (const auto& r : g_results) {
        if (r.passed) passed++;
    }
    std::printf("  Passed: %zu / %zu\n", passed, g_results.size());
    std::printf("  B030 CERTIFICATION: %s\n", all_passed ? "PASS" : "FAIL");
    std::printf("========================================\n");

    return all_passed ? 0 : 1;
}
