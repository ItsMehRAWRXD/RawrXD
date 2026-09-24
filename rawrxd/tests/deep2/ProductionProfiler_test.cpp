// ProductionProfiler_test.cpp — Isolated real provider validation
// DEEP2_LAYER0_PRODUCTION_PROFILER_001
// ============================================================================
#include "deep2/ProductionProfiler.hpp"
#include <cassert>
#include <cstdio>
#include <cstring>
#include <string>
#include <thread>
#include <vector>

using namespace Deep2;

static void test_basic_lifecycle() {
    ProductionProfiler p;
    p.setEnabled(true);
    assert(p.isEnabled());
    assert(p.counters().tokensStarted == 0);
    assert(p.counters().tokensCompleted == 0);

    p.beginToken(0, 0, ProfilePhase::Prefill);
    assert(p.counters().tokensStarted == 1);

    p.recordCpuOverhead(1000);
    p.recordGpuForward(5000);
    p.endToken(0);
    assert(p.counters().tokensCompleted == 1);
    assert(p.counters().tokensAborted == 0);
    assert(p.counters().prefillTokens == 1);
    assert(p.counters().decodeTokens == 0);

    assert(p.historySize() == 1);
    const TokenProfile& tp = p.history().back();
    assert(tp.phase == ProfilePhase::Prefill);
    assert(tp.cpuOverheadNs == 1000);
    assert(tp.gpuForwardNs == 5000);
    assert(tp.tokenLatencyNs > 0); // wall-clock latency is positive, not sum of synthetic values

    TimingStats t = p.timing();
    assert(t.totalTokenNs > 0);
    assert(t.totalGpuForwardNs == 5000);
    assert(t.totalCpuOverheadNs == 1000);
    assert(t.observedTps >= 0.0f);

    std::string json = p.toJSON();
    assert(!json.empty());
    assert(json.find("\"tokens_started\":") != std::string::npos);
    assert(json.find("\"tokens_completed\":") != std::string::npos);
    assert(json.find("\"observed_tps\":") != std::string::npos);

    p.reset();
    assert(p.counters().tokensStarted == 0);
    assert(p.historySize() == 0);

    std::printf("PASS: basic_lifecycle\n");
}

static void test_abort_path() {
    ProductionProfiler p;
    p.setEnabled(true);
    p.beginToken(0, 0, ProfilePhase::Decode);
    assert(p.counters().tokensStarted == 1);
    p.abortToken(0);
    assert(p.counters().tokensCompleted == 0);
    assert(p.counters().tokensAborted == 1);
    assert(p.historySize() == 0);
    std::printf("PASS: abort_path\n");
}

static void test_decode_phase() {
    ProductionProfiler p;
    p.setEnabled(true);
    p.beginToken(0, 42, ProfilePhase::Decode);
    p.recordGpuForward(2000);
    p.recordSampling(500);
    p.endToken(0);
    assert(p.counters().tokensCompleted == 1);
    assert(p.counters().decodeTokens == 1);
    const TokenProfile& tp = p.history().back();
    assert(tp.seqId == 42);
    assert(tp.gpuForwardNs == 2000);
    assert(tp.samplingNs == 500);
    std::printf("PASS: decode_phase\n");
}

static void test_layer_lifecycle() {
    ProductionProfiler p;
    p.setEnabled(true);
    p.beginLayer(7);
    assert(p.counters().layersStarted == 1);
    p.endLayer(7);
    assert(p.counters().layersCompleted == 1);
    std::printf("PASS: layer_lifecycle\n");
}

static void test_concurrent_safety() {
    ProductionProfiler p;
    p.setEnabled(true);
    constexpr int N = 256;
    std::vector<std::thread> threads;
    threads.reserve(N);
    for (int i = 0; i < N; ++i) {
        threads.emplace_back([&p, i]() {
            p.beginToken(static_cast<uint32_t>(i), static_cast<uint64_t>(i), ProfilePhase::Decode);
            p.recordGpuForward(1000);
            p.endToken(static_cast<uint32_t>(i));
        });
    }
    for (auto& t : threads) t.join();

    ProfileCounters c = p.counters();
    assert(c.tokensStarted == N);
    assert(c.tokensCompleted == N);
    assert(c.tokensAborted == 0);
    assert(p.historySize() == static_cast<size_t>(N));
    std::printf("PASS: concurrent_safety (%d threads)\n", N);
}

static void test_history_bound() {
    ProductionProfiler p;
    p.setEnabled(true);
    for (size_t i = 0; i < ProductionProfiler::MAX_HISTORY + 100; ++i) {
        p.beginToken(static_cast<uint32_t>(i % UINT16_MAX), i, ProfilePhase::Decode);
        p.endToken(static_cast<uint32_t>(i % UINT16_MAX));
    }
    assert(p.historySize() == ProductionProfiler::MAX_HISTORY);
    assert(p.historyEvictions() == 100);
    std::printf("PASS: history_bound\n");
}

static void test_save_json() {
    ProductionProfiler p;
    p.setEnabled(true);
    p.beginToken(0, 0, ProfilePhase::Prefill);
    p.endToken(0);
    bool ok = p.saveJSON("production_profiler_test_out.json");
    assert(ok);
    FILE* f = std::fopen("production_profiler_test_out.json", "rb");
    assert(f);
    std::fseek(f, 0, SEEK_END);
    long sz = std::ftell(f);
    std::fclose(f);
    assert(sz > 0);
    std::printf("PASS: save_json\n");
}

int main() {
    std::printf("=== ProductionProfiler Isolated Tests ===\n");
    test_basic_lifecycle();
    test_abort_path();
    test_decode_phase();
    test_layer_lifecycle();
    test_concurrent_safety();
    test_history_bound();
    test_save_json();
    std::printf("=== ALL PASSED ===\n");
    return 0;
}
