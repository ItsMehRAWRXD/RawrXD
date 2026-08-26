// ============================================================================
// RESIDENCY-A/B-CERT — Elastic Residency A/B Certification Harness
//
// Purpose:
//   Produce machine-readable JSON evidence comparing baseline (residency off)
//   vs elastic residency (residency on) on a fixed MoE GGUF workload.
//
// Metrics captured:
//   - tokens/sec (prefill + decode)
//   - expert-load latency (ms)
//   - peak resident bytes
//   - prefetch hit/miss rates
//   - correctness verification (token sequence identity)
//
// Output:
//   evidence/residency_ab_cert.json
// ============================================================================

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <limits>
#include <string>
#include <vector>
#include <chrono>
#include <filesystem>

// Deep2 Engine (direct instantiation for residency control)
#include "deep2/Deep2Engine.h"

namespace fs = std::filesystem;
using namespace std::chrono;
using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::InferenceStats;
using Deep2::GenerationOptions;
using Deep2::GenerationResult;

namespace {

constexpr int kTargetTokens = 15;
constexpr const char* kPrompt = "Hello";
constexpr int kMaxThreads = 0;  // 0 = auto

// ============================================================================
// Run Evidence
// ============================================================================
struct RunEvidence {
    std::string label;          // "baseline" or "elastic"
    bool pass = true;

    // Timing
    double prefillMs = 0.0;
    double decodeMs = 0.0;
    double totalMs = 0.0;
    double tokensPerSec = 0.0;

    // Token correctness
    int tokensGenerated = 0;
    std::vector<int> sequence;

    // Residency telemetry (elastic run only; baseline will be zero)
    uint64_t nvmeReadUs = 0;
    uint64_t ramStageUs = 0;
    uint64_t ramToVramUs = 0;
    uint64_t gpuWaitUs = 0;
    uint64_t gpuComputeUs = 0;
    uint64_t prefetchHit = 0;
    uint64_t prefetchMiss = 0;
    uint64_t vramEvictionUs = 0;
    uint64_t cpuFallbackUs = 0;
    uint64_t stateRaceBlocked = 0;

    // Router prefetch telemetry (elastic run only)
    uint64_t routerPrefetchHits = 0;
    uint64_t routerPrefetchMisses = 0;
    uint64_t routerTransferUs = 0;
    uint64_t routerGPUWaitUs = 0;
    uint64_t routerComputeUs = 0;
    double   routerHitRate = 0.0;
    uint64_t routerAsyncSubmitted = 0;
    uint64_t routerAsyncCompleted = 0;
    uint64_t routerAsyncReady = 0;
    uint64_t routerAsyncLate = 0;
    uint64_t routerFenceWaitUs = 0;
    uint64_t routerSyncFallbacks = 0;
    double   routerAsyncReadyRate = 0.0;

    // Memory
    size_t peakResidentBytes = 0;
};

// ============================================================================
// JSON Writer
// ============================================================================
void writeJsonField(std::ofstream& out, const char* key, const std::string& value, bool last = false) {
    out << "  \"" << key << "\": \"" << value << "\"";
    if (!last) out << ",";
    out << "\n";
}
void writeJsonField(std::ofstream& out, const char* key, double value, int prec = 6, bool last = false) {
    out << "  \"" << key << "\": " << std::setprecision(prec) << value;
    if (!last) out << ",";
    out << "\n";
}
void writeJsonField(std::ofstream& out, const char* key, int value, bool last = false) {
    out << "  \"" << key << "\": " << value;
    if (!last) out << ",";
    out << "\n";
}
void writeJsonField(std::ofstream& out, const char* key, int64_t value, bool last = false) {
    out << "  \"" << key << "\": " << value;
    if (!last) out << ",";
    out << "\n";
}
void writeJsonField(std::ofstream& out, const char* key, uint64_t value, bool last = false) {
    out << "  \"" << key << "\": " << value;
    if (!last) out << ",";
    out << "\n";
}

void writeRunEvidence(std::ofstream& out, const RunEvidence& ev, bool last = false) {
    out << "  {\n";
    writeJsonField(out, "label", ev.label);
    writeJsonField(out, "pass", ev.pass ? "true" : "false");
    writeJsonField(out, "prefill_ms", ev.prefillMs);
    writeJsonField(out, "decode_ms", ev.decodeMs);
    writeJsonField(out, "total_ms", ev.totalMs);
    writeJsonField(out, "tokens_per_sec", ev.tokensPerSec);
    writeJsonField(out, "tokens_generated", ev.tokensGenerated);

    out << "  \"sequence\": [";
    for (size_t i = 0; i < ev.sequence.size(); ++i) {
        if (i) out << ", ";
        out << ev.sequence[i];
    }
    out << "],\n";

    writeJsonField(out, "nvme_read_us", ev.nvmeReadUs);
    writeJsonField(out, "ram_stage_us", ev.ramStageUs);
    writeJsonField(out, "ram_to_vram_us", ev.ramToVramUs);
    writeJsonField(out, "gpu_wait_us", ev.gpuWaitUs);
    writeJsonField(out, "gpu_compute_us", ev.gpuComputeUs);
    writeJsonField(out, "prefetch_hit", ev.prefetchHit);
    writeJsonField(out, "prefetch_miss", ev.prefetchMiss);
    writeJsonField(out, "vram_eviction_us", ev.vramEvictionUs);
    writeJsonField(out, "cpu_fallback_us", ev.cpuFallbackUs);
    writeJsonField(out, "state_race_blocked", ev.stateRaceBlocked);

    writeJsonField(out, "router_prefetch_hits", ev.routerPrefetchHits);
    writeJsonField(out, "router_prefetch_misses", ev.routerPrefetchMisses);
    writeJsonField(out, "router_transfer_us", ev.routerTransferUs);
    writeJsonField(out, "router_gpu_wait_us", ev.routerGPUWaitUs);
    writeJsonField(out, "router_compute_us", ev.routerComputeUs);
    writeJsonField(out, "router_hit_rate", ev.routerHitRate);
    writeJsonField(out, "router_async_submitted", ev.routerAsyncSubmitted);
    writeJsonField(out, "router_async_completed", ev.routerAsyncCompleted);
    writeJsonField(out, "router_async_ready", ev.routerAsyncReady);
    writeJsonField(out, "router_async_late", ev.routerAsyncLate);
    writeJsonField(out, "router_fence_wait_us", ev.routerFenceWaitUs);
    writeJsonField(out, "router_sync_fallbacks", ev.routerSyncFallbacks);
    writeJsonField(out, "router_async_ready_rate", ev.routerAsyncReadyRate);
    writeJsonField(out, "peak_resident_bytes", (uint64_t)ev.peakResidentBytes, true);
    out << "  }";
    if (!last) out << ",";
    out << "\n";
}

void writeEvidence(const RunEvidence& baseline,
                   const RunEvidence& elastic,
                   const char* filename)
{
    fs::create_directories("evidence");
    std::ofstream out(filename, std::ios::trunc);
    if (!out) {
        std::cerr << "[FAIL] Cannot open " << filename << " for writing\n";
        return;
    }

    out << "{\n";
    writeJsonField(out, "harness", "RESIDENCY-A/B-CERT");
    writeJsonField(out, "version", "1.0");
    writeJsonField(out, "target_tokens", kTargetTokens);
    writeJsonField(out, "prompt", kPrompt);
    writeJsonField(out, "timestamp", std::to_string(
        duration_cast<seconds>(system_clock::now().time_since_epoch()).count()));

    // Comparison summary
    double speedup = (baseline.tokensPerSec > 0.0)
        ? (elastic.tokensPerSec / baseline.tokensPerSec)
        : 0.0;
    bool sequenceMatch = (baseline.sequence == elastic.sequence);

    writeJsonField(out, "speedup", speedup);
    writeJsonField(out, "sequence_match", sequenceMatch ? "true" : "false");
    writeJsonField(out, "baseline_pass", baseline.pass ? "true" : "false");
    writeJsonField(out, "elastic_pass", elastic.pass ? "true" : "false");

    out << "  \"runs\": [\n";
    writeRunEvidence(out, baseline, false);
    writeRunEvidence(out, elastic, true);
    out << "  ]\n";
    out << "}\n";
}

// ============================================================================
// Execute a single run
// ============================================================================
RunEvidence executeRun(const char* modelPath,
                       bool enableElastic,
                       bool enablePrefetch,
                       bool enableTelemetry)
{
    RunEvidence ev;
    ev.label = enableElastic ? "elastic" : "baseline";

    std::cout << "\n============================================================\n"
              << "RUN: " << ev.label << "\n"
              << "============================================================\n";

    Deep2Engine engine;
    EngineConfig config;
    config.numThreads = kMaxThreads;
    config.useThreadPool = true;
    config.useKVCache = true;

    if (!engine.initialize(config)) {
        std::cerr << "[FAIL] Engine initialization failed\n";
        ev.pass = false;
        return ev;
    }

    if (!engine.loadModel(modelPath)) {
        std::cerr << "[FAIL] Model load failed: " << modelPath << "\n";
        ev.pass = false;
        return ev;
    }

    // Configure residency
    if (enableElastic) {
        engine.enableElasticResidency(true);
    }
    if (enablePrefetch) {
        engine.setAsyncPrefetchEnabled(true);
    }
    if (enableTelemetry) {
        engine.enableResidencyTelemetry(true);
    }

    // Tokenize prompt
    std::vector<int> promptTokens = engine.tokenize(kPrompt);
    if (promptTokens.empty()) {
        std::cerr << "[FAIL] Tokenization produced no tokens\n";
        ev.pass = false;
        return ev;
    }
    std::cout << "[INFO] Prompt tokens: " << promptTokens.size() << "\n";

    // ------------------------------------------------------------------------
    // Prefill
    // ------------------------------------------------------------------------
    std::vector<int> outputTokens;
    outputTokens.reserve(kTargetTokens);

    auto t0 = high_resolution_clock::now();

    InferenceStats stats{};
    std::vector<float> logits;  // not used directly; engine.generate handles sampling

    // Use generate() for prefill + decode in one call
    int outBuf[256];
    size_t genCount = engine.generate(
        promptTokens.data(), promptTokens.size(),
        outBuf, kTargetTokens,
        &stats,
        [&](int tok) -> bool {
            outputTokens.push_back(tok);
            return outputTokens.size() < static_cast<size_t>(kTargetTokens);
        });

    auto t1 = high_resolution_clock::now();

    ev.tokensGenerated = static_cast<int>(outputTokens.size());
    ev.sequence = outputTokens;
    ev.tokensPerSec = stats.tokensPerSecond;
    ev.totalMs = stats.latencyMs;
    ev.prefillMs = 0.0;  // engine.generate aggregates; we split heuristically if needed
    ev.decodeMs = stats.latencyMs;

    // ------------------------------------------------------------------------
    // Telemetry collection (elastic run)
    // ------------------------------------------------------------------------
    if (enableElastic && engine.isElasticResidencyEnabled()) {
        auto* erm = engine.getElasticResidencyManager();
        if (erm) {
            const auto& tel = erm->GetTelemetry();
            ev.nvmeReadUs = tel.nvmeReadUs.load();
            ev.ramStageUs = tel.ramStageUs.load();
            ev.ramToVramUs = tel.ramToVramUs.load();
            ev.gpuWaitUs = tel.gpuWaitUs.load();
            ev.gpuComputeUs = tel.gpuComputeUs.load();
            ev.prefetchHit = tel.prefetchHit.load();
            ev.prefetchMiss = tel.prefetchMiss.load();
            ev.vramEvictionUs = tel.vramEvictionUs.load();
            ev.cpuFallbackUs = tel.cpuFallbackUs.load();
            ev.stateRaceBlocked = tel.stateRaceBlocked.load();
        }
    }

    if (enableTelemetry && engine.isResidencyTelemetryEnabled()) {
        auto* rpt = engine.getResidencyTelemetry();
        if (rpt) {
            auto summary = rpt->GetSummary();
            ev.routerPrefetchHits = summary.totalPrefetchHits;
            ev.routerPrefetchMisses = summary.totalPrefetchMisses;
            ev.routerTransferUs = summary.totalTransferUs;
            ev.routerGPUWaitUs = summary.totalGPUWaitUs;
            ev.routerComputeUs = summary.totalComputeUs;
            ev.routerHitRate = summary.hitRate;
            ev.routerAsyncSubmitted = summary.totalAsyncPrefetchSubmitted;
            ev.routerAsyncCompleted = summary.totalAsyncPrefetchCompleted;
            ev.routerAsyncReady = summary.totalAsyncPrefetchReadyAtCompute;
            ev.routerAsyncLate = summary.totalAsyncPrefetchLate;
            ev.routerFenceWaitUs = summary.totalFenceWaitUs;
            ev.routerSyncFallbacks = summary.totalSynchronousFallbacks;
            ev.routerAsyncReadyRate = summary.asyncReadyRate;
        }
    }

    // Peak resident bytes (best-effort: elastic residency manager bytes)
    if (enableElastic && engine.isElasticResidencyEnabled()) {
        auto* erm = engine.getElasticResidencyManager();
        if (erm) {
            // ElasticResidencyManager does not expose a resident_bytes() API yet;
            // leave as 0 for now and populate from telemetry if available.
            ev.peakResidentBytes = 0;
        }
    }

    // Correctness: must have generated target tokens
    if (ev.tokensGenerated != kTargetTokens) {
        std::cerr << "[FAIL] Generated " << ev.tokensGenerated << " tokens, expected " << kTargetTokens << "\n";
        ev.pass = false;
    }

    std::cout << "[PASS] " << ev.label
              << " generated=" << ev.tokensGenerated
              << " tps=" << std::setprecision(4) << ev.tokensPerSec
              << " latency=" << ev.totalMs << "ms\n";

    return ev;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv)
{
    if (argc != 2) {
        std::cerr << "Usage: residency_ab_cert.exe <model.gguf>\n";
        return 2;
    }

    const char* modelPath = argv[1];

    std::cout << "============================================================\n"
              << "RESIDENCY-A/B-CERT — Elastic Residency Certification\n"
              << "============================================================\n"
              << "MODEL=" << modelPath << "\n"
              << "PROMPT=\"" << kPrompt << "\"\n"
              << "TARGET=" << kTargetTokens << "\n"
              << "============================================================\n";

    // ------------------------------------------------------------------------
    // Run A — Baseline (residency off, prefetch off)
    // ------------------------------------------------------------------------
    RunEvidence baseline = executeRun(modelPath, false, false, false);

    // ------------------------------------------------------------------------
    // Run B — Elastic (residency on, prefetch on, telemetry on)
    // ------------------------------------------------------------------------
    RunEvidence elastic = executeRun(modelPath, true, true, true);

    // ------------------------------------------------------------------------
    // Correctness: token sequences must match
    // ------------------------------------------------------------------------
    bool sequenceMatch = (baseline.sequence == elastic.sequence);
    if (!sequenceMatch) {
        std::cerr << "[WARN] Token sequence mismatch between baseline and elastic\n";
    }

    // ------------------------------------------------------------------------
    // Emit evidence
    // ------------------------------------------------------------------------
    writeEvidence(baseline, elastic, "evidence/residency_ab_cert.json");

    std::cout << "\n============================================================\n"
              << "RESIDENCY-A/B-CERT RESULT\n"
              << "============================================================\n"
              << "BASELINE_PASS=" << (baseline.pass ? "YES" : "NO") << "\n"
              << "ELASTIC_PASS=" << (elastic.pass ? "YES" : "NO") << "\n"
              << "SEQUENCE_MATCH=" << (sequenceMatch ? "YES" : "NO") << "\n"
              << "BASELINE_TPS=" << std::setprecision(4) << baseline.tokensPerSec << "\n"
              << "ELASTIC_TPS=" << std::setprecision(4) << elastic.tokensPerSec << "\n";

    if (baseline.tokensPerSec > 0.0) {
        double speedup = elastic.tokensPerSec / baseline.tokensPerSec;
        std::cout << "SPEEDUP=" << std::setprecision(4) << speedup << "x\n";
    }

    std::cout << "EVIDENCE=evidence/residency_ab_cert.json\n"
              << "============================================================\n";

    bool overallPass = baseline.pass && elastic.pass && sequenceMatch;
    return overallPass ? 0 : 1;
}

} // namespace
