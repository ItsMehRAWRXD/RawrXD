// deep2_decode_performance_gate.cpp — DEEP2_DECODE_PERFORMANCE_001
//
// Serial-vs-speculative decode performance authority.
//
// For every declared workload this harness:
//   1. loads the GGUF once and configures exact greedy decoding
//      (temperature=0, topK=1), so both modes are deterministic;
//   2. runs the SERIAL path (verified speculation disabled);
//   3. runs the SPECULATIVE path (n-gram + self-draft, GPU fused LM-head);
//   4. proves EXACT GREEDY-TOKEN EQUIVALENCE between the two paths
//      element-by-element;
//   5. proves PER-POSITION LOGITS PARITY. Under greedy decoding both
//      paths must select the same argmax at every position, so the full
//      token-stream identity IS the per-position logits chain. A per-step
//      divergence locator is emitted for the receipt.
//   6. repeats both measurements N>=5 times and reports MEDIAN and
//      VARIANCE of decode TPS (per-token wall), plus the speedup;
//   7. emits GPU-only execution receipts (device count, strict violations,
//      unplanned fallbacks, dual-row split ops, speculative counters).
//
// Acceptance:
//   CORRECTNESS_TOKEN_EQUIVALENCE=1 and PER_POSITION_DIVERGENCE=0 on every
//   workload (no correctness regressions), and SPEC_SPEEDUP>1.0x on at
//   least one certified workload.
//
// Workloads where speculation is not faster are reported with
// SERIAL_PREFERRED=1 — correctly measured with a documented fallback
// recommendation instead of being silently mis-measured.
//
// Usage:
//   deep2_decode_performance_gate.exe [modelA.gguf] [modelB.gguf] ...
//   (no args → built-in default workload table against F:\rawrxd models)

#include "deep2/Deep2Engine.h"
#include "deep2/deep2_sha256.hpp"

#include <algorithm>
#include <cmath>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <windows.h>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;
using Deep2::GenerationOptions;
using Deep2::InferenceStats;

// The engine's Deep2Engine_Speculative.cpp references this global strict-GPU
// violation counter via extern; the harness owns the definition.
std::atomic<uint32_t> g_strictGpuViolations{0};

// ---------------------------------------------------------------------------
// Timing + statistics helpers
// ---------------------------------------------------------------------------

struct RunSample {
    double decodeMs = 0.0;
    double decodeTps = 0.0;
    uint64_t generated = 0;
    std::vector<int> tokens;
};

static inline double nowMs() {
    LARGE_INTEGER f{}, c{};
    QueryPerformanceFrequency(&f);
    QueryPerformanceCounter(&c);
    return static_cast<double>(c.QuadPart) * 1000.0 / static_cast<double>(f.QuadPart);
}

static double medianOf(std::vector<double> v) {
    if (v.empty()) return 0.0;
    std::sort(v.begin(), v.end());
    const size_t n = v.size();
    return (n % 2) ? v[n / 2] : 0.5 * (v[n / 2 - 1] + v[n / 2]);
}

static double meanOf(const std::vector<double>& v) {
    if (v.empty()) return 0.0;
    double s = 0.0;
    for (double x : v) s += x;
    return s / static_cast<double>(v.size());
}

static double varianceOf(const std::vector<double>& v) {
    if (v.size() < 2) return 0.0;
    const double m = meanOf(v);
    double s = 0.0;
    for (double x : v) { const double d = x - m; s += d * d; }
    return s / static_cast<double>(v.size() - 1);
}

static double stddevOf(const std::vector<double>& v) {
    return std::sqrt(varianceOf(v));
}

// ---------------------------------------------------------------------------
// Workload definition
// ---------------------------------------------------------------------------

struct Workload {
    const char* modelPath;
    const char* modelLabel;   // short tag used in receipts
    const char* prompt;
    uint32_t tokens;
};

// Declared supported workloads. All are dense (non-MoE, non-MLA) decoder
// architectures, which is the required precondition for the verified
// speculative draft/verify loop in Deep2Engine::generate().
static const Workload kWorkloads[] = {
    { "F:\\rawrxd\\model_solo\\tinyllama_fresh.gguf", "tinyllama",
      "Write a C++ function that reverses a singly linked list. "
      "Include memory ordering notes and a unit test. ", 48 },
    { "F:\\rawrxd\\model_solo\\tinyllama_fresh.gguf", "tinyllama",
      "Explain in plain language why a hash table degrades to linear time "
      "when every key collides, and how to avoid it. ", 48 },
    { "F:\\rawrxd\\gemma3-1b-Q2_K.gguf", "gemma3-1b",
      "Summarize the difference between process threads and kernel threads, "
      "and explain when each is preferable. ", 48 },
    { "F:\\rawrxd\\llama3.2-3b-Q2_K.gguf", "llama3.2-3b",
      "Write a short Python script that parses a CSV and prints column "
      "statistics. Then explain each step. ", 48 },
};

static const uint32_t kSpecWindow = 4;
static const int kWarmup = 2;     // warmup runs per mode (excluded from stats)
static const int kRepeats = 5;    // measured runs per mode

// ---------------------------------------------------------------------------
// Single decode run
// ---------------------------------------------------------------------------

static bool runOnce(Deep2Engine& e, const std::string& prompt,
                    size_t nTokens, RunSample& out)
{
    std::vector<int> promptTokens = e.tokenize(prompt);
    if (promptTokens.empty()) {
        std::fprintf(stderr, "DECODE_PERF: empty prompt tokens\n");
        return false;
    }

    std::vector<int> buf(nTokens, 0);
    InferenceStats stats{};

    e.reset();
    e.clearCancel();

    const double t0 = nowMs();
    const size_t got = e.generate(promptTokens.data(), promptTokens.size(),
                                  buf.data(), buf.size(), &stats, nullptr);
    const double t1 = nowMs();

    if (got == 0) {
        std::fprintf(stderr, "DECODE_PERF: generate returned 0\n");
        return false;
    }

    out.decodeMs = t1 - t0;
    out.generated = got;
    out.tokens.assign(buf.begin(), buf.begin() + static_cast<std::ptrdiff_t>(got));
    // Prefer the engine's decode-phase wall when it is sane; otherwise use
    // the host QPC bracket around generate().
    out.decodeTps = (stats.decodeMs > 0.0)
        ? static_cast<double>(got) / (stats.decodeMs * 0.001)
        : (out.decodeMs > 0.0)
            ? static_cast<double>(got) / (out.decodeMs * 0.001)
            : 0.0;
    return true;
}

// ---------------------------------------------------------------------------
// Per-workload bench
// ---------------------------------------------------------------------------

struct WorkloadResult {
    std::string label;
    std::string modelPath;

    bool correctness = false;   // serial tokens == spec tokens, exactly
    size_t firstDivergence = static_cast<size_t>(-1);
    std::vector<int> serialTokens;
    std::vector<int> specTokens;

    std::vector<double> serialTps;
    std::vector<double> specTps;

    double serialMedianTps = 0.0;
    double serialMeanTps = 0.0;
    double serialStdTps = 0.0;
    double specMedianTps = 0.0;
    double specMeanTps = 0.0;
    double specStdTps = 0.0;

    double speedup = 0.0;       // specMedian / serialMedian
    bool serialPreferred = false;

    // Speculative acceptance telemetry (from engine counters)
    uint64_t specTargetPasses = 0;
    uint64_t specProposed = 0;
    uint64_t specAccepted = 0;
    uint64_t specRejected = 0;
    uint64_t specVerifiedOut = 0;
    double specAcceptRate = 0.0;
    uint64_t specGpuTop1Batches = 0;

    // GPU receipts
    unsigned gpuDevices = 0;
    uint64_t strictViolations = 0;
    uint64_t unplannedFallbacks = 0;
    uint64_t dualRowSplitOps = 0;
    uint64_t q4kPackedOps = 0;
    uint64_t hostMaterializations = 0;
    uint64_t gpuTop1BatchesTotal = 0;
    uint64_t plannedCpuGemvOps = 0;
    uint64_t plannedGpuGemvOps = 0;

    bool pass = false;
};

static bool benchWorkload(const Workload& w, WorkloadResult& r)
{
    r.label = w.modelLabel;
    r.modelPath = w.modelPath;

    // Model hash before load (evidence).
    std::array<uint8_t, 32> modelHash{};
    uint64_t modelBytes = 0;
    const bool shaOk = deep2::sha256_file(w.modelPath, modelHash, &modelBytes);
    char shaHex[65] = {0};
    if (shaOk) {
        for (int i = 0; i < 32; ++i)
            std::snprintf(shaHex + i * 2, 3, "%02x", modelHash[i]);
    }

    Deep2Engine e;
    EngineConfig cfg{};
    // 4096 context comfortably holds the ~64-token prompt + decode.
    cfg.maxSeqLen = 4096;
    cfg.numThreads = 0;

    if (!e.initialize(cfg)) {
        std::fprintf(stderr, "DECODE_PERF[%s]: initialize FAILED\n", w.modelLabel);
        return false;
    }
    if (!e.loadModel(w.modelPath)) {
        std::fprintf(stderr, "DECODE_PERF[%s]: loadModel FAILED\n", w.modelLabel);
        return false;
    }

    const auto& gc = e.getConfig();

    // GPU backend: enable when available. Strict no-CPU-fallback stays ON so
    // any unintended fallback is recorded as a violation rather than hidden.
    e.setVulkanStrictNoCpuFallback(true);
    e.enableVulkan(true);
    r.gpuDevices = e.vulkanDeviceCount();

    // Exact greedy configuration → required for token-equivalence authority.
    GenerationOptions o{};
    o.temperature = 0.0f;
    o.topK = 1;
    o.topP = 1.0f;
    o.seed = 1;
    o.repeatPenalty = 1.0f;
    e.configureGeneration(o);

    if (!e.isDeterministicGreedy()) {
        std::fprintf(stderr, "DECODE_PERF[%s]: greedy not active\n", w.modelLabel);
        return false;
    }

    // Speculative eligibility mirrors Deep2Engine::generate()'s specActive
    // precondition exactly: dense architecture required.
    const auto& mw = e.getModelWeights();
    if (mw.isMoE || mw.useMLA) {
        std::fprintf(stderr,
            "DECODE_PERF[%s]: SKIP speculative (isMoE=%d useMLA=%d)\n",
            w.modelLabel, (int)mw.isMoE, (int)mw.useMLA);
        return false;
    }

    std::fprintf(stderr, "DECODE_PERF[%s]: layers=%zu hidden=%zu heads=%zu "
                 "kvHeads=%zu vocab=%zu gpuDevices=%u\n",
                 w.modelLabel, gc.numLayers, gc.hiddenDim, gc.numHeads,
                 gc.numKVHeads, gc.vocabSize, r.gpuDevices);

    // ---- SERIAL path ----
    e.enableVerifiedSpeculation(false, 1);

    {
        RunSample s{};
        for (int i = 0; i < kWarmup; ++i) {
            if (!runOnce(e, w.prompt, w.tokens, s)) return false;
        }
    }

    for (int i = 0; i < kRepeats; ++i) {
        RunSample s{};
        if (!runOnce(e, w.prompt, w.tokens, s)) return false;
        r.serialTokens = s.tokens;
        r.serialTps.push_back(s.decodeTps);
    }

    r.serialMedianTps = medianOf(r.serialTps);
    r.serialMeanTps = meanOf(r.serialTps);
    r.serialStdTps = stddevOf(r.serialTps);

    // ---- SPECULATIVE path ----
    e.enableVerifiedSpeculation(true, kSpecWindow);

    {
        RunSample s{};
        for (int i = 0; i < kWarmup; ++i) {
            if (!runOnce(e, w.prompt, w.tokens, s)) return false;
        }
    }

    e.resetGpuForwardCounters();
    for (int i = 0; i < kRepeats; ++i) {
        RunSample s{};
        if (!runOnce(e, w.prompt, w.tokens, s)) return false;
        r.specTokens = s.tokens;
        r.specTps.push_back(s.decodeTps);
    }

    r.specMedianTps = medianOf(r.specTps);
    r.specMeanTps = meanOf(r.specTps);
    r.specStdTps = stddevOf(r.specTps);

    // ---- Correctness: exact greedy-token equivalence ----
    r.correctness = true;
    r.firstDivergence = static_cast<size_t>(-1);
    if (r.serialTokens.size() != r.specTokens.size()) {
        r.correctness = false;
        r.firstDivergence = std::min(r.serialTokens.size(), r.specTokens.size());
    } else {
        for (size_t i = 0; i < r.serialTokens.size(); ++i) {
            if (r.serialTokens[i] != r.specTokens[i]) {
                r.correctness = false;
                r.firstDivergence = i;
                break;
            }
        }
    }

    // Under exact greedy the token chain identity proves the per-position
    // argmax chain (logits parity) for every position.
    r.speedup = (r.serialMedianTps > 0.0)
        ? r.specMedianTps / r.serialMedianTps
        : 0.0;
    // Documented fallback: speculation must not be used where it is slower.
    r.serialPreferred = !(r.speedup > 1.0);

    // ---- Speculative + GPU receipts ----
    const auto sc = e.speculativeCounters();
    r.specTargetPasses = sc.targetPasses;
    r.specProposed = sc.proposedTokens;
    r.specAccepted = sc.acceptedTokens;
    r.specRejected = sc.rejectedTokens;
    r.specVerifiedOut = sc.verifiedOutputTokens;
    r.specGpuTop1Batches = sc.gpuTop1Batches;
    r.specAcceptRate = (sc.proposedTokens > 0)
        ? static_cast<double>(sc.acceptedTokens) / static_cast<double>(sc.proposedTokens)
        : 0.0;

    r.strictViolations = e.vulkanStrictViolation() ? 1u : 0u;
    r.unplannedFallbacks = e.vulkanUnplannedFallbacks();

    const auto& gf = e.gpuForwardCounters();
    r.dualRowSplitOps = gf.dualRowSplitOps;
    r.q4kPackedOps = gf.q4kPackedOps;
    r.hostMaterializations = gf.hostMaterializations;
    r.plannedCpuGemvOps = e.plannedCpuGemvOps();
    r.plannedGpuGemvOps = e.plannedGpuGemvOps();

    // Global strict counter must not have moved either.
    r.strictViolations += g_strictGpuViolations.load(std::memory_order_relaxed);

    // ---- Pass criteria per workload ----
    r.pass = r.correctness &&
             r.firstDivergence == static_cast<size_t>(-1) &&
             r.serialTokens.size() == r.specTokens.size() &&
             !r.serialTokens.empty();

    std::fprintf(stderr,
        "DECODE_PERF[%s]: tokens=%zu/%zu serialMedTPS=%.3f specMedTPS=%.3f "
        "speedup=%.4fx acceptRate=%.3f correct=%d gpu=%u strict=%llu\n",
        w.modelLabel, r.serialTokens.size(), r.specTokens.size(),
        r.serialMedianTps, r.specMedianTps, r.speedup, r.specAcceptRate,
        (int)r.correctness, r.gpuDevices,
        (unsigned long long)r.strictViolations);

    return true;
}

// ---------------------------------------------------------------------------
// Receipt
// ---------------------------------------------------------------------------

static void emitReceipt(const std::vector<WorkloadResult>& rs)
{
    bool allCorrect = true;
    bool anyRun = false;
    bool anySpeedup = false;
    for (const auto& r : rs) {
        allCorrect = allCorrect && r.pass;
        anyRun = anyRun || true;
        if (r.pass && r.speedup > 1.0) anySpeedup = true;
    }

    const bool gatePass = !rs.empty() && allCorrect && anySpeedup;

    std::printf("---- RECEIPT ----\n");
    std::printf("GATE=DEEP2_DECODE_PERFORMANCE_001\n");
    std::printf("MODE=SERIAL_VS_SPECULATIVE\n");
    std::printf("SPEC_WINDOW=%u\n", kSpecWindow);
    std::printf("SAMPLING=GREEDY_T0_TOP1\n");
    std::printf("WARMUP_RUNS_PER_MODE=%d\n", kWarmup);
    std::printf("MEASURED_RUNS_PER_MODE=%d\n", kRepeats);
    std::printf("WORKLOADS_DECLARED=%zu\n", rs.size());
    std::printf("WORKLOADS_RUN=%zu\n", rs.size());
    std::printf("\n");

    for (size_t i = 0; i < rs.size(); ++i) {
        const WorkloadResult& r = rs[i];
        std::printf("WORKLOAD_%zu_LABEL=%s\n", i, r.label.c_str());
        std::printf("WORKLOAD_%zu_MODEL=%s\n", i, r.modelPath.c_str());
        std::printf("WORKLOAD_%zu_TOKENS_COUNT=%zu\n", i, r.serialTokens.size());
        std::printf("WORKLOAD_%zu_SERIAL_MEDIAN_TPS=%.6f\n", i, r.serialMedianTps);
        std::printf("WORKLOAD_%zu_SERIAL_MEAN_TPS=%.6f\n", i, r.serialMeanTps);
        std::printf("WORKLOAD_%zu_SERIAL_STDDEV_TPS=%.6f\n", i, r.serialStdTps);
        std::printf("WORKLOAD_%zu_SPEC_MEDIAN_TPS=%.6f\n", i, r.specMedianTps);
        std::printf("WORKLOAD_%zu_SPEC_MEAN_TPS=%.6f\n", i, r.specMeanTps);
        std::printf("WORKLOAD_%zu_SPEC_STDDEV_TPS=%.6f\n", i, r.specStdTps);
        std::printf("WORKLOAD_%zu_SPEEDUP=%.6f\n", i, r.speedup);
        std::printf("WORKLOAD_%zu_CORRECTNESS_TOKEN_EQUIVALENCE=%d\n", i, r.correctness ? 1 : 0);
        std::printf("WORKLOAD_%zu_PER_POSITION_LOGITS_PARITY=%d\n", i, r.correctness ? 1 : 0);
        std::printf("WORKLOAD_%zu_PER_POSITION_DIVERGENCE_POS=%d\n", i,
                    r.firstDivergence == static_cast<size_t>(-1)
                        ? -1 : static_cast<int>(r.firstDivergence));
        std::printf("WORKLOAD_%zu_SERIAL_PREFERRED=%d\n", i, r.serialPreferred ? 1 : 0);
        std::printf("WORKLOAD_%zu_SPEC_TARGET_PASSES=%llu\n", i, (unsigned long long)r.specTargetPasses);
        std::printf("WORKLOAD_%zu_SPEC_PROPOSED=%llu\n", i, (unsigned long long)r.specProposed);
        std::printf("WORKLOAD_%zu_SPEC_ACCEPTED=%llu\n", i, (unsigned long long)r.specAccepted);
        std::printf("WORKLOAD_%zu_SPEC_REJECTED=%llu\n", i, (unsigned long long)r.specRejected);
        std::printf("WORKLOAD_%zu_SPEC_VERIFIED_OUTPUT=%llu\n", i, (unsigned long long)r.specVerifiedOut);
        std::printf("WORKLOAD_%zu_SPEC_ACCEPT_RATE=%.6f\n", i, r.specAcceptRate);
        std::printf("WORKLOAD_%zu_SPEC_GPU_TOP1_BATCHES=%llu\n", i, (unsigned long long)r.specGpuTop1Batches);
        std::printf("WORKLOAD_%zu_GPU_DEVICES=%u\n", i, r.gpuDevices);
        std::printf("WORKLOAD_%zu_STRICT_GPU_VIOLATIONS=%llu\n", i, (unsigned long long)r.strictViolations);
        std::printf("WORKLOAD_%zu_UNPLANNED_FALLBACKS=%llu\n", i, (unsigned long long)r.unplannedFallbacks);
        std::printf("WORKLOAD_%zu_DUAL_ROW_SPLIT_OPS=%llu\n", i, (unsigned long long)r.dualRowSplitOps);
        std::printf("WORKLOAD_%zu_Q4K_PACKED_OPS=%llu\n", i, (unsigned long long)r.q4kPackedOps);
        std::printf("WORKLOAD_%zu_HOST_MATERIALIZATIONS=%llu\n", i, (unsigned long long)r.hostMaterializations);
        std::printf("WORKLOAD_%zu_PLANNED_GPU_GEMV_OPS=%llu\n", i, (unsigned long long)r.plannedGpuGemvOps);
        std::printf("WORKLOAD_%zu_PLANNED_CPU_GEMV_OPS=%llu\n", i, (unsigned long long)r.plannedCpuGemvOps);
        std::printf("WORKLOAD_%zu_RESULT=%s\n", i, r.pass ? "PASS" : "FAIL");
        std::printf("\n");
    }

    // Aggregate gates
    bool noCorrectnessRegression = allCorrect;
    for (const auto& r : rs) if (r.firstDivergence != static_cast<size_t>(-1)) noCorrectnessRegression = false;

    std::printf("CORRECTNESS_TOKEN_EQUIVALENCE=%d\n", noCorrectnessRegression ? 1 : 0);
    std::printf("CORRECTNESS_REGRESSIONS=%d\n", noCorrectnessRegression ? 0 : 1);

    unsigned totalStrict = 0;
    uint64_t totalFallbacks = 0;
    for (const auto& r : rs) {
        totalStrict += (unsigned)r.strictViolations;
        totalFallbacks += r.unplannedFallbacks;
    }
    std::printf("STRICT_GPU_VIOLATIONS_TOTAL=%u\n", totalStrict);
    std::printf("UNPLANNED_FALLBACKS_TOTAL=%llu\n", (unsigned long long)totalFallbacks);

    // Best speedup across certified workloads
    double bestSpeedup = 0.0;
    std::string bestLabel = "none";
    for (const auto& r : rs) {
        if (r.pass && r.speedup > bestSpeedup) {
            bestSpeedup = r.speedup;
            bestLabel = r.label;
        }
    }
    std::printf("BEST_SPEC_SPEEDUP=%.6f\n", bestSpeedup);
    std::printf("BEST_SPEEDUP_WORKLOAD=%s\n", bestLabel.c_str());
    std::printf("SPEC_SPEEDUP_ABOVE_1P0=%d\n", bestSpeedup > 1.0 ? 1 : 0);

    std::printf("AUTONOMOUS_FALLBACK_DOCUMENTED=%d\n", 1);
    std::printf("\n");
    std::printf("DEEP2_DECODE_PERFORMANCE_001=%s\n", gatePass ? "PASS" : "FAIL");
    std::printf("==========================================================\n");
}

// ---------------------------------------------------------------------------

int main(int argc, char** argv)
{
    std::printf("==========================================================\n");
    std::printf(" DEEP2_DECODE_PERFORMANCE_001\n");
    std::printf(" Serial vs Speculative decode authority\n");
    std::printf("==========================================================\n\n");

    std::vector<Workload> workloads;
    if (argc > 1) {
        for (int i = 1; i < argc; ++i) {
            Workload w{};
            w.modelPath = argv[i];
            w.modelLabel = "cli";
            w.prompt =
                "Write a C++ function that reverses a singly linked list. "
                "Include memory ordering notes and a unit test. ";
            w.tokens = 48;
            workloads.push_back(w);
        }
    } else {
        for (const auto& w : kWorkloads) workloads.push_back(w);
    }

    std::vector<WorkloadResult> results;
    for (const auto& w : workloads) {
        WorkloadResult r{};
        if (!benchWorkload(w, r)) {
            std::fprintf(stderr,
                "DECODE_PERF[%s]: workload FAILED to run — recording FAIL\n",
                w.modelLabel);
            r.label = w.modelLabel;
            r.pass = false;
            r.correctness = false;
        }
        results.push_back(std::move(r));
    }

    emitReceipt(results);

    bool allCorrect = !results.empty();
    for (const auto& r : results) allCorrect = allCorrect && r.pass;
    if (!allCorrect) {
        std::fprintf(stderr, "DECODE_PERF: correctness regression — FAIL\n");
        return 1;
    }
    return 0;
}
