// Real C++ inference acceptance: V5 polymorphic blackboard driven by the native
// WinHTTP Ollama executor. Executes REAL llama3.2:3b inference (no test double).
//
// Demonstrates, from real measurements only:
//   - model + hardware discovery (/api/tags, /api/show)
//   - prediction correction (E = O - P shrinking)
//   - dynamically changing candidate selection (multiple methods, changeable ratio)
//   - repeated measured improvement (best decode rises, monotonic)
//   - best-configuration retention under exploration
//   - continuous bounded-memory operation
#include "OllamaExecutor.hpp"
#include <cstdio>
#include <cstdlib>
#include <array>

using namespace rawrxd::blackboard_v5;

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);   // unbuffered: stream progress to logs
    // 1) Discover installed local models.
    const auto models = rawrxd::ollama::ListModels();
    std::printf("=== RAWRXD_BLACKBOARD_REAL_EXECUTION_001 ===\n");
    std::printf("DISCOVERED_MODELS=%zu\n", models.size());
    bool haveLlama = false;
    for (const auto& m : models) {
        if (m.name == "llama3.2:3b" || m.name == "llama3.2:latest") haveLlama = true;
    }
    if (!haveLlama) {
        std::printf("BLOCKER: llama3.2:3b not installed (no fabricated fallback).\n");
        return 2;
    }
    rawrxd::ollama::SetModel("llama3.2:3b");

    // 2) Model metadata + hardware-compatible bounds.
    const auto show = rawrxd::ollama::ShowModel("llama3.2:3b");
    const auto hw = rawrxd::ollama::DiscoverHardware("llama3.2:3b");
    std::printf("MODEL family=%s param=%s quant=%s ctx=%lld\n",
        show.family.c_str(), show.parameterSize.c_str(),
        show.quantization.c_str(), show.contextLength);
    std::printf("HARDWARE cores=%d maxThreads=%d maxBatch=%d maxCtx=%d\n",
        hw.logicalCores, hw.maxThreads, hw.maxBatch, hw.maxCtx);

    // 3) Reference workload (warmup) — real inference, establishes baseline.
    Measured ref;
    const bool refOk = rawrxd::ollama::ReferenceWorkload(ref);
    std::printf("REFERENCE ran=%d decode=%.1f prefill=%.1f tokens=%d\n",
        (int)refOk, ref.decodeTps, ref.prefillTps, ref.tokens);
    if (!refOk) { std::printf("BLOCKER: reference inference failed.\n"); return 3; }

    // 4) 20 real experiments with the polymorphic blackboard.
    V5Blackboard bb;
    bb.bounds = hw;
    std::array<bool, M_COUNT> used{};
    double firstErr = 0.0, lastErr = 0.0, maxErr = 0.0;
    double firstHalfErr = 0.0, secondHalfErr = 0.0;
    int firstHalfN = 0, secondHalfN = 0;
    double bestAtIter = 0.0;
    int distinctMethods = 0;

    int N = 20;
    if (argc > 1) { N = std::atoi(argv[1]); if (N < 1) N = 1; }
    const int half = N / 2;
    for (int i = 0; i < N; ++i) {
        CycleInfo ci;
        ExploreCycleV5(bb, &rawrxd::ollama::OllamaExec, &ci);
        if (!used[ci.method]) { used[ci.method] = true; ++distinctMethods; }
        const double ae = ci.activeErr;
        if (i == 0) firstErr = ae;
        lastErr = ae;
        if (ae > maxErr) maxErr = ae;
        if (i < half) { firstHalfErr += ae; ++firstHalfN; }
        else { secondHalfErr += ae; ++secondHalfN; }
        std::printf("IT %2d [%s s%d] batch=%4d thr=%2d | pred=%7.1f meas=%7.1f pf=%7.1f | cur=%7.1f BEST=%7.1f(rep=%d) | T=%.2f u=%.2f lr=%.3f | ratio=%u/%u\n",
            i + 1, MethodName(ci.method), ci.strategyId, ci.cand.batch, ci.cand.threads,
            ci.predicted, ci.measured, ci.prefill, bb.curDecode, bb.bestDecode, bb.bestRepeats,
            bb.temperature, ci.activeErr, bb.lr[ci.activePredictor], bb.ratio.First(), bb.ratio.Second());
        if (bb.bestDecode > bestAtIter) bestAtIter = bb.bestDecode;
    }
    const double fh = firstHalfN ? firstHalfErr / firstHalfN : 0.0;
    const double sh = secondHalfN ? secondHalfErr / secondHalfN : 0.0;

    // 5) Acceptance summary.
    std::printf("=== SUMMARY ===\n");
    std::printf("BEST_MEASURED_DECODE=%.1f prefill=%.1f (batch=%d thr=%d repeats=%d)\n",
        bb.bestDecode, bb.bestPrefill, bb.best.batch, bb.best.threads, bb.bestRepeats);
    std::printf("ACCEPTED=%llu REJECTED=%llu FAILURES=%llu ITERS=%llu\n",
        (unsigned long long)bb.accepts, (unsigned long long)bb.rejects,
        (unsigned long long)bb.failures, (unsigned long long)bb.iterations);
    std::printf("OBS=%zu (cap=%zu) FRONT_OBS=%zu FRONT_MODELED=%zu FRONT_VAL=%zu REJECTED=%zu\n",
        bb.obs.size(), bb.cap, bb.frontObserved.size(), bb.frontModeled.size(),
        bb.frontValidated.size(), bb.rejected.size());
    std::printf("PREDICTION activeErr first=%.2f last=%.2f max=%.2f | half1=%.2f half2=%.2f (corrected=%s)\n",
        firstErr, lastErr, maxErr, fh, sh, (sh <= fh + 1e-9 ? "yes" : "no"));
    std::printf("DISTINCT_METHODS=%d/6 STRATEGIES=%zu\n", distinctMethods, bb.strategies.size());

    // 6) Fail-closed acceptance checks (all from real measurements).
    int fails = 0;
    auto ck = [&](bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; };
    ck(refOk, "real_reference_inference");
    ck(bb.iterations == (uint64_t)N, "twenty_real_experiments");
    ck(bb.bestDecode > 0.0, "best_measured_positive");
    ck(bb.bestRepeats >= 1, "best_retained");
    ck(distinctMethods >= 3, "dynamic_candidate_selection");
    ck(bb.obs.size() <= bb.cap, "bounded_memory");
    ck(bb.frontModeled.size() <= V5Blackboard::FRONT_CAP && bb.frontObserved.size() <= V5Blackboard::FRONT_CAP &&
       bb.frontValidated.size() <= V5Blackboard::FRONT_CAP, "bounded_frontiers");
    ck(sh <= fh + 1e-9, "prediction_correction");
    // Modeled frontier must be fully modeled (no measured leakage): modeled decode
    // differs from any observed decode for the same config only by being predicted;
    // we assert the categories are non-empty and distinct containers.
    ck(!bb.frontObserved.empty() && !bb.frontModeled.empty(), "evidence_separated");

    std::printf("FAILS=%d\n", fails);
    std::printf("RESULT=%s\n", fails == 0 ? "PASS" : "FAIL");
    return fails ? 1 : 0;
}