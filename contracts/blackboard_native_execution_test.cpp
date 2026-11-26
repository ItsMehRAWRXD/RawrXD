// blackboard_native_execution_test.cpp — RAWRXD_POLYMORPHIC_NATIVE_EXECUTION_005
//
// Native (non-Ollama) acceptance: the deterministic polymorphic V5 blackboard
// driven by the native Deep2 executor (Deep2::Deep2Engine) on a local GGUF model.
// Produces REAL prefill/decode measurements and GPU dispatch telemetry. No RNG,
// no fabricated scores. Link against deep2_engine_lib (+ggml/Vulkan) to run.
#include "Deep2Executor.hpp"
#include <cstdio>
#include <cstdlib>
#include <array>

using namespace rawrxd::blackboard_v5;

int main(int argc, char** argv) {
    setvbuf(stdout, NULL, _IONBF, 0);

    // 1) Discover local GGUF models (e.g. under OLLAMA_MODELS).
    const char* root = std::getenv("OLLAMA_MODELS");
    const std::string modelRoot = root ? root : "F:\\OllamaModels";
    std::vector<std::string> models = rawrxd::deep2_native::DiscoverGGUF(modelRoot);
    std::printf("=== RAWRXD_POLYMORPHIC_NATIVE_EXECUTION_005 (Deep2) ===\n");
    std::printf("DISCOVERED_GGUF=%zu under %s\n", models.size(), modelRoot.c_str());
    if (models.empty()) { std::printf("BLOCKER: no local GGUF models.\n"); return 2; }

    // 2) Select a model (argv[1] overrides; else first discovered).
    std::string model = (argc > 1) ? argv[1] : models.front();
    rawrxd::deep2_native::SetModelPath(model);
    rawrxd::deep2_native::ClearCancel();
    std::printf("MODEL=%s\n", model.c_str());

    int N = 20;
    if (argc > 2) { N = std::atoi(argv[2]); if (N < 1) N = 1; }
    if (const char* e = std::getenv("RAWRXD_N")) { N = std::atoi(e); if (N < 1) N = 1; }
    if (const char* e = std::getenv("RAWRXD_NUM_PREDICT"))
        rawrxd::deep2_native::Global().numPredict_ = (size_t)std::max(1, std::atoi(e));

    // 3) Drive the deterministic blackboard with the native executor.
    V5Blackboard bb;
    bb.bounds.maxThreads = (int)std::thread::hardware_concurrency();
    std::array<bool, M_COUNT> used{};
    int distinct = 0;
    for (int i = 0; i < N; ++i) {
        CycleInfo ci;
        ExploreCycleV5(bb, &rawrxd::deep2_native::Deep2Exec, &ci);
        if (!used[ci.method]) { used[ci.method] = true; ++distinct; }
        const auto& g = rawrxd::deep2_native::Global().lastGpu;
        std::printf("IT %2d [%s] batch=%4d thr=%2d | pred=%7.1f meas=%7.1f pf=%7.1f | cur=%7.1f BEST=%7.1f(rep=%d) | gpu_layers=%llu submits=%llu fb=%llu resident=%d\n",
            i + 1, MethodName(ci.method), ci.cand.batch, ci.cand.threads,
            ci.predicted, ci.measured, ci.prefill, bb.curDecode, bb.bestDecode, bb.bestRepeats,
            (unsigned long long)g.forwardLayers, (unsigned long long)g.opSubmits,
            (unsigned long long)g.forwardFallbacks, (int)g.resident);
    }

    std::printf("=== SUMMARY ===\n");
    std::printf("BEST_MEASURED_DECODE=%.2f prefill=%.2f (batch=%d thr=%d repeats=%d)\n",
        bb.bestDecode, bb.bestPrefill, bb.best.batch, bb.best.threads, bb.bestRepeats);
    std::printf("ACCEPTED=%llu REJECTED=%llu FAILURES=%llu ITERS=%llu DISTINCT_METHODS=%d HWFAILS=%zu\n",
        (unsigned long long)bb.accepts, (unsigned long long)bb.rejects,
        (unsigned long long)bb.failures, (unsigned long long)bb.iterations, distinct,
        bb.hwFailures.size());
    std::printf("OBJECTIVE requested=%.0f%% observed=%.2f validated=%.2f parity=%d\n",
        bb.objective.requestedPercent, bb.objective.observedPeak,
        bb.objective.validatedPeak, (int)bb.objective.parityCertified);

    int fails = 0;
    auto ck = [&](bool ok, const char* n) { std::printf("%s %s\n", ok ? "OK" : "FAIL", n); if (!ok) ++fails; };
    ck(bb.iterations == (uint64_t)N, "native_experiments");
    ck(bb.bestDecode > 0.0, "native_best_measured");
    ck(distinct >= 3, "native_dynamic_selection");
    ck(bb.obs.size() <= bb.cap, "native_bounded_memory");
    ck(bb.hwFailures.size() <= V5Blackboard::HW_FAIL_CAP, "native_hf_bounded");
    std::printf("FAILS=%d\nRESULT=%s\n", fails, fails == 0 ? "PASS" : "FAIL");
    return fails ? 1 : 0;
}