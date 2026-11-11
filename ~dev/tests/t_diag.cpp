// t_diag.cpp — GPU GEMV defect isolator
// Runs ONE prefill forward for a single layer with full tracing so the
// exact failing dispatch is visible.
#include "deep2/Deep2Engine.h"
#include <cstdio>
#include <vector>
#include <string>

using Deep2::Deep2Engine;
using Deep2::EngineConfig;

std::atomic<uint32_t> g_strictGpuViolations{0};

int main(int argc, char** argv) {
    const char* model = argc > 1 ? argv[1] : "F:\\rawrxd\\model_solo\\tinyllama_fresh.gguf";
    const int strict = argc > 2 ? atoi(argv[2]) : 1;

    Deep2Engine e;
    EngineConfig cfg{};
    cfg.maxSeqLen = 512;
    cfg.numThreads = 0;
    if (!e.initialize(cfg)) { fprintf(stderr, "INIT FAIL\n"); return 1; }
    if (!e.loadModel(model)) { fprintf(stderr, "LOAD FAIL\n"); return 1; }

    e.setVulkanStrictNoCpuFallback(strict != 0);
    e.enableVulkan(true);
    fprintf(stderr, "vulkanInit=%d devices=%u\n", (int)e.isVulkanInitialized(), e.vulkanDeviceCount());

    auto toks = e.tokenize("Hello world, this is a test of the decode path. ");
    fprintf(stderr, "tokens=%zu\n", toks.size());

    // Use the public single-forward bridge for layer 0 on the first token
    std::vector<float> h(2048, 0.0f), out(2048, 0.0f);
    if (!e.embedToken(toks[0], h.data())) { fprintf(stderr, "EMBED FAIL\n"); return 2; }

    // API contract: seqLen must equal kvCache->currentLength()+1, exactly as
    // the production decode loop derives it (Deep2Engine::generate).
    const size_t seq = 1;
    const bool ok = e.forwardTokenAllLayers(h.data(), seq);
    fprintf(stderr, "FORWARD_OK=%d strictViolation=%u unplanned=%llu\n",
        (int)ok, (unsigned)e.vulkanStrictViolation(),
        (unsigned long long)e.vulkanUnplannedFallbacks());

    const auto& gf = e.gpuForwardCounters();
    fprintf(stderr, "rmsNormOps=%llu qkvOps=%llu ropeOps=%llu attnScore=%llu softmax=%llu "
        "attnVal=%llu oProj=%llu residual=%llu ffnNorm=%llu ffnAct=%llu ffnResid=%llu "
        "forwardLayers=%llu dualRow=%llu q4kPacked=%llu hostMat=%llu gemvSucc=%llu gemvFail=%llu\n",
        (unsigned long long)gf.rmsNormOps, (unsigned long long)gf.qkvOps,
        (unsigned long long)gf.ropeOps, (unsigned long long)gf.attnScoreOps,
        (unsigned long long)gf.softmaxOps, (unsigned long long)gf.attnValueOps,
        (unsigned long long)gf.oProjOps, (unsigned long long)gf.residualOps,
        (unsigned long long)gf.ffnNormOps, (unsigned long long)gf.ffnActOps,
        (unsigned long long)gf.ffnResidualOps, (unsigned long long)gf.forwardLayers,
        (unsigned long long)gf.dualRowSplitOps, (unsigned long long)gf.q4kPackedOps,
        (unsigned long long)gf.hostMaterializations,
        (unsigned long long)e.vulkanGemvSuccessCount(),
        (unsigned long long)e.vulkanGemvFallbackCount());
    return ok ? 0 : 3;
}
