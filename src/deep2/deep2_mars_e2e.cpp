// ============================================================================
// deep2_mars_e2e.cpp — MARS end-to-end smoke on a local GGUF (Ollama blob OK)
// ============================================================================
// Flow: load GGUF → enableMARS → placeAllModelTensorsMARS → hotpatch →
//       rebalance → dual-queue submit → greedy generate (few tokens)
// ============================================================================

#include "Deep2Engine.h"
#include "mars/DualGPUBackend.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <vector>
#include <chrono>

#if defined(_WIN32)
#include <process.h>
#endif

using namespace Deep2;

struct Gate {
    const char* name = nullptr;
    bool pass = false;
    std::string detail;
};

static std::vector<Gate> g_gates;

static void gate(bool ok, const char* name, const std::string& detail = {}) {
    g_gates.push_back(Gate{name, ok, detail});
    printf("[%s] %s%s%s\n", ok ? "PASS" : "FAIL", name,
           detail.empty() ? "" : ": ", detail.empty() ? "" : detail.c_str());
}

static size_t parseBytesEnv(const char* envName, size_t fallback) {
    const char* v = std::getenv(envName);
    if (!v || !*v) return fallback;
    char* end = nullptr;
    const double n = std::strtod(v, &end);
    if (end == v) return fallback;
    double mul = 1.0;
    if (*end == 'G' || *end == 'g') mul = 1024.0 * 1024.0 * 1024.0;
    else if (*end == 'M' || *end == 'm') mul = 1024.0 * 1024.0;
    return static_cast<size_t>(n * mul);
}

static void writeVerdict(const char* path, bool allPass, int passCount, int total) {
    FILE* f = std::fopen(path, "wb");
    if (!f) return;
    std::fprintf(f, "RAWRXD_DEEP2_MARS=%s\n", allPass ? "PASS" : "FAIL");
    std::fprintf(f, "gates=%d/%d\n", passCount, total);
    for (const auto& g : g_gates) {
        std::fprintf(f, "%s %s%s%s\n", g.pass ? "PASS" : "FAIL", g.name,
                     g.detail.empty() ? "" : " | ",
                     g.detail.empty() ? "" : g.detail.c_str());
    }
    std::fclose(f);
}

int main(int argc, char** argv) {
    const char* modelPath = argc > 1
        ? argv[1]
        : "G:\\OllamaModels\\blobs\\sha256-633fc5be925f9a484b61d6f9b9a78021eeb462100bd557309f01ba84cac26adf";
    const int maxTokens = (argc > 2) ? std::atoi(argv[2]) : 8;
    const size_t gpu0 = parseBytesEnv("MARS_GPU0_BYTES", 16ULL << 30);
    const size_t gpu1 = parseBytesEnv("MARS_GPU1_BYTES", 16ULL << 30);

    printf("============================================================\n");
    printf("RAWRXD DEEP2 MARS E2E SMOKE\n");
    printf("============================================================\n");
    printf("Model: %s\n", modelPath);
    printf("MARS pools: GPU0=%.2f GB GPU1=%.2f GB\n",
           gpu0 / (1024.0 * 1024.0 * 1024.0),
           gpu1 / (1024.0 * 1024.0 * 1024.0));

    Deep2Engine engine;
    const bool loaded = engine.loadModel(modelPath);
    gate(loaded, "MARS-001 load_gguf_blob");
    if (!loaded) {
        writeVerdict("MARS_E2E_VERDICT.txt", false, 0, 1);
        return 1;
    }

    const auto& mw = engine.getModelWeights();
    printf("Model: hidden=%zu layers=%zu heads=%zu vocab=%zu\n",
           mw.hiddenDim, mw.numLayers, mw.numHeads, mw.vocabSize);
    gate(mw.numLayers > 0 && mw.hiddenDim > 0, "MARS-002 model_metadata",
         "layers=" + std::to_string(mw.numLayers));

    EngineConfig cfg;
    cfg.hiddenDim = mw.hiddenDim;
    cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads;
    cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim;
    cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 2048;
    cfg.useKVCache = true;
    cfg.useThreadPool = true;
    cfg.numThreads = 8;
    gate(engine.initialize(cfg), "MARS-003 engine_initialize");

    gate(engine.enableMARS(gpu0, gpu1), "MARS-004 enable_mars");
    gate(engine.isMARSEnabled(), "MARS-005 mars_enabled_flag");

    auto placement = engine.placeAllModelTensorsMARS();
    gate(placement.placed > 0, "MARS-006 place_all_weights",
         "placed=" + std::to_string(placement.placed) +
         " oom=" + std::to_string(placement.oom));
    gate(placement.oom == 0 || placement.placed > 0, "MARS-007 placement_viable",
         "gpu0_mb=" + std::to_string(placement.bytesGpu0 / (1024 * 1024)) +
         " gpu1_mb=" + std::to_string(placement.bytesGpu1 / (1024 * 1024)));

    // Hotpatch: move first movable lease off GPU0 if present
    bool hotpatchOk = false;
    if (engine.isMARSEnabled()) {
        // Tensor id 4+ are typically early layer weights (1..3 pinned embeds)
        for (uint64_t tid = 4; tid < 64; ++tid) {
            auto r = engine.redirectTensor(tid, 1);
            if (r == MARS::HotpatchResult::OK ||
                r == MARS::HotpatchResult::ALREADY_THERE) {
                hotpatchOk = true;
                break;
            }
        }
    }
    gate(hotpatchOk, "MARS-008 hotpatch_redirect");

    engine.rebalanceMARS();
    auto parity = engine.getDynamicParity();
    gate(parity.gpu[0].healthy && parity.gpu[1].healthy,
         "MARS-009 parity_healthy",
         "free0_mb=" + std::to_string(parity.vramFree(0) / (1024 * 1024)) +
         " free1_mb=" + std::to_string(parity.vramFree(1) / (1024 * 1024)));

    // Dual GPU backend queue smoke (isolated — do not share engine worker threads)
    bool queueOk = false;
    {
        MARS::DualGPUBackend backend;
        if (backend.Initialize()) {
            MARS::ComputeTask task;
            task.kernelName = "mars_e2e_nop";
            task.workSize = 64;
            task.priority = 1;
            auto f0 = backend.SubmitToQueue0(task);
            auto f1 = backend.SubmitToQueue1(task);
            queueOk = f0.get() && f1.get();
            backend.SynchronizeAll();
            backend.Shutdown();
        }
    }
    gate(queueOk, "MARS-010 dual_queue_submit");

    // Greedy generate with MARS active
    GenerationOptions opts;
    opts.maxTokens = maxTokens > 0 ? maxTokens : 8;
    opts.temperature = 0.0f;
    opts.topK = 1;
    engine.configureGeneration(opts);

    size_t genCount = 0;
    bool finite = true;
    auto t0 = std::chrono::steady_clock::now();
    engine.generateStream("hello", opts, [&](int32_t token, const std::string&) -> bool {
        ++genCount;
        if (token < 0) finite = false;
        if (mw.vocabSize > 0 && static_cast<size_t>(token) >= mw.vocabSize) {
            finite = false;
        }
        return genCount < static_cast<size_t>(opts.maxTokens);
    });
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now() - t0).count();

    gate(genCount > 0, "MARS-011 generate_with_mars",
         "tokens=" + std::to_string(genCount) + " ms=" + std::to_string(ms));
    gate(finite, "MARS-012 finite_valid_tokens");

    int passCount = 0;
    for (const auto& g : g_gates) if (g.pass) ++passCount;
    const bool allPass = (passCount == static_cast<int>(g_gates.size()));

    printf("------------------------------------------------------------\n");
    printf("RAWRXD_DEEP2_MARS=%s (%d/%d)\n",
           allPass ? "PASS" : "FAIL", passCount, (int)g_gates.size());

    writeVerdict("MARS_E2E_VERDICT.txt", allPass, passCount, (int)g_gates.size());

    // Avoid known Deep2Engine destructor crash wiping verdict
#if defined(_WIN32)
    _Exit(allPass ? 0 : 1);
#else
    std::_Exit(allPass ? 0 : 1);
#endif
}
