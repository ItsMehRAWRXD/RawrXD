// batch2_live_decode_cert.cpp — BIND16 live 16/16 (DEEP2_ENGINE_SSVK_DECODE_BIND_001)
// OWNER=BIND16_16_16 — do not switch to SOLO; dual-slot deltas required.
#include "Deep2Engine.h"
#include "d2_engine_ssvk_bind16.h"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#ifdef _WIN32
#include <windows.h>
#endif
using namespace Deep2;

int main(int argc, char** argv) {
#ifdef _WIN32
    SetEnvironmentVariableA("DISABLE_LAYER_AMD_SWITCHABLE_GRAPHICS_1", "1");
    _putenv_s("DEEP2_WEIGHT_MODE", "BOUNDED_STREAM");
    _putenv_s("DEEP2_WEIGHT_BUDGET_MIB", "2048");
    _putenv_s("RAWRXD_GPU_POLICY", "MULTI");
    _putenv_s("RAWRXD_GPU_DEVICES", "ALL");
    _putenv_s("RAWRXD_GPU_FWD", "1");
    _putenv_s("RAWRXD_ALLOW_GPU", "1");
    _putenv_s("DEEP2_DUALSTICK_ARM", "1");
    _putenv_s("RAWRXD_DEEP2_SSVK_PRODUCT_STRICT", "1");
    _putenv_s("RAWRXD_DEEP2_GPU_RESIDENT_STRICT", "1");
    _putenv_s("RAWRXD_Q2K_PRODUCT_DECODE", "1");
    _putenv_s("DEEP2_WEIGHT_PREFETCH", "0");
#endif
    const char* model = argc > 1 ? argv[1]
        : "G:\\~dev\\rawrxd\\llama3.2-3b-Q2_K.gguf";
    const char* logPath = argc > 2 ? argv[2]
        : "G:\\~dev\\rawrxd\\evidence\\RAWRXD_PERFORMANCE_001\\"
          "DEEP2_ENGINE_SSVK_DECODE_BIND_001\\bind16_live.log";
    freopen(logPath, "w", stderr);
    printf("GATE=DEEP2_ENGINE_SSVK_DECODE_BIND_001 LIVE model=%s\n", model);
    Deep2Engine engine;
    if (!engine.loadModel(model)) { printf("FAIL load\n"); return 1; }
    const auto& mw = engine.getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true; cfg.useThreadPool = true;
    cfg.numThreads = 16;
    std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", model);
    if (!engine.initialize(cfg)) { printf("FAIL init\n"); return 1; }
    engine.enableVulkan(true);
    engine.enableMedusa(false);
    GenerationOptions o{};
    o.maxTokens = 17; o.temperature = 0; o.topK = 1; o.seed = 42;
    size_t n = 0;
    engine.generateStream("hi", o, [&](int32_t, const std::string&) -> bool {
        ++n; return true;
    });
    const D2Bind16Window* w = engine.ssVkDecodeBindWindow();
    const uint32_t auth = (w && w->authority) ? 1u : 0u;
    const uint32_t pass = w ? w->tokens_pass : 0u;
    const uint32_t committed = w ? w->tokens_committed : 0u;
    if (auth) std::fprintf(stderr, "BIND16_WINDOW_AUTHORITY=1\n");
    else
        std::fprintf(stderr, "BIND16_WINDOW_AUTHORITY=0 pass=%u committed=%u\n",
                     pass, committed);
    printf("TOKENS=%zu BIND16_WINDOW_AUTHORITY=%u pass=%u/%u\n",
           n, auth, pass, committed);
    fflush(stdout); fflush(stderr);
    return (auth && n >= 16) ? 0 : 2;
}
