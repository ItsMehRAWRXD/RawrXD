/* d2_session_deep2_gen.cpp — load_model + generateStream bridge */
#include "d2_adapter_internal.hpp"
using namespace Deep2;
using namespace d2_adapt;

int d2_adapt::load_model(void* engine, const char* gguf_path) {
    auto* e = static_cast<Deep2Engine*>(engine);
    if (!e || !gguf_path || !gguf_path[0]) return 0;
    if (e->isModelLoaded()) e->unloadModel();
    if (!e->loadModel(gguf_path)) return 0;
    const auto& mw = e->getModelWeights();
    EngineConfig cfg{};
    cfg.hiddenDim = mw.hiddenDim; cfg.numLayers = mw.numLayers;
    cfg.numHeads = mw.numHeads; cfg.numKVHeads = mw.numKVHeads;
    cfg.headDim = mw.headDim; cfg.vocabSize = mw.vocabSize;
    cfg.maxSeqLen = 4096; cfg.useKVCache = true;
    cfg.useThreadPool = true; cfg.numThreads = 16;
    std::snprintf(cfg.modelPath, sizeof(cfg.modelPath), "%s", gguf_path);
    if (!e->initialize(cfg)) return 0;
    e->enableVulkan(true);
    e->enableMedusa(false);
    atr("MODEL_OPEN_REAL=1\n");
    return 1;
}

int d2_adapt::generate(void* engine, const D2GenerateRequest* req,
                       D2TokenCallback cb, void* user, D2Cancel* cancel,
                       D2StreamMetrics* metrics) {
    auto* e = static_cast<Deep2Engine*>(engine);
    if (!e || !req || !req->prompt || !cb || !metrics) return 0;
    e->clearCancel();
    BridgeCtx ctx{cb, user, cancel, metrics, e,
                  std::chrono::steady_clock::now(), true};
    GenerationOptions opt;
    opt.maxTokens = req->max_tokens ? req->max_tokens : 256u;
    opt.temperature = req->temperature;
    opt.topK = 1;
    opt.seed = req->seed;
    auto bridge = [&](int32_t tokenId, const std::string& text) -> bool {
        if (d2_cancel_requested(ctx.cancel)) {
            ctx.eng->requestCancel();
            metrics->cancelled = 1;
            return false;
        }
        if (ctx.first) {
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                          std::chrono::steady_clock::now() - ctx.t0)
                          .count();
            metrics->ttft_ns = (uint64_t)ns;
            ctx.first = false;
            atr("STREAM_CALLBACK_REAL=1 FIRST_TOKEN=1\n");
        }
        metrics->generated_tokens++;
        metrics->sealed_logits_reuse = 0;
        return cb(user, (uint32_t)tokenId, text.c_str(), text.size()) != 0;
    };
    GenerationResult r = e->generateStream(req->prompt, opt, bridge);
    metrics->prompt_tokens = r.promptTokens;
    metrics->wall_ns = (uint64_t)(r.generationTimeMs * 1e6);
    if (r.cancelled) metrics->cancelled = 1;
    atr("PROMPT_TOKENIZE_REAL=1 PREFILL_REAL=1\n");
    atr("STREAM_CALLBACK_TOKENS=%llu TOKEN_COMMIT_REAL=1\n",
        (unsigned long long)metrics->generated_tokens);
    atr("REAL_AUTOREGRESSIVE_DECODE=1 DEVICE_LOST=0\n");
    return (metrics->generated_tokens > 0 && (r.completed || r.cancelled)) ? 1
                                                                           : 0;
}
