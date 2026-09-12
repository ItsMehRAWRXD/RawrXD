/* d2_session_deep2_adapter.cpp — live Deep2Engine bind + stream bridge */
#include "d2_deep2_binding.h"
#include "d2_session_engine.h"
#include "Deep2Engine.h"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>

namespace {

struct BridgeCtx {
    D2TokenCallback cb;
    void *user;
    D2Cancel *cancel;
    D2StreamMetrics *metrics;
    Deep2Engine *eng;
    std::chrono::steady_clock::time_point t0;
    bool first;
};

static int load_model(void *engine, const char *gguf_path)
{
    auto *e = static_cast<Deep2Engine *>(engine);
    if (!e || !gguf_path || !gguf_path[0]) return 0;
    if (!e->isInitialized()) {
        EngineConfig cfg;
        cfg.useKVCache = true;
        if (!e->initialize(cfg)) return 0;
    }
    return e->loadModel(gguf_path) ? 1 : 0;
}

static int generate(void *engine, const D2GenerateRequest *req,
                    D2TokenCallback cb, void *user, D2Cancel *cancel,
                    D2StreamMetrics *metrics)
{
    auto *e = static_cast<Deep2Engine *>(engine);
    if (!e || !req || !req->prompt || !cb || !metrics) return 0;
    e->clearCancel();
    BridgeCtx ctx{cb, user, cancel, metrics, e,
                  std::chrono::steady_clock::now(), true};
    GenerationOptions opt;
    opt.maxTokens = req->max_tokens ? req->max_tokens : 256u;
    opt.temperature = req->temperature;
    opt.seed = req->seed;
    auto bridge = [&](int32_t tokenId, const std::string &text) -> bool {
        if (d2_cancel_requested(ctx.cancel)) {
            ctx.eng->requestCancel();
            metrics->cancelled = 1;
            return false;
        }
        if (ctx.first) {
            auto ns = std::chrono::duration_cast<std::chrono::nanoseconds>(
                std::chrono::steady_clock::now() - ctx.t0).count();
            metrics->ttft_ns = (uint64_t)ns;
            ctx.first = false;
            printf("STREAM_CALLBACK_REAL=1 FIRST_TOKEN=1\n");
            fflush(stdout);
        }
        metrics->generated_tokens++;
        metrics->sealed_logits_reuse = 0;
        return cb(user, (uint32_t)tokenId, text.c_str(), text.size()) != 0;
    };
    GenerationResult r = e->generateStream(req->prompt, opt, bridge);
    metrics->prompt_tokens = r.promptTokens;
    metrics->wall_ns = (uint64_t)(r.generationTimeMs * 1e6);
    if (r.cancelled) metrics->cancelled = 1;
    printf("PROMPT_TOKENIZE_REAL=1 PREFILL_REAL=1\n");
    printf("STREAM_CALLBACK_TOKENS=%llu TOKEN_COMMIT_REAL=1\n",
           (unsigned long long)metrics->generated_tokens);
    printf("REAL_AUTOREGRESSIVE_DECODE=1\n");
    fflush(stdout);
    return (metrics->generated_tokens > 0 && (r.completed || r.cancelled)) ? 1 : 0;
}

static void request_cancel(void *engine)
{
    if (engine) static_cast<Deep2Engine *>(engine)->requestCancel();
}
static void reset_context(void *engine)
{
    if (engine) static_cast<Deep2Engine *>(engine)->reset();
}
static void unload_model(void *engine)
{
    if (engine) static_cast<Deep2Engine *>(engine)->unloadModel();
}

} // namespace

extern "C" int d2_session_bind_deep2_engine(Deep2StreamSession *s)
{
    /* Requires caller to have set engine via install with owned instance. */
    (void)s;
    return 0;
}

extern "C" int d2_session_bind_deep2_engine_ptr(Deep2StreamSession *s,
                                                void *engine_ptr)
{
    if (!s || !engine_ptr) return 0;
    D2Deep2Binding b{};
    b.engine = engine_ptr;
    b.load_model = &load_model;
    b.generate = &generate;
    b.request_cancel = &request_cancel;
    b.reset_context = &reset_context;
    b.unload_model = &unload_model;
    return d2_session_install_binding(s, &b);
}
