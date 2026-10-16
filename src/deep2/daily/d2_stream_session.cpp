// ============================================================================
// d2_stream_session.cpp — real Deep2Engine-backed daily session implementation
//
// Replaces the mock/stub session design (mock_backend flag, unimplemented
// session hooks) with a live binding to Deep2::Deep2Engine. Every session owns
// a real engine instance; d2_session_open_model loads a real GGUF through the
// engine; d2_session_generate streams real tokens through the caller's callback
// with cooperative cancel. No simulated output, no mock backend.
// ============================================================================

#include "d2_stream_session.h"
#include "d2_session_internal.h"
#include "d2_deep2_binding.h"
#include "d2_session_engine.h"
#include "d2_stream_metrics.h"
#include "d2_token_sink.h"
#include "d2_adapter_internal.hpp"
#include "Deep2Engine.h"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <new>

namespace {

// ----------------------------------------------------------------------------
// Adapter: real Deep2Engine behind the session's C function-pointer hooks.
// ----------------------------------------------------------------------------

// load_model — load a GGUF into the real engine. Returns 1 on success.
int load_model(void* engine, const char* gguf_path) {
    if (!engine || !gguf_path || gguf_path[0] == '\0') return 0;
    auto* eng = static_cast<Deep2::Deep2Engine*>(engine);
    return eng->loadModel(gguf_path) ? 1 : 0;
}

// generate — stream real tokens from the real engine through the caller's
// D2TokenCallback, honoring cooperative cancel. D2TokenCallback semantics:
// non-zero = keep going, 0 = stop.
int generate(void* engine, const D2GenerateRequest* req, D2TokenCallback cb,
             void* user, D2Cancel* cancel, D2StreamMetrics* metrics) {
    if (!engine || !req || !req->prompt) return 0;
    auto* eng = static_cast<Deep2::Deep2Engine*>(engine);

    d2_cancel_clear(cancel);

    Deep2::GenerationOptions opts{};
    opts.maxTokens = req->max_tokens ? req->max_tokens : 256u;
    opts.temperature = req->temperature;
    opts.seed = req->seed;
    // topP/topK/repeatPenalty/minP stay at GenerationOptions defaults.

    uint64_t generated = 0;
    auto t0 = std::chrono::steady_clock::now();

    Deep2::GenerationResult result = eng->generateStream(req->prompt, opts,
        [&](int32_t tokenId, const std::string& token) -> bool {
            // Cooperative cancel: stop when the caller requests it.
            if (cancel && d2_cancel_requested(cancel)) return false;
            // Forward to the caller's sink callback.
            if (cb) {
                int rc = cb(user, static_cast<uint32_t>(tokenId),
                            token.c_str(), token.size());
                if (rc == 0) return false; // caller asked to stop
            }
            return true;
        });

    generated = result.generatedTokens;
    if (metrics) {
        metrics->prompt_tokens = result.promptTokens;
        metrics->generated_tokens = generated;
        auto t1 = std::chrono::steady_clock::now();
        metrics->wall_ns =
            std::chrono::duration_cast<std::chrono::nanoseconds>(t1 - t0).count();
    }
    return (result.completed && !result.cancelled) ? 1 : 0;
}

} // namespace

// ============================================================================
// Public session API (C linkage, declared in d2_stream_session.h)
// ============================================================================

Deep2StreamSession *d2_session_create(void) {
    auto* s = new (std::nothrow) Deep2StreamSession();
    if (!s) return nullptr;
    std::memset(s, 0, sizeof(*s));

    // Live Deep2Engine backend, not a mock. mock_backend stays 0 for the
    // lifetime of a real session; d2_session_backend_is_mock() reports 0.
    s->mock_backend = 0;

    s->engine = new (std::nothrow) Deep2::Deep2Engine();
    if (!s->engine) {
        delete s;
        return nullptr;
    }

    // Install the default real adapter bindings.
    s->fn_open = load_model;
    s->fn_gen = generate;
    s->fn_cancel = d2_adapt::request_cancel;
    s->fn_reset = d2_adapt::reset_context;
    s->fn_close = d2_adapt::unload_model;

    return s;
}

void d2_session_destroy(Deep2StreamSession *s) {
    if (!s) return;
    if (s->engine) {
        auto* eng = static_cast<Deep2::Deep2Engine*>(s->engine);
        eng->unloadModel();
        delete eng;
        s->engine = nullptr;
    }
    delete s;
}

void d2_session_set_trace(Deep2StreamSession *s, int on) {
    if (!s) return;
    s->trace = (on != 0) ? 1 : 0;
}

// ----------------------------------------------------------------------------
// Model operations
// ----------------------------------------------------------------------------

int d2_session_open_model(Deep2StreamSession *s, const char *gguf_path) {
    if (!s || !gguf_path) return 0;
    if (!s->engine) return 0;

    int rc = 0;
    if (s->fn_open) {
        rc = s->fn_open(s->engine, gguf_path);
    } else {
        // Direct engine fallback when no binding is installed.
        auto* eng = static_cast<Deep2::Deep2Engine*>(s->engine);
        rc = eng->loadModel(gguf_path) ? 1 : 0;
    }
    s->model_loaded = (rc != 0) ? 1 : 0;
    return rc;
}

void d2_session_close_model(Deep2StreamSession *s) {
    if (!s) return;
    if (s->fn_close) {
        s->fn_close(s->engine);
    } else if (s->engine) {
        static_cast<Deep2::Deep2Engine*>(s->engine)->unloadModel();
    }
    s->model_loaded = 0;
}

// ----------------------------------------------------------------------------
// Generation
// ----------------------------------------------------------------------------

int d2_session_generate(Deep2StreamSession *s, const D2GenerateRequest *req,
                        D2TokenCallback cb, void *user) {
    if (!s || !req) return 0;
    if (!s->model_loaded || !s->engine) return 0;

    d2_metrics_reset(&s->metrics);
    d2_cancel_clear(&s->cancel);

    int rc = 0;
    if (s->fn_gen) {
        rc = s->fn_gen(s->engine, req, cb, user, &s->cancel, &s->metrics);
    } else {
        // Direct engine fallback when no binding is installed.
        rc = generate(s->engine, req, cb, user, &s->cancel, &s->metrics) ? 1 : 0;
    }

    if (rc) {
        s->last_generated = s->metrics.generated_tokens;
    }
    return rc;
}

// ----------------------------------------------------------------------------
// Control
// ----------------------------------------------------------------------------

void d2_session_cancel(Deep2StreamSession *s) {
    if (!s) return;
    d2_cancel_request(&s->cancel);
    if (s->fn_cancel) {
        s->fn_cancel(s->engine);
    } else if (s->engine) {
        static_cast<Deep2::Deep2Engine*>(s->engine)->requestCancel();
    }
}

void d2_session_reset_context(Deep2StreamSession *s) {
    if (!s) return;
    d2_cancel_clear(&s->cancel);
    if (s->fn_reset) {
        s->fn_reset(s->engine);
    } else if (s->engine) {
        static_cast<Deep2::Deep2Engine*>(s->engine)->reset();
    }
}

// ----------------------------------------------------------------------------
// Query
// ----------------------------------------------------------------------------

int d2_session_model_loaded(const Deep2StreamSession *s) {
    return s ? s->model_loaded : 0;
}

uint64_t d2_session_last_generated(const Deep2StreamSession *s) {
    return s ? s->last_generated : 0ull;
}
