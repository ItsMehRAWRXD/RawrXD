#include "AggregateDecodeDeep2Backend.hpp"
#include <chrono>

#if defined(AGGREGATE_DECODE_USE_DEEP2)
#include "Deep2Engine.h"
#endif

namespace rawr::aggdec {
namespace {
uint64_t now_ns() {
    using clock = std::chrono::steady_clock;
    return (uint64_t)std::chrono::duration_cast<std::chrono::nanoseconds>(
               clock::now().time_since_epoch())
        .count();
}
} // namespace

AggregateDecodeDeep2Backend::AggregateDecodeDeep2Backend(std::string gguf_path)
    : gguf_path_(std::move(gguf_path)) {}

AggregateDecodeDeep2Backend::~AggregateDecodeDeep2Backend() { close(); }

bool AggregateDecodeDeep2Backend::linked() const {
#if defined(AGGREGATE_DECODE_USE_DEEP2)
    return true;
#else
    return false;
#endif
}

bool AggregateDecodeDeep2Backend::open() {
#if defined(AGGREGATE_DECODE_USE_DEEP2)
    if (open_ && engine_) return true;
    engine_ = std::make_unique<Deep2::Deep2Engine>();
    Deep2::EngineConfig cfg{};
    if (!engine_->initialize(cfg)) { engine_.reset(); return false; }
    if (!engine_->loadModel(gguf_path_)) { engine_.reset(); return false; }
    open_ = true;
    return true;
#else
    open_ = false;
    return false;
#endif
}

void AggregateDecodeDeep2Backend::close() {
#if defined(AGGREGATE_DECODE_USE_DEEP2)
    if (engine_) {
        engine_->unloadModel();
        engine_.reset();
    }
#endif
    open_ = false;
}

SessionMetrics AggregateDecodeDeep2Backend::decode(const DecodeRequest& req,
                                                   TokenEmitFn on_token) {
    SessionMetrics m{};
    m.session_id = req.session_id;
    m.backend = BackendKind::Deep2Engine;
#if defined(AGGREGATE_DECODE_USE_DEEP2)
    std::lock_guard<std::mutex> lock(decode_mu_);
    if (!open_ || !engine_) return m;
    Deep2::GenerationOptions opts;
    opts.maxTokens = req.max_tokens;
    opts.temperature = 0.0f;
    opts.topP = 1.0f;
    opts.topK = 1;
    engine_->configureGeneration(opts);
    const uint64_t t0 = now_ns();
    uint64_t first = 0;
    uint64_t emit = 0;
    auto gr = engine_->generateStream(
        req.prompt, opts,
        [&](int32_t, const std::string&) -> bool {
            if (first == 0) first = now_ns() - t0;
            ++emit;
            return !on_token || on_token((uint32_t)emit);
        });
    const uint64_t t1 = now_ns();
    m.wall_ns = (t1 > t0) ? (t1 - t0) : 0;
    m.first_token_ns = first;
    m.generated_tokens = gr.generatedTokens ? gr.generatedTokens : emit;
    m.tps = (m.wall_ns > 0)
                ? (double)m.generated_tokens / ((double)m.wall_ns / 1e9)
                : 0.0;
    m.ok = m.generated_tokens > 0;
#else
    (void)req;
    (void)on_token;
    // Not linked: refuse fake tokens. Caller must use Ollama or rebuild w/ DEEP2.
    m.ok = false;
#endif
    return m;
}

} // namespace rawr::aggdec
