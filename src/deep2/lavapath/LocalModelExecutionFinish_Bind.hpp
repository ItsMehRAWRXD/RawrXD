#pragma once
/* ProductRuntime / Deep2Engine::generateStream bind — no alt generator. ≤99. */
#include "LocalModelExecutionFinish.hpp"
#include "ProductRuntime.hpp"
#include <string>

namespace RawrXD::Finish {

inline EndReason MapEnd(const Deep2::GenerationResult& gr, uint32_t maxTokens) {
    if (gr.cancelled) return EndReason::Cancelled;
    if (gr.generatedTokens == 0) return EndReason::Error;
    if (gr.generatedTokens < maxTokens) return EndReason::Eos;
    return EndReason::MaxTokens;
}

inline Deep2Binding BindProductDeep2() {
    static thread_local std::string stash;
    static thread_local SessionId sid = kInvalidSession;
    Deep2Binding ops;
    ops.create_session = [](const Authority& a, std::string& err) -> std::optional<SessionId> {
        auto& rt = rawr::product_run::SharedProductRuntime();
        if (rt.IsOpen()) rt.CloseSession();
        if (!rt.OpenSession(a.canonical_model.c_str())) {
            err = "ProductRuntime OpenSession failed";
            return std::nullopt;
        }
        sid = 1;
        stash.clear();
        return sid;
    };
    ops.prefill = [](SessionId s, std::string_view prompt, std::string& err) -> bool {
        auto& rt = rawr::product_run::SharedProductRuntime();
        if (s != sid || !rt.IsOpen()) {
            err = "prefill: no active ProductRuntime session";
            return false;
        }
        rt.Eng().clearCancel();
        rt.Eng().reset();
        stash.assign(prompt.begin(), prompt.end());
        if (rt.Eng().tokenize(stash).empty()) {
            err = "Deep2 tokenize(prefill) returned empty";
            return false;
        }
        return true;
    };
    ops.generate_stream = [](SessionId s, uint32_t maxTokens,
                             const std::function<bool(const StreamToken&)>& cb) {
        StreamResult sr;
        auto& rt = rawr::product_run::SharedProductRuntime();
        if (s != sid || !rt.IsOpen() || stash.empty()) {
            sr.error = stash.empty() ? "prefill stash empty" : "no active session";
            return sr;
        }
        Deep2::GenerationOptions opts{};
        opts.maxTokens = maxTokens;
        opts.temperature = 0.f;
        opts.topK = 1;
        opts.seed = 42;
        rt.Eng().clearCancel();
        auto gr = rt.Eng().generateStream(stash, opts, [&](int32_t id, const std::string& p) {
            return cb(StreamToken{id, p});
        });
        sr.tokens = static_cast<uint32_t>(gr.generatedTokens);
        sr.reason = MapEnd(gr, maxTokens);
        if (sr.reason == EndReason::Error) sr.error = "Deep2 generateStream produced 0 tokens";
        return sr;
    };
    ops.request_cancel = [](SessionId s, std::string& err) {
        auto& rt = rawr::product_run::SharedProductRuntime();
        if (s != sid || !rt.IsOpen()) {
            err = "cancel: no active session";
            return false;
        }
        if (!rt.CancelGeneration()) {
            err = "CancelGeneration refused";
            return false;
        }
        return true;
    };
    ops.unload = [](SessionId s, std::string& err) {
        auto& rt = rawr::product_run::SharedProductRuntime();
        if (s != sid) {
            err = "unload: session id mismatch";
            return false;
        }
        rt.CloseSession();
        sid = kInvalidSession;
        stash.clear();
        if (rt.IsOpen()) {
            err = "unload: session still open";
            return false;
        }
        return true;
    };
    return ops;
}

} // namespace RawrXD::Finish
