// StrataTextRunner.hpp -- reusable, tokenizer-injected Strata text-inference core.
//
// This is the SINGLE production text-inference pipeline used by both the native
// IDE bridge (AgenticBridge::ChatViaStrata) and the headless acceptance harness.
// The tokenizer is injected (model-identity matched by the caller) so there is
// no duplicated inference pipeline and no test-only reimplementation.
//
// Flow: tokenize -> StrataChatSession prefill -> autoregressive Step (with
// cooperative cancellation + model-derived max) -> incremental UTF-8 detokenize
// -> structured StrataChatStats. No external server, no subprocess.

#pragma once

#include "deep2/strata_chat.hpp"

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

namespace rawrxd {

struct StrataRunOptions {
    size_t maxTokens = 2048;                         // model-derived cap (caller)
    std::function<bool()> cancelled;                 // optional cooperative cancel
    std::function<void(const std::string&)> onText;  // streaming UTF-8 delta
};

struct StrataRunResult {
    std::string text;
    uint64_t expertAccesses = 0;
    uint64_t expertHits = 0;
    uint64_t expertMisses = 0;
    uint64_t expertEvictions = 0;
    uint64_t transferredBytes = 0;
    uint64_t gpuCalls = 0;
    uint64_t cpuCalls = 0;
    double expertHitRate = 0.0;
    bool ok = false;
    std::string error;
};

class StrataTextRunner {
public:
    using TokenizeFn = std::function<std::vector<int>(const std::string&)>;
    using DetokenizeFn = std::function<std::string(const std::vector<int>&)>;

    StrataTextRunner(std::string modelPath, TokenizeFn tok, DetokenizeFn detok)
        : model_(std::move(modelPath)), tok_(std::move(tok)), detok_(std::move(detok)) {}

    StrataRunResult Run(const std::string& prompt, const StrataRunOptions& opt) {
        StrataRunResult r;
        if (!tok_ || !detok_) { r.error = "tokenizer not provided"; return r; }
        const std::vector<int> inIds = tok_(prompt);
        if (inIds.empty()) { r.error = "tokenizer produced no tokens"; return r; }

        deep2::StrataChatOptions so;
        so.gpu = true;
        so.expertTracking = true;  // R05 cross-token expert residency
        deep2::StrataChatSession sess;
        if (!sess.Open(model_, so)) {
            r.error = sess.Stats().error.empty() ? "strata open failed" : sess.Stats().error;
            return r;
        }
        std::vector<uint32_t> up(inIds.begin(), inIds.end());
        if (!sess.Prefill(up)) {
            sess.Finalise();
            r.error = "strata prefill failed";
            return r;
        }

        std::vector<int> outIds;
        std::string streamed;
        uint32_t next = 0;
        // Strip non-printable control characters (keep \n, \t, and >= 0x20) so
        // the reported/visible text matches the raw detokenized bytes. Control
        // bytes are single-byte, so this is UTF-8 safe and never splits a
        // multibyte sequence. Special-token glyphs are thus excluded.
        auto clean = [](const std::string& s) {
            std::string o;
            o.reserve(s.size());
            for (char c : s) {
                const unsigned char u = static_cast<unsigned char>(c);
                if (u >= 0x20 || c == '\n' || c == '\t') o += c;
            }
            return o;
        };
        for (size_t i = 0; i < opt.maxTokens; ++i) {
            if (opt.cancelled && opt.cancelled()) break;
            if (!sess.Step(next)) break;
            outIds.push_back(static_cast<int>(next));
            // Incremental UTF-8: detokenize the accumulated ids, strip control
            // chars, and emit only the newly completed suffix.
            const std::string full = clean(detok_(outIds));
            if (full.size() > streamed.size()) {
                const std::string piece = full.substr(streamed.size());
                streamed = full;
                if (opt.onText && !piece.empty()) opt.onText(piece);
            }
        }
        sess.Finalise();

        const auto& s = sess.Stats();
        r.text = streamed;
        r.expertAccesses = s.expertAccesses;
        r.expertHits = s.expertHits;
        r.expertMisses = s.expertMisses;
        r.expertEvictions = s.expertEvictions;
        r.transferredBytes = s.expertTransferredBytes;
        r.gpuCalls = s.gpuCalls;
        r.cpuCalls = s.cpuCalls;
        r.expertHitRate = s.expertHitRate;
        r.error = s.error;
        r.ok = s.error.empty() && s.gpuCalls > 0;
        return r;
    }

private:
    std::string model_;
    TokenizeFn tok_;
    DetokenizeFn detok_;
};

}  // namespace rawrxd