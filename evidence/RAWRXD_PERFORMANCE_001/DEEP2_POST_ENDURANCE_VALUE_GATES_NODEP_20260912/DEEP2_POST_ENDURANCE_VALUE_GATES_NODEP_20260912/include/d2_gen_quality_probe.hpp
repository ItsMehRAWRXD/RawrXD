#pragma once
#include <cmath>
#include <cstdint>
#include <cstdio>

// Side-only decode-quality seam. No heap ownership, no external deps.
// Emit after logits are finalized and after sampling selects a token.
struct D2GenQualityProbe {
    FILE* f = nullptr;
    bool owned = false;

    bool open(const char* path) {
        close();
        f = std::fopen(path, "wb");
        owned = (f != nullptr);
        return owned;
    }
    void attach(FILE* stream) { close(); f = stream; owned = false; }

    void emit(uint64_t ordinal,
              int64_t selected_token_id,
              double selected_logit,
              double selected_prob,
              int64_t argmax_token_id,
              double argmax_logit,
              bool sampler_valid,
              bool tokenizer_roundtrip,
              bool chat_template_valid) {
        if (!f) return;
        const bool finite = std::isfinite(selected_logit) && std::isfinite(selected_prob) && std::isfinite(argmax_logit);
        std::fprintf(f,
            "token_ordinal=%llu selected_token_id=%lld selected_logit=%.17g selected_prob=%.17g argmax_token_id=%lld argmax_logit=%.17g finite=%d sampler_valid=%d tokenizer_roundtrip=%d chat_template_valid=%d\n",
            (unsigned long long)ordinal,
            (long long)selected_token_id,
            selected_logit,
            selected_prob,
            (long long)argmax_token_id,
            argmax_logit,
            finite ? 1 : 0,
            sampler_valid ? 1 : 0,
            tokenizer_roundtrip ? 1 : 0,
            chat_template_valid ? 1 : 0);
        std::fflush(f);
    }

    void close() { if (owned && f) std::fclose(f); f=nullptr; owned=false; }
    ~D2GenQualityProbe() { close(); }
};
