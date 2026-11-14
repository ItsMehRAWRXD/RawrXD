#pragma once
#include <cmath>
#include <cstdint>
#include <cstdio>

// Side-only decode-quality seam. No heap ownership, no external deps.
// Emit after logits are finalized and after sampling selects a token.
struct D2GenQualityProbe {
    FILE* f = nullptr;
    bool owned = false;
    /* AA4F/AVFIX083: keep counters HERE — not on Deep2Engine tail.
     * Tip-land ProductRuntime embeds sizeof(Deep2Engine)==0x2868; +0x10
     * engine-tail fields overlapped ext@+0x2868 → fclose(modelAlias) VA=-1. */
    uint64_t ordinal = 0;
    int chatValid = 0;
    int tokRoundtrip = 1;

    bool open(const char* path) {
        close();
        f = std::fopen(path, "wb");
        owned = (f != nullptr);
        ordinal = 0;
        tokRoundtrip = 1;
        return owned;
    }
    void attach(FILE* stream) { close(); f = stream; owned = false; }

    void emit(uint64_t ord,
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
            (unsigned long long)ord,
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

    // AVFIX083: reject poison/sentinel FILE* (READ VA=-1). Leak OK.
    void close() {
        FILE* fp = f;
        const bool o = owned;
        f = nullptr;
        owned = false;
        if (!o || !fp) return;
        const auto u = reinterpret_cast<uintptr_t>(fp);
        if (u <= 0x10000ull || u >= (static_cast<uintptr_t>(-1) - 0x1000ull))
            return;
        std::fclose(fp);
    }
    ~D2GenQualityProbe() { close(); }
};

/* AVFIX083: process-local slot so Deep2Engine sizeof matches seh 0x2868. */
struct D2GenQualitySlot {
    D2GenQualityProbe* probe = nullptr;
};
inline D2GenQualitySlot& D2GenQualitySlotFor(const void* /*eng*/) {
    static D2GenQualitySlot s;
    return s;
}
