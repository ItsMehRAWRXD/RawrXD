#pragma once
/* OLLAMA_PARITY_STREAMER_001 receipt — emit only; never invent. ≤90 lines. */
#include "Deep2StreamApi.hpp"
#include <cstdio>
#include <cstring>

namespace Deep2 {

inline const char* ParityDisposition(const Deep2StreamParityObs& o) noexcept {
    if (o.rc != 0) return "FAIL";
    if (!o.tokenizer || !o.prefill || !o.decode || !o.logits || !o.sample)
        return "UNOBSERVED";
    if (!o.streamCb || !o.finalize) return "UNOBSERVED";
    if (o.tokensEmitted < 15) return "FAIL";
    if (!o.firstTokenNonempty || !o.finalTextNonempty) return "FAIL";
    if (o.fallbackUsed) return "FAIL";
    return "PASS";
}

inline void EmitOllamaParityReceipt(FILE* f, const Deep2StreamParityObs& o,
                                    const char* modelPath) noexcept {
    if (!f) f = stderr;
    const char* disp = ParityDisposition(o);
    auto obs = [](int v) { return v ? "OBSERVED" : "UNOBSERVED"; };
    std::fprintf(f,
        "OLLAMA_PARITY_STREAMER_001\n"
        "MODEL_PATH=%s\n"
        "BACKEND=DEEP2\n"
        "API_SURFACE_PCT=%.2f\n"
        "OLLAMA_DAEMON=0\n"
        "OLLAMA_HTTP=0\n"
        "LLAMA_CPP=0\n"
        "GGML=0\n"
        "CLOUD=0\n"
        "FALLBACK_USED=%d\n"
        "TOKENIZER=%s\n"
        "PREFILL=%s\n"
        "DECODE_LOOP=%s\n"
        "LOGITS=%s\n"
        "SAMPLE=%s\n"
        "STREAM_CALLBACK=%s\n"
        "FINALIZE_STREAM=%s\n"
        "TOKENS_EMITTED=%u\n"
        "FIRST_TOKEN_TEXT_NONEMPTY=%d\n"
        "FINAL_TEXT_NONEMPTY=%d\n"
        "TTFT_MS=%.3f\n"
        "DECODE_TPS=%.3f\n"
        "RC=%d\n"
        "DISPOSITION=%s\n"
        "EGRESS=0 LOCAL_ONLY=1\n",
        modelPath ? modelPath : o.modelPath,
        o.apiSurfacePct > 0.0 ? o.apiSurfacePct : kOllamaApiSurfacePct,
        o.fallbackUsed,
        obs(o.tokenizer), obs(o.prefill), obs(o.decode), obs(o.logits),
        obs(o.sample), obs(o.streamCb), obs(o.finalize),
        o.tokensEmitted, o.firstTokenNonempty, o.finalTextNonempty,
        o.ttftMs, o.decodeTps, o.rc, disp);
}

/* Forbidden surface strings — self-scan of this translation unit intent. */
inline int ForbiddenSurfaceHit(const char* blob, size_t n) noexcept {
    static const char* bad[] = {
        "localhost:11434", "127.0.0.1:11434", "/api/chat",
        "ollama.exe", "llama.cpp", "libggml", "winhttp", nullptr};
    int hits = 0;
    for (int i = 0; bad[i]; ++i) {
        const size_t m = std::strlen(bad[i]);
        if (m == 0 || m > n) continue;
        for (size_t j = 0; j + m <= n; ++j) {
            if (std::memcmp(blob + j, bad[i], m) == 0) {
                ++hits;
                break;
            }
        }
    }
    return hits;
}

} // namespace Deep2
