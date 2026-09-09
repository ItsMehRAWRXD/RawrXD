#pragma once
/* Frozen Ollama-parity stream surface — Deep2 owns execution.
 * NOT_REQUIRED: ollama daemon, :11434, llama.cpp, ggml, cloud, fake stream.
 * API_SURFACE_PCT = 11.11 (1/9 of Ollama HTTP surface: stream generate only). */
#include <cstdint>

namespace Deep2 {

/* Declared Ollama-compatible surface fraction (stream path only). */
inline constexpr double kOllamaApiSurfacePct = 11.11;

struct Deep2StreamEvent {
    enum Kind : uint8_t { Token = 0, Complete = 1, Error = 2 };
    Kind kind = Token;
    const char* text = "";
    uint32_t token_id = 0;
    double t_ms = 0.0;
};

using Deep2StreamCallback = void (*)(const Deep2StreamEvent* ev, void* user);

struct Deep2StreamParityObs {
    int tokenizer = 0, prefill = 0, decode = 0, logits = 0, sample = 0;
    int streamCb = 0, finalize = 0;
    uint32_t tokensEmitted = 0;
    int firstTokenNonempty = 0, finalTextNonempty = 0;
    int fallbackUsed = 0, rc = 1;
    const char* modelPath = "";
    const char* backend = "DEEP2";
    double ttftMs = 0.0, decodeTps = 0.0;
    double apiSurfacePct = kOllamaApiSurfacePct;
    char finalText[4096]{};
    char err[256]{};
};

/* open → tokenize→prefill→decode→sample → callback → finalize → unload */
bool Deep2GenerateStream(const char* model_path, const char* prompt,
                         Deep2StreamCallback cb, void* user,
                         Deep2StreamParityObs* obs = nullptr,
                         uint32_t maxTokens = 32);

} // namespace Deep2
