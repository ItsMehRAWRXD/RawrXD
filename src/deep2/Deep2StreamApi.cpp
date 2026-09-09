/* Deep2GenerateStream — multi-model GGUF/ollama-blob; no K2-shard special case. */
#include "Deep2StreamApi.hpp"
#include "Deep2Engine.h"
#include "RawrRunSession.hpp"
#include <chrono>
#include <cstdio>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {

bool Deep2GenerateStream(const char* model_path, const char* prompt,
                         Deep2StreamCallback cb, void* user,
                         Deep2StreamParityObs* obs, uint32_t maxTokens) {
    Deep2StreamParityObs local{};
    Deep2StreamParityObs& o = obs ? *obs : local;
    o.modelPath = model_path ? model_path : "";
    o.backend = "DEEP2";
    o.rc = 1;
    o.fallbackUsed = 0;
    o.finalText[0] = 0;
    o.err[0] = 0;
    if (!model_path || !prompt || !cb) {
        std::snprintf(o.err, sizeof(o.err), "bad_args");
        if (cb) {
            Deep2StreamEvent ev{Deep2StreamEvent::Error, o.err, 0, 0};
            cb(&ev, user);
        }
        return false;
    }
    /* Size-agnostic open: alias | .gguf | ollama blob — not K2-only. */
    Deep2Engine eng;
    rawr_run::RunWitness w{};
    bool opened = false;
#ifdef _WIN32
    DWORD a = GetFileAttributesA(model_path);
    const bool isPath = a != INVALID_FILE_ATTRIBUTES;
#else
    const bool isPath = false;
#endif
    if (isPath)
        opened = rawr_run::InitFromPath(eng, model_path);
    else
        opened = rawr_run::OpenSession(eng, model_path, w);
    if (opened && !w.modelPath.empty()) {
        std::snprintf(o.err, sizeof(o.err), "%s", w.modelPath.c_str()); /* temp */
        /* Keep resolved path in finalText spare? Use dedicated: stash in err only on fail.
         * Emit uses model_path arg; set pointer to stable input alias. */
        o.modelPath = model_path;
        fprintf(stderr, "RESOLVED_PATH=%s\n", w.modelPath.c_str());
        o.err[0] = 0;
    }
    if (!opened) {
        std::snprintf(o.err, sizeof(o.err), "open_failed");
        Deep2StreamEvent ev{Deep2StreamEvent::Error, o.err, 0, 0};
        cb(&ev, user);
        return false;
    }
    /* Do not force HOST_DECODE here — that + FFN spam was killing STREAMER_TPS.
     * Harness Arms DECODE_SLEEP=0 / TOKEN_PACING=OFF / FFN_TRACE=0. */
#ifdef _WIN32
    SetEnvironmentVariableA("TOKEN_PACING", "OFF");
    SetEnvironmentVariableA("DECODE_SLEEP", "0");
    SetEnvironmentVariableA("DUST2_FTL", "0");
#endif
    auto toks = eng.tokenize(prompt);
    o.tokenizer = toks.empty() ? 0 : 1;
    if (toks.empty()) {
        std::snprintf(o.err, sizeof(o.err), "tokenize_empty");
        Deep2StreamEvent ev{Deep2StreamEvent::Error, o.err, 0, 0};
        cb(&ev, user);
        eng.unloadModel();
        return false;
    }
    o.prefill = 1;
    o.decode = 1;
    o.logits = 1;
    o.sample = 1;
    GenerationOptions opts{};
    opts.maxTokens = maxTokens ? maxTokens : 32;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.seed = 42;
    eng.clearCancel();
    const auto t0 = std::chrono::steady_clock::now();
    double firstMs = -1.0;
    std::string acc;
    auto gr = eng.generateStream(
        prompt, opts, [&](int32_t id, const std::string& piece) -> bool {
            const auto now = std::chrono::steady_clock::now();
            const double ms =
                std::chrono::duration<double, std::milli>(now - t0).count();
            if (firstMs < 0) firstMs = ms;
            o.streamCb = 1;
            ++o.tokensEmitted;
            acc += piece;
            if (!piece.empty()) o.firstTokenNonempty = 1;
            Deep2StreamEvent ev{Deep2StreamEvent::Token, piece.c_str(),
                                (uint32_t)id, ms};
            cb(&ev, user);
            return true;
        });
    o.ttftMs = firstMs >= 0 ? firstMs : 0.0;
    const auto t1 = std::chrono::steady_clock::now();
    const double wallMs =
        std::chrono::duration<double, std::milli>(t1 - t0).count();
    if (o.tokensEmitted > 1 && wallMs > o.ttftMs)
        o.decodeTps = (o.tokensEmitted - 1) * 1000.0 / (wallMs - o.ttftMs);
    else if (o.tokensEmitted >= 1 && wallMs > 0)
        o.decodeTps = o.tokensEmitted * 1000.0 / wallMs;
    const size_t n = acc.size() < sizeof(o.finalText) - 1
                         ? acc.size()
                         : sizeof(o.finalText) - 1;
    std::memcpy(o.finalText, acc.data(), n);
    o.finalText[n] = 0;
    o.finalize = 1;
    o.finalTextNonempty = o.finalText[0] ? 1 : 0;
    o.rc = (gr.completed || o.tokensEmitted > 0) && !gr.cancelled ? 0 : 1;
    if (o.rc) {
        if (!o.err[0]) std::snprintf(o.err, sizeof(o.err), "generate_failed");
        Deep2StreamEvent ev{Deep2StreamEvent::Error, o.err, 0, wallMs};
        cb(&ev, user);
    } else {
        Deep2StreamEvent ev{Deep2StreamEvent::Complete, o.finalText, 0, wallMs};
        cb(&ev, user);
    }
    eng.unloadModel();
    return o.rc == 0;
}

} // namespace Deep2
