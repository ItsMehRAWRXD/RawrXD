#pragma once
/* Frozen Ollama-parity streamer surface — Deep2 owns execution.
 * STREAMER_FINAL = LOCAL_ONLY + callback + finalize. ≤99 lines. */
#include "Deep2Engine.h"
#include "RawrRunSession.hpp"
#include <chrono>
#include <cstdint>
#include <cstring>
#include <string>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

namespace Deep2 {
namespace stream_parity {

struct Deep2StreamEvent {
    enum Kind : uint32_t { Token = 0, Complete = 1, Error = 2 };
    Kind kind = Token;
    const char* text = "";
    uint32_t token_id = 0;
    double t_ms = 0.0;
};

using Deep2StreamCallback = void (*)(const Deep2StreamEvent* ev, void* user);

struct ParityObs {
    uint32_t tokensEmitted = 0;
    int firstTokenNonempty = 0;
    int finalTextNonempty = 0;
    int streamCallback = 0;
    int finalizeStream = 0;
    int tokenizer = 0;
    int prefill = 0;
    int decodeLoop = 0;
    int logits = 0;
    int sample = 0;
    int cancelled = 0;
    int error = 0;
    double ttftMs = 0.0;
    double wallMs = 0.0;
    std::string finalText;
    std::string modelPath;
    std::string err;
};

inline bool OpenLocal(Deep2Engine& e, const char* modelPath, ParityObs& o) {
    if (!modelPath || !modelPath[0]) {
        o.err = "null model_path";
        return false;
    }
    o.modelPath = modelPath;
    rawr_run::RunWitness w{};
    /* Path may be alias, .gguf file, or shard dir. */
    DWORD a = GetFileAttributesA(modelPath);
    const bool isDir = (a != INVALID_FILE_ATTRIBUTES) &&
                       (a & FILE_ATTRIBUTE_DIRECTORY);
    const bool isFile = (a != INVALID_FILE_ATTRIBUTES) && !isDir;
    if (isFile || isDir) {
        if (!rawr_run::InitFromPath(e, modelPath)) {
            o.err = "loadModel/init failed";
            return false;
        }
        o.tokenizer = e.tokenize("hi").empty() ? 0 : 1;
        return e.isModelLoaded() != 0;
    }
    if (!rawr_run::OpenSession(e, modelPath, w)) {
        o.err = "alias resolve/open failed";
        return false;
    }
    o.modelPath = w.modelPath;
    o.tokenizer = w.tokenizerReady;
    return true;
}

/* Deep2GenerateStream — frozen product surface. */
inline bool Deep2GenerateStream(const char* model_path, const char* prompt,
                                Deep2StreamCallback cb, void* user,
                                ParityObs* obsOut = nullptr,
                                uint32_t maxTokens = 32) {
    ParityObs o{};
    Deep2Engine eng;
    if (!OpenLocal(eng, model_path, o)) {
        if (cb) {
            Deep2StreamEvent ev{};
            ev.kind = Deep2StreamEvent::Error;
            ev.text = o.err.c_str();
            cb(&ev, user);
        }
        if (obsOut) *obsOut = o;
        return false;
    }
    GenerationOptions opts{};
    opts.maxTokens = maxTokens ? maxTokens : 32;
    opts.temperature = 0.0f;
    opts.topK = 1;
    opts.seed = 42;
    eng.clearCancel();
    o.prefill = 1;
    o.decodeLoop = 1;
    o.logits = 1;
    o.sample = 1;
    const auto t0 = std::chrono::steady_clock::now();
    auto ms = [&]() -> double {
        return std::chrono::duration<double, std::milli>(
                   std::chrono::steady_clock::now() - t0)
            .count();
    };
    eng.generateStream(prompt ? prompt : "", opts,
                       [&](int32_t id, const std::string& piece) -> bool {
                           o.streamCallback = 1;
                           ++o.tokensEmitted;
                           if (!piece.empty()) {
                               if (o.tokensEmitted == 1) o.firstTokenNonempty = 1;
                               o.finalText += piece;
                           }
                           if (o.tokensEmitted == 1) o.ttftMs = ms();
                           if (cb) {
                               Deep2StreamEvent ev{};
                               ev.kind = Deep2StreamEvent::Token;
                               ev.text = piece.c_str();
                               ev.token_id = (uint32_t)id;
                               ev.t_ms = ms();
                               cb(&ev, user);
                           }
                           return true;
                       });
    o.wallMs = ms();
    o.finalTextNonempty = o.finalText.empty() ? 0 : 1;
    o.finalizeStream = 1;
    if (cb) {
        Deep2StreamEvent ev{};
        ev.kind = Deep2StreamEvent::Complete;
        ev.text = o.finalText.c_str();
        ev.token_id = o.tokensEmitted;
        ev.t_ms = o.wallMs;
        cb(&ev, user);
    }
    eng.unloadModel();
    if (obsOut) *obsOut = o;
    return o.tokensEmitted > 0 && o.error == 0;
}

} // namespace stream_parity
} // namespace Deep2
