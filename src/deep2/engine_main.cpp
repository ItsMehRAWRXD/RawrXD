// ============================================================================
// engine_main.cpp — Deep2 engine CLI entry point
//
// Minimal, real entry point so rawrxd_deep2_engine links as an executable.
// Usage:
//   rawrxd_deep2_engine                 -> prints usage and exits 0
//   rawrxd_deep2_engine <model.gguf>    -> loads the model, reports status
//   rawrxd_deep2_engine <model.gguf> "<prompt>" [maxTokens]
//                                      -> loads the model and generates text
//
// The engine object is constructed unconditionally so the deliverable is a
// real, runnable executable; model loading / generation are guarded by args
// so the binary never dereferences an unloaded model.
// ============================================================================

#include "Deep2Engine.h"

#include <windows.h>
#include <cstdio>
#include <cstdlib>
#include <exception>
#include <string>

int main(int argc, char** argv) {
    // Ensure the Windows console emits UTF-8 (not CP1252) so detokenized
    // model output (which is UTF-8 from the BPE tokenizer) renders correctly
    // instead of mojibake like Ã¡lÑ‘Ð½.
    SetConsoleOutputCP(CP_UTF8);
    SetConsoleCP(CP_UTF8);

    std::printf("[deep2-engine] rawrxd_deep2_engine starting\n");

    try {
        Deep2::Deep2Engine engine;

        if (argc < 2) {
            std::printf("usage: %s <model.gguf> [\"prompt\"] [maxTokens]\n",
                        argc > 0 ? argv[0] : "rawrxd_deep2_engine");
            return 0;
        }

        const std::string modelPath = argv[1];
        std::printf("[deep2-engine] loading model: %s\n", modelPath.c_str());
        if (!engine.loadModel(modelPath)) {
            std::fprintf(stderr, "[deep2-engine] loadModel failed: %s\n",
                         modelPath.c_str());
            return 2;
        }
        std::printf("[deep2-engine] model loaded\n");

        // Keep the production executable diagnosable without changing the
        // model or silently changing the default.  A positive bounded value
        // lets a parity run reproduce a single-worker or fixed-width host
        // schedule; when unset, the engine keeps its normal auto-detected
        // pool.  This is intentionally applied after loadModel because the
        // load-only path creates the pool while admitting the real model
        // geometry.
        if (const char* threadEnv = std::getenv("RAWRXD_DEEP2_THREADS")) {
            char* end = nullptr;
            const unsigned long requested = std::strtoul(threadEnv, &end, 10);
            if (end != threadEnv && *end == '\0' && requested >= 1 && requested <= 256) {
                engine.setNumThreads(static_cast<size_t>(requested));
                std::printf("[deep2-engine] ThreadPool: %lu threads (environment override)\n",
                            requested);
            } else {
                std::fprintf(stderr,
                             "[deep2-engine] ignoring invalid RAWRXD_DEEP2_THREADS=%s\n",
                             threadEnv);
            }
        }

        if (argc >= 3) {
            const std::string prompt = argv[2];
            const size_t maxTokens = (argc >= 4)
                ? static_cast<size_t>(std::strtoul(argv[3], nullptr, 10))
                : 256u;
            std::printf("[deep2-engine] prompt: %s\n", prompt.c_str());
            const std::string out = engine.generateText(prompt, maxTokens);
            std::printf("%s\n", out.c_str());
        }
        return 0;
    } catch (const std::exception& e) {
        std::fprintf(stderr, "[deep2-engine] fatal: %s\n", e.what());
        return 3;
    } catch (...) {
        std::fprintf(stderr, "[deep2-engine] fatal: unknown exception\n");
        return 4;
    }
}
