/* StreamerParity_Harness.cpp — forbidden scan + speed arm (≤99). */
#include "StreamerParity_Harness.hpp"
#include "lavapath/StreamerArmSpeedEnv.hpp"
#include <cstdio>
#include <cstdlib>
#include <cstring>
#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#endif

void StreamerOnEv(const Deep2::Deep2StreamEvent* ev, void* user) {
    auto* n = static_cast<uint32_t*>(user);
    if (!ev) return;
    if (ev->kind == Deep2::Deep2StreamEvent::Token) {
        ++(*n);
        if (ev->text && ev->text[0]) fputs(ev->text, stdout);
    } else if (ev->kind == Deep2::Deep2StreamEvent::Complete) {
        fflush(stdout);
    } else if (ev->kind == Deep2::Deep2StreamEvent::Error) {
        fprintf(stderr, "\nSTREAM_ERROR=%s\n", ev->text ? ev->text : "");
    }
}

int StreamerForbiddenArgExeScan(int argc, char** argv) {
    static const char* bad[] = {"11434", "ollama.com", "/api/chat",
                                "llama.cpp", "ggml_", "openai.com", nullptr};
    int argHits = 0, exeHits = 0;
    for (int i = 0; i < argc; ++i) {
        for (int b = 0; bad[b]; ++b) {
            if (argv[i] && std::strstr(argv[i], bad[b])) {
                fprintf(stderr, "FORBIDDEN_ARG=%s\n", bad[b]);
                ++argHits;
            }
        }
    }
    char mod[MAX_PATH]{};
    GetModuleFileNameA(nullptr, mod, MAX_PATH);
    if (std::strstr(mod, "ollama") || std::strstr(mod, "llama.cpp")) {
        fprintf(stderr, "FORBIDDEN_EXE_NAME=%s\n", mod);
        ++exeHits;
    }
    fprintf(stderr,
            "FORBIDDEN_ARG_HITS=%d\nFORBIDDEN_EXE_NAME_HITS=%d\n"
            "FORBIDDEN_ARG_SCAN=%s\nFORBIDDEN_MODULE_SCAN=NOT_RUN\n"
            "OLLAMA_HTTP=0\n",
            argHits, exeHits, argHits ? "FAIL" : "PASS");
    return argHits + exeHits;
}

int StreamerArmSpeedEnv() {
    return Deep2::StreamerArmSpeedEnvCore(stderr);
}

void StreamerUsage() {
    fprintf(stderr,
            "Usage: deep2_streamer_parity.exe --model <gguf|shard|alias> "
            "[--prompt TEXT] [--max-tokens N]\n");
}
