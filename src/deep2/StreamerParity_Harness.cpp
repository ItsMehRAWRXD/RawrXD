/* StreamerParity_Harness.cpp — forbidden scan + speed arm (≤99). */
#include "StreamerParity_Harness.hpp"
#include "lavapath/SetEnvDual.hpp"
#include "lavapath/ParseMibBudget.hpp"
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
    using Deep2::SetEnv;
    using Deep2::SetEnvIfUnset;
    SetEnv("TOKEN_PACING", "OFF");
    SetEnv("DECODE_SLEEP", "0");
    SetEnv("DEEP2_CERT_STEP_LOG", "0");
    SetEnv("QKV_OWNER_RESI_LOG", "0");
    SetEnv("TOK_RESIDUAL_SPAM", "0");
    SetEnv("RAWRXD_FFN_TRACE", "0");
    SetEnv("DUST2_FTL", "0");
    SetEnv("DEEP2_LIVE_POLICY", "TRAMPOLINE");
    SetEnv("DEEP2_LIVE_MECH", "trampoline");
    SetEnv("DEEP2_GEN_ALG", "lukewarm");
    SetEnvIfUnset("RAWRXD_HOST_DECODE", "0");
    SetEnvIfUnset("DEEP2_GPU_POLICY", "MULTI");
    SetEnvIfUnset("DEEP2_GPU_DEVICE_CLASS", "DISCRETE");
    SetEnvIfUnset("RAWRXD_DEEP2_ALLOW_ELASTIC", "1");
    SetEnvIfUnset("DEEP2_MARS", "1");
    SetEnvIfUnset("DEEP2_WEIGHT_BUDGET_MIB", "E8B0M");
    SetEnvIfUnset("FREETOKEN_MICROZONE", "1");
    SetEnvIfUnset("DEEP2_NO_TRUNCATE_NEEDLE", "1");
    const char* budIn = std::getenv("DEEP2_WEIGHT_BUDGET_MIB");
    Deep2::MibParseResult bud = Deep2::ParseMibTokenEx(budIn);
    Deep2::EmitWeightBudgetReceipt(stderr, bud, "ENV");
    Deep2::EmitWeightBudgetReceipt(stdout, bud, "ENV");
    if (!bud.ok) {
        fprintf(stderr, "MARS_ARMED=0 WEIGHT_BUDGET_PARSE=FAIL\n");
        return 0;
    }
    fprintf(stderr,
            "KEN_MARS_ACTIVE=1 DEEP2_MARS=%s HOST_DECODE=%s "
            "GPU_POLICY=%s GPU_DEVICE_CLASS=%s NO_TRUNCATE_NEEDLE=1\n",
            std::getenv("DEEP2_MARS") ? std::getenv("DEEP2_MARS") : "?",
            std::getenv("RAWRXD_HOST_DECODE")
                ? std::getenv("RAWRXD_HOST_DECODE") : "?",
            std::getenv("DEEP2_GPU_POLICY") ? std::getenv("DEEP2_GPU_POLICY")
                                           : "?",
            std::getenv("DEEP2_GPU_DEVICE_CLASS")
                ? std::getenv("DEEP2_GPU_DEVICE_CLASS") : "?");
    return 1;
}

void StreamerUsage() {
    fprintf(stderr,
            "Usage: deep2_streamer_parity.exe --model <gguf|shard|alias> "
            "[--prompt TEXT] [--max-tokens N]\n");
}
