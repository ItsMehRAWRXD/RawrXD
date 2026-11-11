// ============================================================================
// DualLaneStreamHook.cpp — Real C interface to Deep2Engine generateStream.
// ============================================================================

#include "DualLaneStreamHook.hpp"
#include "../Deep2Engine.h"
#include <cstdio>

extern "C" int RawrLaneGenerateStream(void* engine, const char* prompt,
                                       uint32_t maxTok, uint32_t* tokensOut) {
    if (!engine || !prompt || !tokensOut) {
        return -1;
    }

    auto* eng = static_cast<Deep2::Deep2Engine*>(engine);
    std::string result = eng->generateText(prompt, maxTok);

    *tokensOut = static_cast<uint32_t>(result.size());
    std::fprintf(stderr,
        "[RawrLaneGenerateStream] engine=%p prompt=\"%.64s...\" maxTok=%u tokensOut=%u\n",
        engine, prompt, maxTok, *tokensOut);
    return 0;
}

extern "C" int RawrLaneStreamIsLive(void) {
    // No global stream state in this build; stream liveness is per-engine.
    return 0;
}
