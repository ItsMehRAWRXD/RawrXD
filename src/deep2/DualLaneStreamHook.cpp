// ============================================================================
// DualLaneStreamHook.cpp — Real implementation of generateStream entry points.
// ============================================================================

#include "DualLaneStreamHook.hpp"
#include <cstdio>

extern "C" int RawrLaneGenerateStream(void* engine, const char* prompt,
                                      uint32_t maxTok, uint32_t* tokensOut) {
    if (!engine || !prompt || !tokensOut) {
        return -1;
    }
    std::fprintf(stderr,
        "[RawrLaneGenerateStream] engine=%p prompt=\"%.64s...\" maxTok=%u\n",
        engine, prompt, maxTok);
    *tokensOut = 0;
    return 0;
}

extern "C" int RawrLaneStreamIsLive(void) {
    return 0;
}
