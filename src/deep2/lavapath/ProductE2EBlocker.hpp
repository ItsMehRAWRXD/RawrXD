#pragma once
/* Blocker emit for PRODUCT_E2E triad gate. ≤99. */
#include <cstdint>
#include <cstdio>

namespace rawr::product {

inline void EmitBlocker(int functional, int liveWs, int fc, int deadline,
                        int modelAuth, int runtime, uint64_t tok,
                        int complete) noexcept {
    const char* bat = "NONE";
    const char* bow = "NONE";
    const char* nxt = "NONE";
    if (!functional) {
        if (!modelAuth) {
            bat = "MODEL_AUTHORITY";
            bow = "Deep2Engine::loadModel";
            nxt = "Load GGUF; re-enter generateStream";
        } else if (!runtime || tok == 0) {
            bat = "DECODE";
            bow = "Deep2Engine::generateStream";
            nxt = "Emit tokens before seal";
        } else if (!complete) {
            bat = "COMPLETION";
            bow = "token_commit/stream_output";
            nxt = "Commit tokens + stream text";
        } else {
            bat = "HOST_FALLBACK";
            bow = "HOST_FORWARD|CPU_F32";
            nxt = "HOST_FWD=0 CPU_F32=0";
        }
    } else if (!liveWs) {
        bat = "LIVE_WORKING_SET";
        bow = "product_open::AcquireWorkingSet";
        nxt = "Bounded WS; OPEN≠FULL_RESIDENCY";
    } else if (!fc) {
        bat = "FUTURE_CONSUMER_READY";
        bow = "HostFutureConsumerPrefetch";
        nxt = "Kick Future1 before Current";
    } else if (!deadline) {
        bat = "TOKEN_WALL_NS";
        bow = "tokenwall::EmitCommitted";
        nxt = "TOKEN_WALL_NS<=6666667";
    }
    std::printf("SPIN_CLOSE_BLOCKER=%s\nSPIN_CLOSE_BLOCKER_OWNER=%s\n", bat,
                bow);
    if (bat[0] != 'N')
        std::printf("BLOCKED_AT=%s\nBLOCKED_OWNER=%s\nNEXT_RUNTIME_ACTION=%s\n",
                    bat, bow, nxt);
}

} // namespace rawr::product
