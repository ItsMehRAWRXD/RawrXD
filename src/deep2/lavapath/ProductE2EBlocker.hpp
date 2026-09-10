#pragma once
/* Blocker emit for live-generate promote tetrad. ≤99. */
#include <cstdint>
#include <cstdio>

namespace rawr::product {

inline void EmitBlocker(int openPass, int sessionEnter, uint64_t genTok,
                        int commitPass) noexcept {
    const char* bat = "NONE";
    const char* bow = "NONE";
    const char* nxt = "NONE";
    if (!openPass) {
        bat = "PRODUCT_OPEN_PASS";
        bow = "ProductOpenSession|OpenSession";
        nxt = "Streamable OPEN; OPEN≠FULL_RESIDENCY";
    } else if (!sessionEnter) {
        bat = "SESSION_ENTER_PASS";
        bow = "ProductRun|generateStream";
        nxt = "Enter product decode session";
    } else if (genTok == 0) {
        bat = "GENERATED_TOKENS";
        bow = "generateStream/token_emit";
        nxt = "Emit GENERATED_TOKENS>0";
    } else if (!commitPass) {
        bat = "TOKEN_COMMIT_PASS";
        bow = "token_commit/stream_output";
        nxt = "Commit tokens + stream receipt";
    }
    std::printf("SPIN_CLOSE_BLOCKER=%s\nSPIN_CLOSE_BLOCKER_OWNER=%s\n", bat,
                bow);
    if (bat[0] != 'N')
        std::printf("BLOCKED_AT=%s\nBLOCKED_OWNER=%s\nNEXT_RUNTIME_ACTION=%s\n",
                    bat, bow, nxt);
}

} // namespace rawr::product
