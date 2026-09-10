#pragma once
/* MODEL_SIZE/FULL_RESIDENCY are not gates. ≤99.
   PROMOTE_IF = LIVE_WORKING_SET && FUTURE_CONSUMER_READY && TOKEN_WALL_NS<=6666667;
   PROMOTE=0 until live product E2E correctness + deadline; TIP_CLIMB=HOLD. */
#include "TokenWallNs.hpp"
#include <cstdint>

namespace Deep2 {
namespace product_gate {

inline int DeadlineOk(uint64_t tokenWallNs) noexcept {
    return (tokenWallNs > 0 && tokenWallNs <= TOKEN_WALL_TARGET_NS) ? 1 : 0;
}

/* Mean wall from session total; 0 tokens → not ready. */
inline int MeanDeadlineOk(uint64_t tokens, uint64_t wallNs) noexcept {
    if (!tokens || !wallNs) return 0;
    return DeadlineOk(wallNs / tokens);
}

inline int PromoteReady(int liveWs, int fcReady, uint64_t tokenWallNs) noexcept {
    return (liveWs && fcReady && DeadlineOk(tokenWallNs)) ? 1 : 0;
}

} /* namespace product_gate */
} /* namespace Deep2 */
