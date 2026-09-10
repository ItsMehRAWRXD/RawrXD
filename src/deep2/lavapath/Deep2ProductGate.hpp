#pragma once
/* Readiness/promote = live generate probe. ≤99.
   PROMOTE_IF = PRODUCT_OPEN_PASS && SESSION_ENTER_PASS
                && GENERATED_TOKENS>0 && TOKEN_COMMIT_PASS;
   PROMOTE=0 until that probe passes. MULTI_FAMILY is next independent gate
   (not part of TinyLlama R25 ProductOpen). MODEL_SIZE/FULL_RESIDENCY ≠ gates. */
#include "TokenWallNs.hpp"
#include <cstdint>

namespace Deep2 {
namespace product_gate {

inline int DeadlineOk(uint64_t tokenWallNs) noexcept {
    return (tokenWallNs > 0 && tokenWallNs <= TOKEN_WALL_TARGET_NS) ? 1 : 0;
}

inline int MeanDeadlineOk(uint64_t tokens, uint64_t wallNs) noexcept {
    if (!tokens || !wallNs) return 0;
    return DeadlineOk(wallNs / tokens);
}

/* Final readiness/promote gate (not MULTI_FAMILY, not TPS). */
inline int PromoteReady(int productOpenPass, int sessionEnterPass,
                        uint64_t generatedTokens,
                        int tokenCommitPass) noexcept {
    return (productOpenPass && sessionEnterPass && generatedTokens > 0ull &&
            tokenCommitPass)
               ? 1
               : 0;
}

} /* namespace product_gate */
} /* namespace Deep2 */
