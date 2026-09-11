#pragma once
/* ScoreboardEnsureReady — prime+pump one tensor to GpuReady. LIVE=0. ≤99. */
#include "ProductScoreboardPrime.hpp"
#include "ProductScoreboardBind.hpp"

namespace Deep2 {
namespace scoreboard {

inline int EnsureTensorGpuReady(TensorId id) noexcept {
    ProductScoreboardState& s = ProductSb();
    TensorScore* t = s.sb.get(id);
    if (!t)
        return 0;
    uint32_t st = t->state.load(std::memory_order_acquire);
    if (st == (uint32_t)ResidencyState::GpuReady)
        return 1;
    if (st == (uint32_t)ResidencyState::Retired ||
        st == (uint32_t)ResidencyState::Executing)
        return 0;
    if (st == (uint32_t)ResidencyState::Absent)
        (void)ProductScoreboardPrime::Prime(s.sb, id);
    for (int i = 0; i < 12; ++i) {
        st = t->state.load(std::memory_order_acquire);
        if (st == (uint32_t)ResidencyState::GpuReady)
            return 1;
        if (st == (uint32_t)ResidencyState::Retired)
            return 0;
        (void)s.eng.pumpOnce(nullptr, 0, nullptr, 0);
    }
    return t->state.load(std::memory_order_acquire) ==
                   (uint32_t)ResidencyState::GpuReady
               ? 1
               : 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
