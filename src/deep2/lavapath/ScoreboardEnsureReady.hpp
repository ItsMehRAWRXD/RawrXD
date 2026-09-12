#pragma once
/* ScoreboardEnsureReady — prime+pump one tensor to GpuReady. LIVE=0. ≤99. */
#include "ProductScoreboardPrime.hpp"
#include "ScoreboardProductState.hpp"

namespace Deep2 {
namespace scoreboard {

inline void RearmTensorAbsent(TensorScore* t) noexcept {
    if (!t)
        return;
    const uint32_t st = t->state.load(std::memory_order_acquire);
    if (st == (uint32_t)ResidencyState::Absent ||
        st == (uint32_t)ResidencyState::IoPending ||
        st == (uint32_t)ResidencyState::RamReady ||
        st == (uint32_t)ResidencyState::GpuPending ||
        st == (uint32_t)ResidencyState::GpuReady)
        return;
    t->state.store((uint32_t)ResidencyState::Absent, std::memory_order_release);
    t->ramWindow = nullptr;
    t->gpuWindow = nullptr;
    t->consumersRemaining.store(1, std::memory_order_relaxed);
}

inline void RearmAllRetiredForWalk() noexcept {
    ProductScoreboardState& s = ProductSb();
    for (uint32_t i = 0; i < s.sb.n && i < 64u; ++i)
        RearmTensorAbsent(s.sb.get(i));
}

inline int EnsureTensorGpuReady(TensorId id) noexcept {
    ProductScoreboardState& s = ProductSb();
    TensorScore* t = s.sb.get(id);
    if (!t)
        return 0;
    uint32_t st = t->state.load(std::memory_order_acquire);
    if (st == (uint32_t)ResidencyState::GpuReady)
        return 1;
    RearmTensorAbsent(t);
    st = t->state.load(std::memory_order_acquire);
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
