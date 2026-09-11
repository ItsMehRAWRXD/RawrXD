#pragma once
/* ScoreboardJoinDemote — first ForwardMLALayers ready-await tip.
   SCOREBOARD_WAIT_PER_LAYER stays 1; WAIT_PER_LAYER_LIVE stays 0. ≤99. */
#include "ProductScoreboardBind.hpp"
#include <atomic>
#include <cstdint>

namespace Deep2 {
namespace scoreboard {

struct JoinDemoteHooks {
    std::atomic<uint32_t> readySkipObs{0};
    std::atomic<uint32_t> pumpContinueObs{0};
    std::atomic<uint32_t> fallbackJoinObs{0};
};

inline JoinDemoteHooks& JoinDemote() {
    static JoinDemoteHooks h;
    return h;
}

/* Returns 1 if caller may skip join (already ready). Else 0 → join. */
template <typename GateT>
inline int TryReadyAwaitTip(GateT& gate) noexcept {
    if (gate.ready.load(std::memory_order_acquire)) {
        JoinDemote().readySkipObs.fetch_add(1, std::memory_order_acq_rel);
        return 1;
    }
    if (P1Wit().bindObs.load(std::memory_order_acquire)) {
        (void)ProductSb().eng.pumpOnce(nullptr, 0, nullptr, 0);
        JoinDemote().pumpContinueObs.fetch_add(1, std::memory_order_acq_rel);
        if (gate.ready.load(std::memory_order_acquire)) {
            JoinDemote().readySkipObs.fetch_add(1, std::memory_order_acq_rel);
            return 1;
        }
    }
    JoinDemote().fallbackJoinObs.fetch_add(1, std::memory_order_acq_rel);
    return 0;
}

} /* namespace scoreboard */
} /* namespace Deep2 */
