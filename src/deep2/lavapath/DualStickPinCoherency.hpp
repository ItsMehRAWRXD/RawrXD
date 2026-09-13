#pragma once
/* DualStick pin-eviction coherency — CACHE_RESIDENT=0 ⇒ meta not ready. */
#include "DualStickExpertBundle.hpp"
#include <cstdint>

namespace Deep2 {

/* LRU / Release victim was MoE expert pin → clear bundle + resident slot. */
void DualStickOnGemvPinEvicted(uint64_t pinKey, int mlaCaused);

/* Drop DualStick meta for (layer,expert); pins_ready becomes false. */
void DualStickInvalidateExpert(int layer, int expert);

/* Secondary: bump lastUse on gate+up+down if still pinned. */
void DualStickBundleTouchPins(unsigned stick, int layer, int expert, size_t H,
                              size_t I);

} // namespace Deep2
