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

/* 1 if MoE pin is hot-set or live DualStick bundle (protect from cold thrash). */
int DualStickMoePinProtected(uint64_t pinKey);

/* Re-publish VC quota floors into MoEPlaceLive after LiveReset. */
void DualStickSyncQuotaLiveCounters();

} // namespace Deep2
