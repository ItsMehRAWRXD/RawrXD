/* DualStickBundle_Evict.cpp — gemv LRU → DualStick meta clear. ≤99. */
#include "DualStickPinCoherency.hpp"
#include "MoEPlaceLiveCounters.hpp"

namespace Deep2 {

void DualStickOnGemvPinEvicted(uint64_t pinKey, int mlaCaused) {
    const uint64_t role = pinKey & 0xffu;
    if ((pinKey >> 24) == 0 || role < 1u || role > 3u) return;
    const int layer = (int)(pinKey >> 24);
    const int expert = (int)((pinKey >> 8) & 0xffffu);
    MoEPlaceLive().moe_pin_evictions++;
    if (mlaCaused)
        MoEPlaceLive().mla_caused_moe_evictions++;
    else
        MoEPlaceLive().general_caused_moe_evictions++;
    DualStickInvalidateExpert(layer, expert);
}

} // namespace Deep2
