/* DualStickBundle_Evict.cpp — gemv LRU → DualStick meta clear. ≤99. */
#include "DualStickPinCoherency.hpp"
#include "DualStickReloadAttr.hpp"
#include "MoEPlaceLiveCounters.hpp"

namespace Deep2 {

void DualStickOnGemvPinEvicted(uint64_t pinKey, int mlaCaused) {
    if (ClassifyPinKey(pinKey) != PinWeightClass::MoE) return;
    const int layer = (int)(pinKey >> 24);
    const int expert = (int)((pinKey >> 8) & 0xffffu);
    MoEPlaceLive().moe_pin_evictions++;
    /* mlaCaused: 1=MLA inserter, 2=GENERAL inserter, 0=MoE self-pressure. */
    if (mlaCaused == 1)
        MoEPlaceLive().mla_caused_moe_evictions++;
    else if (mlaCaused == 2)
        MoEPlaceLive().general_caused_moe_evictions++;
    DualStickMarkMoeKeyEvicted(pinKey);
    DualStickInvalidateExpert(layer, expert);
}

} // namespace Deep2
