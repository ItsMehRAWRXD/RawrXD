/* DualStickBundle_Pins.cpp — PinsReady + stale-meta repair. ≤99. */
#include "DualStickExpertBundle.hpp"
#include "DualStickPinCoherency.hpp"
#include "DualStickStreamWindow.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "vulkan_compute.h"

namespace Deep2 {

int DualStickBundlePinsReady(unsigned stick, int layer, int expert, size_t H,
                             size_t I) {
    DualStickBundleMeta m{};
    if (!DualStickBundleLookup(layer, expert, &m)) return 0;
    if ((m.stick & 1u) != (stick & 1u)) return 0;
    auto* vc = DualStickVc(stick);
    if (!vc || !H || !I || !m.gb || !m.ub || !m.db) return 0;
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    const int ok =
        vc->HasPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 1),
                                m.gb, rI, cH) &&
        vc->HasPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 2),
                                m.ub, rI, cH) &&
        vc->HasPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 3),
                                m.db, rH, cI);
    /* Invariant: never PinsReady while CACHE_RESIDENT=0. */
    if (!ok) {
        MoEPlaceLive().dualstick_stale_pin_metadata++;
        DualStickInvalidateExpert(layer, expert);
        MoEPlaceLive().pinsready_repair++;
        /* pinsready_false_positive stays 0: we never return 1 on miss. */
        return 0;
    }
    return 1;
}

} // namespace Deep2
