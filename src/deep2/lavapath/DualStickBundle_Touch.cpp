/* DualStickBundle_Touch.cpp — secondary gate+up+down lastUse bump. ≤99. */
#include "DualStickPinCoherency.hpp"
#include "DualStickStreamWindow.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "vulkan_compute.h"

namespace Deep2 {

void DualStickBundleTouchPins(unsigned stick, int layer, int expert, size_t H,
                              size_t I) {
    DualStickBundleMeta m{};
    if (!DualStickBundleLookup(layer, expert, &m)) return;
    auto* vc = DualStickVc(stick);
    if (!vc || !H || !I) return;
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    int n = 0;
    if (vc->TouchPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 1),
                                  m.gb, rI, cH))
        ++n;
    if (vc->TouchPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 2),
                                  m.ub, rI, cH))
        ++n;
    if (vc->TouchPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 3),
                                  m.db, rH, cI))
        ++n;
    if (n) {
        MoEPlaceLive().moe_pin_touches += (uint64_t)n;
        MoEPlaceLive().moe_bundle_touches++;
    }
}

} // namespace Deep2
