/* DualStickBundle_Quota.cpp — hot protect + quota live sync. ≤99. */
#include "DualStickPinCoherency.hpp"
#include "DualStickReloadAttr.hpp"
#include "DualStickStreamWindow.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include "vulkan_compute.h"

namespace Deep2 {

int DualStickMoePinProtected(uint64_t pinKey) {
    if (ClassifyPinKey(pinKey) != PinWeightClass::MoE) return 0;
    const int layer = (int)(pinKey >> 24);
    const int expert = (int)((pinKey >> 8) & 0xffffu);
    if (MoEPlaceGlobal().IsHot(layer, expert)) return 1;
    DualStickBundleMeta m{};
    return DualStickBundleLookup(layer, expert, &m) ? 1 : 0;
}

void DualStickSyncQuotaLiveCounters() {
    auto& L = MoEPlaceLive();
    uint64_t reserved = 0, moeR = 0, mlaR = 0, genR = 0, blocked = 0;
    for (unsigned s = 0; s < 2u; ++s) {
        auto* vc = DualStickVc(s);
        if (!vc) continue;
        if (vc->MoeReservedBytes() > reserved)
            reserved = vc->MoeReservedBytes();
        moeR += vc->MoeResidentBytes();
        mlaR += vc->MlaResidentBytes();
        genR += vc->GeneralResidentBytes();
        blocked += vc->PinBudgetShrinkBlocked();
        if (vc->MlaQuotaBytes()) L.mla_quota_bytes = vc->MlaQuotaBytes();
        if (vc->GeneralQuotaBytes())
            L.general_quota_bytes = vc->GeneralQuotaBytes();
    }
    if (reserved) L.moe_reserved_bytes = reserved;
    L.moe_resident_bytes = moeR;
    L.mla_resident_bytes = mlaR;
    L.general_resident_bytes = genR;
    if (blocked) L.cache_budget_shrink_blocked = blocked;
}

} // namespace Deep2
