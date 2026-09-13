/* DualStickExpertBundle.cpp — live/any lookup + soft invalidate. ≤99. */
#include "DualStickBundle_Table.hpp"
#include "DualStickPinCoherency.hpp"
#include "DualStickStreamWindow.hpp"
#include "DualStickMetaLock.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "MoEPlaceLiveCounters.hpp"

namespace Deep2 {

int DualStickBundleLookup(int layer, int expert, DualStickBundleMeta* out) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    int i = ds_bundle::Find(layer, expert);
    if (i < 0 || !out || !ds_bundle::g_tab[(uint32_t)i].live) return 0;
    ds_bundle::Fill(out, ds_bundle::g_tab[(uint32_t)i]);
    return 1;
}

int DualStickBundleLookupAny(int layer, int expert, DualStickBundleMeta* out) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    int i = ds_bundle::Find(layer, expert);
    if (i < 0 || !out) return 0;
    ds_bundle::Fill(out, ds_bundle::g_tab[(uint32_t)i]);
    return 1;
}

void DualStickBundleNoteReuse(int layer, int expert) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    int i = ds_bundle::Find(layer, expert);
    if (i < 0) return;
    ds_bundle::g_tab[(uint32_t)i].reuse_bundle_noted = 1;
    ds_bundle::g_tab[(uint32_t)i].pending_reload = 0;
}

void DualStickInvalidateExpert(int layer, int expert) {
    int soft = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
        int i = ds_bundle::Find(layer, expert);
        if (i < 0) return;
        auto& e = ds_bundle::g_tab[(uint32_t)i];
        if (!e.live) return;
        e.live = 0;
        e.eviction_epoch = ++ds_bundle::g_ep;
        e.pending_reload = 1;
        e.reuse_bundle_noted = 0;
        soft = 1;
    }
    if (!soft) return;
    DualStickForgetExpertResident(layer, expert);
    MoEPlaceGlobal().MarkCold(layer, expert);
    MoEPlaceLive().dualstick_slot_invalidated++;
    MoEPlaceLive().moe_evicted_bundles++;
}

} // namespace Deep2
