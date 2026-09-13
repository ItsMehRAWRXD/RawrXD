/* DualStickBundle_Attr.cpp — MoE eviction→reuse byte attribution. ≤99. */
#include "DualStickReloadAttr.hpp"
#include "DualStickExpertBundle.hpp"
#include "MoEPlaceLiveCounters.hpp"
#include <unordered_set>

namespace Deep2 {
namespace {
std::unordered_set<uint64_t> g_evictedMoeKeys;
}

void DualStickMarkMoeKeyEvicted(uint64_t pinKey) {
    if (ClassifyPinKey(pinKey) != PinWeightClass::MoE) return;
    if (g_evictedMoeKeys.insert(pinKey).second)
        MoEPlaceLive().moe_evicted_keys++;
}

void DualStickNoteMoePinUpload(uint64_t pinKey, size_t bytes, int firstEver) {
    if (ClassifyPinKey(pinKey) != PinWeightClass::MoE || !bytes) return;
    const int layer = (int)(pinKey >> 24);
    const int expert = (int)((pinKey >> 8) & 0xffffu);
    DualStickBundleMeta m{};
    const int have = DualStickBundleLookupAny(layer, expert, &m);
    const int fromSet = g_evictedMoeKeys.erase(pinKey) > 0 ? 1 : 0;
    const int wasEv =
        fromSet || (have && m.eviction_epoch != 0 &&
                    (m.live == 0 || m.pending_reload));
    if (wasEv) {
        MoEPlaceLive().moe_reload_after_eviction_bytes += bytes;
        MoEPlaceLive().moe_evicted_then_reused_keys++;
        if (have && !m.reuse_bundle_noted) {
            DualStickBundleNoteReuse(layer, expert);
            MoEPlaceLive().moe_evicted_then_reused_bundles++;
        }
    } else if (firstEver) {
        MoEPlaceLive().moe_compulsory_load_bytes += bytes;
    }
}

} // namespace Deep2
