#pragma once
/* DualStickExpertBundle — pin key + stick-resident Gate/Up/Down meta. */
#include <cstdint>
#include <cstddef>

namespace Deep2 {

inline uint64_t DualStickExpertPin(uint32_t layer, int expertId, uint8_t role) {
    return ((uint64_t)layer << 24) | ((uint64_t)(expertId & 0xffff) << 8) |
           (uint64_t)role;
}

struct DualStickBundleMeta {
    uint32_t handle;
    uint32_t stick;
    uint32_t gen;
    size_t gb, ub, db;
    int gt, ut, dt;
    uint8_t live;
    uint8_t pending_reload;
    uint8_t reuse_bundle_noted;
    uint64_t resident_epoch;
    uint64_t eviction_epoch;
    uint64_t last_acquire_epoch;
};

/* Live-only lookup (PinsReady / hit path). */
int DualStickBundleLookup(int layer, int expert, DualStickBundleMeta* out);
/* Any entry including soft-invalidated (attribution epochs). */
int DualStickBundleLookupAny(int layer, int expert, DualStickBundleMeta* out);
void DualStickBundleNoteReuse(int layer, int expert);
void DualStickNoteExpertBundle(int layer, int expert, unsigned stick,
                               size_t gb, size_t ub, size_t db, int gt, int ut,
                               int dt);
int DualStickBundlePinsReady(unsigned stick, int layer, int expert, size_t H,
                             size_t I);
void DualStickBundleTableReset();

} // namespace Deep2
