#pragma once
/* DualStickExpertBundle — pin key + stick-resident Gate/Up/Down meta. */
#include <cstdint>
#include <cstddef>

namespace Deep2 {

inline uint64_t DualStickExpertPin(uint32_t layer, int expertId, uint8_t role) {
    return ((uint64_t)layer << 24) | ((uint64_t)(expertId & 0xffff) << 8) |
           (uint64_t)role;
}

/* role: 1=Gate 2=Up 3=Down. handle: 0 = none; else opaque residency id. */
struct DualStickBundleMeta {
    uint32_t handle;
    uint32_t stick;
    uint32_t gen;
    size_t gb, ub, db;
    int gt, ut, dt;
};

int DualStickBundleLookup(int layer, int expert, DualStickBundleMeta* out);
void DualStickNoteExpertBundle(int layer, int expert, unsigned stick,
                               size_t gb, size_t ub, size_t db, int gt, int ut,
                               int dt);
/* 1 if stick VC has all three pins for (layer,expert) at dims HxI. */
int DualStickBundlePinsReady(unsigned stick, int layer, int expert, size_t H,
                             size_t I);

void DualStickBundleTableReset();

} // namespace Deep2
