/* DualStickExpertBundle.cpp — residency meta for acquire-hit / no host bounce. */
#include "DualStickExpertBundle.hpp"
#include "DualStickStreamWindow.hpp"
#include "DualStickMetaLock.hpp"
#include "vulkan_compute.h"

namespace Deep2 {
namespace {
struct BundleEnt {
    int32_t layer, expert;
    uint32_t stick, gen, handle;
    size_t gb, ub, db;
    int gt, ut, dt;
};
enum { BCAP = 2048 };
BundleEnt g_b[BCAP];
uint32_t g_bn = 0;
uint32_t g_nextHandle = 1;
uint32_t g_gen = 1;

int Find(int layer, int expert) {
    for (uint32_t i = 0; i < g_bn; ++i)
        if (g_b[i].layer == layer && g_b[i].expert == expert) return (int)i;
    return -1;
}
} // namespace

int DualStickBundleLookup(int layer, int expert, DualStickBundleMeta* out) {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    int i = Find(layer, expert);
    if (i < 0 || !out) return 0;
    const BundleEnt& e = g_b[(uint32_t)i];
    out->handle = e.handle;
    out->stick = e.stick;
    out->gen = e.gen;
    out->gb = e.gb;
    out->ub = e.ub;
    out->db = e.db;
    out->gt = e.gt;
    out->ut = e.ut;
    out->dt = e.dt;
    return 1;
}

void DualStickNoteExpertBundle(int layer, int expert, unsigned stick, size_t gb,
                               size_t ub, size_t db, int gt, int ut, int dt) {
    stick &= 1u;
    {
        std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
        int i = Find(layer, expert);
        if (i < 0 && g_bn < BCAP) i = (int)g_bn++;
        if (i < 0) return;
        BundleEnt& e = g_b[(uint32_t)i];
        e.layer = layer;
        e.expert = expert;
        e.stick = stick;
        e.gb = gb;
        e.ub = ub;
        e.db = db;
        e.gt = gt;
        e.ut = ut;
        e.dt = dt;
        e.gen = g_gen;
        if (!e.handle) e.handle = g_nextHandle++;
    }
    DualStickNoteExpertResident(layer, expert, stick, (uint64_t)gb + ub + db);
}

int DualStickBundlePinsReady(unsigned stick, int layer, int expert, size_t H,
                             size_t I) {
    DualStickBundleMeta m{};
    if (!DualStickBundleLookup(layer, expert, &m)) return 0;
    if ((m.stick & 1u) != (stick & 1u)) return 0;
    auto* vc = DualStickVc(stick);
    if (!vc || !H || !I || !m.gb || !m.ub || !m.db) return 0;
    const uint32_t rI = (uint32_t)I, cH = (uint32_t)H, rH = (uint32_t)H,
                   cI = (uint32_t)I;
    if (!vc->HasPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 1),
                                 m.gb, rI, cH))
        return 0;
    if (!vc->HasPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 2),
                                 m.ub, rI, cH))
        return 0;
    if (!vc->HasPinnedGemvWeight(DualStickExpertPin((uint32_t)layer, expert, 3),
                                 m.db, rH, cI))
        return 0;
    return 1;
}

void DualStickBundleTableReset() {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    g_bn = 0;
    g_nextHandle = 1;
    ++g_gen;
}

} // namespace Deep2
