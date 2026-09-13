/* DualStickExpertBundle.cpp — bundle table + invalidate. ≤99. */
#include "DualStickExpertBundle.hpp"
#include "DualStickPinCoherency.hpp"
#include "DualStickStreamWindow.hpp"
#include "DualStickMetaLock.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "MoEPlaceLiveCounters.hpp"

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
void EraseAt(uint32_t i) {
    if (i >= g_bn) return;
    g_b[i] = g_b[g_bn - 1];
    --g_bn;
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

void DualStickInvalidateExpert(int layer, int expert) {
    int erased = 0;
    {
        std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
        int i = Find(layer, expert);
        if (i >= 0) {
            EraseAt((uint32_t)i);
            erased = 1;
        }
    }
    if (!erased) return;
    DualStickForgetExpertResident(layer, expert);
    MoEPlaceGlobal().MarkCold(layer, expert);
    MoEPlaceLive().dualstick_slot_invalidated++;
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

void DualStickBundleTableReset() {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    g_bn = 0;
    g_nextHandle = 1;
    ++g_gen;
}

} // namespace Deep2
