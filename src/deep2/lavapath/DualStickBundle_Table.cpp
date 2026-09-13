/* DualStickBundle_Table.cpp — shared bundle storage. ≤99. */
#include "DualStickExpertBundle.hpp"
#include "DualStickMetaLock.hpp"

namespace Deep2 {
namespace ds_bundle {

struct Ent {
    int32_t layer, expert;
    uint32_t stick, gen, handle;
    size_t gb, ub, db;
    int gt, ut, dt;
    uint8_t live, pending_reload, reuse_bundle_noted;
    uint64_t resident_epoch, eviction_epoch, last_acquire_epoch;
};
enum { CAP = 2048 };
Ent g_tab[CAP];
uint32_t g_n = 0, g_nextH = 1, g_gen = 1;
uint64_t g_ep = 0;

int Find(int layer, int expert) {
    for (uint32_t i = 0; i < g_n; ++i)
        if (g_tab[i].layer == layer && g_tab[i].expert == expert) return (int)i;
    return -1;
}
void Fill(DualStickBundleMeta* o, const Ent& e) {
    o->handle = e.handle;
    o->stick = e.stick;
    o->gen = e.gen;
    o->gb = e.gb;
    o->ub = e.ub;
    o->db = e.db;
    o->gt = e.gt;
    o->ut = e.ut;
    o->dt = e.dt;
    o->live = e.live;
    o->pending_reload = e.pending_reload;
    o->reuse_bundle_noted = e.reuse_bundle_noted;
    o->resident_epoch = e.resident_epoch;
    o->eviction_epoch = e.eviction_epoch;
    o->last_acquire_epoch = e.last_acquire_epoch;
}

} // namespace ds_bundle
} // namespace Deep2
