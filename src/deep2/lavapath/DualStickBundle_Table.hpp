#pragma once
/* Internal DualStick bundle table accessors (same TU friends via header). */
#include "DualStickExpertBundle.hpp"
#include <cstdint>

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
extern Ent g_tab[CAP];
extern uint32_t g_n, g_nextH, g_gen;
extern uint64_t g_ep;
int Find(int layer, int expert);
void Fill(DualStickBundleMeta* o, const Ent& e);

} // namespace ds_bundle
} // namespace Deep2
