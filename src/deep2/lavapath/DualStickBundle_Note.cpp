/* DualStickBundle_Note.cpp — NoteExpertBundle + table reset. ≤99. */
#include "DualStickBundle_Table.hpp"
#include "DualStickStreamWindow.hpp"
#include "DualStickMetaLock.hpp"

namespace Deep2 {

void DualStickNoteExpertBundle(int layer, int expert, unsigned stick, size_t gb,
                               size_t ub, size_t db, int gt, int ut, int dt) {
    stick &= 1u;
    {
        std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
        int i = ds_bundle::Find(layer, expert);
        if (i < 0 && ds_bundle::g_n < ds_bundle::CAP)
            i = (int)ds_bundle::g_n++;
        if (i < 0) return;
        auto& e = ds_bundle::g_tab[(uint32_t)i];
        e.layer = layer;
        e.expert = expert;
        e.stick = stick;
        e.gb = gb;
        e.ub = ub;
        e.db = db;
        e.gt = gt;
        e.ut = ut;
        e.dt = dt;
        e.gen = ds_bundle::g_gen;
        if (!e.handle) e.handle = ds_bundle::g_nextH++;
        e.live = 1;
        e.resident_epoch = ++ds_bundle::g_ep;
        e.last_acquire_epoch = e.resident_epoch;
    }
    DualStickNoteExpertResident(layer, expert, stick, (uint64_t)gb + ub + db);
}

void DualStickBundleTableReset() {
    std::lock_guard<std::recursive_mutex> lk(DualStickMetaMu());
    ds_bundle::g_n = 0;
    ds_bundle::g_nextH = 1;
    ++ds_bundle::g_gen;
    ds_bundle::g_ep = 0;
}

} // namespace Deep2
