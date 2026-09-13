/* DualStickImbalance_Steal.cpp — #10 late expert work steal. ≤99. */
#include "DualStickImbalance.hpp"
#include "DualStickImbalance_State.hpp"
#include "DualStickStreamWindow.hpp"
#include "MoEExpertResidencyPlace.hpp"
#include "MoEPlaceLiveCounters.hpp"

namespace Deep2 {

void DualStickImbalanceSteal(MoEPlacePlan& plan, int layer) {
    using namespace ds_imb;
    for (int pass = 0; pass < 8; ++pass) {
        int n0 = 0, n1 = 0;
        for (uint32_t si = 0; si < plan.count; ++si) {
            if (plan.slots[si].expertId < 0) continue;
            if ((plan.slots[si].stick & 1u) == 0) ++n0;
            else ++n1;
        }
        const uint64_t a0 = g_avail[0], a1 = g_avail[1];
        const uint64_t mx = (a0 > a1) ? a0 : a1;
        const uint64_t mn = (a0 < a1) ? a0 : a1;
        const unsigned heavy = (n0 >= n1) ? 0u : 1u;
        const unsigned light = heavy ^ 1u;
        const int nh = (heavy == 0u) ? n0 : n1;
        const int nl = (light == 0u) ? n0 : n1;
        const int need = (nh >= nl + 2) ||
                         (mx && ((mx - mn) * 100ull) / mx >= 5ull);
        if (!need) return;

        int32_t victim = -1;
        float bestW = 1e30f;
        for (uint32_t si = 0; si < plan.count; ++si) {
            MoEPlaceSlot& s = plan.slots[si];
            if (s.expertId < 0 || (s.stick & 1u) != heavy || s.hit) continue;
            if (s.weight <= bestW) {
                bestW = s.weight;
                victim = (int32_t)si;
            }
        }
        if (victim < 0) return;

        MoEPlaceSlot& mut = plan.slots[(uint32_t)victim];
        const int pref = DualStickExpertStickOf(layer, mut.expertId);
        const uint64_t bytes = DualStickExpertBytesOf(layer, mut.expertId);
        /* Refuse steal onto stick that already holds more VRAM. */
        if (DualStickStickResBytes(light) > DualStickStickResBytes(heavy) +
                                                (1ull << 20))
            return;
        const uint64_t cH = FullCost(heavy, pref, bytes, 0);
        const uint64_t cL = FullCost(light, pref, bytes, 0);
        const uint64_t afterH =
            (g_avail[heavy] >= cH) ? (g_avail[heavy] - cH) : 0ull;
        const uint64_t afterL = g_avail[light] + cL;
        if (((afterH > afterL) ? afterH : afterL) >= mx && nh < nl + 2)
            return;

        mut.stick = (uint8_t)light;
        g_avail[heavy] = afterH;
        g_avail[light] = afterL;
        g_predLayer[0] = g_avail[0];
        g_predLayer[1] = g_avail[1];
        MoEPlaceLive().work_steals++;
        if (pref >= 0 && (unsigned)pref != light) {
            MoEPlaceLive().stick_migrations++;
            MoEPlaceLive().residency_lost_to_rebalance_bytes += bytes;
        }
    }
}

} // namespace Deep2
