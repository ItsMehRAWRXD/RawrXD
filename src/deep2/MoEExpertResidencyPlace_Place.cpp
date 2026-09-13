/* MoEExpertResidencyPlace_Place.cpp — hits-first plan + residentHandle. */
#include "MoEExpertResidencyPlace.hpp"
#include "lavapath/DualStickExpertBundle.hpp"

namespace Deep2 {

static void SortByWeightDesc(MoEPlaceSlot* a, uint32_t n) {
    for (uint32_t i = 1; i < n; ++i)
        for (uint32_t j = i; j && a[j].weight > a[j - 1].weight; --j) {
            MoEPlaceSlot t = a[j];
            a[j] = a[j - 1];
            a[j - 1] = t;
        }
}

MoEPlacePlan MoEExpertResidencyPlace::Place(int layer, const MoEPlaceIn* in,
                                            uint32_t n) {
    MoEPlacePlan p{};
    ++ctr_.place_calls;
    if (!in || n == 0) return p;
    if (n > MOE_PLACE_MAX_K) n = MOE_PLACE_MAX_K;

    MoEPlaceSlot hits[MOE_PLACE_MAX_K];
    MoEPlaceSlot miss[MOE_PLACE_MAX_K];
    uint32_t nh = 0, nm = 0;
    uint64_t missBytes = 0;
    const uint64_t eb = expertBytes_ ? expertBytes_ : (1ull << 20);

    for (uint32_t i = 0; i < n; ++i) {
        if (in[i].expertId < 0) continue;
        MoEPlaceSlot s{};
        s.expertId = in[i].expertId;
        s.weight = in[i].weight;
        int hi = FindHot(layer, s.expertId);
        int hit = hi >= 0 ? 1 : 0;
        if (!hit && probe_)
            hit = probe_(probeCtx_, layer, s.expertId) ? 1 : 0;
        if (hit && hi < 0) hi = FindHot(layer, s.expertId);
        s.hit = (uint8_t)hit;
        s.fetch = hit ? 0 : 1;
        DualStickBundleMeta bm{};
        const int haveB = DualStickBundleLookup(layer, s.expertId, &bm);
        if (haveB) s.residentHandle = bm.handle;
        if (hi >= 0) {
            s.stick = (uint8_t)(hot_[(uint32_t)hi].stick & 1u);
            Touch(hi);
            ++ctr_.place_reuse;
        } else if (haveB) {
            s.stick = (uint8_t)(bm.stick & 1u);
        } else {
            s.stick = (uint8_t)((uint32_t)s.expertId % sticks_);
        }
        if (hit) {
            hits[nh++] = s;
            ++ctr_.expert_hits;
        } else {
            miss[nm++] = s;
            missBytes += eb;
            ++ctr_.expert_misses;
        }
    }

    SortByWeightDesc(hits, nh);
    SortByWeightDesc(miss, nm);
    const int tight =
        (budget_ && missBytes && (hotBytes_ + missBytes > budget_)) ? 1 : 0;
    for (uint32_t i = 0; i < nh; ++i)
        p.slots[p.count++] = hits[i];
    for (uint32_t i = 0; i < nm; ++i) {
        if (tight) {
            miss[i].thrash = 1;
            ++ctr_.thrash_flags;
        }
        p.slots[p.count++] = miss[i];
    }
    p.hits = nh;
    p.misses = nm;
    p.bytesFetchPlan = missBytes;
    ctr_.bytes_fetched += missBytes;
    return p;
}

} // namespace Deep2
