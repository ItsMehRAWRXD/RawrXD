/* selftest_moe_place.cpp — nodep unit for MoEExpertResidencyPlace */
#include "../../../src/deep2/MoEExpertResidencyPlace.hpp"
#include <cstdio>
#include <cstdlib>

using Deep2::MoEExpertResidencyPlace;
using Deep2::MoEPlaceIn;
using Deep2::MoEPlacePlan;
using Deep2::MOE_PLACE_MAX_K;

static int g_fail = 0;
#define CHECK(c) do { if (!(c)) { std::fprintf(stderr, "FAIL %s\n", #c); ++g_fail; } } while (0)

int main() {
    MoEExpertResidencyPlace place;
    place.Reset();
    place.SetBudget(8ull << 20, 1ull << 20);
    place.SetStickCount(2);

    /* Mark expert 7 hot on stick 1 before place. */
    place.MarkHot(/*layer=*/3, /*expert=*/7, /*stick=*/1, 1ull << 20);

    MoEPlaceIn in[4];
    in[0] = {11, 0.40f};
    in[1] = {7, 0.25f};   /* hot — must execute before cold despite lower weight */
    in[2] = {3, 0.20f};
    in[3] = {19, 0.15f};

    MoEPlacePlan p = place.Place(3, in, 4);
    CHECK(p.count == 4);
    CHECK(p.hits == 1);
    CHECK(p.misses == 3);
    CHECK(p.slots[0].expertId == 7);
    CHECK(p.slots[0].hit == 1);
    CHECK(p.slots[0].stick == 1);
    CHECK(p.slots[0].fetch == 0);
    /* Remaining misses ordered by weight desc: 11, 3, 19 */
    CHECK(p.slots[1].expertId == 11);
    CHECK(p.slots[1].fetch == 1);
    CHECK(p.slots[2].expertId == 3);
    CHECK(p.slots[3].expertId == 19);

    place.MarkHot(3, 11, p.slots[1].stick, 1ull << 20);
    MoEPlacePlan p2 = place.Place(3, in, 4);
    CHECK(p2.hits == 2);
    CHECK(p2.slots[0].hit == 1);
    CHECK(p2.slots[1].hit == 1);
    CHECK(place.Counters().place_reuse > 0);

    place.EmitTrace(stderr);
    if (g_fail) {
        std::fprintf(stderr, "UNIT_PLACE_PASS=0 fails=%d\n", g_fail);
        return 1;
    }
    std::fprintf(stderr, "UNIT_PLACE_PASS=1\n");
    return 0;
}
