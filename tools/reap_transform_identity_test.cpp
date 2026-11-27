// RAWRXD REAP V06.2: CPU regression for deterministic transformation identity.
#include "deep2/ReapTransformIdentity.hpp"
#include <cstdio>
#include <string>

using namespace RawrXD::Reap;
static int g_fail = 0;
#define CHECK(c, m) do { if (!(c)) { std::printf("FAIL: %s\n", m); ++g_fail; } } while (0)

int main() {
    Selection a{{0, {0, 1, 2}}, {1, {1, 2, 3}}};
    Selection b{{0, {0, 1, 2}}, {1, {1, 2, 3}}};
    CHECK(SelectionFingerprint(a) == SelectionFingerprint(b), "identical selections -> same fp");

    Selection reorder{{0, {0, 2, 1}}, {1, {1, 2, 3}}};  // expert order changed in layer 0
    CHECK(SelectionFingerprint(a) != SelectionFingerprint(reorder), "expert order -> distinct fp");

    Selection different{{0, {0, 1, 2}}, {1, {1, 2, 4}}};
    CHECK(SelectionFingerprint(a) != SelectionFingerprint(different), "different selection -> distinct fp");

    TransformIdentity id1{/*source*/42, /*tensor*/7, SelectionFingerprint(a), /*mode*/1, /*quant*/12};
    TransformIdentity id2 = id1;
    CHECK(TransformIdentityHash(id1) == TransformIdentityHash(id2), "same identity -> same hash");
    id2.selectionFp = SelectionFingerprint(reorder);
    CHECK(TransformIdentityHash(id1) != TransformIdentityHash(id2), "selection change -> distinct hash");
    id2 = id1; id2.mode = 2;
    CHECK(TransformIdentityHash(id1) != TransformIdentityHash(id2), "mode change -> distinct hash");
    id2 = id1; id2.sourceId = 43;
    CHECK(TransformIdentityHash(id1) != TransformIdentityHash(id2), "source change -> distinct hash");
    id2 = id1; id2.quantLayout = 10;
    CHECK(TransformIdentityHash(id1) != TransformIdentityHash(id2), "quant change -> distinct hash");
    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}