// RAWRXD NP-05A: CPU regression for the device-independent resident-weight identity.
// Exercises the SAME component production uses (include/weight_identity.h). No Vulkan,
// no GPU: build with cl and run. Exit 0 = all pass, 1 = failure.
#include "weight_identity.h"
#include <cstdio>
#include <cstring>
#include <vector>

using namespace RawrXD::Deep2::WeightIdentity;

static int g_fail = 0;
#define CHECK(cond, msg) do { if (!(cond)) { std::printf("FAIL: %s\n", msg); ++g_fail; } } while (0)

int main() {
    // Two distinct host buffers with IDENTICAL content (simulates a relocated copy).
    unsigned char a[16], b[16];
    for (int i = 0; i < 16; ++i) a[i] = (unsigned char)(i * 7 + 1);
    std::memcpy(b, a, sizeof(a));

    // 1. Relocated host memory, same content/model/geometry/format -> SAME identity.
    Key ka = Make(1, a, sizeof(a), 0);
    Key kb = Make(1, b, sizeof(b), 0);
    CHECK(ka.fingerprint == kb.fingerprint, "relocated: fingerprint equal");
    CHECK(Matches(ka, kb), "relocated: identity matches (host-pointer-independent)");

    // 2. Changed revision (different content) -> DIFFERENT identity.
    b[0] ^= 0xFF;
    Key kr = Make(1, b, sizeof(b), 0);
    CHECK(kr.fingerprint != ka.fingerprint, "revision: fingerprint differs");
    CHECK(!Matches(ka, kr), "revision: identity does NOT match");

    // 3. Different model id, same content -> DIFFERENT identity (no cross-model reuse).
    std::memcpy(b, a, sizeof(a));
    Key km = Make(2, b, sizeof(b), 0);
    CHECK(km.fingerprint == ka.fingerprint, "model: content fingerprint equal");
    CHECK(!Matches(ka, km), "model: identity does NOT match across models");

    // 4. Different geometry (byte count) -> DIFFERENT identity.
    Key kg = Make(1, a, 8, 0);
    CHECK(!Matches(ka, kg), "geometry: identity does NOT match on byte count");

    // 5. Different quant format -> DIFFERENT identity.
    Key kf = Make(1, a, sizeof(a), 1);
    CHECK(!Matches(ka, kf), "format: identity does NOT match on kind");

    // 6. Identical request -> matches (baseline reuse).
    Key ka2 = Make(1, a, sizeof(a), 0);
    CHECK(Matches(ka, ka2), "identical: identity matches");

    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}