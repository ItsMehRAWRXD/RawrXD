// RAWRXD NP-05A: CPU regression for the device-independent resident-weight identity.
// Exercises the SAME component production uses (include/weight_identity.h). No Vulkan,
// no GPU: build with cl and run. Exit 0 = all pass, 1 = failure.
#include "weight_identity.h"
#include "weight_cache_table.h"
#include <cstdio>
#include <cstring>
#include <vector>

using namespace RawrXD::Deep2::WeightIdentity;
using namespace RawrXD::Deep2::WeightCache;

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

    // 7. Same content/model/geometry/format but DIFFERENT logical tensor id ->
    //    distinct tensors (no content-dedup collision).
    Key kt = Make(1, a, sizeof(a), 0, /*tensor_id=*/7);
    CHECK(kt.fingerprint == ka.fingerprint, "tensor_id: content fingerprint equal");
    CHECK(!Matches(ka, kt), "tensor_id: distinct logical tensors do NOT match");

    // 8. Same logical tensor id -> matches.
    Key kt2 = Make(1, a, sizeof(a), 0, /*tensor_id=*/7);
    CHECK(Matches(kt, kt2), "tensor_id: same logical tensor matches");

    // ---- Stable cache table: ACTUAL reuse + ownership (production component) ----
    std::memcpy(b, a, sizeof(a));  // reset b to identical content
    {
        Table t;
        Key k1 = Make(1, a, sizeof(a), 0);
        Entry* e1 = t.Insert(k1);
        // 9. Relocated host buffer (different pointer, identical content) -> SAME entry.
        CHECK(t.Find(Make(1, b, sizeof(b), 0)) == e1, "table: relocated buffer reuses entry");
        // 10. Pin blocks eviction; unpin allows it; reap after generation.
        CHECK(t.Pin(k1), "table: pin ok");
        CHECK(!t.Evict(k1), "table: pinned entry NOT evicted");
        t.Unpin(k1);
        CHECK(t.Evict(k1), "table: unpinned entry evicted");
        CHECK(t.Reap(e1->generation) == 1, "table: reaped after generation");
    }
    {
        // 11. Revision change -> distinct entry (no false reuse).
        Table t2;
        unsigned char c[16]; std::memcpy(c, a, sizeof(a)); c[0] ^= 0xFF;
        Entry* r1 = t2.Insert(Make(1, a, sizeof(a), 0));
        CHECK(t2.Find(Make(1, c, sizeof(c), 0)) == nullptr, "table: revision -> miss");
        Entry* r2 = t2.Insert(Make(1, c, sizeof(c), 0));
        CHECK(r2 != r1, "table: revision -> distinct entry");
    }
    {
        // 12. Lease holds the entry; release then evicts.
        Table t3;
        t3.Insert(Make(1, a, sizeof(a), 0));
        uint64_t lease = t3.AcquireLease(Make(1, a, sizeof(a), 0));
        CHECK(lease != 0, "table: lease acquired");
        CHECK(!t3.Evict(Make(1, a, sizeof(a), 0)), "table: leased entry NOT evicted");
        t3.ReleaseLease(lease);
        CHECK(t3.Evict(Make(1, a, sizeof(a), 0)), "table: evicted after lease release");
    }
    {
        // 13. Cross-model isolation in the table.
        Table t4;
        Entry* m1 = t4.Insert(Make(1, a, sizeof(a), 0));
        CHECK(t4.Find(Make(2, a, sizeof(a), 0)) == nullptr, "table: cross-model miss");
        CHECK(t4.Find(Make(1, a, sizeof(a), 0)) == m1, "table: same-model hit");
    }

    if (g_fail == 0) { std::printf("ALL PASS\n"); return 0; }
    std::printf("%d FAILURE(S)\n", g_fail);
    return 1;
}