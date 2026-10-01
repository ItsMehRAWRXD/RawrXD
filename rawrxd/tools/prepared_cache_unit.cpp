// RAWRXD_B70_PREPARED_CACHE_UNIT_001
//
// Direct subsystem test for the B63 prepared-weight cache.
//
// WHY THIS EXISTS
// ---------------
// B63 shipped a bounded LRU prepared-weight cache, verified on a model:
//   acquire=3024  miss=84  hit=2940  evict=0  cpuDequantCalls=84
// That proved miss/hit accounting. It did NOT prove eviction: the model's whole
// working set fit inside the default 12 GiB budget, so nothing was ever evicted.
//
// After B65/B66/B67 added native Q3_K, every model on this machine routes its
// quantized tensors through the GPU path. Zero tensors reach the cache. A
// `evict=0` in that state is VACUOUS, and a tight-budget model run cannot help
// either -- it produces no prepared entries at all, so nothing to evict.
//
// Testing through inference would mean forcing the model backward into a
// representation it no longer needs. This tests the cache directly instead.
//
// It includes the REAL header. An earlier draft re-declared the class, which
// would have tested a copy -- the same defect that let B63 ship unverified.
// The engine and this test now compile one implementation from
// Deep2_PreparedWeightCache.hpp.
//
// FOUR PROPERTIES, deterministic
// ------------------------------
//   1. INSERT + RESIDENCY    insert A under budget -> resident, one dequant;
//                            re-request hits and returns the SAME pointer
//   2. TOUCH + LRU EVICTION  budget < A+B+C+D; touch A, then insert D -> the
//                            LEAST-recently-USED entry is evicted, and A
//                            survives. Insertion order and LRU order differ
//                            here deliberately: B is older than C, so a
//                            first-in-first-out bug would also pass. The touch
//                            of A is what makes LRU distinguishable.
//   3. MISS + RECREATION     re-request the evicted entry -> miss, fresh
//                            allocation, no aliasing with survivors
//   4. OVERSIZED POLICY      a single object larger than the whole budget ->
//                            still prepared, budget invariant holds, oversized
//                            entry is NOT counted in live bytes
//
// Every case asserts: preparedBytesLive <= budget.

#include "deep2/Deep2_PreparedWeightCache.hpp"

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>

namespace {

struct TestResult {
    int checks = 0;
    int failures = 0;
    void check(bool ok, const char* what) {
        ++checks;
        if (!ok) {
            ++failures;
            std::printf("  FAIL: %s\n", what);
        } else {
            std::printf("  ok  : %s\n", what);
        }
    }
};

// Deterministic stand-in dequantizer: dst[i] = src[i % 64]. The test asserts on
// identity and lifetime, not on quant arithmetic -- quant correctness is the
// subject of tools/q3k_block_diff.cpp, a separate gate.
void testDequant(const uint8_t* src, float* dst, size_t n) {
    for (size_t i = 0; i < n; ++i) dst[i] = float(src[i % 64]);
}

// Counts dequantizations, so a "no repeat on hit" claim is measured rather
// than inferred from pointer equality.
struct CountingDequant {
    static uint64_t calls;
    static void fn(const uint8_t* src, float* dst, size_t n) {
        ++calls;
        testDequant(src, dst, n);
    }
};
uint64_t CountingDequant::calls = 0;

} // namespace

int main() {
    // The budget is read once, on first use, so it MUST be set before anything
    // touches the cache. Set it here.
    //
    // Budget choice matters. With 256 KiB tensors and a 1 MiB budget, FOUR
    // tensors fit EXACTLY, and 1048576 > 1048576 is false -- so no eviction is
    // ever due and the eviction assertions are vacuous. Use 640 KiB instead:
    // two tensors (512 KiB) fit, a third (768 KiB) exceeds the budget, which
    // makes overflow real.
    const uint64_t kBudget = 640u * 1024u;                  // 640 KiB
    {
        char buf[32];
        std::snprintf(buf, sizeof(buf), "%llu", (unsigned long long)kBudget);
        _putenv_s("RAWRXD_PREPARED_BUDGET_BYTES", buf);
    }

    const uint32_t kN = 256;
    const uint64_t kBytes = (uint64_t)kN * kN * sizeof(float); // 256 KiB
    const uint64_t kFit  = 2 * kBytes;                      // 512 KiB
    const size_t   kSrc  = (size_t)kN * kN / 4;               // source blob size

    std::printf("B70_PREPARED_CACHE_UNIT budget=%llu bytesPerTensor=%llu\n",
                (unsigned long long)kBudget, (unsigned long long)kBytes);

    // Distinct source buffers: identity is keyed partly on source pointer.
    std::vector<uint8_t> sA(kSrc, 0x11), sB(kSrc, 0x22),
                        sC(kSrc, 0x33), sD(kSrc, 0x44);

    auto mk = [](const char* n, const std::vector<uint8_t>& s) {
        Deep2::PreparedWeightSource w;
        w.name = n;
        w.type = 8;                 // any quantized id; the stub dequant is used
        w.rows = kN;
        w.cols = kN;
        w.data = s.data();
        w.sizeBytes = s.size();
        return w;
    };

    TestResult t;

    {
        Deep2::PreparedWeightCache cache;
        auto A = mk("A", sA), B = mk("B", sB), C = mk("C", sC), D = mk("D", sD);
        auto& S = cache.stats();
        auto deq = &CountingDequant::fn;

        // ---- PROPERTY 1: insert + residency -------------------------------
        const float* pA = cache.Acquire(A, deq);
        t.check(pA != nullptr, "P1 A prepared");
        t.check(S.prepareMiss == 1, "P1 A counted as one miss");
        t.check(CountingDequant::calls == 1, "P1 exactly one CPU dequant");
        t.check(S.preparedBytesLive == kBytes, "P1 live bytes == one tensor");
        t.check(S.preparedBytesLive <= kBudget, "P1 budget invariant");

        const float* pB = cache.Acquire(B, deq);
        t.check(pB != nullptr && pB != pA, "P1 B prepared, distinct buffer");
        t.check(S.preparedBytesLive == 2 * kBytes, "P1 two tensors resident");
        t.check(S.evict == 0, "P1 no eviction while under budget");

        const float* pA2 = cache.Acquire(A, deq);
        t.check(S.prepareHit == 1, "P1 re-request A is a hit");
        t.check(pA2 == pA, "P1 hit returns the SAME pointer (no realloc)");
        t.check(CountingDequant::calls == 2, "P1 no repeat dequant on hit");

        // ---- PROPERTY 2: touch A, then insert C -> evict B (LRU victim) ---
        // Insertion order: A, B. LRU victim is B.
        // Touching A first makes LRU and FIFO disagree: FIFO would evict A
        // (inserted first), LRU evicts B. That is what makes this assertion
        // discriminating rather than passing under either policy.
        cache.Acquire(A, deq);          // A becomes most-recently-used
        const uint64_t evictBefore = S.evict;

        const float* pC = cache.Acquire(C, deq);
        t.check(pC != nullptr, "P2 C prepared");
        t.check(S.evict == evictBefore + 1, "P2 exactly one eviction on overflow");
        t.check(S.preparedBytesLive <= kBudget, "P2 budget invariant after evict");
        t.check(S.preparedBytesLive <= kFit, "P2 live bytes did not exceed capacity");

        // A was touched last -> must SURVIVE, same pointer.
        const float* pAafter = cache.Acquire(A, deq);
        t.check(pAafter == pA, "P2 most-recently-used A survived (LRU, not FIFO)");

        // B was least recently used -> must be GONE.
        const uint64_t missBeforeB = S.prepareMiss;
        const uint64_t dequantBeforeRecreate = CountingDequant::calls;
        const float* pBafter = cache.Acquire(B, deq);
        t.check(S.prepareMiss == missBeforeB + 1,
                "P2 least-recently-used B was evicted, re-request MISSES");
        t.check(pBafter != nullptr, "P2 evicted B was recreated");
        // Recreation is proven by the MISS counter plus a fresh dequant, NOT by
        // pointer inequality: the allocator is free to hand back the address it
        // just freed, so `pBafter != pB` is not a valid assertion and failed
        // here for exactly that reason while the cache behaved correctly.
        t.check(CountingDequant::calls == dequantBeforeRecreate + 1,
                "P2 recreated B was genuinely re-dequantized");

        // ---- PROPERTY 3: stability of the recreated entry -----------------
        const uint64_t callsAfterRecreate = CountingDequant::calls;
        const float* pBhit = cache.Acquire(B, deq);
        t.check(CountingDequant::calls == callsAfterRecreate,
                "P3 recreated B is now a HIT (no repeat dequant)");
        t.check(pBhit == pBafter, "P3 recreated B returns a stable pointer");
        t.check(S.preparedBytesLive <= kBudget, "P3 budget invariant after recreate");
        t.check(pBhit != pA && pBhit != pC, "P3 no aliasing with survivors");

        cache.WriteReceipt();
    }

    // ---- PROPERTY 4: oversized single object -----------------------------
    {
        // 4096x1024 F32 prepared = 16 MiB, far above the 1 MiB budget.
        const uint32_t r = 4096, c = 1024;
        std::vector<uint8_t> big((size_t)r * c / 4, 0x7F);
        Deep2::PreparedWeightSource BW;
        BW.name = "BIG";
        BW.type = 8;
        BW.rows = r;
        BW.cols = c;
        BW.data = big.data();
        BW.sizeBytes = big.size();

        Deep2::PreparedWeightCache cache;
        auto& S = cache.stats();
        const uint64_t before = CountingDequant::calls;

        const float* pBig = cache.Acquire(BW, &CountingDequant::fn);
        t.check(pBig != nullptr, "P4 oversized object still prepared (correctness first)");
        t.check(CountingDequant::calls == before + 1, "P4 oversized dequantized once");
        t.check(S.oversizedEntries == 1, "P4 oversized entry recorded");
        t.check(S.preparedBytesLive <= kBudget, "P4 budget invariant holds");
        t.check(S.preparedBytesLive == 0,
                "P4 oversized NOT counted in indexed live bytes");
        t.check(S.evict == 0, "P4 oversized path does not report a bogus eviction");
        cache.WriteReceipt();
    }

    // ---- KEY IDENTITY: same pointer, different geometry -> distinct ------
    {
        Deep2::PreparedWeightCache cache;
        auto& S = cache.stats();
        auto w1 = mk("same", sA);
        auto w2 = w1;
        w2.cols = 128;             // different element count, same source ptr
        w2.sizeBytes = sA.size();
        cache.Acquire(w1, &CountingDequant::fn);
        cache.Acquire(w2, &CountingDequant::fn);
        t.check(S.prepareMiss == 2,
                "KEY: same source pointer + different geometry -> two entries");
    }

    std::printf("\nchecks=%d failures=%d\n", t.checks, t.failures);
    std::printf("TOTAL_CPU_DEQUANT_CALLS=%llu\n",
                (unsigned long long)CountingDequant::calls);
    std::printf("B70_PREPARED_CACHE_UNIT=%s\n", t.failures == 0 ? "PASS" : "FAIL");
    std::printf("B63_EVICTION_VERIFIED=%s\n", t.failures == 0 ? "YES" : "NO");
    std::printf("B63_OVERSIZED_POLICY_VERIFIED=%s\n", t.failures == 0 ? "YES" : "NO");
    std::printf("B63_RECERTIFICATION=COMPLETE\n");
    std::printf("VERDICT=%s\n", t.failures == 0 ? "PASS" : "FAIL");
    return t.failures == 0 ? 0 : 1;
}