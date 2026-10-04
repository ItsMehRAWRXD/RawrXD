// ============================================================================
// deep2_sovereign_kernel_cert_001.cpp
// RAWRXD_DEEP2_SOVEREIGN_KERNEL_001 — runtime proof for Batch 1.
//
// Proves, by execution, that the three formerly-stubbed types are real:
//
//   ResidencyManager        bounded-window admission + LRU eviction
//   RouterPrefetchTelemetry monotonic counters + COMPUTED rates
//   SlidingWindowEngine     real eviction + real window arithmetic
//
// Every expectation below is an OBSERVATION of program state, never a literal.
// The verdict is computed from the checks; it is not printed as a constant.
//
// FALSIFICATION: cases F1..F4 are negative controls. They assert that the
// computed properties CAN fail -- if a rate were stored rather than derived, or
// an eviction were counted without releasing bytes, these would not fail and the
// positive controls would be meaningless.
// ============================================================================
#include "ResidencyManager.hpp"
#include "RouterPrefetchTelemetry.hpp"
#include "SlidingWindowEngine.h"
#include "NUFusedPacker.hpp"
#include "WarmupScheduler.hpp"

#include <cmath>
#include <cstdint>
#include <cstdio>
#include <string>

using namespace Deep2;

static int g_checks = 0, g_fails = 0;

static void check(bool ok, const char* what) {
    ++g_checks;
    if (!ok) {
        ++g_fails;
        std::printf("  FAIL: %s\n", what);
    } else {
        std::printf("  ok  : %s\n", what);
    }
}

static void hdr(const char* s) { std::printf("\n== %s ==\n", s); }

// ---------------------------------------------------------------------------
// 1. ResidencyManager -- real budget, real eviction, real accounting
// ---------------------------------------------------------------------------
static void testResidency() {
    hdr("ResidencyManager");
    // 4 tensors of 1000 bytes, budget 2500 -> at most 2 resident at a time.
    ResidencyManager rm(2500);

    check(rm.budget() == 2500, "budget is what was configured");
    check(rm.registerTensor("a", 1000, 0, 5) == 0, "register a -> idx 0");
    check(rm.registerTensor("b", 1000, 0, 5) == 1, "register b -> idx 1");
    check(rm.registerTensor("c", 1000, 0, 5) == 2, "register c -> idx 2");
    check(rm.registerTensor("", 1000, 0, 5) == SIZE_MAX, "empty name is refused");
    check(rm.registerTensor("d", 0, 0, 5) == SIZE_MAX, "zero bytes is refused");
    check(rm.stats().rejected == 2, "both refusals were counted");
    check(rm.stats().registered == 3, "three registrations counted");

    check(rm.request(0), "admit a");
    check(rm.request(1), "admit b");
    check(rm.residentBytes() == 2000, "resident bytes == 2000 after two admits");
    check(rm.residentCount() == 2, "two tensors resident");

    // Re-request a: must be a HIT and must not change residency.
    check(rm.request(0), "re-request a succeeds");
    check(rm.stats().hits == 1, "re-request counted as a hit");
    check(rm.residentBytes() == 2000, "hit did not move bytes");
    check(rm.stats().admitted == 2, "hit did not count as an admission");

    // Admit c -> 3000 > 2500, so the LRU victim (b, untouched) must be evicted.
    check(rm.request(2), "admit c succeeds after eviction");
    check(rm.stats().evictions == 1, "exactly one eviction happened");
    check(rm.stats().evictedBytes == 1000, "eviction released 1000 bytes");
    check(rm.residentBytes() <= 2500, "residency respects the budget");
    check(rm.residentCount() == 2, "still two resident after evict+admit");
    check(rm.residentBytes() == 2000, "resident bytes back to 2000");

    // The victim must be the LEAST RECENTLY USED. a was touched by the re-request,
    // so b (untouched) is older and must be the one that went.
    check(!rm.at(1)->resident, "b (least recently used) was the victim");
    check(rm.at(0)->resident, "a (recently touched) survived");

    // Derived, not stored: hitRate == hits/(hits+misses).
    const double hr = rm.hitRate();
    check(std::fabs(hr - (1.0 / 4.0)) < 1e-12, "hitRate is computed from counters");
    check(rm.stats().misses == 3, "three misses recorded");
    check(std::fabs(rm.utilisation() - 2000.0 / 2500.0) < 1e-12,
          "utilisation is computed from real bytes");

    // A tensor larger than the whole budget can never be admitted. The index
    // is taken from registerTensor rather than hardcoded, because a hardcoded
    // index is exactly the defect this case originally had.
    const std::size_t hugeIdx = rm.registerTensor("huge", 9999, 0, 1);
    check(hugeIdx != SIZE_MAX, "oversized tensor registered");
    const std::uint64_t evictionsBefore = rm.stats().evictions;
    check(!rm.request(hugeIdx), "oversized tensor is refused");
    check(rm.stats().budgetRejections == 1, "refusal counted as a budget rejection");
    check(rm.stats().evictions == evictionsBefore, "refusal did NOT fake an eviction");

    // An out-of-range index must be an ACCOUNTED refusal, not a silent false.
    const std::uint64_t refusalsBefore = rm.stats().admitRefused;
    check(!rm.request(rm.size() + 100), "out-of-range request returns false");
    check(rm.stats().invalidRequests == 1, "out-of-range request is COUNTED");
    check(rm.stats().admitRefused == refusalsBefore + 1,
          "out-of-range refusal is visible in admitRefused");

    // Pinned entries are never eviction victims.
    rm.pin(0);
    check(rm.request(1), "re-admit b");
    rm.request(3); // force pressure; a is pinned and must survive
    check(rm.at(0)->resident, "pinned tensor survived eviction pressure");
    check(rm.stats().pins == 1, "pin counted");

    std::printf("  MEASURED registered=%llu admitted=%llu refused=%llu hits=%llu "
                "misses=%llu evictions=%llu evicted_bytes=%llu budget=%llu resident=%llu\n",
                (unsigned long long)rm.stats().registered,
                (unsigned long long)rm.stats().admitted,
                (unsigned long long)rm.stats().admitRefused,
                (unsigned long long)rm.stats().hits,
                (unsigned long long)rm.stats().misses,
                (unsigned long long)rm.stats().evictions,
                (unsigned long long)rm.stats().evictedBytes,
                (unsigned long long)rm.budget(),
                (unsigned long long)rm.residentBytes());
}

// ---------------------------------------------------------------------------
// 2. RouterPrefetchTelemetry -- rates must be DERIVED
// ---------------------------------------------------------------------------
static void testTelemetry() {
    hdr("RouterPrefetchTelemetry");
    RouterPrefetchTelemetry t;

    check(t.hitRate() == 0.0, "hitRate is 0 with no events (not NaN, not 1.0)");
    check(!t.healthy(), "not healthy before any request");

    t.noteRouteDecision(4);
    t.noteRouteDecision(6);
    check(t.counters().routeDecisions == 2, "two route decisions recorded");
    check(t.counters().routeKeys == 10, "route keys accumulated");

    // 3 requests: 1 hit (already resident), 2 misses (streamed).
    t.notePrefetchHit(2048, 100);
    t.notePrefetchMiss(4096, 900);
    t.notePrefetchMiss(8192, 1100);
    check(t.counters().prefetchRequests == 3, "three requests recorded");
    check(t.counters().prefetchHits == 1, "one hit recorded");
    check(t.counters().prefetchMisses == 2, "two misses recorded");

    // hitRate must equal 1/3, derived from the events.
    check(std::fabs(t.hitRate() - (1.0 / 3.0)) < 1e-12, "hitRate derived = 1/3");
    check(std::fabs(t.missRate() - (2.0 / 3.0)) < 1e-12, "missRate derived = 2/3");
    check(std::fabs(t.hitRate() + t.missRate() - 1.0) < 1e-12, "rates sum to 1");
    check(t.meanHitLatencyNs() == 100, "mean hit latency is the measured 100ns");
    check(t.meanMissLatencyNs() == 1000, "mean miss latency is the measured 1000ns");

    // One completion fails -> fulfilmentRate must drop below 1 and healthy()=false.
    t.notePrefetchCompletion(true, 100);
    t.notePrefetchCompletion(false, 5000);
    check(t.counters().prefetchFulfilled == 1, "one fulfilment");
    check(t.counters().prefetchFailed == 1, "one failure");
    check(std::fabs(t.fulfilmentRate() - 0.5) < 1e-12, "fulfilmentRate derived = 0.5");
    check(!t.healthy(), "a failed prefetch makes it unhealthy");

    // streamedRatio must reflect bytes, not request counts.
    // resident 2048 vs streamed 4096+8192=12288 -> 12288/14336 = 6/7
    check(std::fabs(t.streamedRatio() - (12288.0 / 14336.0)) < 1e-12,
          "streamedRatio is byte-weighted, not count-weighted");

    std::printf("  MEASURED requests=%llu hits=%llu misses=%llu fulfilled=%llu "
                "failed=%llu hit_rate_x1000=%llu fulfil_x1000=%llu streamed_x1000=%llu "
                "healthy=%d\n",
                (unsigned long long)t.counters().prefetchRequests,
                (unsigned long long)t.counters().prefetchHits,
                (unsigned long long)t.counters().prefetchMisses,
                (unsigned long long)t.counters().prefetchFulfilled,
                (unsigned long long)t.counters().prefetchFailed,
                (unsigned long long)(t.hitRate() * 1000.0),
                (unsigned long long)(t.fulfilmentRate() * 1000.0),
                (unsigned long long)(t.streamedRatio() * 1000.0),
                t.healthy() ? 1 : 0);
}

// ---------------------------------------------------------------------------
// 3. SlidingWindowEngine -- real eviction arithmetic
// ---------------------------------------------------------------------------
static void testSlidingWindow() {
    hdr("SlidingWindowEngine");
    SlidingWindowConfig cfg;
    cfg.maxWindow = 4;
    SlidingWindowEngine sw(cfg);

    check(sw.windowSize() == 4, "window size is 4");
    SlidingWindowConfig bad; bad.maxWindow = 0;
    check(!sw.configure(bad), "a zero window is refused");

    // 6 tokens at absolute positions 0..5 with window 4 -> the first 2 must go.
    for (int i = 0; i < 6; ++i) check(sw.append(100 + i, (std::uint64_t)i), "append");

    check(sw.stats().tokensAppended == 6, "six tokens appended");
    check(sw.stats().tokensEvicted == 2, "two tokens evicted (window 4 over span 6)");
    check(sw.buffered() == 4, "four tokens retained");
    check(sw.oldestPosition() == 2, "oldest retained position is 2");
    check(sw.newestPosition() == 5, "newest position is 5");
    check(sw.tokens()[0] == 102, "the retained buffer starts at token 102");

    // Window arithmetic: at absolute position p the span is min(p+1, window).
    std::size_t s = 0, e = 0;
    check(sw.querySpan(2, s, e), "querySpan answers");
    check(s == 0 && e == 3, "span at p=2 is [0,3)");
    check(sw.querySpan(5, s, e), "querySpan answers at p=5");
    check(s == 2 && e == 6, "span at p=5 is [2,6) -- exactly the window");
    check(sw.spanSizeAt(0) == 1, "span size at p=0 is 1 (itself only)");
    check(sw.spanSizeAt(99) == 4, "span size saturates at the window");

    // retention is derived
    check(std::fabs(sw.retention() - (4.0 / 6.0)) < 1e-12, "retention derived = 4/6");

    // A pinned head cannot be silently dropped: the engine must say so rather
    // than corrupt the buffer.
    sw.clear();
    sw.pinHead(true);
    for (int i = 0; i < 6; ++i) sw.append(200 + i, (std::uint64_t)i);
    check(sw.stats().evictionsSuppressed >= 1,
          "pinning the head suppressed an eviction instead of corrupting it");

    std::printf("  MEASURED appended=%llu evicted=%llu buffered=%zu oldest=%llu "
                "newest=%llu retention_x1000=%llu suppressed=%llu\n",
                (unsigned long long)sw.stats().tokensAppended,
                (unsigned long long)sw.stats().tokensEvicted,
                sw.buffered(),
                (unsigned long long)sw.oldestPosition(),
                (unsigned long long)sw.newestPosition(),
                (unsigned long long)(sw.retention() * 1000.0),
                (unsigned long long)sw.stats().evictionsSuppressed);
}

// ---------------------------------------------------------------------------
// 4. Falsification -- the checks above must be able to FAIL
// ---------------------------------------------------------------------------
static void testFalsifiable() {
    hdr("Falsification (these prove the positive controls can fail)");

    // F1: if eviction freed no bytes, would we notice? Compare resident bytes
    //     to the sum of the resident entries' bytes.
    ResidencyManager rm(2500);
    rm.registerTensor("a", 1000); rm.registerTensor("b", 1000); rm.registerTensor("c", 1000);
    rm.request(0); rm.request(1); rm.request(2);
    std::uint64_t summed = 0;
    for (std::size_t i = 0; i < rm.size(); ++i)
        if (rm.at(i)->resident) summed += rm.at(i)->bytes;
    check(summed == rm.residentBytes(),
          "F1 residentBytes() equals the sum of resident entries (accounting is real)");

    // F2: a derived rate must change when the events change.
    RouterPrefetchTelemetry t1, t2;
    t1.notePrefetchHit(1, 1);
    t2.notePrefetchHit(1, 1); t2.notePrefetchMiss(1, 1);
    check(t1.hitRate() != t2.hitRate(),
          "F2 hitRate responds to events (it is derived, not a stored constant)");

    // F3: an all-hit stream and an all-miss stream must disagree.
    RouterPrefetchTelemetry a, b;
    for (int i = 0; i < 5; ++i) a.notePrefetchHit(10, 1);
    for (int i = 0; i < 5; ++i) b.notePrefetchMiss(10, 1);
    check(a.hitRate() == 1.0 && b.hitRate() == 0.0,
          "F3 pure-hit and pure-miss streams give 1.0 and 0.0");

    // F4: window arithmetic must actually depend on the window size.
    SlidingWindowConfig w2, w8;
    w2.maxWindow = 2; w8.maxWindow = 8;
    SlidingWindowEngine s2(w2), s8(w8);
    check(s2.spanSizeAt(100) != s8.spanSizeAt(100),
          "F4 span size depends on the configured window");

    // F5: eviction must actually free the budget (a no-op evictor would pass a
    //     naive "evictions>0" check).
    ResidencyManager rm2(1000);
    rm2.registerTensor("x", 600); rm2.registerTensor("y", 600);
    rm2.request(0);
    check(rm2.request(1), "second tensor admitted after eviction");
    check(rm2.residentBytes() == 600, "resident bytes == 600 (the victim really went)");
    check(rm2.at(0)->resident == false, "the first tensor is the one that was evicted");
}

// ---------------------------------------------------------------------------
// 5. NUFusedPacker -- real bf16 numerics, verified against known values
// ---------------------------------------------------------------------------
static void testNUPacker() {
    hdr("NUFusedPacker (bf16)");
    NUPackerConfig cfg;
    cfg.blockSize = 4;
    cfg.useBlockScale = false;
    NUFusedPacker packer(cfg);

    // Exact bf16 round-trips: every value with <=8 mantissa bits survives.
    check(packer.f32ToBf16(1.0f) == 0x3F80, "1.0f -> 0x3F80");
    check(packer.bf16ToF32(0x3F80) == 1.0f, "0x3F80 -> 1.0f");
    check(packer.bf16ToF32(packer.f32ToBf16(-2.0f)) == -2.0f, "-2.0f round-trips exactly");
    check(packer.bf16ToF32(packer.f32ToBf16(0.0f)) == 0.0f, "0.0f round-trips exactly");

    // Refusals must be counted and must not claim work.
    check(!packer.pack(nullptr, 4, nullptr), "null pointers are refused");
    check(packer.stats().packRefused == 1, "refusal counted");
    check(packer.stats().packCalls == 0, "refusal did NOT count as a pack");
    std::uint16_t dst[8] = {0};
    check(!packer.pack(nullptr, 0, dst), "zero count is refused");

    // A real pack over representable and non-representable values.
    const float src[6] = {1.0f, 2.0f, 0.5f, 3.14159265f, 1.0000001f, 100.0f};
    check(packer.pack(src, 6, dst), "pack of 6 elements succeeded");
    check(packer.stats().packCalls == 1, "one pack call counted");
    check(packer.stats().blocksPacked == 2, "two blocks of 4 (last partial) counted");
    check(packer.stats().elementsPacked == 6, "six elements counted");
    check(packer.stats().bytesIn == 24, "bytesIn == 6*4");
    check(packer.stats().bytesOut == 12, "bytesOut == 6*2");

    // Real byte counts must give a real compression ratio: 12/24 = 0.5.
    check(std::fabs(packer.compressionRatio() - 0.5) < 1e-12,
          "compressionRatio is computed from real bytes");

    // The MEASURED error must be nonzero (pi is not representable in bf16) and
    // must sit inside bf16's envelope. If this were hardcoded to 0 the pack
    // would be a no-op.
    check(packer.stats().maxRelError > 0.0, "maxRelError is nonzero (pi is not exact)");
    check(packer.withinBf16Envelope(), "measured error is inside the bf16 envelope");

    // Independent re-measurement: unpack and compare element by element. This
    // does not trust stats() at all.
    float back[6] = {0};
    NUFusedPacker::unpack(dst, 6, back);
    double worst = 0.0;
    for (int i = 0; i < 6; ++i) {
        const float d = std::fabs(back[i] - src[i]);
        const float den = src[i] != 0.0f ? std::fabs(src[i]) : 1.0f;
        const double rel = d / den;
        if (rel > worst) worst = rel;
        if (src[i] == 1.0f || src[i] == 2.0f || src[i] == 0.5f ||
            src[i] == 100.0f) {
            if (back[i] != src[i]) {
                check(false, "exact value did not round-trip");
            }
        }
    }
    check(worst <= (1.0 / 128.0), "independently re-measured error is within bf16 envelope");
    check(std::fabs(worst - packer.stats().maxRelError) < 1e-9,
          "stats().maxRelError matches an independent measurement");

    // A tolerance is a gate on MEASURED error: a value bf16 cannot hold must
    // trip it, and the trip must be counted.
    NUPackerConfig strict;
    strict.blockSize = 4;
    strict.useBlockScale = false;
    strict.maxRelErrorTolerance = 1e-9;   // far tighter than bf16 can hold
    NUFusedPacker strictPacker(strict);
    std::uint16_t dst2[8] = {0};
    check(!strictPacker.pack(src, 6, dst2),
          "a tolerance tighter than bf16 precision rejects the pack");
    check(strictPacker.stats().toleranceRejects == 1, "tolerance rejection counted");

    std::printf("  MEASURED pack_calls=%llu blocks=%llu elements=%llu bytes_in=%llu "
                "bytes_out=%llu max_rel_err=%.9f mean_rel_err=%.9f "
                "ratio_x1000=%llu tolerance_rejects=%llu\n",
                (unsigned long long)packer.stats().packCalls,
                (unsigned long long)packer.stats().blocksPacked,
                (unsigned long long)packer.stats().elementsPacked,
                (unsigned long long)packer.stats().bytesIn,
                (unsigned long long)packer.stats().bytesOut,
                packer.stats().maxRelError,
                packer.stats().meanRelError,
                (unsigned long long)(packer.compressionRatio() * 1000.0),
                (unsigned long long)packer.stats().toleranceRejects);
}

// ---------------------------------------------------------------------------
// 6. WarmupScheduler -- the predictor must be able to be WRONG
// ---------------------------------------------------------------------------
static void testWarmup() {
    hdr("WarmupScheduler (predictive prefetch)");
    WarmupConfig cfg;
    cfg.lookahead = 2;
    cfg.minSamplesForPrediction = 2;
    WarmupScheduler w(cfg);

    check(w.hitRate() == 0.0, "hitRate is 0 before any observation");
    check(!w.trustworthy(), "not trustworthy before any observation");

    // The FIRST observation cannot be predicted: there is no history. The
    // scheduler must decline rather than guess.
    w.observe(0);
    check(w.stats().observations == 1, "one observation");
    check(w.stats().suppressed == 1, "first observation is not predicted from nothing");
    check(w.stats().prefetchIssued == 0, "no prediction issued without evidence");

    // Learn a strict 0->1->2->3 cycle. Four reps are needed before the recent
    // window holds kRecentWindow-satisfying evidence: trustworthiness requires
    // at least minRecent=4 SCORED outcomes, and a cold predictor is correctly
    // reported as untrustworthy rather than assumed good.
    for (int rep = 0; rep < 4; ++rep)
        for (std::uint32_t layer = 0; layer < 4; ++layer) w.observe(layer);

    check(w.stats().transitions >= 12, "transitions learned from the cycle");
    check(w.predictNext(0) == 1, "predictNext(0) == 1 from the learned cycle");
    check(w.predictNext(2) == 3, "predictNext(2) == 3 from the learned cycle");

    // Continue the SAME cycle: the predictions must now be right, and the hit
    // rate must reflect that.
    const std::uint64_t hitsBefore = w.stats().hits;
    for (std::uint32_t layer = 0; layer < 4; ++layer) w.observe(layer);
    check(w.stats().hits > hitsBefore, "following the learned cycle scores hits");
    check(w.hitRate() > 0.5, "hit rate is high when the order is learnable");
    check(w.recentPrecision() > 0.9, "recent precision is high on a learnable order");
    check(w.trustworthy(), "predictor becomes trustworthy on a learnable order");

    const double goodRate = w.hitRate();

    // FALSIFICATION: break the order. A predictor that cannot be wrong is not a
    // predictor.
    //
    // NOTE the earlier revision of this case used {3,1,0,2} then {2,3,1,0} and
    // called it "broken". It is not: that second sequence is a ROTATION of the
    // first, so the transition table was correct and the 100% hit rate was the
    // right answer. The test was wrong, not the scheduler. A genuinely
    // unlearnable order interleaves a layer the table has never seen.
    WarmupScheduler bad(cfg);
    for (int rep = 0; rep < 4; ++rep)
        for (std::uint32_t layer = 0; layer < 4; ++layer) bad.observe(layer);
    check(bad.trustworthy(), "predictor is confident on the learned cycle first");

    const std::uint64_t badMissBefore = bad.stats().misses;
    const std::uint64_t badIssuedBefore = bad.stats().prefetchIssued;
    // 0 predicts 1; feed 7 (never seen). Then 0 again, then 7 again.
    for (std::uint32_t layer : {0u, 7u, 0u, 7u, 0u, 7u}) bad.observe(layer);
    check(bad.stats().misses > badMissBefore,
          "an order that violates the learned cycle scores MISSES");
    check(bad.stats().prefetchIssued > badIssuedBefore,
          "predictions really were issued into the violating order");
    check(bad.hitRate() < goodRate, "hit rate is lower on an unlearnable order");
    check(!bad.trustworthy(), "predictor is not trustworthy on a broken order");

    std::printf("  MEASURED learned: observations=%llu transitions=%llu issued=%llu "
                "hits=%llu misses=%llu hit_rate_x1000=%llu precision_x1000=%llu\n",
                (unsigned long long)w.stats().observations,
                (unsigned long long)w.stats().transitions,
                (unsigned long long)w.stats().prefetchIssued,
                (unsigned long long)w.stats().hits,
                (unsigned long long)w.stats().misses,
                (unsigned long long)(w.hitRate() * 1000.0),
                (unsigned long long)(w.precision() * 1000.0));
    std::printf("  MEASURED broken: observations=%llu issued=%llu hits=%llu "
                "hit_rate_x1000=%llu trustworthy=%d\n",
                (unsigned long long)bad.stats().observations,
                (unsigned long long)bad.stats().prefetchIssued,
                (unsigned long long)bad.stats().hits,
                (unsigned long long)(bad.hitRate() * 1000.0),
                bad.trustworthy() ? 1 : 0);
}

int main() {
    std::printf("RAWRXD_DEEP2_SOVEREIGN_KERNEL_001\n");
    std::printf("TOOL=rawrxd/tools/deep2_sovereign_kernel_cert_001.cpp\n\n");

    testResidency();
    testTelemetry();
    testSlidingWindow();
    testNUPacker();
    testWarmup();
    testFalsifiable();

    std::printf("\nCHECKS_RUN=%d\nCHECKS_FAIL=%d\n", g_checks, g_fails);
    if (g_fails == 0) {
        std::printf("VERDICT=PASS\n");
        return 0;
    }
    std::printf("VERDICT=FAIL\n");
    return 1;
}
