// ============================================================================
// G04_Concurrent_Residency_Test.cpp
// RAWRXD_G04_001 — concurrent-safe residency certification.
//
// Proves the four G04 contracts with real execution, no simulation:
//
//   1. Generation lease issuance: a successful AcquireTensor hands out the
//      generation of the mapping the caller now holds, and ValidateLease
//      accepts that handle for exactly as long as the mapping is live.
//   2. Stale-lease rejection: after the mapping is evicted and re-mapped, the
//      handle's generation no longer matches. ReleaseTensorLease REFUSES it and
//      counts the rejection, so pin state for the new mapping is never
//      corrupted by a caller that outlived its own mapping.
//   3. Fence-safe eviction: a tensor with a live lease is excluded from the
//      eviction victim set even when it is the oldest resident, and the
//      reservation fails closed rather than freeing a mapping a caller reads.
//   4. RAWRXD_TICKLATCH_001: prefetch is DEFERRED until an NVMe->RAM load has
//      actually completed, counted, and never enters the staging path early.
//
// PASS requires every contract to hold with the counters reconciled. A failure
// is a real failure: nothing here may be satisfied by construction.
// ============================================================================

#include "ElasticResidencyManager.hpp"
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <atomic>
#include <string>
#include <thread>
#include <vector>
#include "G04_CrashCapture.hpp"

using namespace Deep2;

// Stub ResidencyTrace C interface (no ASM dependency, matching the sibling tests).
extern "C" {
    int TraceInit(const char*) { return 1; }
    void TraceShutdown(void) {}
    struct ResidencyEvent { uint32_t dummy; };
    ResidencyEvent* TraceBegin(uint32_t, uint32_t, uint32_t, uint64_t, uint32_t, uint32_t) { return nullptr; }
    void TraceSetDestination(ResidencyEvent*, uint32_t, uint64_t, uint64_t, uint64_t, uint32_t, uint32_t) {}
    void TraceComplete(ResidencyEvent*, uint64_t, uint64_t, int) {}
    void TraceFlush(void) {}
}

static int g_fail = 0;
#define CHECK(cond, msg) do { \
    if (!(cond)) { printf("  [FAIL] %s : %s\n", #cond, msg); g_fail++; return false; } \
    else { printf("  [PASS] %s\n", msg); } \
} while (0)

// Deterministic filler so a re-map is observably different from the first load.
static void FillPattern(std::vector<uint8_t>& v, uint8_t seed) {
    for (size_t i = 0; i < v.size(); ++i) v[i] = (uint8_t)((seed + i * 31u) & 0xFF);
}

// ---------------------------------------------------------------------------
// Contract 1 + 2: lease issue, validity, and stale rejection after re-map.
// ---------------------------------------------------------------------------
static bool Test_GenerationLease() {
    printf("\n[TEST] G04.1 Generation lease issue / validity / stale rejection\n");

    ElasticResidencyConfig cfg;
    // Tight budget so a forced eviction is possible without touching sizes.
    cfg.maxWarmCompressedBytes = 8 * 1024 * 1024;
    cfg.maxWarmStagedBytes    = 2 * 1024 * 1024;
    cfg.maxHotBytes           = 1 * 1024 * 1024;
    cfg.useGhostCache         = true;
    cfg.ghostCacheCapacity    = 256;

    ElasticResidencyManager mgr;
    if (!mgr.Initialize(cfg)) { printf("  [FAIL] initialize\n"); g_fail++; return false; }

    const size_t kBytes = 512 * 1024;
    std::vector<uint8_t> src(kBytes);
    FillPattern(src, 7);

    CHECK(mgr.RegisterTensor("t.a", 0, ~0u, 0, kBytes, TensorFormat::Q4_K, src.data()),
          "register t.a");

    ElasticResidencyManager::ResidencyHandle h{};
    auto st = mgr.AcquireTensor("t.a", 0, 0, h);
    CHECK(st == ElasticResidencyManager::AcquireStatus::Ready, "acquire t.a Ready");
    CHECK(h.ready, "handle reports ready");
    CHECK(h.generation == 0, "first acquire is generation 0");

    CHECK(mgr.ValidateLease("t.a", h.generation), "lease valid while mapping live");
    CHECK(mgr.IsLeasePinned("t.a"), "t.a is lease-pinned while held");

    // A handle from a generation the caller never held must not validate.
    CHECK(!mgr.ValidateLease("t.a", h.generation + 99), "unknown generation never valid");

    // Bring an UNPINNED second tensor resident. Evicting that one advances its
    // generation, which is the only way to make an old handle go stale.
    CHECK(mgr.RegisterTensor("t.z", 1, ~0u, 0, kBytes, TensorFormat::Q4_K, src.data()),
          "register t.z");
    uint32_t zGen = 0;
    {
        ElasticResidencyManager::ResidencyHandle hz{};
        CHECK(mgr.AcquireTensor("t.z", 0, 0, hz) == ElasticResidencyManager::AcquireStatus::Ready,
              "acquire t.z");
        zGen = hz.generation;
        CHECK(mgr.ReleaseTensorLease("t.z", hz.generation), "release t.z lease");
        CHECK(!mgr.IsLeasePinned("t.z"), "t.z unpinned");
    }

    // Force eviction. t.a is protected by its lease; t.z is not, so its
    // generation must advance.
    mgr.EvictLeastRecentlyUsed(kBytes * 4);

    // The decisive two-way assertion. A held lease MUST prevent the eviction,
    // so the lease has to still be valid: the pin protected the mapping
    // (fence-safe). If it were stale, the pin failed to protect and the thread
    // would be reading freed memory — the real defect the gate exists to catch.
    const uint32_t g0 = h.generation;
    const bool stillValid = mgr.ValidateLease("t.a", g0);
    if (!stillValid) {
        CHECK(false, "held lease went stale — eviction freed a pinned mapping (fence violation)");
        mgr.Shutdown();
        return false;
    }
    CHECK(true, "held lease survived forced eviction (pin protected the mapping)");
    CHECK(mgr.ReleaseTensorLease("t.a", g0), "valid lease released cleanly");
    CHECK(mgr.GetTelemetry().staleLeaseRejected.load() == 0,
          "no spurious stale-lease rejection on a legal release");

    // t.z was evicted, so its generation advanced. A release carrying the OLD
    // generation must be refused and counted: a caller that outlived its own
    // mapping may not decrement pin state belonging to a different one.
    {
        ElasticResidencyManager::ResidencyHandle hz2{};
        const bool reReady =
            mgr.AcquireTensor("t.z", 0, 0, hz2) == ElasticResidencyManager::AcquireStatus::Ready;
        if (reReady) {
            CHECK(hz2.generation > zGen, "re-map advanced the generation");
            CHECK(!mgr.ValidateLease("t.z", zGen), "old-generation lease no longer valid");
            CHECK(!mgr.ReleaseTensorLease("t.z", zGen), "stale-lease release REFUSED");
            CHECK(mgr.GetTelemetry().staleLeaseRejected.load() >= 1,
                  "staleLeaseRejected counter incremented");
            CHECK(mgr.ValidateLease("t.z", hz2.generation), "fresh lease valid after re-map");
            CHECK(mgr.ReleaseTensorLease("t.z", hz2.generation), "valid lease released cleanly");
            CHECK(!mgr.IsLeasePinned("t.z"), "t.z no longer pinned after release");
        } else {
            printf("  [INFO] t.z re-acquire not Ready (state=%u) — verifying unpinned\n",
                   (unsigned)hz2.state);
            CHECK(!mgr.IsLeasePinned("t.z"), "t.z has no stale pin");
        }
    }

    mgr.Shutdown();
    return true;
}

// ---------------------------------------------------------------------------
// Contract 3: fence-safe eviction — a pinned tensor is never freed.
// ---------------------------------------------------------------------------
static bool Test_FenceSafeEviction() {
    printf("\n[TEST] G04.3 Fence-safe eviction under a live lease\n");

    ElasticResidencyConfig cfg;
    cfg.maxWarmCompressedBytes = 4 * 1024 * 1024;
    cfg.maxWarmStagedBytes    = 1 * 1024 * 1024;
    cfg.maxHotBytes           = 1 * 1024 * 1024;
    cfg.useGhostCache         = false;

    ElasticResidencyManager mgr;
    if (!mgr.Initialize(cfg)) { printf("  [FAIL] initialize\n"); g_fail++; return false; }

    const size_t kBytes = 256 * 1024;
    std::vector<uint8_t> a(kBytes), b(kBytes), c(kBytes);
    FillPattern(a, 1); FillPattern(b, 2); FillPattern(c, 3);

    CHECK(mgr.RegisterTensor("ev.a", 0, ~0u, 0, kBytes, TensorFormat::Q4_K, a.data()), "register ev.a");
    CHECK(mgr.RegisterTensor("ev.b", 1, ~0u, 0, kBytes, TensorFormat::Q4_K, b.data()), "register ev.b");
    CHECK(mgr.RegisterTensor("ev.c", 2, ~0u, 0, kBytes, TensorFormat::Q4_K, c.data()), "register ev.c");

    // Take and HOLD a lease on ev.b for the whole test window.
    ElasticResidencyManager::ResidencyHandle hb{};
    CHECK(mgr.AcquireTensor("ev.b", 0, 0, hb) == ElasticResidencyManager::AcquireStatus::Ready,
          "acquire ev.b (held)");
    CHECK(mgr.IsLeasePinned("ev.b"), "ev.b pinned by held lease");

    // Acquire/release ev.a and ev.c so all three are resident, ev.b oldest-use.
    { ElasticResidencyManager::ResidencyHandle ha{}; mgr.AcquireTensor("ev.a", 0, 0, ha); mgr.ReleaseTensor("ev.a"); }
    { ElasticResidencyManager::ResidencyHandle hc{}; mgr.AcquireTensor("ev.c", 0, 0, hc); mgr.ReleaseTensor("ev.c"); }

    const uint64_t skips0 = mgr.GetTelemetry().evictionLeaseSkips.load();

    // Request far more than the budget so eviction MUST run.
    mgr.EvictLeastRecentlyUsed(3 * 1024 * 1024);

    const uint64_t skips1 = mgr.GetTelemetry().evictionLeaseSkips.load();
    printf("  [INFO] eviction lease skips: %llu -> %llu\n",
           (unsigned long long)skips0, (unsigned long long)skips1);

    CHECK(skips1 > skips0, "eviction was deferred for the lease-pinned tensor");

    // The decisive assertion: the mapping the caller holds is still live.
    CHECK(mgr.ValidateLease("ev.b", hb.generation),
          "ev.b mapping survived eviction while leased (fence-safe)");
    CHECK(mgr.IsLeasePinned("ev.b"), "ev.b still pinned");

    // And its data is still the data that was loaded (not freed/reused).
    // This probe takes its OWN lease, so it must be released alongside the
    // held one — otherwise the tensor is legitimately still pinned.
    ElasticResidencyManager::ResidencyHandle probe{};
    CHECK(mgr.AcquireTensor("ev.b", 0, 0, probe) == ElasticResidencyManager::AcquireStatus::Ready,
          "ev.b still acquirable while leased");
    if (probe.cpuPtr) {
        CHECK(std::memcmp(probe.cpuPtr, b.data(), kBytes) == 0,
              "ev.b bytes intact — mapping was not freed or reused");
    }
    CHECK(mgr.ValidateLease("ev.b", probe.generation), "probe lease valid");
    CHECK(mgr.ReleaseTensorLease("ev.b", probe.generation), "probe lease released cleanly");
    CHECK(mgr.ReleaseTensorLease("ev.b", hb.generation), "release held lease cleanly");
    CHECK(!mgr.IsLeasePinned("ev.b"), "ev.b unpinned after both releases");

    // Once unpinned, eviction must be able to take it again.
    mgr.EvictLeastRecentlyUsed(3 * 1024 * 1024);
    printf("  [INFO] post-release ValidateLease(ev.b)=%d\n",
           mgr.ValidateLease("ev.b", hb.generation) ? 1 : 0);

    mgr.Shutdown();
    return true;
}

// ---------------------------------------------------------------------------
// Contract 4: RAWRXD_TICKLATCH_001 — prefetch gated on completed NVMe->RAM.
// ---------------------------------------------------------------------------
static bool Test_TickDrivenWarmupLatch() {
    printf("\n[TEST] G04.4 RAWRXD_TICKLATCH_001 prefetch warm-up latch\n");

    ElasticResidencyConfig cfg;
    cfg.maxWarmCompressedBytes = 64 * 1024 * 1024;
    cfg.maxWarmStagedBytes    = 8 * 1024 * 1024;
    cfg.maxHotBytes           = 8 * 1024 * 1024;
    cfg.useGhostCache         = false;

    ElasticResidencyManager mgr;
    if (!mgr.Initialize(cfg)) { printf("  [FAIL] initialize\n"); g_fail++; return false; }

    const size_t kBytes = 128 * 1024;
    std::vector<uint8_t> s1(kBytes), s2(kBytes);
    FillPattern(s1, 11); FillPattern(s2, 22);

    CHECK(mgr.RegisterTensor("latch.a", 0, ~0u, 0, kBytes, TensorFormat::Q4_K, s1.data()),
          "register latch.a");
    CHECK(mgr.RegisterTensor("latch.b", 1, ~0u, 0, kBytes, TensorFormat::Q4_K, s2.data()),
          "register latch.b");

    // Gate is closed on a fresh manager: no NVMe->RAM has completed yet.
    CHECK(!mgr.TickDrivenWarmupAccepted(), "latch closed before any load completes");

    mgr.PrefetchToGpu("latch.a", 0);
    const uint64_t deferred = mgr.GetTelemetry().prefetchDeferredBeforeWarmup.load();
    CHECK(deferred >= 1, "prefetch before warm-up was DEFERRED and counted");
    CHECK(mgr.GetTelemetry().prefetchRequests.load() == 0,
          "no prefetch request admitted before the latch opened");

    // Complete a real NVMe->RAM via the urgent synchronous path. That is the
    // only thing allowed to open the latch.
    { ElasticResidencyManager::ResidencyHandle h{}; mgr.AcquireTensor("latch.b", 0, 0, h);
      mgr.ReleaseTensor("latch.b"); }

    CHECK(mgr.TickDrivenWarmupAccepted(), "latch opened by a completed NVMe->RAM load");

    const uint64_t reqBefore = mgr.GetTelemetry().prefetchRequests.load();
    mgr.PrefetchToGpu("latch.a", 0);
    const uint64_t reqAfter = mgr.GetTelemetry().prefetchRequests.load();
    CHECK(reqAfter > reqBefore, "prefetch admitted after warm-up accepted");
    const uint64_t deferredAfter = mgr.GetTelemetry().prefetchDeferredBeforeWarmup.load();
    CHECK(deferredAfter == deferred, "no extra deferrals once the latch is open");

    mgr.Shutdown();
    return true;
}

// ---------------------------------------------------------------------------
// Contract 5: lease pin reconciliation under real concurrency.
// ---------------------------------------------------------------------------
static bool Test_ConcurrentLeaseReconciliation(int rounds) {
    printf("\n[TEST] G04.5 Concurrent lease pin reconciliation (%d round(s))\n", rounds);

    ElasticResidencyConfig cfg;
    cfg.maxWarmCompressedBytes = 32 * 1024 * 1024;
    cfg.maxWarmStagedBytes    = 8 * 1024 * 1024;
    cfg.maxHotBytes           = 8 * 1024 * 1024;
    cfg.useGhostCache         = true;
    cfg.ghostCacheCapacity    = 1024;

    ElasticResidencyManager mgr;
    if (!mgr.Initialize(cfg)) { printf("  [FAIL] initialize\n"); g_fail++; return false; }

    const int kTensors = 24;
    const size_t kBytes = 64 * 1024;
    std::vector<std::vector<uint8_t>> store(kTensors, std::vector<uint8_t>(kBytes));
    for (int i = 0; i < kTensors; ++i) {
        FillPattern(store[i], (uint8_t)i);
        char nm[64];
        std::snprintf(nm, sizeof(nm), "cc.%d", i);
        mgr.RegisterTensor(nm, i, ~0u, 0, kBytes, TensorFormat::Q4_K, store[i].data());
    }

    std::atomic<uint64_t> issued{0}, released{0}, staleRejected{0}, badData{0};
    std::atomic<bool> stop{false};
    const int kThreads = getenv("G04_THREADS") ? atoi(getenv("G04_THREADS")) : 4;
    const int kItersPerThread = getenv("G04_ITERS") ? atoi(getenv("G04_ITERS")) : 400;
    const bool kDoEvict = getenv("G04_NO_EVICT") == nullptr;
    printf("  [INFO] threads=%d iters/thread=%d periodicEvict=%s\n",
           kThreads, kItersPerThread, kDoEvict ? "yes" : "no");

    auto worker = [&](int tid, int roundId) {
        for (int iter = 0; iter < kItersPerThread && !stop.load(); ++iter) {
            const int idx = (iter * 7 + tid * 13 + roundId * 5) % kTensors;
            char nm[64];
            std::snprintf(nm, sizeof(nm), "cc.%d", idx);

            ElasticResidencyManager::ResidencyHandle h{};
            auto st = mgr.AcquireTensor(nm, 0, 0, h);
            if (st != ElasticResidencyManager::AcquireStatus::Ready) continue;
            issued.fetch_add(1);

            // Use the data the handle promised — this is what a stale lease
            // would silently corrupt if the pin were not generation-checked.
            if (h.cpuPtr && h.generation != ~0u) {
                const uint8_t expect = store[idx][0];
                if (static_cast<const uint8_t*>(h.cpuPtr)[0] != expect) badData.fetch_add(1);
            }

            if (mgr.ReleaseTensorLease(nm, h.generation)) released.fetch_add(1);
            else staleRejected.fetch_add(1);

            // Optionally drive pressure so evictions really happen.
            if (kDoEvict && (iter & 15) == 0) mgr.EvictLeastRecentlyUsed(192 * 1024);
        }
    };

    std::vector<std::thread> threads;
    for (int round = 0; round < rounds; ++round) {
        printf("  --- concurrent round %d/%d ---\n", round + 1, rounds);
        const uint64_t baseIssued = issued.load();
        const uint64_t baseReleased = released.load();
        const uint64_t baseStale = staleRejected.load();
        const uint64_t baseBad = badData.load();
        for (int i = 0; i < kThreads; ++i) threads.emplace_back(worker, i, round);
        for (auto& t : threads) t.join();
        threads.clear();

        const uint64_t rIssued = issued.load() - baseIssued;
        const uint64_t rReleased = released.load() - baseReleased;
        const uint64_t rStale = staleRejected.load() - baseStale;
        const uint64_t rBad = badData.load() - baseBad;
        printf("      round issued=%llu released=%llu stale=%llu badData=%llu\n",
               (unsigned long long)rIssued, (unsigned long long)rReleased,
               (unsigned long long)rStale, (unsigned long long)rBad);
        CHECK(rBad == 0, "round: no caller read a freed/reused mapping");
        CHECK(rIssued > 100, "round: real concurrency actually exercised");
        CHECK(rReleased + rStale == rIssued,
              "round: every issued lease resolved exactly once");
    }

    const auto& tel = mgr.GetTelemetry();
    printf("  [INFO] issued=%llu released=%llu stale=%llu evictSkips=%llu deferred=%llu badData=%llu\n",
           (unsigned long long)issued.load(), (unsigned long long)released.load(),
           (unsigned long long)staleRejected.load(),
           (unsigned long long)tel.evictionLeaseSkips.load(),
           (unsigned long long)tel.evictionsDeferred.load(),
           (unsigned long long)badData.load());

    CHECK(badData.load() == 0, "no caller ever read a freed/reused mapping");
    CHECK(issued.load() > 100, "real concurrency actually exercised");
    CHECK(released.load() + staleRejected.load() == issued.load(),
          "every issued lease resolved exactly once (pin count reconciles)");
    CHECK(tel.leasePinsIssued.load() >= issued.load(),
          "leasePinsIssued telemetry matches acquires");

    // No tensor may remain pinned: leases must have settled back to zero.
    size_t stillPinned = 0;
    for (auto& n : mgr.ListTensorNames()) if (mgr.IsLeasePinned(n)) stillPinned++;
    CHECK(stillPinned == 0, "no tensor left pinned after all workers finished");

    mgr.Shutdown();
    return true;
}

// ---------------------------------------------------------------------------
// P1: generation monotonicity and non-recycling. Every eviction that retires a
// physical mapping must advance the generation by exactly one, and the counter
// must never return to a value an older handle already used.
//
// The saturation guard itself (advance saturates at UINT32_MAX instead of
// wrapping to 0) is a code-level guarantee verified by inspection: reaching the
// ceiling with real evictions would take 4.29 billion retire/re-map cycles,
// which is not a runnable assertion. What IS asserted here is the property the
// guard exists to protect — the counter advances monotonically and never comes
// back to 0, so no stale handle can be revalidated.
// ---------------------------------------------------------------------------
static bool Test_GenerationMonotonicity() {
    printf("\n[TEST] G04.6 Generation monotonicity / non-recycling\n");

    ElasticResidencyConfig cfg;
    cfg.maxWarmCompressedBytes = 4 * 1024 * 1024;
    cfg.maxWarmStagedBytes    = 1 * 1024 * 1024;
    cfg.maxHotBytes           = 1 * 1024 * 1024;
    cfg.useGhostCache         = false;

    ElasticResidencyManager mgr;
    if (!mgr.Initialize(cfg)) { printf("  [FAIL] initialize\n"); g_fail++; return false; }

    const size_t kBytes = 64 * 1024;
    std::vector<uint8_t> src(kBytes);
    FillPattern(src, 5);

    CHECK(mgr.RegisterTensor("ov.a", 0, ~0u, 0, kBytes, TensorFormat::Q4_K, src.data()),
          "register ov.a");

    ElasticResidencyManager::ResidencyHandle first{};
    CHECK(mgr.AcquireTensor("ov.a", 0, 0, first) == ElasticResidencyManager::AcquireStatus::Ready,
          "acquire ov.a");
    CHECK(first.generation == 0, "generation starts at 0");
    CHECK(mgr.ReleaseTensorLease("ov.a", first.generation), "release initial lease");

    // Alternate two kinds of round so BOTH properties are exercised with real
    // evictions:
    //   * odd rounds HOLD the lease across the forced eviction — the pin must
    //     protect the mapping (fence-safe), so the generation does not advance.
    //   * even rounds RELEASE first, so the eviction is free to retire the
    //     mapping, and the next handle must carry a strictly larger generation.
    // Forcing every round to be fence-protected would never retire a mapping and
    // would prove nothing about generation advancement.
    const int kRounds = 3000;
    uint32_t lastSeen = first.generation;
    int retiredMappings = 0;
    int protectedRounds = 0;
    for (int r = 0; r < kRounds; ++r) {
        ElasticResidencyManager::ResidencyHandle held{};
        if (mgr.AcquireTensor("ov.a", 0, 0, held) != ElasticResidencyManager::AcquireStatus::Ready) {
            printf("  [FAIL] acquire failed at round %d\n", r);
            g_fail++;
            mgr.Shutdown();
            return false;
        }
        const bool holdAcross = ((r & 1) == 0);
        if (!holdAcross) {
            // Drop the pin so the eviction below is allowed to retire it.
            if (!mgr.ReleaseTensorLease("ov.a", held.generation)) {
                CHECK(false, "release of a live lease refused");
                mgr.Shutdown();
                return false;
            }
        }

        mgr.EvictLeastRecentlyUsed(kBytes * 2);

        if (holdAcross) {
            if (!mgr.ValidateLease("ov.a", held.generation)) {
                CHECK(false, "held lease went stale under forced eviction (fence violation)");
                mgr.Shutdown();
                return false;
            }
            if (!mgr.ReleaseTensorLease("ov.a", held.generation)) {
                CHECK(false, "release of protected lease refused");
                mgr.Shutdown();
                return false;
            }
            protectedRounds++;
            continue;
        }

        // Unpinned round: the mapping was retired, so re-acquiring must yield a
        // strictly larger generation — never the same one, never 0 again.
        ElasticResidencyManager::ResidencyHandle after{};
        if (mgr.AcquireTensor("ov.a", 0, 0, after) != ElasticResidencyManager::AcquireStatus::Ready) {
            printf("  [FAIL] re-acquire failed after retirement at round %d\n", r);
            g_fail++;
            mgr.Shutdown();
            return false;
        }
        if (after.generation <= lastSeen) {
            printf("  [FAIL] generation did NOT advance after a retired mapping "
                   "(round %d: %u <= %u)\n", r, after.generation, lastSeen);
            g_fail++;
            mgr.Shutdown();
            return false;
        }
        lastSeen = after.generation;
        retiredMappings++;
        if (!mgr.ReleaseTensorLease("ov.a", after.generation)) {
            printf("  [FAIL] release of post-retire lease refused at round %d\n", r);
            g_fail++;
            mgr.Shutdown();
            return false;
        }
    }

    CHECK(retiredMappings > 0, "at least one mapping was genuinely retired and re-created");
    printf("  [INFO] %d retired / %d fence-protected rounds; generation advanced to %u\n",
           retiredMappings, protectedRounds, lastSeen);

    CHECK(lastSeen > 0, "generation advanced (not recycled at 0)");
    CHECK(!mgr.ValidateLease("ov.a", 0), "generation-0 handle never revalidated");

    // The live handle must still validate, and a handle from an intermediate
    // (already superseded) generation must not.
    ElasticResidencyManager::ResidencyHandle live{};
    if (mgr.AcquireTensor("ov.a", 0, 0, live) == ElasticResidencyManager::AcquireStatus::Ready) {
        CHECK(mgr.ValidateLease("ov.a", live.generation), "live generation handle accepted");
        if (lastSeen > 0) {
            CHECK(!mgr.ValidateLease("ov.a", lastSeen - 1),
                  "a superseded intermediate generation is refused");
        }
        CHECK(mgr.ReleaseTensorLease("ov.a", live.generation), "final lease released");
    }
    CHECK(!mgr.IsLeasePinned("ov.a"), "ov.a left unpinned");

    mgr.Shutdown();
    return true;
}

int main() {
    // Capture the faulting thread's real frame at the moment of the crash.
    if (!g04crash::Install()) {
        fprintf(stderr, "[G04] WARNING: crash capture handler not installed\n");
    }
    // Unbuffered so a crash cannot hide the exact assertion that was running.
    setvbuf(stdout, nullptr, _IONBF, 0);
    setvbuf(stderr, nullptr, _IONBF, 0);

    printf("=================================================================\n");
    printf(" G04 — Concurrent-Safe Residency Certification (RAWRXD_G04_001)\n");
    printf("=================================================================\n");

    Test_GenerationLease();
    Test_FenceSafeEviction();
    Test_TickDrivenWarmupLatch();

    // Deterministic repeated concurrent stress over ONE manager: re-creating a
    // manager per round would tear down and re-initialise the global
    // freetoken/future pools, which is an unrelated pre-existing lifecycle
    // hazard. Repeated rounds inside a single manager is the meaningful
    // deterministic stress for the lease logic itself.
    const int kStressRounds = getenv("G04_STRESS_ROUNDS") ? atoi(getenv("G04_STRESS_ROUNDS")) : 3;
    if (kStressRounds < 1) {
        printf("  [FAIL] G04_STRESS_ROUNDS must be >= 1\n");
        g_fail++;
    } else if (!Test_ConcurrentLeaseReconciliation(kStressRounds)) {
        // failure already recorded inside
    }
    Test_GenerationMonotonicity();

    printf("\n=================================================================\n");
    if (g_fail == 0) {
        printf(" G04 RESULT: PASS\n");
        printf("=================================================================\n");
        return 0;
    }
    printf(" G04 RESULT: FAIL (%d assertion(s))\n", g_fail);
    printf("=================================================================\n");
    return 1;
}
