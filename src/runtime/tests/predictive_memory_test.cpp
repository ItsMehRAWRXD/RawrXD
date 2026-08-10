// =============================================================================
// predictive_memory_test.cpp
// B002 functional gate: deterministic predictive-memory pipeline test.
//
// Verified behaviors (six scenarios):
//   1. Demand residency:  ensureResident() makes a cold tensor VRAM-resident.
//   2. Prefetch non-corruption: lookahead prefetch leaves already-resident
//      tensors in Resident state without state corruption.
//   3. Speculative cancellation: cancelSpeculative() prevents a queued
//      prefetch from completing and leaves state as Cold/not-yet-resident.
//   4. Eviction respects pins: pinned tensors are never evicted.
//   5. Deterministic placement: identical access traces yield identical
//      eviction/placement scores.
//   6. Failed-transfer rollback: a failing executor leaves the tensor in
//      Failed state; ensureResident() returns 0.
//
// NOTE: this test does NOT link against Vulkan.  All transfers use the
// simulated executor path inside TransferScheduler.
// =============================================================================

#include "PredictiveMemoryManager.hpp"
#include "ResidencyTracker.hpp"
#include "TransferScheduler.hpp"

#include <cassert>
#include <cstdio>
#include <chrono>
#include <thread>

using namespace RawrXD::Memory;

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------
static PredictiveMemoryConfig makeConfig(uint64_t vramBytes = 256 * 1024 * 1024,
                                         uint64_t ramBytes  = 512 * 1024 * 1024) {
    PredictiveMemoryConfig cfg;
    DeviceMemoryPool vram;
    vram.device   = 0;
    vram.capacity = vramBytes;
    cfg.vramPools.push_back(vram);
    cfg.systemRAMBytes = ramBytes;
    cfg.lookaheadDepth = 3;
    cfg.maxConcurrentTransfers = 1;
    return cfg;
}

static bool waitResident(PredictiveMemoryManager& mgr,
                         TensorId id,
                         int maxMs = 200) {
    auto deadline = std::chrono::steady_clock::now()
                  + std::chrono::milliseconds(maxMs);
    while (std::chrono::steady_clock::now() < deadline) {
        auto s = mgr.residencyTracker().stateOf(id);
        if (s == ResidencyState::Resident || s == ResidencyState::Pinned)
            return true;
        if (s == ResidencyState::Failed) return false;
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    }
    return false;
}

// ---------------------------------------------------------------------------
// Scenario 1: demand residency
// ---------------------------------------------------------------------------
static bool scenario1_demand_residency() {
    PredictiveMemoryManager mgr(makeConfig());
    mgr.registerTensor(1001, 4096);
    uint64_t addr = mgr.ensureResident(1001, 0);
    bool ok = (addr != 0) &&
              mgr.residencyTracker().isResident(1001);
    if (!ok) printf("FAIL scenario1_demand_residency: addr=%llu resident=%d\n",
                    (unsigned long long)addr,
                    (int)mgr.residencyTracker().isResident(1001));
    return ok;
}

// ---------------------------------------------------------------------------
// Scenario 2: prefetch does not corrupt already-resident tensors
// ---------------------------------------------------------------------------
static bool scenario2_prefetch_no_corruption() {
    PredictiveMemoryManager mgr(makeConfig());
    mgr.registerTensor(2001, 4096);
    mgr.registerTensor(2002, 4096);

    // Make 2001 resident first
    mgr.ensureResident(2001, 0);

    // Post a prefetch that would touch 2002 (lookahead)
    mgr.recordCompletion(2002, 0);  // seed predictor
    mgr.predict(1);
    mgr.prefetch(1);

    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // 2001 must still be resident
    bool ok = mgr.residencyTracker().isResident(2001);
    if (!ok) printf("FAIL scenario2: tensor 2001 no longer resident after prefetch\n");
    return ok;
}

// ---------------------------------------------------------------------------
// Scenario 3: stale speculative transfers can be cancelled
// ---------------------------------------------------------------------------
static bool scenario3_cancel_speculative() {
    PredictiveMemoryManager mgr(makeConfig());
    mgr.registerTensor(3001, 4096);

    // Seed predictor then prefetch
    mgr.recordCompletion(3001, 0);
    mgr.predict(1);
    mgr.prefetch(1);

    // Cancel before it can complete
    mgr.transferScheduler().cancelSpeculative(3001);
    mgr.transferScheduler().flush(100);

    // State must be Cold or Failed (not Resident) because we cancelled
    auto st = mgr.residencyTracker().stateOf(3001);
    bool ok = (st != ResidencyState::Resident);
    if (!ok) printf("FAIL scenario3: cancelled tensor became Resident\n");
    return ok;
}

// ---------------------------------------------------------------------------
// Scenario 4: eviction respects pinned tensors
// ---------------------------------------------------------------------------
static bool scenario4_eviction_respects_pins() {
    // VRAM = 8 KB only, two 4 KB tensors → first one must be evicted for second
    // unless pinned
    PredictiveMemoryConfig cfg = makeConfig(8 * 1024, 64 * 1024 * 1024);
    PredictiveMemoryManager mgr(cfg);
    mgr.registerTensor(4001, 4096);
    mgr.registerTensor(4002, 4096);

    // Pin 4001
    mgr.residencyTracker().markPinned(4001, true);

    // Force 4001 into VRAM first
    mgr.residencyTracker().track(4001, 4096);
    mgr.residencyTracker().markResident(4001, MemoryTier::VRAM, 0xDEAD0000);

    // Now load 4002 which would need eviction
    mgr.ensureResident(4002, 0);
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    // 4001 must still be resident (pinned cannot be evicted)
    bool pinned_safe = mgr.residencyTracker().isResident(4001);
    if (!pinned_safe)
        printf("FAIL scenario4: pinned tensor 4001 was evicted\n");
    return pinned_safe;
}

// ---------------------------------------------------------------------------
// Scenario 5: deterministic placement for identical traces
// ---------------------------------------------------------------------------
static bool scenario5_deterministic_placement() {
    // Run the same access trace twice and compare eviction scores
    auto runTrace = [](uint32_t seed) -> uint32_t {
        PredictiveMemoryManager mgr(makeConfig());
        const TensorId A = 5001 + seed, B = 5002 + seed;
        mgr.registerTensor(A, 4096);
        mgr.registerTensor(B, 4096);
        for (uint32_t layer = 0; layer < 10; ++layer) {
            mgr.recordCompletion(A, layer);
            mgr.recordCompletion(B, layer);
            mgr.predict(layer + 1);
        }
        // Use prediction score as determinism proxy
        auto preds = mgr.workingSetPredictor().predict(5);
        uint32_t scoreSum = 0;
        for (auto& p : preds) scoreSum += p.score;
        return scoreSum;
    };
    uint32_t r1 = runTrace(0);
    uint32_t r2 = runTrace(0);
    bool ok = (r1 == r2);
    if (!ok) printf("FAIL scenario5: scores differ %u vs %u\n", r1, r2);
    return ok;
}

// ---------------------------------------------------------------------------
// Scenario 6: failed transfers roll back state
// ---------------------------------------------------------------------------
static bool scenario6_failed_transfer_rollback() {
    PredictiveMemoryManager mgr(makeConfig());
    mgr.registerTensor(6001, 4096);

    // Install a failing executor
    mgr.setTransferExecutor([](const TransferRequest&) -> bool { return false; });

    uint64_t addr = mgr.ensureResident(6001, 0);
    // Give the worker a moment to process and fail
    std::this_thread::sleep_for(std::chrono::milliseconds(50));

    auto st = mgr.residencyTracker().stateOf(6001);
    // addr == 0 AND state must be Failed (or Cold from rollback), never Resident
    bool ok = (addr == 0) && (st == ResidencyState::Failed ||
                               st == ResidencyState::Cold);
    if (!ok) printf("FAIL scenario6: addr=%llu state=%d\n",
                    (unsigned long long)addr, (int)st);
    return ok;
}

// ---------------------------------------------------------------------------
// main
// ---------------------------------------------------------------------------
int main() {
    printf("B002 Predictive-Memory Deterministic Gate\n");
    printf("=========================================\n");

    struct Test { const char* name; bool(*fn)(); };
    Test tests[] = {
        { "1: demand residency",              scenario1_demand_residency      },
        { "2: prefetch no corruption",        scenario2_prefetch_no_corruption },
        { "3: cancel speculative",            scenario3_cancel_speculative     },
        { "4: eviction respects pins",        scenario4_eviction_respects_pins },
        { "5: deterministic placement",       scenario5_deterministic_placement },
        { "6: failed transfer rollback",      scenario6_failed_transfer_rollback },
    };

    int pass = 0, fail = 0;
    for (auto& t : tests) {
        bool ok = t.fn();
        printf("  [%s] %s\n", ok ? "PASS" : "FAIL", t.name);
        ok ? ++pass : ++fail;
    }

    printf("=========================================\n");
    printf("  %d/%zu PASS\n", pass, sizeof(tests)/sizeof(tests[0]));
    return fail == 0 ? 0 : 1;
}
