#include "runtime/memory/PlacementPolicy.hpp"
#include "runtime/memory/ResidencyTracker.hpp"
#include "runtime/memory/CapacityManager.hpp"
#include "runtime/memory/WorkingSetPredictor.hpp"
#include "runtime/memory/TransferScheduler.hpp"
#include "runtime/memory/TensorPlacementManager.hpp"
#include "runtime/memory/PredictiveMemoryManager.hpp"

#include <algorithm>
#include <atomic>
#include <chrono>
#include <cstdint>
#include <iostream>
#include <mutex>
#include <string>
#include <thread>
#include <vector>

using namespace RawrXD::Memory;

namespace {

bool check(bool cond, const std::string& msg) {
    if (!cond) {
        std::cerr << "[FAIL] " << msg << "\n";
        return false;
    }
    return true;
}

bool test_capacity_invariant() {
    CapacityPolicy policy;
    policy.prefetchCeiling = 0.95;
    policy.emergencyReserve = 0.10;

    CapacityManager cm(policy);

    DeviceMemoryPool pool;
    pool.device = 0;
    pool.capacity = 1000;
    cm.registerPool(pool);

    // Effective capacity should be 900 because emergency reserve is 10%.
    bool ok = true;
    ok &= check(cm.canFit(0, MemoryTier::VRAM, 800), "canFit should allow 800 bytes");
    ok &= check(cm.reserve(0, MemoryTier::VRAM, 800), "reserve should succeed for 800 bytes");
    ok &= check(!cm.canFit(0, MemoryTier::VRAM, 101), "canFit must reject when used+incoming+reserve exceeds capacity");
    ok &= check(!cm.reserve(0, MemoryTier::VRAM, 101), "reserve must fail when breaching reserve invariant");

    auto state = cm.poolState(0);
    ok &= check(state.reserved == 800, "reserved bytes should remain unchanged after failed reserve");

    cm.release(0, MemoryTier::VRAM, 200);
    state = cm.poolState(0);
    ok &= check(state.reserved == 600, "release should decrement reserved bytes");

    return ok;
}

bool test_transfer_priority_ordering_policy() {
    // Lower enum value means higher urgency in the scheduler's priority queue.
    bool ok = true;
    ok &= check(static_cast<uint32_t>(TransferPriority::Blocking) < static_cast<uint32_t>(TransferPriority::Imminent),
                "Blocking must outrank Imminent");
    ok &= check(static_cast<uint32_t>(TransferPriority::Imminent) < static_cast<uint32_t>(TransferPriority::Speculative),
                "Imminent must outrank Speculative");
    ok &= check(static_cast<uint32_t>(TransferPriority::Speculative) < static_cast<uint32_t>(TransferPriority::Opportunistic),
                "Speculative must outrank Opportunistic");
    return ok;
}

bool test_residency_tracker_concurrent_transitions() {
    ResidencyTracker tracker;
    constexpr TensorId kId = 0xABC;
    tracker.track(kId, 4096);

    std::atomic<bool> start{false};
    std::vector<std::thread> workers;
    workers.reserve(4);

    workers.emplace_back([&]() {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < 2000; ++i) {
            tracker.markPrefetching(kId, MemoryTier::VRAM);
            tracker.markResident(kId, MemoryTier::VRAM, 0x1000 + static_cast<uint64_t>(i));
            tracker.recordUse(kId, static_cast<uint64_t>(i + 1));
        }
    });

    workers.emplace_back([&]() {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < 2000; ++i) {
            tracker.markEvicting(kId);
            tracker.markCold(kId);
        }
    });

    workers.emplace_back([&]() {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < 2000; ++i) {
            tracker.markPinned(kId, (i % 2) == 0);
        }
    });

    workers.emplace_back([&]() {
        while (!start.load(std::memory_order_acquire)) {
        }
        for (int i = 0; i < 2000; ++i) {
            (void)tracker.get(kId);
            (void)tracker.bytesInTier(MemoryTier::VRAM);
        }
    });

    start.store(true, std::memory_order_release);
    for (auto& t : workers) {
        t.join();
    }

    auto r = tracker.get(kId);
    bool ok = true;
    ok &= check(tracker.known(kId), "tensor must remain tracked after concurrent transitions");
    ok &= check(r.bytes == 4096, "tensor byte size must remain stable");
    ok &= check(r.state <= ResidencyState::Failed, "final state must be a valid residency enum value");
    return ok;
}

bool test_predictor_determinism() {
    WorkingSetPredictor a(3);
    WorkingSetPredictor b(3);

    std::vector<AccessRecord> trace = {
        {1, 1, 100, 1024, MemoryTier::VRAM, 1000, UINT32_MAX},
        {2, 1, 200, 2048, MemoryTier::SYSTEM_RAM, 3000, UINT32_MAX},
        {1, 3, 300, 1024, MemoryTier::VRAM, 1500, UINT32_MAX},
        {2, 4, 400, 2048, MemoryTier::SYSTEM_RAM, 4000, UINT32_MAX},
        {1, 5, 500, 1024, MemoryTier::VRAM, 1300, UINT32_MAX},
    };

    for (const auto& rec : trace) {
        a.recordAccess(rec);
        b.recordAccess(rec);
        a.advanceLayer(rec.layer);
        b.advanceLayer(rec.layer);
    }

    auto pa = a.predict(5);
    auto pb = b.predict(5);

    bool ok = true;
    ok &= check(pa.size() == pb.size(), "predictor outputs must have equal size for identical traces");

    if (pa.size() != pb.size()) {
        return false;
    }

    for (size_t i = 0; i < pa.size(); ++i) {
        ok &= check(pa[i].id == pb[i].id, "prediction order must be deterministic");
        ok &= check(pa[i].score == pb[i].score, "prediction scores must be deterministic");
        ok &= check(pa[i].nextPredictedLayer == pb[i].nextPredictedLayer, "predicted layer must be deterministic");
    }
    return ok;
}

bool test_transactional_promote_and_evict_path() {
    PredictiveMemoryConfig cfg;
    DeviceMemoryPool pool;
    pool.device = 0;
    pool.capacity = 1ull << 20;
    cfg.vramPools.push_back(pool);
    cfg.systemRAMBytes = 1ull << 22;
    cfg.maxConcurrentTransfers = 1;
    cfg.lookaheadDepth = 2;

    PredictiveMemoryManager mgr(cfg);
    mgr.registerTensor(7, 4096);
    mgr.registerTensor(8, 4096);

    // Deterministic executor for transactional transfer semantics.
    mgr.setTransferExecutor([](const TransferRequest&) {
        return true;
    });

    uint64_t addr = mgr.ensureResident(7, 0);
    bool ok = true;
    ok &= check(addr != 0, "ensureResident must return a non-zero address on successful transfer");

    auto r = mgr.residencyTracker().get(7);
    ok &= check(r.tier == MemoryTier::VRAM, "tensor must end in VRAM after promote");
    ok &= check(r.state == ResidencyState::Resident, "tensor must be resident after promote");

    // Exercise eviction path directly through placement manager and ensure resulting state is coherent.
    auto all = mgr.residencyTracker().all();
    std::vector<TensorResidency> evictList;
    for (const auto& t : all) {
        if (t.id == 7) {
            evictList.push_back(t);
            break;
        }
    }

    mgr.placementManager().evict(evictList);
    mgr.transferScheduler().flush(1000);

    auto after = mgr.residencyTracker().get(7);
    ok &= check(after.state == ResidencyState::Cold || after.state == ResidencyState::Failed,
                "evict path must converge to Cold or Failed");
    return ok;
}

} // namespace

int main() {
    bool ok = true;
    ok &= test_capacity_invariant();
    ok &= test_transfer_priority_ordering_policy();
    ok &= test_residency_tracker_concurrent_transitions();
    ok &= test_predictor_determinism();
    ok &= test_transactional_promote_and_evict_path();

    if (!ok) {
        std::cerr << "Predictive memory subsystem validation FAILED\n";
        return 1;
    }

    std::cout << "Predictive memory subsystem validation PASSED\n";
    return 0;
}
