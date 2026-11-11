// ============================================================================
// TensorPlacementManager.cpp
// ============================================================================
#include "TensorPlacementManager.hpp"
#include <algorithm>
#include <chrono>

namespace RawrXD {
namespace Memory {

static uint64_t nowNs() noexcept {
    using namespace std::chrono;
    return static_cast<uint64_t>(
        duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());
}

TensorPlacementManager::TensorPlacementManager(ResidencyTracker&    tracker,
                                               CapacityManager&     capacity,
                                               WorkingSetPredictor& predictor,
                                               TransferScheduler&   scheduler)
    : m_tracker(tracker)
    , m_capacity(capacity)
    , m_predictor(predictor)
    , m_scheduler(scheduler)
{}

double TensorPlacementManager::transferCostMs(MemoryTier src, MemoryTier dst) const noexcept {
    // Rough empirical estimates (ms) – callers can override via policy.
    if (src == dst) return 0.0;
    // SSD -> RAM
    if (src == MemoryTier::SSD    && dst == MemoryTier::SYSTEM_RAM) return 10.0;
    // RAM -> VRAM (PCIe)
    if (src == MemoryTier::SYSTEM_RAM && dst == MemoryTier::VRAM)   return  2.0;
    // VRAM -> RAM
    if (src == MemoryTier::VRAM   && dst == MemoryTier::SYSTEM_RAM) return  2.0;
    // SSD -> VRAM (two-hop)
    if (src == MemoryTier::SSD    && dst == MemoryTier::VRAM)       return 12.0;
    return 5.0;
}

PlacementDecision TensorPlacementManager::plan(TensorId id, DeviceId targetDevice) const {
    PlacementDecision d;
    d.id           = id;
    d.targetTier   = MemoryTier::VRAM;
    d.targetDevice = targetDevice;
    d.needsTransfer = false;
    d.speculative   = false;

    auto res = m_tracker.get(id);
    if (res.tier == MemoryTier::VRAM && res.state == ResidencyState::Resident) {
        d.needsTransfer = false;
        return d;
    }
    d.needsTransfer = true;
    return d;
}

uint64_t TensorPlacementManager::ensureResident(TensorId id, DeviceId targetDevice) {
    auto res = m_tracker.get(id);

    // Already resident on the correct tier.
    if ((res.tier == MemoryTier::VRAM || res.tier == MemoryTier::SYSTEM_RAM) &&
        (res.state == ResidencyState::Resident || res.state == ResidencyState::Pinned)) {
        m_tracker.recordUse(id, nowNs());
        return res.address;
    }

    // Make room if necessary.
    if (!m_capacity.canFit(targetDevice, MemoryTier::VRAM, res.bytes)) {
        auto evictions = selectEvictions(targetDevice, MemoryTier::VRAM, res.bytes);
        evict(evictions);
    }

    // Issue a blocking transfer and wait inline (synchronous path).
    uint64_t resultAddr = 0;
    bool     done       = false;
    bool     ok         = false;

    TransferRequest req;
    req.tensor      = id;
    req.source      = res.tier;
    req.destination = MemoryTier::VRAM;
    req.bytes       = res.bytes;
    req.deadline    = 0;
    req.priority    = TransferPriority::Blocking;
    req.speculative = false;

    m_tracker.markPrefetching(id, MemoryTier::VRAM);

    m_scheduler.schedule(req, [&](TensorId, bool success) {
        ok = success;
        done = true;
    });

    // Spin-wait (acceptable for blocking path; real impl would use a semaphore).
    while (!done) {
        std::this_thread::sleep_for(std::chrono::microseconds(100));
    }

    if (ok) {
        m_capacity.reserve(targetDevice, MemoryTier::VRAM, res.bytes);
        // Address assignment: in a real implementation the DMA executor fills this.
        // Here we preserve the existing address or set a placeholder.
        resultAddr = res.address ? res.address : reinterpret_cast<uint64_t>(nullptr) + id;
        m_tracker.markResident(id, MemoryTier::VRAM, resultAddr);
        m_tracker.recordUse(id, nowNs());
    } else {
        m_tracker.markFailed(id);
    }

    return resultAddr;
}

void TensorPlacementManager::prefetch(uint32_t currentLayer, uint32_t lookahead) {
    auto predictions = m_predictor.predict(currentLayer);
    for (auto& tp : predictions) {
        auto res = m_tracker.get(tp.id);
        if (res.state == ResidencyState::Resident ||
            res.state == ResidencyState::Prefetching ||
            res.state == ResidencyState::Pinned) continue;

        // Check capacity before posting.
        auto devices = m_capacity.vramDevices();
        if (devices.empty()) continue;
        DeviceId dev = devices.front();   // simplistic: use first device

        if (!m_capacity.canFit(dev, MemoryTier::VRAM, res.bytes)) continue;

        TransferRequest req;
        req.tensor      = tp.id;
        req.source      = res.tier;
        req.destination = MemoryTier::VRAM;
        req.bytes       = res.bytes;
        req.deadline    = 0;
        req.priority    = (tp.reuseDistance <= 1) ? TransferPriority::Imminent
                                                  : TransferPriority::Speculative;
        req.speculative = true;

        m_tracker.markPrefetching(tp.id, MemoryTier::VRAM);
        m_scheduler.schedule(req, [this, dev, &res](TensorId tid, bool success) {
            if (success) {
                m_capacity.reserve(dev, MemoryTier::VRAM, res.bytes);
                m_tracker.markResident(tid, MemoryTier::VRAM, res.address);
            } else {
                m_tracker.markFailed(tid);
            }
        });
    }
}

std::vector<TensorResidency> TensorPlacementManager::selectEvictions(
    DeviceId    device,
    MemoryTier  tier,
    uint64_t    bytesNeeded) const
{
    auto candidates = m_tracker.byTier(tier);

    // Remove ineligible tensors.
    candidates.erase(
        std::remove_if(candidates.begin(), candidates.end(),
            [](const TensorResidency& r){
                return r.pinned
                    || r.state == ResidencyState::Evicting
                    || r.state == ResidencyState::Prefetching;
            }),
        candidates.end());

    // Sort by eviction score descending (best candidate first).
    std::sort(candidates.begin(), candidates.end(),
        [this](const TensorResidency& a, const TensorResidency& b){
            auto scoreA = evictionScore(a,
                static_cast<double>(a.nextPredictedUse - a.lastUse) / 1e9,
                transferCostMs(a.tier, MemoryTier::SYSTEM_RAM));
            auto scoreB = evictionScore(b,
                static_cast<double>(b.nextPredictedUse - b.lastUse) / 1e9,
                transferCostMs(b.tier, MemoryTier::SYSTEM_RAM));
            return scoreA > scoreB;
        });

    // Take enough to cover bytesNeeded.
    std::vector<TensorResidency> result;
    uint64_t freed = 0;
    for (auto& r : candidates) {
        if (freed >= bytesNeeded) break;
        result.push_back(r);
        freed += r.bytes;
    }
    return result;
}

void TensorPlacementManager::evict(const std::vector<TensorResidency>& candidates) {
    for (auto& r : candidates) {
        m_tracker.markEvicting(r.id);
        // Demote to system RAM (issue async transfer at opportunistic priority).
        TransferRequest req;
        req.tensor      = r.id;
        req.source      = r.tier;
        req.destination = MemoryTier::SYSTEM_RAM;
        req.bytes       = r.bytes;
        req.priority    = TransferPriority::Opportunistic;
        req.speculative = false;

        m_predictor.notifyEviction();

        m_scheduler.schedule(req, [this](TensorId tid, bool success) {
            if (success) m_tracker.markCold(tid);
            else         m_tracker.markFailed(tid);
        });
    }
}

} // namespace Memory
} // namespace RawrXD
