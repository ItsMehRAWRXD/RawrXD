// ============================================================================
// PredictiveMemoryManager.cpp
// ============================================================================
#include "PredictiveMemoryManager.hpp"
#include <iomanip>
#include <chrono>

namespace RawrXD {
namespace Memory {

PredictiveMemoryManager::PredictiveMemoryManager(PredictiveMemoryConfig cfg)
    : m_cfg(cfg)
    , m_predictor(cfg.lookaheadDepth)
    , m_capacity(cfg.capacityPolicy)
    , m_scheduler(cfg.maxConcurrentTransfers)
    , m_placement(m_tracker, m_capacity, m_predictor, m_scheduler)
{
    // Register VRAM pools.
    for (auto& pool : cfg.vramPools)
        m_capacity.registerPool(pool);

    // Register system RAM.
    if (cfg.systemRAMBytes > 0)
        m_capacity.registerSystemRAM(cfg.systemRAMBytes);
}

// ── Execution-path API ────────────────────────────────────────────────────────

void PredictiveMemoryManager::predict(uint32_t currentLayer) {
    m_predictor.advanceLayer(currentLayer);
}

void PredictiveMemoryManager::prefetch(uint32_t currentLayer) {
    m_placement.prefetch(currentLayer, m_cfg.lookaheadDepth);
}

std::vector<TensorId> PredictiveMemoryManager::lookahead(uint32_t currentLayer,
                                                          uint32_t depth) const {
    // Re-use the predictor's predict() but only return IDs.
    // predict() is const-qualified; we need a non-const object.
    auto predictions = const_cast<WorkingSetPredictor&>(m_predictor)
                           .predict(currentLayer);
    std::vector<TensorId> ids;
    ids.reserve(predictions.size());
    for (auto& p : predictions) {
        if (p.nextPredictedLayer <= currentLayer + depth)
            ids.push_back(p.id);
    }
    return ids;
}

uint64_t PredictiveMemoryManager::ensureResident(TensorId id, DeviceId device) {
    // Check whether this was a prefetch hit.
    auto r = m_tracker.get(id);
    bool wasSpeculative = (r.state == ResidencyState::Resident &&
                           r.tier  == MemoryTier::VRAM);
    if (wasSpeculative) m_stats.prefetchHits++;
    else                m_stats.prefetchMisses++;

    return m_placement.ensureResident(id, device);
}

void PredictiveMemoryManager::recordCompletion(TensorId   id,
                                               uint32_t   layer,
                                               uint64_t   transferTimeNs) {
    using namespace std::chrono;
    uint64_t now = static_cast<uint64_t>(
        duration_cast<nanoseconds>(steady_clock::now().time_since_epoch()).count());

    auto res = m_tracker.get(id);

    AccessRecord rec;
    rec.id             = id;
    rec.layer          = layer;
    rec.timestampNs    = now;
    rec.bytes          = res.bytes;
    rec.residency      = res.tier;
    rec.transferTimeNs = transferTimeNs;
    rec.reuseDistance  = UINT32_MAX;   // predictor fills this from history

    m_predictor.recordAccess(rec);
    m_tracker.recordUse(id, now);
}

void PredictiveMemoryManager::registerTensor(TensorId id, uint64_t bytes) {
    m_tracker.track(id, bytes);
}

void PredictiveMemoryManager::setTransferExecutor(
    TransferScheduler::TransferExecutor exec) {
    m_scheduler.setExecutor(std::move(exec));
}

// ── Telemetry ─────────────────────────────────────────────────────────────────

MemoryTelemetry PredictiveMemoryManager::telemetry() const {
    MemoryTelemetry t;

    // Pool info.
    for (auto dev : m_capacity.vramDevices()) {
        auto p = m_capacity.poolState(dev);
        MemoryTelemetry::PoolInfo pi;
        pi.device      = dev;
        pi.tier        = MemoryTier::VRAM;
        pi.usedBytes   = p.used + p.reserved;
        pi.capacityBytes = p.capacity;
        pi.utilization = m_capacity.utilization(dev);
        t.pools.push_back(pi);
    }
    {
        auto sys = m_capacity.poolState(UINT32_MAX);
        if (sys.capacity > 0) {
            MemoryTelemetry::PoolInfo pi;
            pi.device      = UINT32_MAX;
            pi.tier        = MemoryTier::SYSTEM_RAM;
            pi.usedBytes   = sys.used + sys.reserved;
            pi.capacityBytes = sys.capacity;
            pi.utilization = (sys.capacity > 0)
                           ? static_cast<double>(sys.used + sys.reserved) /
                             static_cast<double>(sys.capacity)
                           : 0.0;
            t.pools.push_back(pi);
        }
    }

    // Prefetch metrics.
    uint64_t total = m_stats.prefetchHits + m_stats.prefetchMisses;
    t.prefetchHitRate  = (total > 0)
                       ? static_cast<double>(m_stats.prefetchHits) / total
                       : 0.0;
    t.prefetchWasteRate = (total > 0)
                        ? static_cast<double>(m_stats.prefetchWaste) / total
                        : 0.0;

    // Transfer scheduler metrics.
    t.blockingTransfersPerSec = 0.0;   // TODO: time-windowed counter
    t.avgTransferLatencyMs    = 0.0;   // TODO: EMA from executor callbacks
    t.pcieUtilization         = 0.0;   // TODO: from executor

    // Eviction rate from predictor.
    t.evictionsPerSec = 0.0;           // TODO: time-windowed counter

    // Lookahead depth.
    t.lookaheadDepth = m_cfg.lookaheadDepth;

    // Tensor counts.
    auto all = m_tracker.all();
    t.activeTensors   = static_cast<uint32_t>(all.size());
    uint32_t resident = 0;
    for (auto& r : all)
        if (r.state == ResidencyState::Resident ||
            r.state == ResidencyState::Pinned)   ++resident;
    t.residentTensors = resident;

    return t;
}

void PredictiveMemoryManager::printDashboard(std::ostream& out) const {
    auto t = telemetry();
    out << "\nPredictive Memory\n"
        << std::string(44, '-') << "\n";
    for (auto& p : t.pools) {
        double gbUsed = static_cast<double>(p.usedBytes)   / 1073741824.0;
        double gbCap  = static_cast<double>(p.capacityBytes) / 1073741824.0;
        if (p.tier == MemoryTier::VRAM)
            out << "VRAM " << p.device << "      ";
        else
            out << "RAM         ";
        out << std::fixed << std::setprecision(1)
            << gbUsed << " / " << gbCap << " GB    "
            << std::setprecision(1) << (p.utilization * 100.0) << "%\n";
    }
    out << "\n"
        << "Prefetch hit rate        "
        << std::setprecision(1) << (t.prefetchHitRate  * 100.0) << "%\n"
        << "Prefetch waste           "
        << std::setprecision(1) << (t.prefetchWasteRate * 100.0) << "%\n"
        << "Lookahead depth          " << t.lookaheadDepth << "\n"
        << "Active tensors           " << t.activeTensors  << "\n"
        << "Resident tensors         " << t.residentTensors << "\n";
}

} // namespace Memory
} // namespace RawrXD
