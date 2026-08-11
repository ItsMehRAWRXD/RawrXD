// ============================================================================
// StreamingMatMulResidencyBridge.cpp
// ============================================================================
#include "StreamingMatMulResidencyBridge.hpp"
#include <cstdio>

namespace RawrXD {
namespace Memory {

StreamingMatMulResidencyBridge::StreamingMatMulResidencyBridge(BlockTable& table,
                                                                DRPEvictionEngine& engine,
                                                                SSDWriteBackQueue& queue)
    : m_table(table)
    , m_engine(engine)
    , m_queue(queue)
{}

void StreamingMatMulResidencyBridge::init(const StreamingResidencyConfig& cfg) {
    m_cfg = cfg;
    DRPEvictionEngine::Config ecfg;
    ecfg.ramPressureThreshold = cfg.ramPressureThreshold;
    ecfg.vramPressureThreshold  = cfg.vramPressureThreshold;
    m_engine.setConfig(ecfg);
}

BlockId StreamingMatMulResidencyBridge::resolveOrCreate(const std::string& name) {
    std::lock_guard<std::mutex> lk(m_nameMtx);
    auto it = m_nameToId.find(name);
    if (it != m_nameToId.end()) return it->second;
    BlockId id = m_nextId.fetch_add(1, std::memory_order_relaxed);
    m_nameToId[name] = id;
    return id;
}

bool StreamingMatMulResidencyBridge::registerTensor(const std::string& name,
                                                     uint64_t ssdOffset,
                                                     uint64_t bytes) {
    BlockId id = resolveOrCreate(name);
    if (!m_table.find(id)) {
        if (!m_table.insert(id, bytes, name)) return false;
    }
    BlockMeta* meta = m_table.find(id);
    if (meta) {
        meta->ssdOffset = ssdOffset;
        // Initial state: on SSD, not in RAM
        if (meta->state == BlockResidencyState::UNINITIALISED) {
            m_table.transition(id, BlockResidencyState::SSD_CLEAN);
        }
    }
    return true;
}

bool StreamingMatMulResidencyBridge::commitRamResident(const std::string& name, void* hostPtr) {
    BlockId id = resolveOrCreate(name);
    BlockMeta* meta = m_table.find(id);
    if (!meta) return false;
    meta->dataPtr = reinterpret_cast<uint64_t>(hostPtr);
    return m_table.transition(id, BlockResidencyState::RAM_CLEAN);
}

uint64_t StreamingMatMulResidencyBridge::lookupTensor(const std::string& tensorName,
                                                       bool triggerPromotion) {
    BlockId id = 0;
    {
        std::lock_guard<std::mutex> lk(m_nameMtx);
        auto it = m_nameToId.find(tensorName);
        if (it == m_nameToId.end()) return 0;
        id = it->second;
    }

    {
        std::lock_guard<std::mutex> lk(m_statsMtx);
        m_stats.lookups++;
    }

    ResidencyLookupResult r = m_engine.lookup(id);
    switch (r.action) {
        case ResidencyLookupResult::Action::RAM_HIT:
        case ResidencyLookupResult::Action::VRAM_HIT: {
            std::lock_guard<std::mutex> lk(m_statsMtx);
            if (r.action == ResidencyLookupResult::Action::RAM_HIT) m_stats.ramHits++;
            else m_stats.vramHits++;
            m_engine.recordAccess(id);
            return r.dataPtr;
        }
        case ResidencyLookupResult::Action::VRAM_STALE: {
            // TODO: trigger re-upload
            std::lock_guard<std::mutex> lk(m_statsMtx);
            m_stats.vramHits++;
            return r.dataPtr;
        }
        case ResidencyLookupResult::Action::SSD_PROMOTE: {
            std::lock_guard<std::mutex> lk(m_statsMtx);
            m_stats.ssdMisses++;
            if (triggerPromotion) {
                // Synchronous promotion for now; async loader can be wired later
                bool ok = m_engine.promoteFromSSD(id,
                    [this](uint64_t offset, uint64_t bytes, void* dst) {
                        // Placeholder: real implementation reads from GGUF mmap
                        std::memset(dst, 0, static_cast<size_t>(bytes));
                        return true;
                    });
                if (ok) {
                    m_stats.promotions++;
                    BlockMeta* meta = m_table.find(id);
                    if (meta) return meta->dataPtr;
                }
            }
            return 0;
        }
        default:
            return 0;
    }
}

void StreamingMatMulResidencyBridge::recordTensorAccess(const std::string& tensorName) {
    BlockId id = 0;
    {
        std::lock_guard<std::mutex> lk(m_nameMtx);
        auto it = m_nameToId.find(tensorName);
        if (it == m_nameToId.end()) return;
        id = it->second;
    }
    m_engine.recordAccess(id);
}

void StreamingMatMulResidencyBridge::dirtyTensor(const std::string& tensorName) {
    BlockId id = 0;
    {
        std::lock_guard<std::mutex> lk(m_nameMtx);
        auto it = m_nameToId.find(tensorName);
        if (it == m_nameToId.end()) return;
        id = it->second;
    }
    m_table.dirty(id);
}

void StreamingMatMulResidencyBridge::maybeEvict() {
    if (!m_cfg.enableEviction) return;
    if (m_engine.ramUnderPressure()) {
        m_engine.runEvictionScan(true);
        std::lock_guard<std::mutex> lk(m_statsMtx);
        m_stats.evictionsTriggered++;
    }
}

bool StreamingMatMulResidencyBridge::uploadToGPU(const std::string& tensorName,
                                                  uint64_t deviceBufferPtr) {
    BlockId id = 0;
    {
        std::lock_guard<std::mutex> lk(m_nameMtx);
        auto it = m_nameToId.find(tensorName);
        if (it == m_nameToId.end()) return false;
        id = it->second;
    }
    return m_engine.beginGPUUpload(id, deviceBufferPtr);
}

StreamingMatMulResidencyBridge::Stats StreamingMatMulResidencyBridge::stats() const {
    std::lock_guard<std::mutex> lk(m_statsMtx);
    return m_stats;
}

void StreamingMatMulResidencyBridge::resetStats() {
    std::lock_guard<std::mutex> lk(m_statsMtx);
    m_stats = Stats{};
}

} // namespace Memory
} // namespace RawrXD
