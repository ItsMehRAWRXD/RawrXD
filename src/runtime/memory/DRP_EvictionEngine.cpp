// ============================================================================
// DRP_EvictionEngine.cpp
// ============================================================================
#include "DRP_EvictionEngine.hpp"
#include <cstdio>

namespace RawrXD {
namespace Memory {

DRPEvictionEngine::DRPEvictionEngine(BlockTable& table, SSDWriteBackQueue& queue)
    : m_table(table)
    , m_queue(queue)
{}

ResidencyLookupResult DRPEvictionEngine::lookup(BlockId id) const {
    ResidencyLookupResult r;
    r.blockId = id;

    const BlockMeta* meta = m_table.find(id);
    if (!meta) {
        r.action = ResidencyLookupResult::Action::NOT_FOUND;
        return r;
    }

    r.bytes = meta->bytes;

    switch (meta->state) {
        case BlockResidencyState::RAM_CLEAN:
        case BlockResidencyState::RAM_DIRTY:
        case BlockResidencyState::SSD_WRITE_COMPLETE:
            r.action   = ResidencyLookupResult::Action::RAM_HIT;
            r.dataPtr  = meta->dataPtr;
            break;

        case BlockResidencyState::FLUSH_PENDING:
            // Still in RAM while flush is in-flight
            r.action   = ResidencyLookupResult::Action::RAM_HIT;
            r.dataPtr  = meta->dataPtr;
            break;

        case BlockResidencyState::SSD_CLEAN:
            r.action    = ResidencyLookupResult::Action::SSD_PROMOTE;
            r.ssdOffset = meta->ssdOffset;
            break;

        case BlockResidencyState::VRAM_GPU_VALID:
            r.action   = ResidencyLookupResult::Action::VRAM_HIT;
            r.dataPtr  = meta->dataPtr; // device VA
            break;

        case BlockResidencyState::VRAM_STALE:
            r.action   = ResidencyLookupResult::Action::VRAM_STALE;
            r.dataPtr  = meta->dataPtr;
            break;

        default:
            r.action = ResidencyLookupResult::Action::NOT_FOUND;
            break;
    }
    return r;
}

void DRPEvictionEngine::recordAccess(BlockId id) {
    BlockMeta* meta = m_table.find(id);
    if (meta) {
        meta->lastAccess++; // monotonic; real impl would use rdtsc or steady_clock
    }
}

bool DRPEvictionEngine::ramUnderPressure() const {
    return m_table.residentRamBytes() > m_cfg.ramPressureThreshold;
}

bool DRPEvictionEngine::vramUnderPressure() const {
    return m_table.residentVramBytes() > m_cfg.vramPressureThreshold;
}

uint64_t DRPEvictionEngine::runEvictionScan(bool flushDirtyFirst) {
    std::lock_guard<std::mutex> lk(m_telemetryMtx);
    m_telemetry.evictionScans++;

    uint64_t totalFreed = 0;

    // Step 1: flush dirty blocks if requested
    if (flushDirtyFirst) {
        size_t flushed = enqueueAllDirtyFlushes();
        (void)flushed; // flushes are async; we continue to eviction
    }

    // Step 2: clock-hand eviction of clean blocks
    uint64_t bytesFreed = 0;
    size_t attempts = 0;
    while (ramUnderPressure() && attempts < m_cfg.maxScanPerEviction) {
        BlockId evicted = m_table.runEvictionScan(m_cfg.ramPressureThreshold, bytesFreed, m_cfg.maxScanPerEviction);
        if (evicted == 0) break;
        totalFreed += bytesFreed;
        m_telemetry.blocksEvicted++;
        m_telemetry.bytesEvicted += bytesFreed;
        attempts++;
    }

    return totalFreed;
}

size_t DRPEvictionEngine::enqueueAllDirtyFlushes() {
    std::vector<BlockMeta> snapshot = m_table.snapshot();
    size_t enqueued = 0;

    for (const auto& meta : snapshot) {
        if (meta.state == BlockResidencyState::RAM_DIRTY && meta.refCount == 0) {
            if (enqueueSSDFlush(meta.id)) {
                enqueued++;
            }
        }
    }

    {
        std::lock_guard<std::mutex> lk(m_telemetryMtx);
        m_telemetry.dirtyFlushesEnqueued += enqueued;
    }
    return enqueued;
}

bool DRPEvictionEngine::enqueueSSDFlush(BlockId id) {
    BlockMeta* meta = m_table.find(id);
    if (!meta) return false;
    if (meta->state != BlockResidencyState::RAM_DIRTY) return false;
    if (meta->refCount != 0) return false; // pinned blocks cannot be flushed

    // Transition: RAM_DIRTY → FLUSH_PENDING
    if (!m_table.beginFlush(id)) return false;

    FlushJob job;
    job.blockId   = id;
    job.srcPtr    = meta->dataPtr;
    job.ssdOffset = meta->ssdOffset;
    job.bytes     = meta->bytes;
    job.cpuGen    = meta->generation.cpuGen.load(std::memory_order_relaxed);

    return m_queue.enqueue(job);
}

bool DRPEvictionEngine::promoteFromSSD(BlockId id,
    std::function<bool(uint64_t ssdOffset, uint64_t bytes, void* dst)> loader) {
    BlockMeta* meta = m_table.find(id);
    if (!meta) return false;
    if (meta->state != BlockResidencyState::SSD_CLEAN) return false;

    // Allocate host buffer
    void* hostBuf = nullptr;
#ifdef _WIN32
    hostBuf = _aligned_malloc(meta->bytes, 64);
#else
    posix_memalign(&hostBuf, 64, meta->bytes);
#endif
    if (!hostBuf) return false;

    // Load from SSD
    if (!loader(meta->ssdOffset, meta->bytes, hostBuf)) {
#ifdef _WIN32
        _aligned_free(hostBuf);
#else
        free(hostBuf);
#endif
        return false;
    }

    // Transition: SSD_CLEAN → RAM_CLEAN
    meta->dataPtr = reinterpret_cast<uint64_t>(hostBuf);
    bool ok = m_table.transition(id, BlockResidencyState::RAM_CLEAN);
    if (ok) {
        std::lock_guard<std::mutex> lk(m_telemetryMtx);
        m_telemetry.promotionsFromSSD++;
    }
    return ok;
}

bool DRPEvictionEngine::beginGPUUpload(BlockId id, uint64_t deviceBufferPtr) {
    BlockMeta* meta = m_table.find(id);
    if (!meta) return false;
    if (meta->state != BlockResidencyState::RAM_CLEAN &&
        meta->state != BlockResidencyState::SSD_CLEAN) {
        return false;
    }

    // If on SSD, must promote to RAM first
    if (meta->state == BlockResidencyState::SSD_CLEAN) {
        return false; // caller must promote first
    }

    bool ok = m_table.transition(id, BlockResidencyState::GPU_UPLOAD_PENDING);
    if (ok) {
        meta->dataPtr = deviceBufferPtr; // device VA
        std::lock_guard<std::mutex> lk(m_telemetryMtx);
        m_telemetry.gpuUploadsStarted++;
    }
    return ok;
}

bool DRPEvictionEngine::completeGPUUpload(BlockId id) {
    BlockMeta* meta = m_table.find(id);
    if (!meta) return false;
    if (meta->state != BlockResidencyState::GPU_UPLOAD_PENDING) return false;

    bool ok = m_table.transition(id, BlockResidencyState::VRAM_GPU_VALID);
    if (ok) {
        meta->generation.bumpGpu();
        std::lock_guard<std::mutex> lk(m_telemetryMtx);
        m_telemetry.gpuUploadsCompleted++;
    }
    return ok;
}

} // namespace Memory
} // namespace RawrXD
