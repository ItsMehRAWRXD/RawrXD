// ============================================================================
// StreamingMatMulResidencyBridge.hpp
// Integration bridge: wires BlockTable + DRP_EvictionEngine into the existing
// StreamingMatMul hot path.
//
// Path:
//   StreamingMatMul
//        │
//        ▼
//   Residency lookup (BlockTable)
//        │
//        ├── RAM hit ───────────────► compute (dequant + dot)
//        ├── SSD resident ──────────► promote RAM ─► compute
//        └── VRAM resident ────────► GPU compute (or CPU fallback)
//        │
//        ▼
//   access accounting
//        │
//        ▼
//   pressure detection
//        │
//        ▼
//   DRP_RunEvictionScan()
// ============================================================================
#pragma once

#include "DRP_EvictionEngine.hpp"
#include <string>
#include <functional>#include <unordered_map>
namespace RawrXD {
namespace Memory {

// ── Bridge configuration ───────────────────────────────────────────────────

struct StreamingResidencyConfig {
    uint64_t ramPressureThreshold = 48ULL * 1024 * 1024 * 1024; // 48 GB
    uint64_t vramPressureThreshold = 28ULL * 1024 * 1024 * 1024; // 28 GB
    bool     enableEviction       = true;
    bool     enablePrefetch       = true;
    bool     enableGPUUpload      = false; // set true when Vulkan/ROCm ready
    size_t   prefetchLookahead    = 3;     // layers
};

// ── StreamingMatMul Residency Bridge ─────────────────────────────────────────

class StreamingMatMulResidencyBridge {
public:
    StreamingMatMulResidencyBridge(BlockTable& table,
                                    DRPEvictionEngine& engine,
                                    SSDWriteBackQueue& queue);
    ~StreamingMatMulResidencyBridge() = default;

    // Initialise with config.
    void init(const StreamingResidencyConfig& cfg);

    // ── Hot-path API (called from StreamingMatMul) ───────────────────────────

    // Look up a tensor by name.  Returns host VA on RAM hit, or 0 on miss.
    // On SSD miss, optionally triggers async promotion (if 'triggerPromotion' is true).
    uint64_t lookupTensor(const std::string& tensorName, bool triggerPromotion = true);

    // Record that a tensor was accessed (updates lastAccess, secondChance).
    void recordTensorAccess(const std::string& tensorName);

    // After compute, dirty the tensor (if weights were modified, e.g. LoRA).
    void dirtyTensor(const std::string& tensorName);

    // Check pressure and run eviction if needed.
    void maybeEvict();

    // ── Registration ─────────────────────────────────────────────────────────

    // Register a tensor that exists in the model file.
    // 'ssdOffset' is the byte offset in the backing GGUF/SSD file.
    // 'bytes' is the uncompressed size.
    bool registerTensor(const std::string& name, uint64_t ssdOffset, uint64_t bytes);

    // Commit dequantized weights to RAM residency.
    bool commitRamResident(const std::string& name, void* hostPtr);

    // ── GPU path (optional) ──────────────────────────────────────────────────

    // Upload a RAM-resident tensor to VRAM.
    bool uploadToGPU(const std::string& tensorName, uint64_t deviceBufferPtr);

    // ── Telemetry ──────────────────────────────────────────────────────────────

    struct Stats {
        uint64_t lookups = 0;
        uint64_t ramHits = 0;
        uint64_t ssdMisses = 0;
        uint64_t vramHits = 0;
        uint64_t promotions = 0;
        uint64_t evictionsTriggered = 0;
    };
    Stats stats() const;
    void resetStats();

private:
    BlockTable&            m_table;
    DRPEvictionEngine&     m_engine;
    SSDWriteBackQueue&    m_queue;
    StreamingResidencyConfig m_cfg;

    // Name → BlockId mapping
    std::unordered_map<std::string, BlockId> m_nameToId;
    mutable std::mutex                         m_nameMtx;

    // Next synthetic BlockId
    std::atomic<BlockId> m_nextId{1000000};

    Stats m_stats;
    mutable std::mutex m_statsMtx;

    BlockId resolveOrCreate(const std::string& name);
};

} // namespace Memory
} // namespace RawrXD
