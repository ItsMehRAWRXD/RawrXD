// ============================================================================
// StreamEntry.hpp - Streaming Entry Point with Dead/Alive Cycle
// ============================================================================
// For running models larger than available VRAM by cycling chunks:
//   0(streamDead) → compress → load → uncompress → undead → 1(streamAlive)
//   1(streamAlive) → compute → clear → unreverseHot → 0(streamDead)
//
// Entry: unreverseHot
//   ├── patchEngineer     → builds patch from model weight
//   ├── patchCompress     → nanoCompress 8:1 (paradox L3)
//   ├── patchUncompress   → decompress on arrival
//   └── patch(undead)     → neither dead nor alive, bridging
//
// VRAM needed at any time = 1 chunk only.
// Not full model. Just 1 chunk compressed + decompressed on fly.
// ============================================================================

#pragma once
#include "PipelineState.hpp"
#include "DualGPUHook.hpp"
#include "ReverseTensorRecovery.hpp"
#include "ReverseHotpatchEngine.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <functional>
#include <atomic>
#include <chrono>

namespace Deep2 {

// ============================================================================
// Stream State
// ============================================================================
enum class StreamState {
    Dead,      // 0 = streamDead: VRAM cleared, memory = 0, ready for next chunk
    Compressing,
    Loading,
    Uncompressing,
    Undead,    // neither dead nor alive, bridging
    Alive,     // 1 = streamAlive: VRAM loaded, chunk active, compute runs
    Computing,
    Clearing,
    Error
};

// ============================================================================
// Chunk Descriptor
// ============================================================================
struct ChunkDescriptor {
    uint64_t chunkId      = 0;
    uint64_t originalBytes = 0;   // uncompressed size (e.g., 97GB / N chunks)
    uint64_t compressedBytes = 0; // nanoCompressed size (8:1)
    uint64_t vramOffset   = 0;    // where this chunk lives in VRAM
    int      gpuOwner     = -1;   // 0, 1, or -1 (host)
    bool     isCompressed = true;
    bool     isActive     = false;
    std::string name;
};

// ============================================================================
// Stream Telemetry
// ============================================================================
struct StreamTelemetry {
    uint64_t chunksProcessed   = 0;
    uint64_t chunksAlive       = 0;
    uint64_t chunksDead        = 0;
    uint64_t totalBytesIn      = 0;   // compressed bytes streamed
    uint64_t totalBytesOut     = 0;   // decompressed bytes computed
    uint64_t totalCycles       = 0;
    double   avgCompressTimeMs = 0.0;
    double   avgLoadTimeMs     = 0.0;
    double   avgDecompressTimeMs = 0.0;
    double   avgComputeTimeMs  = 0.0;
    double   avgCycleTimeMs    = 0.0;
    uint64_t oomEvents         = 0;
    uint64_t reliveCount       = 0;
};

// ============================================================================
// Stream Entry — unreverseHot
// ============================================================================
class StreamEntry {
public:
    StreamEntry();
    ~StreamEntry();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Initialize(
        ReverseHotpatchEngine* engine,
        DualGPUHook* hook,
        ReverseTensorBackend* backend);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // ------------------------------------------------------------------------
    // Main entry: unreverseHot
    // ------------------------------------------------------------------------
    bool unreverseHot();  // Entry point — starts the cycle

    // ------------------------------------------------------------------------
    // Patch stages
    // ------------------------------------------------------------------------
    bool patchEngineer(const std::vector<std::filesystem::path>& files);
    bool patchCompress(ChunkDescriptor& chunk);
    bool patchUncompress(ChunkDescriptor& chunk);
    bool patchUndead(ChunkDescriptor& chunk);   // bridge dead → alive

    // ------------------------------------------------------------------------
    // State machine transitions
    // ------------------------------------------------------------------------
    bool streamDead();      // 0: clear VRAM, ready for next chunk
    bool streamAlive();     // 1: chunk active, compute runs

    // ------------------------------------------------------------------------
    // Chunk cycle
    // ------------------------------------------------------------------------
    bool ProcessChunk(ChunkDescriptor& chunk);
    bool ProcessAllChunks(const std::vector<ChunkDescriptor>& chunks);

    // ------------------------------------------------------------------------
    // Compression (nanoCompression paradox level 3, 8:1)
    // ------------------------------------------------------------------------
    uint64_t nanoCompress(
        const uint8_t* src,
        uint64_t srcLen,
        uint8_t* dst,
        uint64_t dstCap);

    uint64_t nanoUncompress(
        const uint8_t* src,
        uint64_t srcLen,
        uint8_t* dst,
        uint64_t dstCap);

    // ------------------------------------------------------------------------
    // Queries
    // ------------------------------------------------------------------------
    StreamState GetState() const;
    StreamTelemetry GetTelemetry() const;
    uint64_t GetCurrentChunkId() const;

    // ------------------------------------------------------------------------
    // Configuration
    // ------------------------------------------------------------------------
    void SetCompressionRatio(int ratio);       // default 8
    void SetCompressionLevel(int level);       // default 3 (paradox)
    void SetChunkSize(uint64_t bytes);           // default 1GB
    void SetVerbose(bool v);

    // ------------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------------
    using StateChangeCallback = std::function<void(StreamState oldState, StreamState newState)>;
    using ChunkCycleCallback  = std::function<void(const ChunkDescriptor&, StreamState)>;
    void SetStateChangeCallback(StateChangeCallback cb);
    void SetChunkCycleCallback(ChunkCycleCallback cb);

private:
    bool initialized_ = false;
    std::atomic<StreamState> state_{StreamState::Dead};

    ReverseHotpatchEngine* engine_ = nullptr;
    DualGPUHook* hook_ = nullptr;
    ReverseTensorBackend* backend_ = nullptr;

    // Config
    int compressionRatio_ = 8;
    int compressionLevel_ = 3;
    uint64_t chunkSize_   = 1ULL << 30; // 1GB
    bool verbose_ = false;

    // Current chunk
    mutable std::mutex chunkMutex_;
    uint64_t currentChunkId_ = 0;
    ChunkDescriptor currentChunk_;

    // Telemetry
    mutable std::mutex telemetryMutex_;
    StreamTelemetry telemetry_;
    std::chrono::steady_clock::time_point cycleStart_;

    // Callbacks
    StateChangeCallback onStateChange_;
    ChunkCycleCallback onChunkCycle_;

    // Internal
    void TransitionTo(StreamState newState);
    bool ClearVRAM();
    bool LoadChunkToVRAM(const ChunkDescriptor& chunk);
    bool ComputeChunk(const ChunkDescriptor& chunk);
    void RecordCycleTime();
};

// ============================================================================
// Free helpers
// ============================================================================
inline const char* StreamStateName(StreamState s) {
    switch (s) {
        case StreamState::Dead:          return "Dead";
        case StreamState::Compressing:   return "Compressing";
        case StreamState::Loading:       return "Loading";
        case StreamState::Uncompressing: return "Uncompressing";
        case StreamState::Undead:        return "Undead";
        case StreamState::Alive:         return "Alive";
        case StreamState::Computing:     return "Computing";
        case StreamState::Clearing:      return "Clearing";
        case StreamState::Error:         return "Error";
        default:                         return "Unknown";
    }
}

} // namespace Deep2
