// ============================================================================
// StreamEngine.hpp - Ultimate Universal Streaming Compression VRAM Engine
// ============================================================================
// Runs ANY model size on ANY consumer GPU via streaming layer chunks.
//
// Four optimizations:
//   1. compressEven          - uniform 8:1 compression across all layers
//   2. reuseData             - LRU cache for decompressed layers
//   3. reconstructCompression - partial decompress (only active slices)
//   4. denseModel(+1+1+1+1)  - incremental load with LRU eviction
//
// Three latency-hiding invariants:
//   A. latencyCompute = reversed  - compute prep starts before data movement
//   B. compression + -compute_time = 0*always - compression hidden by compute
//   C. reverse0 → emit           - neutral start, no forced direction
//
// Entry point: unreverseHot
// State machine: streamDead(0) → streamAlive(1) → loop ∞
// ============================================================================

#pragma once

#include "PipelineState.hpp"
#include "DualGPUHook.hpp"
#include "ReverseTensorRecovery.hpp"
#include "ReverseHotpatchEngine.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>
#include <queue>
#include <mutex>
#include <functional>
#include <chrono>
#include <future>

namespace Deep2 {

// ============================================================================
// Stream State
// ============================================================================
enum class StreamState {
    Dead,       // 0 = VRAM cleared, ready for next chunk
    Reverse0,   // neutral start, no forced direction
    Loading,    // SSD → VRAM in progress
    Undead,     // bridging dead→alive
    Alive,      // 1 = VRAM loaded, computing
    Computing,  // active forward pass
    Emitting,   // output stream production
    Evicting    // clearing for next chunk
};

// ============================================================================
// Flight Phase (for latencyCompute = reversed)
// ============================================================================
enum class FlightPhase {
    Normal,     // data → compute (compute waits)
    Reversed    // compute prep || data flight (overlap)
};

// ============================================================================
// Chunk Info
// ============================================================================
struct LayerChunk {
    int         layerIndex    = 0;
    uint64_t    compressedOffset = 0;   // Offset in compressed file
    uint64_t    compressedSize   = 0;   // Compressed bytes (e.g., 1.09GB)
    uint64_t    originalSize     = 0;     // Uncompressed bytes (e.g., 17.5GB)
    uint64_t    reconstructedSize = 0;  // After partial decompress

    // Compression metadata
    uint32_t    compressionRatio = 8;   // 8:1
    uint32_t    compressionLevel = 3;   // paradox level 3
    bool        isCompressed     = true;

    // Latency-hiding: compression cost hidden by compute
    uint64_t    compressionTimeUs = 0;   // microseconds to decompress
    uint64_t    computeTimeUs      = 0;    // microseconds to compute
    bool        compressionHidden  = false; // compression_time <= compute_window

    // Reuse data cache status
    bool        inCache        = false;
    uint64_t    lastAccessTick = 0;
    uint64_t    hitCount       = 0;
    uint64_t    missCount      = 0;

    // Reconstruct compression: active slices
    std::vector<bool> activeSlices;     // Which slices to decompress
    uint32_t    activeSliceCount = 0;
    uint32_t    totalSliceCount  = 32;   // e.g., 32 attention heads

    // reverse0 → emit: neutral state tracking
    bool        reverse0Resolved = false;
    bool        emitted          = false;

    std::string name;
};

// ============================================================================
// Cache Entry (for reuseData)
// ============================================================================
struct CacheEntry {
    int         layerIndex     = 0;
    uint64_t    bytesInVRAM    = 0;
    uint64_t    lastAccessTick = 0;
    bool        valid          = false;
    uint64_t    hitCount       = 0;
    uint64_t    missCount      = 0;
    std::string name;
};

// ============================================================================
// Stream Telemetry
// ============================================================================
struct StreamTelemetry {
    uint64_t totalTokens        = 0;
    uint64_t totalLayers        = 0;
    uint64_t cacheHits          = 0;
    uint64_t cacheMisses        = 0;
    uint64_t partialDecompress  = 0;
    uint64_t fullDecompress     = 0;
    uint64_t evictions          = 0;
    uint64_t bytesSlingshot     = 0;     // Bytes read from SSD
    uint64_t bytesDecompressed  = 0;     // Bytes decompressed in VRAM
    uint64_t bytesReused        = 0;     // Bytes reused from cache
    uint64_t bytesSaved         = 0;     // Bytes saved via compression

    double   avgTokensPerSecond = 0.0;
    double   cacheHitRate       = 0.0;
    double   avgLatencyMs       = 0.0;

    uint64_t flightsHidden      = 0;  // latencyCompute=reversed successes
    uint64_t compressionHidden  = 0;  // 0*always successes
    uint64_t reverse0Resolved   = 0;  // reverse0→emit successes

    std::chrono::steady_clock::time_point startTime;
};

// ============================================================================
// Stream Engine Configuration
// ============================================================================
struct StreamConfig {
    // VRAM budget
    size_t vramBudgetBytes = 16ULL * 1024 * 1024 * 1024;  // 16GB default

    // Compression
    uint32_t compressionRatio    = 8;   // 8:1
    uint32_t compressionLevel    = 3;   // paradox level 3
    bool     compressEven        = true; // uniform across layers

    // Reuse data (LRU cache)
    bool     reuseData           = true;
    size_t   cacheReserveBytes   = 2ULL * 1024 * 1024 * 1024; // 2GB for cache

    // Reconstruct compression (partial decompress)
    bool     reconstructCompression = true;
    uint32_t activeHeads         = 4;   // Only decompress 4 of 32 heads
    uint32_t totalHeads          = 32;

    // Dense model (incremental +1 loading)
    bool     denseModel          = true;
    uint32_t numLayers           = 80;

    // Slingshot (SSD streaming)
    uint64_t slingshotBandwidthBps = 3ULL * 1024 * 1024 * 1024; // 3GB/s SSD
    uint64_t chunkSizeBytes        = 1170225766ULL; // ~1.09GB compressed

    // Undead hop / hotpatch
    bool     undeadHop           = true;
    bool     hotpatchRelive      = true;
};

// ============================================================================
// Stream Engine
// ============================================================================
class StreamEngine {
public:
    StreamEngine();
    ~StreamEngine();

    // ------------------------------------------------------------------------
    // Lifecycle
    // ------------------------------------------------------------------------
    bool Initialize(const StreamConfig& config);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }

    // ------------------------------------------------------------------------
    // Main entry: unreverseHot
    // ------------------------------------------------------------------------
    bool unreverseHot();  // Entry point

    // ------------------------------------------------------------------------
    // Stream cycle
    // ------------------------------------------------------------------------
    bool StreamCycle(int tokenIndex);  // One token = all layers
    bool StreamLayer(int layerIndex);  // One layer

    // ------------------------------------------------------------------------
    // State machine
    // ------------------------------------------------------------------------
    StreamState GetState() const;
    const char* GetStateName() const;

    // ------------------------------------------------------------------------
    // Four optimizations
    // ------------------------------------------------------------------------
    // 1. compressEven
    bool CompressEven(LayerChunk& chunk);

    // 2. reuseData
    bool reuseData(int layerIndex);           // Try to reuse cached layer
    void EvictLRU();                          // Evict oldest cached layer
    void UpdateCacheHit(int layerIndex);
    void UpdateCacheMiss(int layerIndex);
    double GetCacheHitRate() const;

    // 3. reconstructCompression
    bool ReconstructCompression(LayerChunk& chunk);
    void SetActiveSlices(LayerChunk& chunk, const std::vector<bool>& active);

    // 4. denseModel (+1+1+1+1)
    bool denseModelAdd(int layerIndex);       // +1 layer
    bool denseModelEvict(int layerIndex);     // -1 layer (LRU)
    size_t GetCachedLayerCount() const;

    // ------------------------------------------------------------------------
    // Chunk management
    // ------------------------------------------------------------------------
    bool LoadChunk(int layerIndex);           // SSD → VRAM
    bool ClearChunk(int layerIndex);          // VRAM → dead
    bool DecompressChunk(int layerIndex);     // compressed → decompressed
    bool ComputeChunk(int layerIndex);        // forward pass on chunk

    // ------------------------------------------------------------------------
    // Telemetry
    // ------------------------------------------------------------------------
    StreamTelemetry GetTelemetry() const;
    void PrintTelemetry() const;
    void ResetTelemetry();

    // ------------------------------------------------------------------------
    // Integration with existing systems
    // ------------------------------------------------------------------------
    void SetReverseHotpatchEngine(ReverseHotpatchEngine* engine);
    void SetDualGPUHook(DualGPUHook* hook);
    void SetTensorBackend(ReverseTensorBackend* backend);

    // ------------------------------------------------------------------------
    // Events
    // ------------------------------------------------------------------------
    using StateChangeCallback = std::function<void(StreamState oldState, StreamState newState)>;
    using ChunkLoadedCallback = std::function<void(int layerIndex, bool fromCache)>;
    void SetStateChangeCallback(StateChangeCallback cb);
    void SetChunkLoadedCallback(ChunkLoadedCallback cb);

    // ------------------------------------------------------------------------
    // Three latency-hiding invariants
    // ------------------------------------------------------------------------
    // A. latencyCompute = reversed: compute prep starts before data movement
    bool PrepareComputeAsync(int layerIndex);      // Start compute prep early
    bool WaitForDataFlight(int layerIndex);         // Block until data arrives
    bool IsFlightHiddenByCompute(int layerIndex) const;

    // B. compression + -compute_time = 0*always: compression hidden by compute
    bool HideCompressionByCompute(int layerIndex);  // Overlap decompress with compute
    bool IsCompressionHidden(int layerIndex) const;

    // C. reverse0 → emit: neutral start, no forced direction
    bool ResolveReverse0(int layerIndex);           // Resolve neutral state
    bool EmitOutput(int layerIndex);                // Produce output stream
    bool RereverseValidation(int layerIndex);       // Verify before emit

    // ------------------------------------------------------------------------
    // Stats
    // ------------------------------------------------------------------------
    struct Stats {
        uint64_t cyclesCompleted = 0;
        uint64_t tokensGenerated = 0;
        uint64_t layersStreamed    = 0;
        uint64_t bytesFromSSD      = 0;
        uint64_t bytesInVRAM       = 0;
        uint64_t bytesReused       = 0;
        uint64_t bytesSaved        = 0;  // By reconstructCompression
        uint64_t flightsHidden     = 0;  // latencyCompute=reversed successes
        uint64_t compressionHidden = 0;  // 0*always successes
        uint64_t reverse0Resolved  = 0;  // reverse0→emit successes
        double   avgTokensPerSec   = 0.0;
    };
    Stats GetStats() const;

private:
    bool initialized_ = false;
    StreamConfig config_;
    StreamState currentState_ = StreamState::Dead;
    FlightPhase flightPhase_ = FlightPhase::Reversed;  // Default: reversed

    // Layer chunks
    std::vector<LayerChunk> chunks_;

    // LRU cache for reuseData
    std::unordered_map<int, CacheEntry> cache_;
    std::queue<int> lruQueue_;
    mutable std::mutex cacheMutex_;

    // Async compute preparation (for latencyCompute=reversed)
    std::unordered_map<int, std::future<bool>> computePrepFutures_;
    mutable std::mutex futureMutex_;

    // Telemetry
    StreamTelemetry telemetry_;
    mutable std::mutex telemetryMutex_;

    // Integration
    ReverseHotpatchEngine* hotpatchEngine_ = nullptr;
    DualGPUHook* gpuHook_ = nullptr;
    ReverseTensorBackend* tensorBackend_ = nullptr;

    // Callbacks
    StateChangeCallback onStateChange_;
    ChunkLoadedCallback onChunkLoaded_;

    // Internal
    uint64_t currentTick_ = 0;
    size_t vramUsed_ = 0;

    bool TransitionTo(StreamState newState);
    bool IsLayerCached(int layerIndex) const;
    size_t GetLayerVRAMUsage(int layerIndex) const;
    void RecordSlingshotBytes(uint64_t bytes);
    void RecordDecompressBytes(uint64_t bytes);
    void RecordReuseBytes(uint64_t bytes);
    void RecordFlightHidden();
    void RecordCompressionHidden();
    void RecordReverse0Resolved();
};

// ============================================================================
// Free helpers
// ============================================================================
inline const char* StreamStateName(StreamState s) {
    switch (s) {
        case StreamState::Dead:      return "Dead";
        case StreamState::Reverse0:  return "Reverse0";
        case StreamState::Loading:   return "Loading";
        case StreamState::Undead:    return "Undead";
        case StreamState::Alive:     return "Alive";
        case StreamState::Computing: return "Computing";
        case StreamState::Emitting:  return "Emitting";
        case StreamState::Evicting:  return "Evicting";
        default:                     return "Unknown";
    }
}

} // namespace Deep2
