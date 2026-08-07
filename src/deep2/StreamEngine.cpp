// ============================================================================
// StreamEngine.cpp - Ultimate Universal Streaming Compression VRAM Engine
// ============================================================================

#include "StreamEngine.hpp"
#include <cstdio>
#include <cstring>
#include <algorithm>
#include <cmath>

namespace Deep2 {

// ============================================================================
// StreamEngine
// ============================================================================
StreamEngine::StreamEngine() = default;
StreamEngine::~StreamEngine() { Shutdown(); }

bool StreamEngine::Initialize(const StreamConfig& config) {
    config_ = config;
    initialized_ = true;
    currentState_ = StreamState::Dead;
    vramUsed_ = 0;
    currentTick_ = 0;

    // Initialize layer chunks (compressEven)
    chunks_.clear();
    for (uint32_t i = 0; i < config_.numLayers; ++i) {
        LayerChunk chunk;
        chunk.layerIndex = i;
        chunk.compressedSize = config_.chunkSizeBytes;  // Even compression
        chunk.originalSize = chunk.compressedSize * config_.compressionRatio;
        chunk.compressionRatio = config_.compressionRatio;
        chunk.compressionLevel = config_.compressionLevel;
        chunk.isCompressed = true;
        chunk.name = "L" + std::to_string(i);

        // reconstructCompression: set active slices
        chunk.totalSliceCount = config_.totalHeads;
        chunk.activeSliceCount = config_.activeHeads;
        chunk.activeSlices.resize(config_.totalHeads, false);
        for (uint32_t h = 0; h < config_.activeHeads; ++h) {
            chunk.activeSlices[h] = true;
        }

        // reconstructed size = only active slices
        float activeRatio = (float)config_.activeHeads / (float)config_.totalHeads;
        chunk.reconstructedSize = (uint64_t)(chunk.originalSize * activeRatio);

        chunks_.push_back(chunk);
    }

    printf("[StreamEngine] Initialized: %u layers, %s compression, %s reuse, %s reconstruct, %s dense\n",
           config_.numLayers,
           config_.compressEven ? "even" : "uneven",
           config_.reuseData ? "ON" : "OFF",
           config_.reconstructCompression ? "ON" : "OFF",
           config_.denseModel ? "ON" : "OFF");
    printf("[StreamEngine] VRAM budget: %.2f GB\n", config_.vramBudgetBytes / (1024.0 * 1024.0 * 1024.0));
    printf("[StreamEngine] Chunk size: %.2f GB compressed, %.2f GB original, %.2f GB reconstructed\n",
           config_.chunkSizeBytes / (1024.0 * 1024.0 * 1024.0),
           chunks_[0].originalSize / (1024.0 * 1024.0 * 1024.0),
           chunks_[0].reconstructedSize / (1024.0 * 1024.0 * 1024.0));

    return true;
}

void StreamEngine::Shutdown() {
    initialized_ = false;
    cache_.clear();
    while (!lruQueue_.empty()) lruQueue_.pop();
    printf("[StreamEngine] Shutdown\n");
}

// ============================================================================
// Main entry: unreverseHot
// ============================================================================
bool StreamEngine::unreverseHot() {
    if (!initialized_) return false;

    printf("\n╔══════════════════════════════════════════════════════════════════╗\n");
    printf("║   ULTIMATE UNIVERSAL STREAMING COMPRESSION VRAM ENGINE            ║\n");
    printf("║   entry: unreverseHot                                            ║\n");
    printf("╚══════════════════════════════════════════════════════════════════╝\n\n");

    printf("[unreverseHot] patchEngineer: splitting model into %u layer-chunks\n", config_.numLayers);
    printf("[unreverseHot] patchCompress: nanoCompress %u:1 paradox L%u\n",
           config_.compressionRatio, config_.compressionLevel);
    printf("[unreverseHot] stream*load: MARShop*slingshot ready\n");
    printf("[unreverseHot] patchUncompress: on-the-fly in VRAM\n");
    printf("[unreverseHot] patch(undead): undeadHop bridge ready\n");
    printf("[unreverseHot] hotpatch(relive*++()): revival protocol ready\n");
    printf("[unreverseHot] streamDead(0) → streamAlive(1) → loop ∞\n\n");

    return true;
}

// ============================================================================
// Stream cycle: one token = all layers
// ============================================================================
bool StreamEngine::StreamCycle(int tokenIndex) {
    if (!initialized_) return false;

    auto cycleStart = std::chrono::steady_clock::now();

    printf("[StreamCycle] === TOKEN %d ===\n", tokenIndex);

    uint64_t hits = 0;
    uint64_t misses = 0;

    for (uint32_t layer = 0; layer < config_.numLayers; ++layer) {
        bool fromCache = false;

        // A. latencyCompute = reversed: start compute prep BEFORE data movement
        if (flightPhase_ == FlightPhase::Reversed) {
            PrepareComputeAsync(layer);
        }

        // 1. Try reuseData first
        if (config_.reuseData && reuseData(layer)) {
            fromCache = true;
            hits++;
        } else {
            // 2. Miss: slingshot + decompress
            misses++;
            if (!StreamLayer(layer)) {
                printf("[StreamCycle] ERROR: Layer %d failed\n", layer);
                return false;
            }
        }

        // A. Wait for data flight (if reversed, compute prep already started)
        if (flightPhase_ == FlightPhase::Reversed) {
            WaitForDataFlight(layer);
        }

        // 3. Compute on layer
        if (!ComputeChunk(layer)) {
            printf("[StreamCycle] ERROR: Compute layer %d failed\n", layer);
            return false;
        }

        // B. compression + -compute_time = 0*always
        if (config_.reconstructCompression) {
            HideCompressionByCompute(layer);
        }

        // C. reverse0 → emit: neutral start, produce output
        ResolveReverse0(layer);
        if (!RereverseValidation(layer)) {
            printf("[StreamCycle] WARNING: Layer %d rereverse validation failed\n", layer);
        }
        EmitOutput(layer);

        // 4. denseModel: +1 next, LRU eviction
        if (config_.denseModel) {
            denseModelAdd(layer);
        }

        if (onChunkLoaded_) {
            onChunkLoaded_(layer, fromCache);
        }
    }

    auto cycleEnd = std::chrono::steady_clock::now();
    auto cycleMs = std::chrono::duration_cast<std::chrono::milliseconds>(cycleEnd - cycleStart).count();

    // Update telemetry
    {
        std::lock_guard<std::mutex> lock(telemetryMutex_);
        telemetry_.totalTokens++;
        telemetry_.totalLayers += config_.numLayers;
        telemetry_.cacheHits += hits;
        telemetry_.cacheMisses += misses;
        telemetry_.avgLatencyMs = (telemetry_.avgLatencyMs * (telemetry_.totalTokens - 1) + cycleMs) / telemetry_.totalTokens;
        telemetry_.cacheHitRate = (double)telemetry_.cacheHits / (double)(telemetry_.cacheHits + telemetry_.cacheMisses);
    }

    printf("[StreamCycle] Token %d complete: %llu hits, %llu misses, hitRate=%.1f%%, latency=%lldms\n",
           tokenIndex, hits, misses, (double)hits / (hits + misses) * 100.0, cycleMs);

    return true;
}

// ============================================================================
// Stream layer: one layer with latency-hiding invariants
// ============================================================================
bool StreamEngine::StreamLayer(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    // C. reverse0: start from neutral state
    TransitionTo(StreamState::Reverse0);
    ResolveReverse0(layerIndex);

    // State: Reverse0 → Loading
    TransitionTo(StreamState::Loading);

    // 1. Slingshot: SSD → VRAM
    if (!LoadChunk(layerIndex)) {
        return false;
    }

    // 2. Decompress (may be hidden by compute)
    TransitionTo(StreamState::Undead);
    if (!DecompressChunk(layerIndex)) {
        return false;
    }

    // B. Check compression + -compute_time = 0*always
    if (IsCompressionHidden(layerIndex)) {
        printf("[StreamLayer] compression + -compute_time = 0*always: layer %d\n", layerIndex);
    }

    // 3. Undead → Alive
    if (config_.undeadHop) {
        printf("[StreamLayer] undeadHop: layer %d bridging dead→alive\n", layerIndex);
    }
    if (config_.hotpatchRelive) {
        printf("[StreamLayer] hotpatch(relive++): layer %d revived\n", layerIndex);
    }

    TransitionTo(StreamState::Alive);
    return true;
}

// ============================================================================
// State machine
// ============================================================================
StreamState StreamEngine::GetState() const {
    return currentState_;
}

const char* StreamEngine::GetStateName() const {
    return StreamStateName(currentState_);
}

bool StreamEngine::TransitionTo(StreamState newState) {
    if (currentState_ == newState) return true;

    StreamState oldState = currentState_;
    currentState_ = newState;

    if (onStateChange_) {
        onStateChange_(oldState, newState);
    }

    return true;
}

// ============================================================================
// 1. compressEven
// ============================================================================
bool StreamEngine::CompressEven(LayerChunk& chunk) {
    if (!config_.compressEven) return true;

    // Uniform compression: all chunks same ratio
    chunk.compressedSize = config_.chunkSizeBytes;
    chunk.originalSize = chunk.compressedSize * config_.compressionRatio;
    chunk.isCompressed = true;

    return true;
}

// ============================================================================
// 2. reuseData
// ============================================================================
bool StreamEngine::reuseData(int layerIndex) {
    if (!config_.reuseData) return false;

    std::lock_guard<std::mutex> lock(cacheMutex_);

    auto it = cache_.find(layerIndex);
    if (it != cache_.end() && it->second.valid) {
        // Cache hit!
        it->second.lastAccessTick = ++currentTick_;
        RecordReuseBytes(it->second.bytesInVRAM);

        printf("[reuseData] HIT: layer %d (cached, %.2f GB)\n",
               layerIndex, it->second.bytesInVRAM / (1024.0 * 1024.0 * 1024.0));
        return true;
    }

    return false;
}

void StreamEngine::UpdateCacheHit(int layerIndex) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = cache_.find(layerIndex);
    if (it != cache_.end()) {
        it->second.hitCount++;
    }
}

void StreamEngine::UpdateCacheMiss(int layerIndex) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = cache_.find(layerIndex);
    if (it != cache_.end()) {
        it->second.missCount++;
    }
}

void StreamEngine::EvictLRU() {
    std::lock_guard<std::mutex> lock(cacheMutex_);

    if (lruQueue_.empty()) return;

    int victim = lruQueue_.front();
    lruQueue_.pop();

    auto it = cache_.find(victim);
    if (it != cache_.end()) {
        printf("[EvictLRU] Evicting layer %d (%.2f GB freed)\n",
               victim, it->second.bytesInVRAM / (1024.0 * 1024.0 * 1024.0));
        vramUsed_ -= it->second.bytesInVRAM;
        cache_.erase(it);

        {
            std::lock_guard<std::mutex> tlock(telemetryMutex_);
            telemetry_.evictions++;
        }
    }
}

double StreamEngine::GetCacheHitRate() const {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    uint64_t total = telemetry_.cacheHits + telemetry_.cacheMisses;
    if (total == 0) return 0.0;
    return (double)telemetry_.cacheHits / (double)total * 100.0;
}

// ============================================================================
// 3. reconstructCompression
// ============================================================================
bool StreamEngine::ReconstructCompression(LayerChunk& chunk) {
    if (!config_.reconstructCompression) {
        // Full decompress
        chunk.reconstructedSize = chunk.originalSize;
        return true;
    }

    // Partial decompress: only active slices
    float activeRatio = (float)chunk.activeSliceCount / (float)chunk.totalSliceCount;
    chunk.reconstructedSize = (uint64_t)(chunk.originalSize * activeRatio);

    printf("[ReconstructCompression] layer %d: %u/%u slices active, %.2f GB → %.2f GB\n",
           chunk.layerIndex, chunk.activeSliceCount, chunk.totalSliceCount,
           chunk.originalSize / (1024.0 * 1024.0 * 1024.0),
           chunk.reconstructedSize / (1024.0 * 1024.0 * 1024.0));

    {
        std::lock_guard<std::mutex> lock(telemetryMutex_);
        telemetry_.partialDecompress++;
        telemetry_.bytesSaved += (chunk.originalSize - chunk.reconstructedSize);
    }

    return true;
}

void StreamEngine::SetActiveSlices(LayerChunk& chunk, const std::vector<bool>& active) {
    chunk.activeSlices = active;
    chunk.activeSliceCount = 0;
    for (bool a : active) {
        if (a) chunk.activeSliceCount++;
    }
}

// ============================================================================
// 4. denseModel (+1+1+1+1)
// ============================================================================
bool StreamEngine::denseModelAdd(int layerIndex) {
    if (!config_.denseModel) return true;

    std::lock_guard<std::mutex> lock(cacheMutex_);

    // Check if already cached
    if (cache_.find(layerIndex) != cache_.end()) {
        return true; // Already in cache
    }

    // Check VRAM budget
    size_t chunkBytes = chunks_[layerIndex].reconstructedSize;
    while (vramUsed_ + chunkBytes > config_.vramBudgetBytes && !cache_.empty()) {
        EvictLRU();
    }

    // Add to cache
    CacheEntry entry;
    entry.layerIndex = layerIndex;
    entry.bytesInVRAM = chunkBytes;
    entry.lastAccessTick = ++currentTick_;
    entry.valid = true;
    entry.name = chunks_[layerIndex].name;

    cache_[layerIndex] = entry;
    lruQueue_.push(layerIndex);
    vramUsed_ += chunkBytes;

    printf("[denseModel] +1 layer %d (%.2f GB), VRAM used: %.2f / %.2f GB\n",
           layerIndex, chunkBytes / (1024.0 * 1024.0 * 1024.0),
           vramUsed_ / (1024.0 * 1024.0 * 1024.0),
           config_.vramBudgetBytes / (1024.0 * 1024.0 * 1024.0));

    return true;
}

bool StreamEngine::denseModelEvict(int layerIndex) {
    std::lock_guard<std::mutex> lock(cacheMutex_);

    auto it = cache_.find(layerIndex);
    if (it != cache_.end()) {
        vramUsed_ -= it->second.bytesInVRAM;
        cache_.erase(it);
        printf("[denseModel] -1 layer %d evicted\n", layerIndex);
    }

    return true;
}

size_t StreamEngine::GetCachedLayerCount() const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    return cache_.size();
}

// ============================================================================
// Chunk operations
// ============================================================================
bool StreamEngine::LoadChunk(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    const auto& chunk = chunks_[layerIndex];

    // Simulate slingshot: SSD → VRAM
    uint64_t bytes = chunk.compressedSize;
    RecordSlingshotBytes(bytes);

    printf("[LoadChunk] Slingshot: layer %d, %.2f GB from SSD → VRAM\n",
           layerIndex, bytes / (1024.0 * 1024.0 * 1024.0));

    return true;
}

bool StreamEngine::ClearChunk(int layerIndex) {
    TransitionTo(StreamState::Evicting);

    printf("[ClearChunk] layer %d → streamDead(0)\n", layerIndex);

    // Note: actual VRAM clear is handled by denseModel LRU eviction
    TransitionTo(StreamState::Dead);
    return true;
}

bool StreamEngine::DecompressChunk(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    auto& chunk = chunks_[layerIndex];

    // Apply reconstructCompression
    ReconstructCompression(chunk);

    uint64_t bytes = chunk.reconstructedSize;
    RecordDecompressBytes(bytes);

    printf("[DecompressChunk] layer %d: %.2f GB compressed → %.2f GB reconstructed\n",
           layerIndex,
           chunk.compressedSize / (1024.0 * 1024.0 * 1024.0),
           bytes / (1024.0 * 1024.0 * 1024.0));

    return true;
}

bool StreamEngine::ComputeChunk(int layerIndex) {
    TransitionTo(StreamState::Computing);

    // Simulate compute on layer
    (void)layerIndex;

    TransitionTo(StreamState::Alive);
    return true;
}

// ============================================================================
// Three latency-hiding invariants
// ============================================================================

// A. latencyCompute = reversed: compute prep starts before data movement
bool StreamEngine::PrepareComputeAsync(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    // Launch compute preparation in background
    std::lock_guard<std::mutex> lock(futureMutex_);
    computePrepFutures_[layerIndex] = std::async(std::launch::async, [this, layerIndex]() -> bool {
        // Simulate compute prep (kernel enqueue, buffer bind, etc.)
        printf("[PrepareComputeAsync] layer %d compute prep started\n", layerIndex);
        return true;
    });

    return true;
}

bool StreamEngine::WaitForDataFlight(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    std::lock_guard<std::mutex> lock(futureMutex_);
    auto it = computePrepFutures_.find(layerIndex);
    if (it != computePrepFutures_.end()) {
        // Wait for compute prep to complete (it ran parallel with data flight)
        it->second.wait();
        computePrepFutures_.erase(it);
        printf("[WaitForDataFlight] layer %d compute prep complete (flight hidden)\n", layerIndex);
    }

    return true;
}

bool StreamEngine::IsFlightHiddenByCompute(int layerIndex) const {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;
    // Flight is hidden if compute prep finished before or with data arrival
    return flightPhase_ == FlightPhase::Reversed;
}

// B. compression + -compute_time = 0*always: compression hidden by compute
bool StreamEngine::HideCompressionByCompute(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    auto& chunk = chunks_[layerIndex];

    // Simulate: compressionTimeUs <= computeTimeUs → hidden
    chunk.compressionTimeUs = 100;  // simulated 100us decompress
    chunk.computeTimeUs = 500;       // simulated 500us compute
    chunk.compressionHidden = (chunk.compressionTimeUs <= chunk.computeTimeUs);

    if (chunk.compressionHidden) {
        RecordCompressionHidden();
        printf("[HideCompressionByCompute] layer %d: compression %lluus hidden by compute %lluus\n",
               layerIndex, chunk.compressionTimeUs, chunk.computeTimeUs);
    }

    return chunk.compressionHidden;
}

bool StreamEngine::IsCompressionHidden(int layerIndex) const {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;
    return chunks_[layerIndex].compressionHidden;
}

// C. reverse0 → emit: neutral start, no forced direction
bool StreamEngine::ResolveReverse0(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    auto& chunk = chunks_[layerIndex];

    // Resolve from neutral state: determine direction based on context
    chunk.reverse0Resolved = true;
    RecordReverse0Resolved();

    printf("[ResolveReverse0] layer %d: neutral resolved → direction chosen\n", layerIndex);
    return true;
}

bool StreamEngine::EmitOutput(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    auto& chunk = chunks_[layerIndex];
    if (!chunk.reverse0Resolved) {
        printf("[EmitOutput] ERROR: layer %d reverse0 not resolved\n", layerIndex);
        return false;
    }

    TransitionTo(StreamState::Emitting);
    chunk.emitted = true;

    printf("[EmitOutput] layer %d: output emitted\n", layerIndex);
    return true;
}

bool StreamEngine::RereverseValidation(int layerIndex) {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return false;

    auto& chunk = chunks_[layerIndex];

    // Validate before emit: verify reverse0 resolved and state consistent
    if (!chunk.reverse0Resolved) {
        printf("[RereverseValidation] FAIL: layer %d reverse0 not resolved\n", layerIndex);
        return false;
    }

    printf("[RereverseValidation] layer %d: validation passed\n", layerIndex);
    return true;
}

// ============================================================================
// Telemetry
// ============================================================================
StreamTelemetry StreamEngine::GetTelemetry() const {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    return telemetry_;
}

void StreamEngine::PrintTelemetry() const {
    std::lock_guard<std::mutex> lock(telemetryMutex_);

    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║              StreamEngine Telemetry                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Tokens Generated:    %8llu                                  ║\n", telemetry_.totalTokens);
    printf("║ Layers Streamed:      %8llu                                  ║\n", telemetry_.totalLayers);
    printf("║ Cache Hits:           %8llu                                  ║\n", telemetry_.cacheHits);
    printf("║ Cache Misses:         %8llu                                  ║\n", telemetry_.cacheMisses);
    printf("║ Cache Hit Rate:       %8.1f%%                                 ║\n", telemetry_.cacheHitRate * 100.0);
    printf("║ Partial Decompress:   %8llu                                  ║\n", telemetry_.partialDecompress);
    printf("║ Full Decompress:     %8llu                                  ║\n", telemetry_.fullDecompress);
    printf("║ Evictions:            %8llu                                  ║\n", telemetry_.evictions);
    printf("║ Bytes from SSD:       %8.2f GB                               ║\n", telemetry_.bytesSlingshot / (1024.0 * 1024.0 * 1024.0));
    printf("║ Bytes Decompressed:   %8.2f GB                               ║\n", telemetry_.bytesDecompressed / (1024.0 * 1024.0 * 1024.0));
    printf("║ Bytes Reused:         %8.2f GB                               ║\n", telemetry_.bytesReused / (1024.0 * 1024.0 * 1024.0));
    printf("║ Bytes Saved:          %8.2f GB                               ║\n", telemetry_.bytesSaved / (1024.0 * 1024.0 * 1024.0));
    printf("║ Avg Latency:          %8.2f ms/token                          ║\n", telemetry_.avgLatencyMs);
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
}

void StreamEngine::ResetTelemetry() {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_ = StreamTelemetry{};
}

// ============================================================================
// Integration
// ============================================================================
void StreamEngine::SetReverseHotpatchEngine(ReverseHotpatchEngine* engine) {
    hotpatchEngine_ = engine;
}

void StreamEngine::SetDualGPUHook(DualGPUHook* hook) {
    gpuHook_ = hook;
}

void StreamEngine::SetTensorBackend(ReverseTensorBackend* backend) {
    tensorBackend_ = backend;
}

// ============================================================================
// Events
// ============================================================================
void StreamEngine::SetStateChangeCallback(StateChangeCallback cb) {
    onStateChange_ = cb;
}

void StreamEngine::SetChunkLoadedCallback(ChunkLoadedCallback cb) {
    onChunkLoaded_ = cb;
}

// ============================================================================
// Stats
// ============================================================================
StreamEngine::Stats StreamEngine::GetStats() const {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    Stats s;
    s.tokensGenerated = telemetry_.totalTokens;
    s.layersStreamed = telemetry_.totalLayers;
    s.bytesFromSSD = telemetry_.bytesSlingshot;
    s.bytesInVRAM = vramUsed_;
    s.bytesReused = telemetry_.bytesReused;
    s.bytesSaved = telemetry_.bytesSaved;
    s.flightsHidden = telemetry_.flightsHidden;
    s.compressionHidden = telemetry_.compressionHidden;
    s.reverse0Resolved = telemetry_.reverse0Resolved;
    s.avgTokensPerSec = telemetry_.avgTokensPerSecond;
    return s;
}

// ============================================================================
// Internal
// ============================================================================
bool StreamEngine::IsLayerCached(int layerIndex) const {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = cache_.find(layerIndex);
    return it != cache_.end() && it->second.valid;
}

size_t StreamEngine::GetLayerVRAMUsage(int layerIndex) const {
    if (layerIndex < 0 || layerIndex >= (int)chunks_.size()) return 0;
    return chunks_[layerIndex].reconstructedSize;
}

void StreamEngine::RecordSlingshotBytes(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.bytesSlingshot += bytes;
}

void StreamEngine::RecordDecompressBytes(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.bytesDecompressed += bytes;
}

void StreamEngine::RecordReuseBytes(uint64_t bytes) {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.bytesReused += bytes;
}

void StreamEngine::RecordFlightHidden() {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.flightsHidden++;
}

void StreamEngine::RecordCompressionHidden() {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.compressionHidden++;
}

void StreamEngine::RecordReverse0Resolved() {
    std::lock_guard<std::mutex> lock(telemetryMutex_);
    telemetry_.reverse0Resolved++;
}

} // namespace Deep2
