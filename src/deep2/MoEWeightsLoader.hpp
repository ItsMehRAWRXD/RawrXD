// ============================================================================
// MoEWeightsLoader.hpp - Mixture of Experts Weight Loader
// Streams expert weights from GGUF files for MoE models
// Memory-efficient: LRU cache with LRU eviction
// ============================================================================

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>
#include <atomic>
#include <chrono>
#include <cstdint>

// Include GGUF types from GGUFLoader.hpp to avoid redefinition
#include "GGUFLoader.hpp"

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/stat.h>
#endif

namespace Deep2 {

// Use types from GGUFLoader.hpp

// Projection type for MoE experts
enum class ExpertProjection : uint8_t {
    Gate = 0,
    Up   = 1,
    Down = 2
};

// Tensor info for one expert projection across a layer
struct ExpertProjectionInfo {
    int layerIdx = 0;
    int expertIdx = -1;  // -2 = shared, -3 = router gate
    ExpertProjection proj = ExpertProjection::Gate;
    std::string tensorName;
    GGMLType type = GGMLType::GGML_TYPE_F32;
    uint64_t fileOffset = 0;    // Offset from start of file to data
    uint64_t sizeBytes = 0;     // Total bytes for ALL experts in this tensor
    size_t numExperts = 0;      // Number of experts stacked in this tensor
    size_t bytesPerExpert = 0;  // Bytes for a single expert slice
    
    // For the Q input projection (shape: [numExperts, hidden, expertDim])
    size_t rows() const { return 0; }  // Total expert rows
    size_t cols() const { return 0; }  // hidden dim
    size_t expertDim() const { return 0; }  // intermediate dim
};

// Loading progress tracking
struct LoadProgress {
    std::atomic<uint64_t> tensorsTotal{0};
    std::atomic<uint64_t> tensorsLoaded{0};
    std::atomic<uint64_t> bytesTotal{0};
    std::atomic<uint64_t> bytesStreamed{0};
    std::atomic<int>      lastLayer{-1};
    std::atomic<int>      lastExpert{-1};
    std::atomic<bool>     complete{false};
    std::atomic<bool>     cancelled{false};
    
    void Reset() {
        tensorsTotal = tensorsLoaded = 0;
        bytesTotal = bytesStreamed = 0;
        lastLayer = lastExpert = -1;
        complete = false;
        cancelled = false;
    }
};

// LRU cache entry
struct ExpertCacheEntry {
    void* data = nullptr;
    size_t bytes = 0;
    std::chrono::steady_clock::time_point lastAccess;
    uint64_t accessCount = 0;
    bool pinned = false;
};

// MoE weights loader - streams expert weights from disk
class MoEWeightsLoader {
public:
    MoEWeightsLoader();
    ~MoEWeightsLoader();
    
    // Open a GGUF file and parse the tensor index
    bool Open(const char* ggufPath);
    void Close();
    
    bool IsOpen() const;
    
    // Get all MoE expert projection tensors discovered
    const std::vector<ExpertProjectionInfo>& GetExpertProjections() const;

    // Get all tensors in the file (raw GGUF tensor index)
    const std::vector<TensorInfo>& GetAllTensors() const { return allTensors_; }
    
    // Load a specific expert's full weights (all 3 projections: gate, up, down)
    // Returns pointer to buffer, or nullptr on failure
    const void* LoadExpert(int layer, int expert);
    
    // Load directly into caller-provided buffer
    bool LoadExpertDirect(int layer, int expert, void* buffer, size_t bufferSize);
    
    // Load just the router gate (ffn_gate_inp) for a layer
    bool LoadRouterGate(int layer, std::vector<float>& outWeights);
    
    // Load shared expert weights for a layer
    bool LoadSharedExpert(int layer, void* buffer, size_t bufferSize);
    
    // Cache management
    void SetMaxCacheSize(size_t bytes);
    size_t GetCacheSize() const;
    void EvictLRU();
    void Pin(int layer, int expert);
    void Unpin(int layer, int expert);
    
    // Get discovered metadata about expert layout
    size_t GetNumExpertLayers() const;
    size_t GetExpertsPerLayer() const;
    const std::string& GetArchitecture() const { return architecture_; }
    
    // Statistics
    struct Stats {
        uint64_t totalLoads = 0;
        uint64_t cacheHits = 0;
        uint64_t cacheMisses = 0;
        uint64_t evictions = 0;
        double avgLoadTimeMs = 0.0;
        uint64_t bytesStreamed = 0;
    };
    Stats GetStats() const;
    void ResetStats();
    
    const LoadProgress& GetProgress() const { return progress_; }
    
    void Cancel() { progress_.cancelled.store(true); }
    void ResetCancel() { progress_.cancelled.store(false); }

private:
    struct CacheKey {
        int layer;
        int expert;
        bool operator==(const CacheKey& o) const {
            return layer == o.layer && expert == o.expert;
        }
    };
    struct CacheKeyHash {
        size_t operator()(const CacheKey& k) const noexcept {
            return std::hash<int>()(k.layer) ^ (std::hash<int>()(k.expert) << 16);
        }
    };
    
#ifdef _WIN32
    HANDLE fileHandle_ = INVALID_HANDLE_VALUE;
    HANDLE fileMapping_ = nullptr;
    void* mappedBase_ = nullptr;
#else
    int fileHandle_ = -1;
    void* mappedBase_ = nullptr;
    size_t mappedSize_ = 0;
#endif
    
    uint64_t fileSize_ = 0;
    uint64_t dataOffset_ = 0;
    
    // All tensors from GGUF
    std::vector<TensorInfo> allTensors_;
    
    // MoE-specific projections discovered
    std::vector<ExpertProjectionInfo> expertProjections_;
    std::unordered_map<std::string, size_t> tensorNameMap_;
    
    // LRU cache
    std::unordered_map<CacheKey, ExpertCacheEntry, CacheKeyHash> cache_;
    mutable std::mutex cacheMutex_;
    size_t maxCacheBytes_ = 4ULL * 1024 * 1024 * 1024; // 4 GB default
    size_t currentCacheBytes_ = 0;
    
    // Stats
    mutable Stats stats_;
    mutable std::mutex statsMutex_;
    
    // Progress
    LoadProgress progress_;
    
    // Discovered metadata
    std::string architecture_;
    size_t numExpertLayers_ = 0;
    size_t expertsPerLayer_ = 0;
    
    // File I/O
    bool OpenFile(const char* path);
    void CloseFile();
    bool ReadAt(uint64_t offset, void* buffer, size_t size);
    
    // Parse GGUF header and tensor index
    bool ParseIndex();
    
    // Discover MoE expert projection tensors
    size_t DiscoverExpertProjections();
    
    // Read a single expert slice from the stacked tensor
    const void* LoadExpertInternal(int layer, int expert);
    
    // Parse expert name to extract layer and projection
    static bool ParseExpertName(const std::string& name, int& layer, 
                                 int& expertIdx, ExpertProjection& proj);
};

} // namespace Deep2
