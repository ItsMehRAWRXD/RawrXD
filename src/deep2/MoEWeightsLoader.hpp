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

#ifdef _WIN32
    #include <windows.h>
#else
    #include <sys/mman.h>
    #include <fcntl.h>
    #include <unistd.h>
    #include <sys/stat.h>
#endif

namespace Deep2 {

// GGML block sizes (matching llama.cpp)
static constexpr size_t QK4_0 = 32;
static constexpr size_t QK4_1 = 32;
static constexpr size_t QK5_0 = 32;
static constexpr size_t QK5_1 = 32;
static constexpr size_t QK8_0 = 32;
static constexpr size_t QK8_1 = 32;
static constexpr size_t QK_K  = 256;
static constexpr size_t QK4_NL = 32;

// GGML quantization types (subset used by Q4_K and friends)
enum class GGMLType : uint32_t {
    GGML_TYPE_F32     = 0,
    GGML_TYPE_F16     = 1,
    GGML_TYPE_Q4_0    = 2,
    GGML_TYPE_Q4_1    = 3,
    GGML_TYPE_Q5_0    = 6,
    GGML_TYPE_Q5_1    = 7,
    GGML_TYPE_Q8_0    = 8,
    GGML_TYPE_Q8_1    = 9,
    GGML_TYPE_Q2_K    = 10,
    GGML_TYPE_Q3_K    = 11,
    GGML_TYPE_Q4_K    = 12,
    GGML_TYPE_Q5_K    = 13,
    GGML_TYPE_Q6_K    = 14,
    GGML_TYPE_Q8_K    = 15,
    GGML_TYPE_IQ2_XXS = 16,
    GGML_TYPE_IQ2_XS  = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S   = 19,
    GGML_TYPE_IQ4_NL  = 20,
    GGML_TYPE_IQ3_S   = 21,
    GGML_TYPE_IQ2_S   = 22,
    GGML_TYPE_IQ4_XS  = 23,
    GGML_TYPE_I8      = 24,
    GGML_TYPE_I16     = 25,
    GGML_TYPE_I32     = 26,
    GGML_TYPE_I64     = 27,
    GGML_TYPE_F64     = 28,
    GGML_TYPE_F32_E8M1 = 29
};

// Tensor info from the GGUF index
struct TensorInfo {
    std::string name;
    GGMLType type = GGMLType::GGML_TYPE_F32;
    std::vector<uint64_t> dimensions;
    uint64_t offset = 0;       // offset within the data section
    size_t size = 0;           // total bytes
};

struct alignas(8) block_q4_0 { uint16_t d; uint8_t qs[QK4_0/2]; };
struct alignas(8) block_q4_1 { uint16_t d; uint16_t m; uint8_t qs[QK4_1/2]; };
struct alignas(8) block_q5_0 { uint16_t d; uint8_t qh[4]; uint8_t qs[QK5_0/2]; };
struct alignas(8) block_q5_1 { uint16_t d; uint16_t m; uint8_t qh[4]; uint8_t qs[QK5_1/2]; };
struct alignas(8) block_q8_0 { uint16_t d; int8_t qs[QK8_0]; };
struct alignas(8) block_q8_1 { uint16_t d; int8_t qs[QK8_1/2]; int8_t bsums[QK8_1/16]; };
struct alignas(8) block_q2_K { uint8_t qs[QK_K/4]; uint8_t scales[QK_K/16]; uint16_t d; uint16_t dmin; };
struct alignas(8) block_q3_K { uint8_t hmask[QK_K/8]; uint8_t qs[QK_K/4]; uint8_t scales[12]; uint16_t d; };
struct alignas(8) block_q4_K { uint8_t scales[3*QK_K/64]; uint8_t qs[QK_K/2]; uint16_t d; uint16_t dmin; };
struct alignas(8) block_q5_K { uint8_t scales[3*QK_K/64]; uint8_t qh[QK_K/8]; uint8_t qs[QK_K/2]; uint16_t d; uint16_t dmin; };
struct alignas(8) block_q6_K { uint8_t ql[QK_K/2]; uint8_t qh[QK_K/4]; int8_t scales[QK_K/16]; uint16_t d; };
struct alignas(8) block_q8_K { int8_t qs[QK_K]; float d; int8_t bsums[QK_K/16]; };
struct alignas(8) block_iq2_xxs { uint16_t d; uint8_t qs[QK_K/8]; uint8_t signs[QK_K/32]; uint8_t scales[QK_K/32]; };
struct alignas(8) block_iq2_xs  { uint16_t d; uint8_t qs[QK_K/8]; uint8_t signs[QK_K/32]; uint8_t scales[QK_K/16]; };
struct alignas(8) block_iq3_xxs { uint16_t d; uint8_t qs[QK_K/8]; uint8_t signs[QK_K/32]; uint8_t scales[QK_K/16]; };
struct alignas(8) block_iq1_s   { uint16_t d; uint8_t qs[QK_K/8]; uint16_t scales[QK_K/32]; };
struct alignas(4) block_iq4_nl  { uint16_t d; int8_t qs[QK4_NL]; };
struct alignas(8) block_iq3_s   { uint16_t d; uint8_t qs[QK_K/8]; uint8_t signs[QK_K/16]; int8_t scales[QK_K/32]; };
struct alignas(8) block_iq2_s   { uint16_t d; uint8_t qs[QK_K/8]; uint8_t signs[QK_K/16]; uint8_t scales[QK_K/16]; };
struct alignas(8) block_iq4_xs  { uint16_t d; int16_t scales[QK_K/32]; uint8_t qs[QK_K/4]; };

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
