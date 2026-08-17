// ============================================================================
// SharedModelRuntime.hpp
// ============================================================================
// Orchestration layer between HTTP inference requests and the existing
// ResidencyTracker / TensorPlacementManager / CapacityManager stack.
//
// Design invariant: the compressed representation remains authoritative.
// Execution tiles are transient, bounded working-set allocations.
// The runtime never creates a second persistent copy of model weights.
// ============================================================================
#pragma once

#include "../memory/ResidencyTracker.hpp"
#include "../memory/TensorPlacementManager.hpp"
#include "../memory/CapacityManager.hpp"
#include "../memory/WorkingSetPredictor.hpp"
#include "../memory/TransferScheduler.hpp"
#include "BP1BraidIndex.hpp"
#include "BP1BraidStreamer.hpp"

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <mutex>
#include <shared_mutex>
#include <atomic>
#include <unordered_map>
#include <functional>

namespace RawrXD {
namespace Serve {

// Forward
struct GenerateRequest;
using StreamTokenFn = std::function<void(const std::string& token, bool done)>;

namespace Shared {

// ============================================================================
// GGML type enumeration (matches GGUF tensor_type values)
// ============================================================================
enum class GGMLType : uint32_t {
    F32     = 0,
    F16     = 1,
    Q4_0    = 2,
    Q4_1    = 3,
    Q5_0    = 6,
    Q5_1    = 7,
    Q8_0    = 8,
    Q8_1    = 9,
    Q2_K    = 10,
    Q3_K    = 11,
    Q4_K    = 12,
    Q5_K    = 13,
    Q6_K    = 14,
    IQ2_XXS = 15,
    IQ2_XS  = 16,
    IQ3_XXS = 17,
    IQ1_S   = 18,
    IQ4_NL  = 19,
    IQ3_S   = 20,
    IQ2_S   = 21,
    IQ1_M   = 28,
    BF16    = 30,
    Unknown = 0xffffffffu
};

// ============================================================================
// Storage / execution formats
// ============================================================================
enum class StorageFormat : uint8_t {
    Unknown = 0,
    GGUF_Q2, GGUF_Q3, GGUF_Q4, GGUF_Q5, GGUF_Q6, GGUF_Q8,
    FP16, BF16, FP32
};

enum class BraidPrecision : uint8_t {
    BP1 = 1, BP2, BP3, BP4, BP5, BP6, BP7, BP8
};

// ExecutionFormat is defined in BP1BraidIndex.hpp

struct PrecisionPlan {
    StorageFormat   storage   = StorageFormat::Unknown;
    BraidPrecision  braid     = BraidPrecision::BP8;
    ExecutionFormat execution = ExecutionFormat::BF16;
    bool            useBraid  = true;
};

// ============================================================================
// Tile identifier
// ============================================================================
struct TileId {
    uint64_t tensorId = 0;
    uint32_t braidId  = 0;
    uint32_t tileIdx  = 0;

    bool operator==(const TileId& o) const noexcept {
        return tensorId == o.tensorId && braidId == o.braidId && tileIdx == o.tileIdx;
    }
};

struct TileIdHash {
    size_t operator()(const TileId& t) const noexcept {
        uint64_t x = t.tensorId;
        x ^= static_cast<uint64_t>(t.braidId) * 0x9E3779B185EBCA87ull;
        x ^= static_cast<uint64_t>(t.tileIdx) * 0xC2B2AE3D27D4EB4Full;
        x ^= x >> 30; x *= 0xBF58476D1CE4E5B9ull;
        x ^= x >> 27; x *= 0x94D049BB133111EBull;
        x ^= x >> 31;
        return static_cast<size_t>(x);
    }
};

// ============================================================================
// Physical tile address within the GGUF file
// ============================================================================
struct TileAddress {
    TileId   id{};
    uint64_t fileOffset           = 0;
    uint64_t fileBytes            = 0;
    uint64_t logicalElementOffset = 0;
    uint64_t logicalElementCount  = 0;
};

// ============================================================================
// Residency handle
// ============================================================================
struct ResidencyHandle {
    TileId             tile{};
    Memory::MemoryTier tier   = Memory::MemoryTier::UNRESIDENT;
    uint64_t           address = 0;
    uint64_t           bytes   = 0;
    bool               ready   = false;
};

// ============================================================================
// Execution tile — transient materialization
// ============================================================================
struct ExecutionTile {
    TileId      tile{};
    uint64_t    address     = 0;   // host VA (transient)
    uint64_t    bytes       = 0;
    ExecutionFormat format  = ExecutionFormat::BF16;
    uint64_t    elementCount = 0;
    void*       allocation  = nullptr;  // owned pointer, released via ::operator delete
};

// ============================================================================
// Runtime capacity configuration
// ============================================================================
struct RuntimeCapacity {
    uint64_t vramBytes = 0;
    uint64_t ramBytes  = 0;
};
// ============================================================================
struct RuntimeStats {
    uint64_t tilesMaterialized   = 0;
    uint64_t tilesReused         = 0;
    uint64_t tilesEvicted        = 0;
    uint64_t bytesStreamed       = 0;
    uint64_t bytesDecompressed   = 0;
    double   avgTileLatencyMs    = 0.0;
    double   cacheHitRate        = 0.0;
    double   gpuUtilization      = 0.0;
    uint32_t activeSequences     = 0;
    uint32_t residentTileCount   = 0;
    uint64_t residentBytes       = 0;
};

// ============================================================================
// Runtime constraints for adaptive precision selection
// ============================================================================
struct RuntimeConstraints {
    uint64_t availableVramBytes   = 0;
    uint64_t availableRamBytes    = 0;
    uint32_t concurrentSequences  = 1;
    uint32_t currentLayer         = 0;
    bool     isAttention          = false;
    bool     isFFN                = false;
    float    memoryPressure       = 0.0f;
};

// ============================================================================
// Tensor descriptor (discovered from GGUF metadata)
// ============================================================================
struct TensorDescriptor {
    uint64_t    id                = 0;
    std::string name;
    GGMLType    ggmlType          = GGMLType::Unknown;
    StorageFormat storageFormat   = StorageFormat::Unknown;
    uint32_t    layer             = 0;
    bool        isWeight          = true;
    uint32_t    dimensions        = 0;
    std::vector<uint64_t> shape;
    uint64_t    elementCount      = 0;
    uint64_t    uncompressedBytes = 0;
    uint64_t    storedBytes       = 0;
    uint64_t    fileOffset        = 0;   // absolute byte offset in GGUF file
    uint32_t    blockBytes        = 0;
    uint32_t    blockElements     = 0;
};

// ============================================================================
// Inference backend interface
// ============================================================================
class IInferenceBackend {
public:
    virtual ~IInferenceBackend() = default;
    virtual bool loadModel(const std::string& path) = 0;
    virtual void unloadModel() = 0;
    virtual bool ready() const = 0;
    virtual std::string generate(const GenerateRequest& request,
                                 StreamTokenFn stream) = 0;
};

// ============================================================================
// SharedModelRuntime — orchestrates shared model residency across streams
// ============================================================================
class SharedModelRuntime {
public:
    explicit SharedModelRuntime(std::shared_ptr<IInferenceBackend> backend = nullptr);
    ~SharedModelRuntime();

    SharedModelRuntime(const SharedModelRuntime&) = delete;
    SharedModelRuntime& operator=(const SharedModelRuntime&) = delete;

    // Lifecycle
    bool initialize(const RuntimeCapacity& cap);
    void shutdown();

    // Backend
    void setBackend(std::shared_ptr<IInferenceBackend> backend);
    std::shared_ptr<IInferenceBackend> backend() const;

    // Model loading (metadata discovery only; weights stay memory-mapped)
    bool loadModel(const std::string& ggufPath);
    void unloadModel();
    bool isModelLoaded() const;
    std::string currentModelPath() const;

    // Tensor discovery
    bool getTensor(uint64_t tensorId, TensorDescriptor& out) const;
    bool findTensor(const std::string& name, TensorDescriptor& out) const;
    std::vector<TensorDescriptor> tensors() const;

    // Tile addressing
    bool resolveTile(const TileId& tile, TileAddress& out) const;

    // Sequence management
    uint64_t beginSequence();
    void endSequence(uint64_t seqId);

    // Tile materialization — the hot path
    bool materializeTile(const TileId& tile, const RuntimeConstraints& constraints, ExecutionTile& out);
    void releaseTile(ExecutionTile& tile);

    // Prefetch hint (non-blocking)
    bool prefetch(const TileId& tile, const RuntimeConstraints& constraints);

    // Adaptive precision selection
    PrecisionPlan choosePrecision(const TensorDescriptor& tensor, const RuntimeConstraints& constraints) const;

    // Inference entry point
    std::string generate(const GenerateRequest& req, StreamTokenFn onToken);

    // Telemetry
    RuntimeStats stats() const;

    // Memory stack accessors
    Memory::ResidencyTracker&       tracker()    { return *m_tracker; }
    Memory::TensorPlacementManager& placement()  { return *m_placement; }
    Memory::CapacityManager&        capacity()   { return *m_capacity; }

    // Static dequantization entry points (public for test harness access)
    static bool decodeF32 (const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);
    static bool decodeF16 (const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);
    static bool decodeBF16(const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);
    static bool decodeQ4_0(const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);
    static bool decodeQ8_0(const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);
    static bool decodeQ4_K_M(const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);
    static bool decodeQ3_K(const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);
    static bool decodeQ5_K(const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);
    static bool decodeQ6_K(const uint8_t* src, size_t srcBytes, float* dst, uint64_t count);

private:
    // GGUF parsing
    bool parseGGUF();
    bool parseMetadata(uint64_t& cursor);
    bool parseTensorDirectory();

    // Tile access
    bool ensureTileResident(const TileAddress& tile, const RuntimeConstraints& constraints, ResidencyHandle& out);
    bool readTile(const TileAddress& tile, std::vector<uint8_t>& data);
    bool materializeExecutionTile(const TileAddress& tile, const PrecisionPlan& plan, const std::vector<uint8_t>& source, ExecutionTile& out);

    // Dequantization
    bool decodeTile(const TensorDescriptor& tensor, const PrecisionPlan& plan, const uint8_t* source, size_t sourceBytes,
                    void* destination, size_t destinationBytes, uint64_t elementOffset, uint64_t elementCount);

    // Helpers
    static StorageFormat storageFormatFromGGML(GGMLType type);
    static uint32_t blockBytesFor(GGMLType type);
    static uint32_t blockElementsFor(GGMLType type);
    static uint64_t elementSizeFor(GGMLType type);
    static uint64_t tensorStoredBytes(GGMLType type, uint64_t elementCount);
    static uint16_t readU16(const uint8_t* p);
    static uint32_t readU32(const uint8_t* p);
    static uint64_t readU64(const uint8_t* p);
    static float halfToFloat(uint16_t h);
    static float bfloatToFloat(uint16_t h);
    void updateStats(bool reused, uint64_t bytes);

    // Subsystems
    std::unique_ptr<Memory::ResidencyTracker>      m_tracker;
    std::unique_ptr<Memory::CapacityManager>         m_capacity;
    std::unique_ptr<Memory::WorkingSetPredictor>     m_predictor;
    std::unique_ptr<Memory::TransferScheduler>       m_scheduler;
    std::unique_ptr<Memory::TensorPlacementManager>  m_placement;

    std::shared_ptr<IInferenceBackend> m_backend;

    // BP1 triple-braid streaming
    std::unique_ptr<BP1BraidIndex>    m_braidIndex;
    std::unique_ptr<BP1BraidStreamer> m_braidStreamer;
    bool                                 m_useBP1Streaming = false;

    // Capacity
    RuntimeCapacity m_capacityInfo{};

    // Model state (protected by m_modelMu)
    mutable std::shared_mutex m_modelMu;
    std::string m_modelPath;

    // Windows memory-mapped file (no persistent RAM copy of weights)
#ifdef _WIN32
    void*    m_fileMapping = nullptr;
    void*    m_fileView    = nullptr;
#endif
    uint64_t m_fileSize    = 0;
    const uint8_t* m_fileBase = nullptr;

    // Parsed GGUF state
    uint64_t m_tensorCount     = 0;
    uint64_t m_metadataKVCount = 0;
    uint64_t m_ggufAlignment   = 32;
    uint64_t m_dataOffset      = 0;
    uint32_t m_ggufVersion     = 0;
    bool m_modelLoaded = false;

    // Tensor directory (protected by m_modelMu)
    std::unordered_map<uint64_t, TensorDescriptor> m_tensors;

    // Sequence tracking
    mutable std::mutex m_seqMu;
    std::unordered_map<uint64_t, bool> m_sequences;
    std::atomic<uint64_t> m_nextSeqId{1};

    // Tile reference counting (protected by m_refMu)
    mutable std::mutex m_refMu;
    std::unordered_map<TileId, uint32_t, TileIdHash> m_tileRefs;

    // Statistics
    mutable std::mutex m_statMu;
    RuntimeStats m_stats{};

    bool m_initialized = false;
};

} // namespace Shared
} // namespace Serve
} // namespace RawrXD
