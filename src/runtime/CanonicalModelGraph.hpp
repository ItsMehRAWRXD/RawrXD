// ============================================================================
// RawrXD Canonical Model Graph - Format-Agnostic Internal Representation
// ============================================================================
// Purpose: After import, ALL formats (GGUF, Safetensors, ONNX, PT, etc.)
//          become this single representation. The execution engine never
//          knows what format a tensor originally came from.
//
// Design Principle: "The format dies at the border."
// ============================================================================

#pragma once

#include <cstdint>
#include <cstring>
#include <memory>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <variant>
#include <functional>

namespace RawrXD {

// ============================================================================
// Quantization Types - Normalized Across All Formats
// ============================================================================

enum class QuantType : uint8_t {
    // Unquantized
    F32     = 0,
    F16     = 1,
    BF16    = 2,
    
    // Integer
    INT8    = 10,
    INT4    = 11,
    
    // GGUF-style block quants (normalized names)
    Q8_0    = 20,
    Q6_K    = 21,
    Q5_K    = 22,
    Q5_0    = 23,
    Q4_K    = 24,
    Q4_0    = 25,
    Q3_K    = 26,
    Q2_K    = 27,
    IQ2_XXS = 28,
    IQ2_XS  = 29,
    IQ3_XXS = 30,
    IQ4_NL  = 31,
    IQ4_XS  = 32,
    
    // RawrXD native packed formats
    NU_FUSED    = 40,    // NU Fused multi-nibble
    XVA_215     = 41,    // 215XVA resource packing
    RAW_PACKED  = 42,    // Custom runtime packing
    
    // Unknown / custom
    UNKNOWN = 255
};

// ============================================================================
// Tensor Data Type Metadata
// ============================================================================

struct QuantInfo {
    QuantType type = QuantType::UNKNOWN;
    uint32_t blockSize = 0;         // Elements per quantization block
    uint32_t bytesPerBlock = 0;     // Raw bytes per block
    uint32_t bitsPerWeight = 0;     // Effective bits per weight
    
    [[nodiscard]] bool IsQuantized() const { return type != QuantType::F32 && type != QuantType::F16 && type != QuantType::BF16; }
    [[nodiscard]] bool IsBlockQuant() const { return blockSize > 1; }
    [[nodiscard]] float CompressionRatio() const {
        if (bytesPerBlock == 0 || blockSize == 0) return 1.0f;
        return static_cast<float>(blockSize * 4) / static_cast<float>(bytesPerBlock); // vs F32
    }
};

// ============================================================================
// Tensor Descriptor - Normalized View of Any Tensor
// ============================================================================

struct TensorDescriptor {
    std::string name;                   // Canonical name (normalized)
    std::vector<uint64_t> dims;         // Shape dimensions
    QuantInfo quant;                     // Quantization metadata
    uint64_t fileOffset = 0;            // Offset in source file (for mmap)
    uint64_t byteSize = 0;              // Total bytes of raw data
    void* mappedPtr = nullptr;          // Memory-mapped pointer (zero-copy)
    
    // Original format metadata (for debugging only, not used in execution)
    std::string originalFormat;         // "gguf", "safetensors", "onnx", etc.
    std::string originalName;           // Name before normalization
    
    // Computed properties
    [[nodiscard]] uint64_t NumElements() const {
        uint64_t count = 1;
        for (auto d : dims) count *= d;
        return count;
    }
    
    [[nodiscard]] uint32_t NumDims() const { return static_cast<uint32_t>(dims.size()); }
    [[nodiscard]] bool Is2D() const { return dims.size() == 2; }
    [[nodiscard]] bool Is1D() const { return dims.size() == 1; }
    
    // Tensor role classification (set during graph build)
    enum class TensorRole : uint8_t {
        Unknown,
        TokenEmbedding,
        PositionEmbedding,
        LayerNorm,
        RMSNorm,
        AttentionQ,
        AttentionK,
        AttentionV,
        AttentionO,
        AttentionQKV,       // Fused QKV
        FFNGate,
        FFNUp,
        FFNDown,
        MoERouter,          // Expert routing gate
        MoEExpertGate,
        MoEExpertUp,
        MoEExpertDown,
        MoESharedExpert,
        OutputNorm,
        OutputProjection,
        Convolution,
        Bias,
        Scale,
        Other
    };
    TensorRole role = TensorRole::Unknown;
};

// ============================================================================
// Expert Layout - MoE Topology (Normalized)
// ============================================================================

struct ExpertDescriptor {
    uint32_t id = 0;
    uint32_t layerIndex = 0;
    
    // Expert FFN tensors (normalized pointers into tensor DB)
    std::string gateTensorName;    // gate_proj / w1
    std::string upTensorName;       // up_proj / w3
    std::string downTensorName;     // down_proj / w2
    
    // Residency tracking
    enum class Residency : uint8_t {
        Disk,       // Not loaded
        RAM,        // In system RAM (mmap'd)
        VRAM,       // In GPU memory
        Pinned      // Locked in RAM/VRAM (active inference)
    };
    Residency residency = Residency::Disk;
    uint64_t lastAccessTime = 0;   // For LRU
    uint32_t accessCount = 0;
    int32_t refCount = 0;           // RAII pin count (cache reference counting)
};

struct ExpertLayout {
    bool isMoE = false;
    uint32_t numExperts = 0;
    uint32_t numActiveExperts = 0;     // Top-K per token
    uint32_t numSharedExperts = 0;
    uint32_t firstMoELayer = 0;        // first_k_dense_replace
    uint32_t moEIntermediateSize = 0;
    
    std::vector<ExpertDescriptor> experts;   // All experts, indexed by layer*stride+id
    std::vector<ExpertDescriptor> sharedExperts;
    
    [[nodiscard]] bool HasSharedExperts() const { return numSharedExperts > 0; }
    [[nodiscard]] uint32_t ExpertStride() const { return numExperts; }
};

// ============================================================================
// Architecture Descriptor - Normalized Model Topology
// ============================================================================

enum class ArchitectureType : uint8_t {
    Unknown,
    Transformer,        // Standard decoder-only (Llama, Qwen, Mistral)
    MoETransformer,     // Mixture of Experts (DeepSeek, Mixtral, Qwen-MoE)
    RWKV,              // RWKV / RNN-Transformer hybrid
    Mamba,             // State Space Model
    SSM,               // Generic State Space
    CNN,               // Convolutional
    Diffusion,         // Diffusion model
    Vision,            // Vision encoder (ViT, CLIP)
    Speech,            // Audio model (Whisper, etc.)
    Multimodal,        // Multi-modal (text + image + audio)
    EncoderDecoder,    // T5-style encoder-decoder
    Custom             // User-defined architecture
};

struct AttentionConfig {
    uint32_t headCount = 0;
    uint32_t headDim = 0;
    uint32_t kvHeadCount = 0;          // GQA / MQA
    uint32_t maxContextLength = 0;
    float ropeTheta = 10000.0f;
    float ropeScalingFactor = 1.0f;
    std::string ropeScalingType;       // "linear", "dynamic", "yarn", etc.
    bool usesFlashAttention = false;
    bool usesSlidingWindow = false;
    uint32_t slidingWindowSize = 0;
};

struct ArchitectureDescriptor {
    ArchitectureType type = ArchitectureType::Unknown;
    std::string architectureName;      // "llama", "deepseek2", "qwen2", etc.
    
    // Core dimensions
    uint32_t hiddenSize = 0;
    uint32_t intermediateSize = 0;
    uint32_t numLayers = 0;
    uint32_t vocabSize = 0;
    
    // Attention
    AttentionConfig attention;
    
    // Normalization
    std::string normType = "rmsnorm";  // "layernorm", "rmsnorm"
    float normEpsilon = 1e-5f;
    
    // MoE (if applicable)
    ExpertLayout expertLayout;
    
    // Activation
    std::string activation = "silu";   // "silu", "gelu", "relu", "geglu"
    
    // Tokenizer info (not the tokenizer itself, just metadata)
    std::string tokenizerType;         // "bpe", "spm", "wordlevel"
    std::string tokenizerModel;         // Path or inline
    
    // KV cache policy
    enum class KVPolicy : uint8_t {
        Full,           // Keep all KV
        Paged,          // PagedAttention
        Sliding,        // Sliding window
        Hybrid          // Mixed
    };
    KVPolicy kvPolicy = KVPolicy::Full;
    
    // Validation
    [[nodiscard]] bool IsValid() const {
        return hiddenSize > 0 && numLayers > 0 && vocabSize > 0;
    }
    
    [[nodiscard]] bool IsMoE() const { 
        return type == ArchitectureType::MoETransformer || expertLayout.isMoE;
    }
};

// ============================================================================
// Compute Graph - Normalized Operation Graph
// ============================================================================

enum class OpType : uint8_t {
    // Tensor ops
    MatMul,
    MatMulQuant,        // Quantized matmul (dequant on-the-fly)
    Add,
    Multiply,
    RMSNorm,
    LayerNorm,
    Softmax,
    RotaryEmbedding,
    ScaledDotProductAttention,
    SiLU,
    GELU,
    GatedFFN,           // SiLU(gate(x)) * up(x) -> down
    MoERoute,           // Top-K expert selection
    MoEExpertFFN,       // Expert FFN computation
    MoECombine,         // Weighted expert output combination
    Concat,
    Reshape,
    Transpose,
    Embedding,
    Sampler,
    ArgMax,
    TopK,
    // Memory ops
    KVCacheRead,
    KVCacheWrite,
    // Custom
    Custom
};

struct GraphNode {
    uint32_t id = 0;
    OpType op = OpType::Custom;
    std::string opName;                // Human-readable name
    std::vector<uint32_t> inputs;      // Input node IDs
    std::vector<uint32_t> outputs;     // Output node IDs
    std::vector<std::string> tensorInputs;   // Tensor names used
    std::unordered_map<std::string, std::string> attributes;  // Op-specific params
    uint32_t layerIndex = 0;           // Which transformer layer
};

struct ComputeGraph {
    std::vector<GraphNode> nodes;
    std::vector<uint32_t> inputNodes;      // Entry points
    std::vector<uint32_t> outputNodes;     // Exit points (sampler, etc.)
    
    // Layer boundaries (node IDs where each layer starts/ends)
    std::vector<std::pair<uint32_t, uint32_t>> layerBoundaries;
    
    [[nodiscard]] size_t NumNodes() const { return nodes.size(); }
    [[nodiscard]] size_t NumLayers() const { return layerBoundaries.size(); }
};

// ============================================================================
// Tensor Database - Normalized Tensor Storage
// ============================================================================

class TensorDatabase {
public:
    TensorDatabase() = default;
    
    // Add a tensor
    void AddTensor(TensorDescriptor tensor) {
        tensors_[tensor.name] = std::move(tensor);
        nameIndex_.push_back(tensors_.size() - 1);
    }
    
    // Lookup
    [[nodiscard]] const TensorDescriptor* Find(std::string_view name) const {
        auto it = tensors_.find(std::string(name));
        if (it != tensors_.end()) return &it->second;
        return nullptr;
    }
    
    [[nodiscard]] TensorDescriptor* FindMut(std::string_view name) {
        auto it = tensors_.find(std::string(name));
        if (it != tensors_.end()) return &it->second;
        return nullptr;
    }
    
    // Iteration
    [[nodiscard]] std::vector<std::string> GetAllTensorNames() const {
        std::vector<std::string> names;
        names.reserve(tensors_.size());
        for (const auto& [name, _] : tensors_) {
            names.push_back(name);
        }
        return names;
    }
    
    [[nodiscard]] size_t NumTensors() const { return tensors_.size(); }
    [[nodiscard]] uint64_t TotalBytes() const {
        uint64_t total = 0;
        for (const auto& [_, t] : tensors_) total += t.byteSize;
        return total;
    }
    
    // Filter by role
    [[nodiscard]] std::vector<std::string> GetTensorsByRole(TensorDescriptor::TensorRole role) const {
        std::vector<std::string> result;
        for (const auto& [name, t] : tensors_) {
            if (t.role == role) result.push_back(name);
        }
        return result;
    }
    
    // Get all expert tensors for a layer
    [[nodiscard]] std::vector<std::string> GetExpertTensors(uint32_t layer) const {
        std::vector<std::string> result;
        std::string prefix = "blk." + std::to_string(layer) + ".experts.";
        for (const auto& [name, t] : tensors_) {
            if (name.find(prefix) == 0) result.push_back(name);
        }
        return result;
    }
    
private:
    std::unordered_map<std::string, TensorDescriptor> tensors_;
    std::vector<size_t> nameIndex_;
};

// ============================================================================
// Execution Hints - Scheduler Guidance
// ============================================================================

struct ExecutionHints {
    // Memory
    bool useMemoryMapping = true;
    bool useLargePages = false;
    uint64_t maxRAMResident = 0;        // 0 = unlimited
    uint64_t maxVRAMResident = 0;
    
    // Expert caching
    bool enableExpertCache = true;
    uint32_t expertCacheCapacity = 8;   // Max experts in RAM simultaneously
    bool enableExpertPinning = true;    // RAII pinning during inference
    
    // Optimization
    bool enableSlidingWindow = false;
    uint32_t slidingWindowSize = 0;
    bool enableSpeculativeDecode = false;
    uint32_t speculativeDraftSize = 0;
    bool enableMedusa = false;
    uint32_t medusaHeads = 0;
    bool enableTensorFusion = true;
    bool enableWarmupEngine = false;
    
    // NVMe streaming
    bool enableNVMeStreaming = false;
    uint32_t nvmeReadAhead = 0;         // Bytes to prefetch
    
    // KV cache
    bool enablePagedKV = false;
    uint32_t kvPageSize = 0;            // Tokens per page
    
    // Compute
    bool preferAVX512 = true;
    bool preferAMX = false;
    bool preferGPU = false;
    bool enableFlashAttention = true;
    
    // Batch
    uint32_t maxBatchSize = 1;
    bool enableBatchedMoE = false;
};

// ============================================================================
// Canonical Model Graph - The Single Source of Truth
// ============================================================================

struct CanonicalModelGraph {
    // Identity
    std::string modelName;
    std::string sourceFormat;           // "gguf", "safetensors", etc. (debug only)
    std::string sourcePath;
    
    // Architecture
    ArchitectureDescriptor architecture;
    
    // Tensors
    TensorDatabase tensors;
    
    // Compute graph
    ComputeGraph graph;
    
    // Execution hints
    ExecutionHints hints;
    
    // Metadata (arbitrary key-value from source)
    std::unordered_map<std::string, std::string> metadata;
    
    // Validation
    [[nodiscard]] bool IsValid() const {
        if (!architecture.IsValid()) return false;
        if (tensors.NumTensors() == 0) return false;
        return true;
    }
    
    [[nodiscard]] bool IsMoE() const { return architecture.IsMoE(); }
    [[nodiscard]] size_t NumTensors() const { return tensors.NumTensors(); }
    [[nodiscard]] uint64_t TotalTensorBytes() const { return tensors.TotalBytes(); }
};

// ============================================================================
// Format Parser Interface - Converts Any Format → CanonicalModelGraph
// ============================================================================

class IFormatParser {
public:
    virtual ~IFormatParser() = default;
    
    // Parse a memory-mapped stream into canonical graph
    [[nodiscard]] virtual bool Parse(const void* data, size_t size, 
                                     CanonicalModelGraph& outGraph) = 0;
    
    // Get parser metadata
    [[nodiscard]] virtual std::string_view GetName() const = 0;
    [[nodiscard]] virtual std::string_view GetVersion() const = 0;
};

// ============================================================================
// Format Parser Registry
// ============================================================================

class FormatParserRegistry {
public:
    static FormatParserRegistry& Instance();
    
    void Register(std::unique_ptr<IFormatParser> parser);
    void Clear();
    
    // Find parser by format name
    [[nodiscard]] IFormatParser* FindParser(std::string_view formatName) const;
    
    // Auto-detect and parse
    [[nodiscard]] bool AutoParse(const void* data, size_t size,
                                  CanonicalModelGraph& outGraph,
                                  std::string& detectedFormat);
    
    [[nodiscard]] std::vector<std::string_view> ListParsers() const;
    
private:
    FormatParserRegistry() = default;
    std::vector<std::unique_ptr<IFormatParser>> parsers_;
};

// ============================================================================
// Universal Format Parser - High-Level Entry Point
// ============================================================================

class UniversalFormatParser {
public:
    UniversalFormatParser() = default;
    
    // Parse any byte stream into canonical graph
    // The format is auto-detected from magic bytes, not extension
    [[nodiscard]] bool Parse(const void* data, size_t size,
                              CanonicalModelGraph& outGraph);
    
    [[nodiscard]] bool ParseFile(const std::string& path,
                                  CanonicalModelGraph& outGraph);
    
    // Get last detected format
    [[nodiscard]] std::string_view GetLastDetectedFormat() const { return lastFormat_; }
    
private:
    std::string lastFormat_;
};

} // namespace RawrXD
