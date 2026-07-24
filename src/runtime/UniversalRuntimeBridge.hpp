// ============================================================================
// UniversalRuntimeBridge.hpp
// ============================================================================
// Bridges the UniversalHeaderSniffer into the existing RawrXD execution
// pipeline (SovereignGraphRunner + KernelRegistry + IExecutionBackend +
// UnifiedHotpatchManager).
//
// This is the "compile once" boundary:
//   ANY BYTESTREAM -> Sniff -> Parse -> CanonicalModelGraph -> RuntimeImage
//
// After RuntimeImage is built, the hot inference path calls:
//   RuntimeImage::ExecuteNextToken()
// with ZERO format/architecture/quant checks.
//
// Hotpatch integration: the RuntimeImage registers its kernel table and
// tensor pointers with UnifiedHotpatchManager so live patches can swap
// weights/kernels without rebuilding the image.
// ============================================================================

#pragma once

#include "UniversalHeaderSniffer.hpp"
#include "../core/execution/SovereignKernelTypes.hpp"
#include "../core/execution/ExecutionRequest.hpp"
#include "../core/execution/ExecutionResult.hpp"
#include "../core/execution/IExecutionBackend.hpp"

#include <memory>
#include <string>
#include <vector>
#include <unordered_map>
#include <functional>
#include <atomic>

namespace RawrXD {

// ============================================================================
// Canonical Tensor Descriptor (extends sovereign::TensorDesc with source info)
// ============================================================================
struct CanonicalTensor {
    std::string         name;           // e.g. "blk.0.attn_q.weight"
    sovereign::TensorDesc desc;          // Layout + dtype + pointer
    uint64_t            fileOffset{0};   // Offset in original stream
    FileFormat          sourceFormat{FileFormat::Unknown}; // Origin (debug only)
    bool                isExpert{false};
    uint32_t            expertId{0};
    uint32_t            layerId{0};
    
    // Residency tracking (mirrors tensor_residency_pipeline)
    enum class Residency : uint8_t {
        Disk, Mapped, Uploading, GPUResident, Prefetched, Evicting
    } residency{Residency::Disk};
    
    bool IsValid() const { return desc.IsValid() && !name.empty(); }
};

// ============================================================================
// Canonical Model Graph - format-agnostic IR
// ============================================================================
struct CanonicalModelGraph {
    // Architecture metadata (from GGUF/safetensors/ONNX metadata)
    std::string         architecture;       // "deepseek2", "llama", "mixtral"
    uint32_t            hiddenSize{0};
    uint32_t            numLayers{0};
    uint32_t            numHeads{0};
    uint32_t            numKVHeads{0};
    uint32_t            headDim{0};
    uint32_t            vocabSize{0};
    uint32_t            intermediateSize{0};
    uint32_t            maxContext{0};
    float               ropeTheta{10000.0f};
    float               rmsNormEps{1e-5f};
    
    // MoE metadata
    bool                isMoE{false};
    uint32_t            numExperts{0};
    uint32_t            numActiveExperts{0};    // top-k
    uint32_t            numSharedExperts{0};
    uint32_t            moeIntermediateSize{0};
    
    // Tensor catalog
    std::vector<CanonicalTensor> tensors;
    
    // Tensor name -> index lookup
    std::unordered_map<std::string, uint32_t> tensorIndex;
    
    // Expert tensor grouping (for MoE)
    // expertTensors[expertId][tensorRole] -> tensor index
    // tensorRole: 0=gate, 1=up, 2=down
    std::vector<std::array<uint32_t, 3>> expertTensors;
    
    // Tokenizer info
    std::string         tokenizerType;     // "bpe", "spm", "sentencepiece"
    uint32_t            bosTokenId{1};
    uint32_t            eosTokenId{2};
    
    // Validation
    bool IsValid() const {
        return !architecture.empty() && hiddenSize > 0 && numLayers > 0;
    }
    
    // Find tensor by name
    const CanonicalTensor* FindTensor(const std::string& name) const {
        auto it = tensorIndex.find(name);
        if (it == tensorIndex.end()) return nullptr;
        return &tensors[it->second];
    }
};

// ============================================================================
// Kernel Binding - maps graph operation to a registered kernel
// ============================================================================
struct KernelBinding {
    std::string     operationName;     // "matmul", "attention", "rmsnorm"
    std::string     kernelName;        // registered kernel name
    std::string     backendName;       // "masm", "vulkan", "reference"
    uint32_t        inputTensorIdx[4]; // indices into CanonicalModelGraph::tensors
    uint32_t        outputTensorIdx{0};
    uint32_t        numInputs{0};
    
    // Hotpatch handle (for live kernel swap)
    uint64_t        hotpatchHandle{0};
};

// ============================================================================
// Runtime Image - the compiled, immutable hot-path artifact
// ============================================================================
// After this is built, ExecuteNextToken() does ZERO format checks.
// All expensive decisions (format, architecture, quant, kernel selection)
// are baked in here.
struct RuntimeImage {
    // Source (kept for hotpatch/reload)
    std::string             sourcePath;
    FileFormat              sourceFormat{FileFormat::Unknown};
    
    // Canonical graph (tensor catalog + metadata)
    CanonicalModelGraph     graph;
    
    // Compiled kernel bindings (one per graph node)
    std::vector<KernelBinding> kernelTable;
    
    // Execution backend (MASM/Vulkan/CPU)
    Execution::IExecutionBackend* backend{nullptr};
    
    // Memory-mapped source stream (zero-copy weight access)
    MemoryMappedStream       stream;
    
    // KV cache state (opaque, managed by backend)
    void*                    kvCache{nullptr};
    uint32_t                 currentSeqLen{0};
    
    // Scheduler hints (baked at compile time)
    struct SchedulerHints {
        bool     useSlidingWindow{false};
        uint32_t slidingWindowSize{0};
        bool     useMedusa{false};
        uint32_t medusaHeads{0};
        bool     useSpeculativeDecode{false};
        bool     useExpertCache{false};
        uint32_t expertCacheCapacity{0};
        bool     useNVMeStreaming{false};
        bool     useWarmup{false};
        bool     usePagedKV{false};
        uint32_t pagedKVBlockSize{0};
    } hints;
    
    // Status
    std::atomic<bool>       compiled{false};
    std::atomic<bool>       executing{false};
    
    // ---- Hot-path API (no format checks, no branching on architecture) ----
    
    // Execute one token. Returns the token id (or -1 on error).
    int32_t ExecuteNextToken(const std::vector<uint32_t>& inputTokens);
    
    // Execute a batch (for prefill)
    bool ExecutePrefill(const std::vector<uint32_t>& tokens);
    
    // Reset context (clears KV cache)
    void Reset();
    
    // Is this image ready for inference?
    bool IsReady() const { return compiled.load() && backend != nullptr; }
};

// ============================================================================
// Universal Runtime Compiler - the "compile once" boundary
// ============================================================================
// Takes a sniffed stream + detected format and produces a RuntimeImage.
// This is where ALL expensive decisions happen:
//   - Format parsing (GGUF/Safetensors/ONNX -> CanonicalModelGraph)
//   - Architecture detection (deepseek2/llama/mixtral)
//   - Quantization dispatch (Q4_K/Q8_0/FP16 -> kernel selection)
//   - Kernel specialization (AVX-512/Vulkan/CPU)
//   - Scheduler hint computation
//   - Warmup/prefetch planning
class UniversalRuntimeCompiler {
public:
    UniversalRuntimeCompiler();
    ~UniversalRuntimeCompiler();
    
    // Compile a file into a RuntimeImage (the main entry point)
    // This is the ONLY place format/architecture/quant decisions are made.
    std::unique_ptr<RuntimeImage> Compile(const std::string& path);
    
    // Recompile with hotpatch (swap kernels/weights without full rebuild)
    bool HotpatchRecompile(RuntimeImage& image, 
                           const std::string& patchName);
    
    // Access the sniffer (for custom format registration)
    UniversalHeaderSniffer& GetSniffer() { return sniffer_; }
    
    // Register a custom format parser
    using FormatParser = std::function<bool(const MemoryMappedStream& stream,
                                              CanonicalModelGraph& graph)>;
    void RegisterFormatParser(FileFormat fmt, FormatParser parser);
    
private:
    UniversalHeaderSniffer sniffer_;
    std::unordered_map<FileFormat, FormatParser> formatParsers_;
    
    // Internal compilation stages
    bool ParseToCanonicalGraph(const MemoryMappedStream& stream,
                                FileFormat fmt,
                                CanonicalModelGraph& graph);
    
    bool SelectKernels(CanonicalModelGraph& graph,
                       std::vector<KernelBinding>& kernelTable);
    
    bool ComputeSchedulerHints(const CanonicalModelGraph& graph,
                               RuntimeImage::SchedulerHints& hints);
    
    bool BindBackend(RuntimeImage& image);
    
    bool Warmup(RuntimeImage& image);
    
    // Register the compiled image with the hotpatch manager
    bool RegisterWithHotpatch(RuntimeImage& image);
};

// ============================================================================
// Universal Runtime - top-level singleton
// ============================================================================
// The single entry point the frontend/API gateway talks to.
// Replaces the "if (gguf) ... if (deepseek) ..." pattern with:
//   UniversalRuntime::Instance().Load(path) -> RuntimeImage
class UniversalRuntime {
public:
    static UniversalRuntime& Instance();
    
    // Load + compile any file into a runtime image
    // Returns nullptr on failure
    std::shared_ptr<RuntimeImage> Load(const std::string& path);
    
    // Get the currently active image
    std::shared_ptr<RuntimeImage> GetActive() const { return active_; }
    
    // Set active image
    void SetActive(std::shared_ptr<RuntimeImage> img) { active_ = std::move(img); }
    
    // Unload active image
    void Unload() { active_.reset(); }
    
    // List loaded images (for multi-model)
    std::vector<std::string> ListLoaded() const;
    
    // Get the compiler (for format registration)
    UniversalRuntimeCompiler& GetCompiler() { return compiler_; }
    
private:
    UniversalRuntime() = default;
    ~UniversalRuntime() = default;
    
    UniversalRuntimeCompiler compiler_;
    std::shared_ptr<RuntimeImage> active_;
    std::vector<std::shared_ptr<RuntimeImage>> loaded_;
};

} // namespace RawrXD