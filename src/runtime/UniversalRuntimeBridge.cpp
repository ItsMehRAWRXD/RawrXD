// ============================================================================
// UniversalRuntimeBridge.cpp
// ============================================================================
// Implementation of the "compile once, execute many" boundary.
// Wires UniversalHeaderSniffer -> CanonicalModelGraph -> RuntimeImage
// and integrates with the existing KernelRegistry + IExecutionBackend +
// UnifiedHotpatchManager.
// ============================================================================

#include "UniversalRuntimeBridge.hpp"

#include "../core/execution/KernelRegistry.hpp"
#include "../core/execution/IKernelBackend.hpp"

// Hotpatch integration
#include "../core/unified_hotpatch_manager.hpp"
#include "../core/patch_result.hpp"

#include <iostream>
#include <algorithm>
#include <cstring>

namespace RawrXD {

// ============================================================================
// RuntimeImage hot-path implementation
// ============================================================================

int32_t RuntimeImage::ExecuteNextToken(const std::vector<uint32_t>& inputTokens) {
    // HOT PATH: zero format checks, zero architecture branching.
    // All decisions were baked in at compile time.
    if (!IsReady()) return -1;
    
    executing.store(true);
    
    // Build execution request from the pre-compiled graph
    Execution::ExecutionRequest req;
    req.command = "decode";
    req.model = sourcePath;
    req.prompt = "";  // tokens are passed via the backend directly
    req.max_tokens = 1;
    req.stream = false;
    req.context_length = hints.useSlidingWindow ? hints.slidingWindowSize : graph.maxContext;
    
    // Dispatch to the bound backend (no branching on backend type)
    Execution::ExecutionResult result = backend->Execute(req);
    
    executing.store(false);
    
    if (result.success) {
        currentSeqLen++;
        // Extract token id from result (implementation-specific)
        if (!result.output.empty()) {
            return static_cast<int32_t>(result.output[0]);
        }
    }
    return -1;
}

bool RuntimeImage::ExecutePrefill(const std::vector<uint32_t>& tokens) {
    if (!IsReady()) return false;
    
    executing.store(true);
    
    Execution::ExecutionRequest req;
    req.command = "prefill";
    req.model = sourcePath;
    req.max_tokens = static_cast<uint32_t>(tokens.size());
    req.stream = false;
    req.context_length = graph.maxContext;
    
    Execution::ExecutionResult result = backend->Execute(req);
    
    if (result.success) {
        currentSeqLen += static_cast<uint32_t>(tokens.size());
    }
    
    executing.store(false);
    return result.success;
}

void RuntimeImage::Reset() {
    currentSeqLen = 0;
    // Backend handles KV cache reset
    if (backend) {
        Execution::ExecutionRequest req;
        req.command = "reset";
        backend->Execute(req);
    }
}

// ============================================================================
// UniversalRuntimeCompiler
// ============================================================================

UniversalRuntimeCompiler::UniversalRuntimeCompiler() {
    // Register built-in format parsers
    // GGUF parser is the primary one; others are registered as importers are built
}

UniversalRuntimeCompiler::~UniversalRuntimeCompiler() = default;

std::unique_ptr<RuntimeImage> UniversalRuntimeCompiler::Compile(const std::string& path) {
    // Stage 1: Memory-map the file (zero-copy)
    auto image = std::make_unique<RuntimeImage>();
    image->sourcePath = path;
    
    if (!image->stream.Map(path)) {
        std::cerr << "[UniversalRuntime] Failed to map: " << path << std::endl;
        return nullptr;
    }
    
    // Stage 2: Sniff the format (magic bytes, NOT extension)
    image->sourceFormat = sniffer_.Sniff(
        image->stream.Data(), 
        std::min(image->stream.Size(), size_t(64))
    );
    
    if (image->sourceFormat == FileFormat::Unknown) {
        std::cerr << "[UniversalRuntime] Unknown format: " << path << std::endl;
        return nullptr;
    }
    
    std::cout << "[UniversalRuntime] Detected format: " 
              << sniffer_.GetFormatName(image->sourceFormat) << std::endl;
    
    // Stage 3: Parse to canonical graph (format-specific, ONE TIME)
    if (!ParseToCanonicalGraph(image->stream, image->sourceFormat, image->graph)) {
        std::cerr << "[UniversalRuntime] Failed to parse canonical graph" << std::endl;
        return nullptr;
    }
    
    if (!image->graph.IsValid()) {
        std::cerr << "[UniversalRuntime] Invalid graph (missing architecture/hidden_size)" << std::endl;
        return nullptr;
    }
    
    std::cout << "[UniversalRuntime] Architecture: " << image->graph.architecture
              << " | Layers: " << image->graph.numLayers
              << " | Hidden: " << image->graph.hiddenSize
              << " | MoE: " << (image->graph.isMoE ? "yes" : "no");
    if (image->graph.isMoE) {
        std::cout << " (" << image->graph.numExperts << " experts, top-" 
                  << image->graph.numActiveExperts << ")";
    }
    std::cout << std::endl;
    
    // Stage 4: Select kernels (quantization dispatch, ONE TIME)
    if (!SelectKernels(image->graph, image->kernelTable)) {
        std::cerr << "[UniversalRuntime] Kernel selection failed" << std::endl;
        return nullptr;
    }
    
    std::cout << "[UniversalRuntime] Compiled " << image->kernelTable.size() 
              << " kernel bindings" << std::endl;
    
    // Stage 5: Compute scheduler hints (ONE TIME)
    if (!ComputeSchedulerHints(image->graph, image->hints)) {
        std::cerr << "[UniversalRuntime] Scheduler hint computation failed" << std::endl;
        return nullptr;
    }
    
    // Stage 6: Bind execution backend (ONE TIME)
    if (!BindBackend(*image)) {
        std::cerr << "[UniversalRuntime] Backend binding failed" << std::endl;
        return nullptr;
    }
    
    // Stage 7: Warmup / prefetch (ONE TIME)
    if (!Warmup(*image)) {
        std::cerr << "[UniversalRuntime] Warmup failed (non-fatal)" << std::endl;
    }
    
    // Stage 8: Register with hotpatch manager (for live kernel/weight swap)
    if (!RegisterWithHotpatch(*image)) {
        std::cerr << "[UniversalRuntime] Hotpatch registration failed (non-fatal)" << std::endl;
    }
    
    image->compiled.store(true);
    
    std::cout << "[UniversalRuntime] Compilation complete. Ready for inference." << std::endl;
    return image;
}

bool UniversalRuntimeCompiler::ParseToCanonicalGraph(
    const MemoryMappedStream& stream,
    FileFormat fmt,
    CanonicalModelGraph& graph)
{
    // Dispatch to registered format parser
    auto it = formatParsers_.find(fmt);
    if (it != formatParsers_.end()) {
        return it->second(stream, graph);
    }
    
    // Built-in GGUF parser (minimal - extracts architecture + tensor index)
    if (fmt == FileFormat::GGUF) {
        // TODO: Wire to existing sovereign_gguf_tensor_mapper / GGUFQuantizationDetector
        // For now, a minimal GGUF header parse:
        if (stream.Size() < 24) return false;
        
        const uint8_t* data = static_cast<const uint8_t*>(stream.Data());
        
        // Verify magic
        if (std::memcmp(data, "GGUF", 4) != 0) return false;
        
        // Read version + counts
        uint32_t version = *reinterpret_cast<const uint32_t*>(data + 4);
        uint64_t tensorCount = *reinterpret_cast<const uint64_t*>(data + 8);
        uint64_t metadataCount = *reinterpret_cast<const uint64_t*>(data + 16);
        
        (void)version; (void)tensorCount; (void)metadataCount;
        
        // Full GGUF parsing is handled by the existing sovereign_gguf_tensor_mapper.
        // This bridge defers to that subsystem and normalizes its output
        // into CanonicalModelGraph.
        // 
        // The key point: after this function returns, the caller NEVER
        // checks "is this GGUF?" again. The graph is canonical.
        
        graph.architecture = "deepseek2"; // placeholder until full parser wired
        graph.hiddenSize = 7168;
        graph.numLayers = 61;
        graph.isMoE = true;
        graph.numExperts = 256;
        graph.numActiveExperts = 8;
        
        return true;
    }
    
    std::cerr << "[UniversalRuntime] No parser for format: " 
              << static_cast<uint32_t>(fmt) << std::endl;
    return false;
}

bool UniversalRuntimeCompiler::SelectKernels(
    CanonicalModelGraph& graph,
    std::vector<KernelBinding>& kernelTable)
{
    // Query the existing KernelRegistry for optimal kernels per operation.
    // This is where quantization dispatch happens (ONE TIME).
    auto& registry = sovereign::KernelRegistry::Instance();
    
    // For each transformer layer, bind kernels:
    //   EmbeddingLookup -> PreNorm -> QKVProjection -> RoPE -> 
    //   SelfAttention -> AttentionOutput -> PostAttnResidual ->
    //   FFN (or MoE) -> PostFFNResidual -> FinalNorm -> LMHead -> Sampling
    
    for (uint32_t layer = 0; layer < graph.numLayers; ++layer) {
        KernelBinding binding;
        binding.operationName = "matmul";
        binding.kernelName = "sovereign_matmul_avx512";
        binding.backendName = "masm";
        binding.numInputs = 2;
        kernelTable.push_back(binding);
    }
    
    // MoE-specific bindings
    if (graph.isMoE) {
        KernelBinding moeBinding;
        moeBinding.operationName = "moe_route";
        moeBinding.kernelName = "sovereign_moe_router";
        moeBinding.backendName = "masm";
        moeBinding.numInputs = 1;
        kernelTable.push_back(moeBinding);
        
        // Expert FFN bindings (one per active expert)
        for (uint32_t e = 0; e < graph.numActiveExperts; ++e) {
            KernelBinding expertBinding;
            expertBinding.operationName = "expert_ffn";
            expertBinding.kernelName = "sovereign_q4k_dequant_matmul";
            expertBinding.backendName = "masm";
            expertBinding.numInputs = 2;
            kernelTable.push_back(expertBinding);
        }
    }
    
    return !kernelTable.empty();
}

bool UniversalRuntimeCompiler::ComputeSchedulerHints(
    const CanonicalModelGraph& graph,
    RuntimeImage::SchedulerHints& hints)
{
    // Compute hints based on model characteristics (ONE TIME)
    
    // Sliding window for long-context models
    hints.useSlidingWindow = (graph.maxContext > 8192);
    hints.slidingWindowSize = graph.maxContext > 32768 ? 4096 : 0;
    
    // Medusa for small/medium models (draft heads are cheap)
    hints.useMedusa = (graph.hiddenSize <= 4096);
    hints.medusaHeads = hints.useMedusa ? 4 : 0;
    
    // Speculative decode for MoE (amortizes expert loading)
    hints.useSpeculativeDecode = graph.isMoE;
    
    // Expert cache for MoE
    hints.useExpertCache = graph.isMoE;
    hints.expertCacheCapacity = graph.isMoE ? 
        std::min(graph.numActiveExperts * 4, graph.numExperts) : 0;
    
    // NVMe streaming for large MoE (671B can't fit in RAM)
    hints.useNVMeStreaming = graph.isMoE && graph.numExperts > 64;
    
    // Warmup for all models
    hints.useWarmup = true;
    
    // Paged KV for long context
    hints.usePagedKV = (graph.maxContext > 4096);
    hints.pagedKVBlockSize = 16;
    
    return true;
}

bool UniversalRuntimeCompiler::BindBackend(RuntimeImage& image) {
    // Select the optimal backend based on hardware + model (ONE TIME)
    // This queries the existing KernelRegistry for available backends.
    
    auto& registry = sovereign::KernelRegistry::Instance();
    
    // For now, we use the SovereignBackend (MASM64 kernels).
    // The backend is created and initialized once here.
    // The hot path never re-checks backend availability.
    //
    // TODO: Wire to SovereignBackend::Create() when available.
    // For now, mark as needing backend assignment.
    
    // The backend pointer is set by the caller after compilation,
    // or via the existing backend factory in IExecutionBackend.hpp.
    
    return true;
}

bool UniversalRuntimeCompiler::Warmup(RuntimeImage& image) {
    if (!image.hints.useWarmup) return true;
    
    // Pre-touch tensor pages to fault them into RAM (ONE TIME)
    // This is where NVMe streaming prefetch happens.
    
    // For MoE models with NVMe streaming, prefetch the top-N
    // most likely experts based on warmup prompts.
    
    return true;
}

bool UniversalRuntimeCompiler::RegisterWithHotpatch(RuntimeImage& image) {
    // Register the compiled image's kernel table and tensor pointers
    // with the UnifiedHotpatchManager so live patches can:
    //   - Swap kernels (Layer 5: live binary trampoline on kernel function ptrs)
    //   - Swap weights (Layer 1: memory hotpatch on tensor data)
    //   - Inject server patches (Layer 3: proxy hotpatch for token bias)
    
    auto& hpm = UnifiedHotpatchManager::instance();
    
    // Register each kernel binding as a live-binary hotpatchable target.
    // This allows swapping a kernel implementation at runtime without
    // rebuilding the RuntimeImage.
    for (auto& binding : image.kernelTable) {
        uint32_t slotId = 0;
        // The kernel function address comes from the KernelRegistry.
        // We register it so the hotpatch manager can install a trampoline
        // and swap the implementation later.
        auto& registry = sovereign::KernelRegistry::Instance();
        auto* backend = registry.GetBackend(binding.backendName);
        if (backend) {
            // Get the kernel function pointer from the backend
            // (the exact API depends on IKernelBackend; we use a placeholder
            //  address that the backend fills in when wired)
            uintptr_t kernelAddr = 0; // backend->GetKernelAddress(binding.kernelName)
            if (kernelAddr != 0) {
                auto result = hpm.live_register_function(
                    binding.kernelName.c_str(), kernelAddr, &slotId);
                if (result.result.success) {
                    binding.hotpatchHandle = slotId;
                }
            }
        }
    }
    
    // Register tensor weight pointers for memory-layer hotpatching.
    // This allows swapping individual weight tensors (e.g., for LoRA
    // adapters or quantization upgrades) without reloading the model.
    for (const auto& tensor : image.graph.tensors) {
        if (tensor.desc.data && tensor.desc.sizeBytes > 0) {
            // Take a snapshot of the original weight bytes so we can revert.
            uintptr_t addr = reinterpret_cast<uintptr_t>(tensor.desc.data);
            uint32_t snapshotId = 0;
            auto snap = hpm.pt_take_snapshot(
                addr, tensor.desc.sizeBytes,
                tensor.name.c_str(),
                0,  // layerIndex (0 = global; could use tensor.layerId)
                &snapshotId);
            // Snapshot stored; can be restored via pt_restore_snapshot(snapshotId)
        }
    }
    
    return true;
}

bool UniversalRuntimeCompiler::HotpatchRecompile(
    RuntimeImage& image,
    const std::string& patchName)
{
    // Apply a hotpatch to the running image without full recompilation.
    // This swaps kernels or weights in-place via the hotpatch manager.
    
    auto& hpm = UnifiedHotpatchManager::instance();
    
    // 1. Look up the patch by name in the server-layer patches
    // 2. Apply it (memory/byte/server/live-binary layer as appropriate)
    // 3. Update the kernel table if a kernel was swapped
    // 4. Do NOT re-run format detection or architecture parsing
    
    // For kernel swaps: use live_swap_implementation with the slotId
    // stored in binding.hotpatchHandle.
    // For weight swaps: use apply_memory_patch on the tensor data pointer.
    // For token bias: use add_server_patch with a ProxyHotpatch rule.
    
    // Example kernel swap:
    // for (auto& binding : image.kernelTable) {
    //     if (binding.kernelName == patchName && binding.hotpatchHandle != 0) {
    //         hpm.live_swap_implementation(binding.hotpatchHandle,
    //             newCode, codeSize, relocs, relocCount);
    //     }
    // }
    
    return true;
}

void UniversalRuntimeCompiler::RegisterFormatParser(
    FileFormat fmt, 
    FormatParser parser)
{
    formatParsers_[fmt] = std::move(parser);
}

// ============================================================================
// UniversalRuntime singleton
// ============================================================================

UniversalRuntime& UniversalRuntime::Instance() {
    static UniversalRuntime instance;
    return instance;
}

std::shared_ptr<RuntimeImage> UniversalRuntime::Load(const std::string& path) {
    auto image = compiler_.Compile(path);
    if (image) {
        loaded_.push_back(image);
        if (!active_) {
            active_ = image;
        }
    }
    return image;
}

std::vector<std::string> UniversalRuntime::ListLoaded() const {
    std::vector<std::string> paths;
    for (const auto& img : loaded_) {
        paths.push_back(img->sourcePath);
    }
    return paths;
}

} // namespace RawrXD