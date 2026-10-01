#pragma once
// RAWRXD_DEEP2_MODEL_REGISTRY_001
//
// Deep2 model admission + architecture dispatch.
// One registry lookup per model admission. Architecture owns its
// layer topology, loader, context creation, forward, generation reset,
// and destruction. Deep2Engine binds exactly one Architecture during
// loadModel() and delegates thereafter.
//
// Collision-safe alias resolution: FNV-1a hash + string equality.
// No quantization in architecture identity.

#include "Deep2Engine.h"
#include <string>
#include <string_view>
#include <vector>
#include <cstddef>
#include <cstdint>

namespace Deep2 {

// -----------------------------------------------------------------------------
// Compile-time FNV-1a 64-bit hash (constexpr)
// -----------------------------------------------------------------------------
constexpr uint64_t hash_const(const char* s,
                              uint64_t h = 1469598103934665603ull) noexcept {
    return *s
        ? hash_const(s + 1, (h ^ static_cast<uint8_t>(*s)) *
                            1099511628211ull)
        : h;
}

inline uint64_t hash_runtime(const char* s) noexcept {
    uint64_t h = 1469598103934665603ull;
    while (*s) {
        h ^= static_cast<uint8_t>(*s++);
        h *= 1099511628211ull;
    }
    return h;
}

// -----------------------------------------------------------------------------
// Forward declarations
// -----------------------------------------------------------------------------
struct ModelMetadata;
struct LoadResult;
struct ForwardRequest;
struct ArchitectureForwardResult;

class Deep2Engine;

// -----------------------------------------------------------------------------
// Architecture function signatures
// -----------------------------------------------------------------------------
using ProbeFn =
    bool (*)(const ModelMetadata&) noexcept;

using LoadFn =
    LoadResult (*)(Deep2Engine&, const ModelMetadata&);

using CreateContextFn =
    bool (*)(Deep2Engine&, const ModelMetadata&);

using ForwardFn =
    ArchitectureForwardResult (*)(Deep2Engine&, const ForwardRequest&);

using ResetGenerationFn =
    void (*)(Deep2Engine&) noexcept;

using DestroyFn =
    void (*)(Deep2Engine&) noexcept;

// -----------------------------------------------------------------------------
// Architecture descriptor — stable ABI
// -----------------------------------------------------------------------------
struct Architecture {
    std::string_view id;                // "qwen2", "llama", "nemotron_h", "gemma3", "phi3", ...

    ProbeFn          probe = nullptr;          // Can this architecture handle this model?
    LoadFn           load = nullptr;           // Full weight bind + geometry resolution
    CreateContextFn  createContext = nullptr;  // Allocate buffers, KV cache, buffers
    ForwardFn        forward = nullptr;        // Autoregressive generation loop
    ResetGenerationFn resetGeneration = nullptr; // KV reset between generations
    DestroyFn        destroy = nullptr;        // Teardown
};

// -----------------------------------------------------------------------------
// Model alias — maps canonical name to architecture
// -----------------------------------------------------------------------------
struct ModelAlias {
    uint64_t              hash;            // FNV-1a hash of canonical name
    std::string_view      name;            // Canonical name (lowercase, no quantization)
    const Architecture*   architecture;    // Architecture implementation
};

// -----------------------------------------------------------------------------
// Model metadata — parsed from GGUF + tokenizer + config
// -----------------------------------------------------------------------------
struct ModelMetadata {
    std::string_view canonicalName;   // e.g., "nemotron_h", "qwen2", "gemma3"
    std::string_view family;          // e.g., "nemotron", "qwen2.5", "gemma"
    std::string_view variant;         // e.g., "coder", "chat", "instruct" (optional)

    std::string ggufPath;             // Full path to GGUF file
    std::string tokenizerPath;        // Optional tokenizer path
    std::string configPath;           // Optional config path

    // GGUF-parsed geometry (filled by GGUFLoader during probe/load)
    size_t hiddenDim = 0;
    size_t numLayers = 0;
    size_t numHeads = 0;
    size_t numKVHeads = 0;
    size_t headDim = 0;
    size_t vocabSize = 0;
    size_t intermediateDim = 0;
    size_t moeIntermediateDim = 0;
    size_t numExperts = 0;
    size_t numExpertsPerToken = 0;
    size_t numSharedExperts = 0;

    // MLA / K2
    size_t qLoraRank = 0;
    size_t kvLoraRank = 0;
    size_t qkNopeHeadDim = 0;
    size_t qkRopeHeadDim = 0;
    size_t vHeadDim = 0;

    // RoPE
    float ropeTheta = 0.0f;
    float ropeScaling = 1.0f;
    bool  ropeNeoxStyle = false;

    // SSM / Mamba
    size_t ssmInner = 0;
    size_t ssmStateSize = 0;
    size_t ssmHeads = 0;
    size_t ssmGroups = 0;
    size_t ssmConvKernel = 0;

    // Sliding window
    size_t slidingWindowSize = 0;
    size_t slidingWindowPattern = 0;

    // Quantization (NOT part of architecture identity).
    // A storage tag. Parseability is not capability: admission asks the kernel
    // registry whether an executable kernel exists for the resolved type id.
    std::string quantization;  // "Q4_K_M", "Q8_0", "IQ2_M", "BF16", etc.

    // GGML type id resolved from the tensor table (see GGUFLoader.hpp
    // GGMLType). Admission compares this against actually-registered kernels.
    uint32_t quantTypeId = 0;

    // Tensor names present in the GGUF, as parsed. Required-tensor admission
    // matches role patterns against THIS list; it never assumes a tensor exists
    // because the architecture implies it.
    std::vector<std::string> presentTensors;

    // Norm epsilon
    float normEps = 1e-6f;

    // Tie embeddings
    bool tieEmbeddings = false;

    // MLA flag
    bool useMLA = false;

    // Nemotron-H per-layer pattern arrays
    std::vector<int32_t> nemotronHeadKvPerLayer;
    std::vector<int32_t> nemotronFfPerLayer;
    bool nemotronPatternOk = false;

    // Gemma3 sliding window
    bool isGemma3 = false;
};

// -----------------------------------------------------------------------------
// LoadResult — result of architecture load
// -----------------------------------------------------------------------------
struct LoadResult {
    bool ok = false;
    std::string error;
};

// -----------------------------------------------------------------------------
// ForwardRequest — single generation step
// -----------------------------------------------------------------------------
struct ForwardRequest {
    const int32_t* tokens = nullptr;
    size_t tokenCount = 0;
    size_t seqLen = 0;
    bool isPrefill = true;
    bool useKVCache = true;
    // Sampling parameters could go here
};

// -----------------------------------------------------------------------------
// ArchitectureForwardResult — result of an architecture forward step.
//
// Renamed from ForwardResult to avoid collision with the distinct
// Deep2Engine::ForwardResult (src/deep2/Deep2Engine.h), which reports
// ExecutionRoute and gpuCommitted for forwardTokenAllLayers(). This one
// reports a per-step Code, an error string, and the token produced.
struct ArchitectureForwardResult {
    enum class Code : uint8_t {
        Ok = 0,
        NoArchitecture = 1,
        InvalidRequest = 2,
        ForwardFailed = 3,
        Cancelled = 4,
        MaxTokensReached = 5
    };

    Code code = Code::Ok;
    std::string error;
    int32_t generatedToken = -1;
    bool isLastToken = false;
};

// -----------------------------------------------------------------------------
// Admission
// -----------------------------------------------------------------------------
//
// Admission is the enforcement layer above resolve(). resolve() answers "which
// architecture is this?"; admission answers "may this file actually run?".
// A model whose architecture is recognized can still be rejected for missing
// tensors, bad dimensions, unsupported quantization, an unsupported operator,
// or unavailable hardware. Recognition is not admission.

enum class AdmissionReject : uint8_t {
    None = 0,
    NoParsedArchitecture,      // canonicalName empty: nothing authoritative to admit
    UnknownArchitecture,       // architecture authority says Unknown
    ArchitectureUnimplemented, // recognized, but no registered implementation
    UnsupportedForwardFamily,  // recognized, but the forward graph is not runnable
    MalformedMetadata,         // a parsed field is self-inconsistent
    MissingRequiredTensor,     // a required tensor role is absent from the file
    UnsupportedQuant,          // no executable kernel for the resolved type id
    UnsupportedOperator,       // a required operator is not implemented
    TokenizerUnsupported,      // tokenizer cannot be constructed for this vocab
};

// Which execution device an admission check is being made against.
enum class ExecDevice : uint8_t { Cpu = 0, Gpu = 1 };

// Every field is measured or derived from a measured field. Nothing here is a
// literal verdict.
struct AdmissionReport {
    bool admitted = false;
    AdmissionReject reject = AdmissionReject::None;
    // Which field or role failed. Owned by the report: not a pointer into a
    // temporary, so the receipt stays valid after admit() returns.
    std::string field;
    std::string detail;            // human-readable, values interpolated

    // Measured facts behind the verdict.
    const char* architectureId = nullptr;   // canonical arch key
    const char* forwardFamily = nullptr;    // Deep2::Arch::ForwardFamily name
    bool moe = false;
    bool mla = false;
    bool recurrent = false;
    bool slidingWindow = false;
    bool tieEmbeddings = false;
    bool quantCpuExecutable = false;
    bool quantGpuExecutable = false;
    std::size_t requiredTensors = 0;
    std::size_t missingTensors = 0;
};

// -----------------------------------------------------------------------------
// Registry interface
// -----------------------------------------------------------------------------
class ModelRegistry {
public:
    // Resolve architecture from model name (canonicalized)
    // Returns null if unknown architecture (fail-closed)
    static const Architecture* resolve(std::string_view modelName) noexcept;

    // Resolve architecture from ModelMetadata (after GGUF probe)
    static const Architecture* resolve(const ModelMetadata& metadata) noexcept;

    // Canonicalize a model name/alias to registry key
    // "Qwen2.5-Coder-32B-Instruct-Q4_K_M.gguf" -> "qwen2"
    // "nemotron-3-nano:4b" -> "nemotron_h"
    // "llama3.1" -> "llama"
    static std::string_view canonicalize(std::string_view name) noexcept;

    // Check if a model name is known (without resolving architecture)
    static bool knows(std::string_view name) noexcept;

    // Register an architecture (called at static init time)
    static void registerArchitecture(const Architecture* arch);

    // List all registered architecture IDs
    static void listArchitectures(std::vector<std::string_view>& out);

    // List all model aliases
    static void listAliases(std::vector<std::string_view>& out);

    // -------------------------------------------------------------------------
    // Admission — the enforcement path used by the loader.
    //
    // Verifies, in order: parsed architecture present, architecture known,
    // implementation registered, forward family runnable, geometry coherent,
    // required tensor roles present, quantization executable on the requested
    // device, required operators implemented.
    //
    // Fails closed. A false return means DO NOT EXECUTE.
    static bool admit(const ModelMetadata& metadata,
                      ExecDevice device,
                      AdmissionReport& report) noexcept;

    // Quantization execution capability, measured from the kernel registry's
    // actually-registered GEMV and dequant pointers. A format that parses but
    // has no registered kernel returns false. This is the only authority for
    // "can we execute this format".
    static bool quantExecutable(uint32_t ggmlTypeId, ExecDevice device) noexcept;

    // Required tensor roles for a canonical architecture, derived from parsed
    // metadata. Exposed so admission and tests agree on one list.
    static std::size_t countMissingRequiredTensors(const ModelMetadata& metadata,
                                                    std::string& firstMissing) noexcept;
};

} // namespace Deep2