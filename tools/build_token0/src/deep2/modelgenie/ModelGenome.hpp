//=============================================================================
// ModelGenome - Frozen Compiler Input Authority
// RAWRXD_MODEL_GENIE_HEADER_EXPORT_001
//
// This is the SINGLE SOURCE OF TRUTH for the compiler.
// The extractor (NUGVERSE_ESTIMATOR_001) produces this.
// The compiler consumes ONLY this - never re-parses GGUF.
//=============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <array>
#include <optional>

namespace RawrXD {
namespace Deep2 {
namespace ModelGenie {

//=============================================================================
// Architecture Constants (from GGUF metadata)
//=============================================================================
enum class Architecture : uint8_t {
    Unknown = 0,
    DeepSeek2,
    Llama,
    Mistral,
    Qwen,
    GptOss
};

//=============================================================================
// Helpers
//=============================================================================
inline uint64_t ComputeElementCount(const std::array<uint32_t, 4>& dims) {
    uint64_t count = 1;
    for (uint32_t d : dims) {
        if (d > 0) count *= d;
    }
    return count;
}

inline const char* ArchitectureToString(Architecture arch) {
    switch (arch) {
        case Architecture::DeepSeek2: return "deepseek2";
        case Architecture::Llama: return "llama";
        case Architecture::Mistral: return "mistral";
        case Architecture::Qwen: return "qwen";
        case Architecture::GptOss: return "gptoss";
        default: return "unknown";
    }
}

enum class RopeScalingType : uint8_t {
    None = 0,
    Linear,
    Yarn
};

enum class WeightTying : uint8_t {
    Untied = 0,
    Tied
};

//=============================================================================
// Tensor Role Classification
//=============================================================================
enum class TensorRole : uint8_t {
    Unknown = 0,
    Embed,
    Output,
    Norm,
    Attn,
    FFN,
    Router,
    Expert,
    KVLatent
};

inline const char* TensorRoleToString(TensorRole role) {
    switch (role) {
        case TensorRole::Embed: return "EMBED";
        case TensorRole::Output: return "OUTPUT";
        case TensorRole::Norm: return "NORM";
        case TensorRole::Attn: return "ATTN";
        case TensorRole::FFN: return "FFN";
        case TensorRole::Router: return "ROUTER";
        case TensorRole::Expert: return "EXPERT";
        case TensorRole::KVLatent: return "KV_LATENT";
        default: return "UNKNOWN";
    }
}

enum class GGMLType : uint32_t {
    F32 = 0,
    Q4_K,
    Q5_0,
    Q6_K,
    Q8_0
};

//=============================================================================
// Tensor Descriptor (from physical GGUF directory)
//=============================================================================
struct TensorDescriptor {
    uint32_t tensorId;              // Dense index [0..tensor_count-1]
    std::string name;               // Original GGUF name (diagnostic only)
    TensorRole role;                // Functional role
    int32_t blockIndex;             // -1 = global, 0..N-1 = block
    GGMLType type;                  // Quantization type
    std::array<uint32_t, 4> dims;   // Dimensions (padded to 4)
    uint32_t rank;                  // Actual rank (1-4)
    uint64_t encodedBytes;          // File size
    uint64_t fileOffset;            // Offset in GGUF
    uint64_t elementCount;          // Total elements
    
    TensorDescriptor() : tensorId(0), role(TensorRole::Unknown), blockIndex(-2),
                         type(GGMLType::F32), dims{0}, rank(0),
                         encodedBytes(0), fileOffset(0), elementCount(0) {}
};

//=============================================================================
// Block Genome (per-layer tensor topology)
//=============================================================================
struct BlockGenome {
    uint32_t blockIndex;
    bool isDense;                    // Block 0 only for DeepSeek2
    bool isMoE;                      // Blocks 1..N-1 for DeepSeek2
    
    // Dense block tensors (block 0)
    std::optional<uint32_t> attnNorm;
    std::optional<uint32_t> ffnNorm;
    std::optional<uint32_t> attnKvANorm;
    std::optional<uint32_t> attnKvAMqa;
    std::optional<uint32_t> attnKvB;
    std::optional<uint32_t> attnOutput;
    std::optional<uint32_t> attnQ;
    std::optional<uint32_t> ffnDown;
    std::optional<uint32_t> ffnGate;
    std::optional<uint32_t> ffnUp;
    
    // MoE block tensors (blocks 1..N-1)
    std::optional<uint32_t> ffnDownExps;
    std::optional<uint32_t> ffnGateExps;
    std::optional<uint32_t> ffnUpExps;
    std::optional<uint32_t> ffnGateInp;    // Router
    std::optional<uint32_t> ffnDownShExp;  // Shared expert
    std::optional<uint32_t> ffnGateShExp;
    std::optional<uint32_t> ffnUpShExp;
    
    BlockGenome() : blockIndex(0), isDense(false), isMoE(false) {}
};

//=============================================================================
// Expert Bank (for MoE blocks)
//=============================================================================
struct ExpertBank {
    uint32_t blockIndex;
    uint32_t routedExpertCount;    // 64
    uint32_t activeExpertCount;    // 6
    uint32_t sharedExpertCount;    // 2
    
    uint32_t routerTensorId;
    uint32_t sharedDownTensorId;
    uint32_t sharedGateTensorId;
    uint32_t sharedUpTensorId;
    std::vector<uint32_t> routedDownTensorIds;   // 64
    std::vector<uint32_t> routedGateTensorIds;   // 64
    std::vector<uint32_t> routedUpTensorIds;     // 64
    
    // Derived: expert ROM share percentage
    double expertRomSharePercent = 0.0;
    
    ExpertBank() : blockIndex(0), routedExpertCount(0), activeExpertCount(0),
                   sharedExpertCount(0), routerTensorId(0), sharedDownTensorId(0),
                   sharedGateTensorId(0), sharedUpTensorId(0) {}
};

//=============================================================================
// Execution IR (Operation Graph)
//=============================================================================
enum class OpCode : uint8_t {
    Invalid = 0,
    RmsNorm,
    Linear,
    MatMul,
    Attention,
    MlaDecompress,          // REQUIRED primitive missing
    Router,
    TopK,
    MoEExecute,
    ResidualAdd,
    LMHead
};

enum class Primitive : uint16_t {
    None = 0,
    RmsNormFwd,
    LinearFwd,
    MatMulFwd,
    AttentionFwd,
    MlaDecompressFwd,       // FIRST_UNIMPLEMENTED_PRIMITIVE
    RouterFwd,
    TopKFwd,
    MoEExecuteFwd,
    ResidualAddFwd,
    LMHeadFwd
};

//=============================================================================
// Operand Namespace
//=============================================================================
enum class OperandDomain : uint8_t {
    None = 0,
    RomTensor,
    Activation,
    RuntimeScalar
};

struct OperandRef {
    OperandDomain domain;
    uint32_t id;
    
    constexpr OperandRef() : domain(OperandDomain::None), id(0) {}
    constexpr OperandRef(OperandDomain d, uint32_t i) : domain(d), id(i) {}
};

inline const char* OperandDomainToString(OperandDomain domain) {
    switch (domain) {
        case OperandDomain::None: return "NONE";
        case OperandDomain::RomTensor: return "ROM_TENSOR";
        case OperandDomain::Activation: return "ACTIVATION";
        case OperandDomain::RuntimeScalar: return "RUNTIME_SCALAR";
        default: return "UNKNOWN";
    }
}

struct OperationIR {
    uint32_t opId;
    OpCode opcode;
    Primitive requiredPrimitive;
    std::vector<OperandRef> inputs;
    std::vector<OperandRef> weights;
    OperandRef output;
    uint32_t blockIndex;     // UINT32_MAX = global
    
    OperationIR() : opId(0), opcode(OpCode::Invalid), requiredPrimitive(Primitive::None),
                    output{OperandDomain::None, 0}, blockIndex(UINT32_MAX) {}
};

//=============================================================================
// Capability Manifest
//=============================================================================
struct CapabilityManifest {
    std::vector<Primitive> requiredPrimitives;
    std::vector<Primitive> availablePrimitives;
    std::vector<Primitive> unimplementedPrimitives;
    Primitive firstUnimplementedPrimitive = Primitive::None;
    bool runtimeExecutable = false;
    
    CapabilityManifest() = default;
};

//=============================================================================
// Residency IR (Memory Bounds)
//=============================================================================
struct ResidencyBounds {
    uint64_t maxPinnedTensorBytes = 0;
    uint64_t minBlockBytes = 0;
    uint64_t meanBlockBytes = 0;
    uint64_t maxBlockBytes = 0;
    bool uniformTensorSlotsSufficient = false;
    bool meanBlockCapacitySafe = false;
    
    // Expert-specific
    double expertRomSharePercent = 0.0;
    uint64_t expertRomBytes = 0;
    uint64_t maxExpertBlockBytes = 0;
    
    ResidencyBounds() = default;
};

//=============================================================================
// ModelGenome - THE FROZEN COMPILER INPUT
//=============================================================================
struct ModelGenome {
    // Identity
    std::string modelName;
    Architecture architecture = Architecture::Unknown;
    
    // Architecture Parameters (EXPLICIT from GGUF metadata)
    uint32_t blockCount = 0;
    uint32_t embeddingLength = 0;
    uint32_t feedForwardLength = 0;
    uint64_t contextLength = 0;
    uint32_t vocabSize = 0;
    uint32_t headCount = 0;
    uint32_t headCountKv = 0;
    uint64_t ropeFreqBase = 0;
    uint32_t ropeDimensionCount = 0;
    RopeScalingType ropeScalingType = RopeScalingType::None;
    double rmsEps = 0.0;
    
    // MoE Parameters
    uint32_t expertCount = 0;
    uint32_t expertUsedCount = 0;
    uint32_t expertSharedCount = 0;
    uint32_t expertFfnLength = 0;
    uint32_t leadingDenseBlocks = 0;
    
    // MLA Parameters
    uint32_t kvLoraRank = 0;
    uint32_t keyLength = 0;
    uint32_t valueLength = 0;
    WeightTying weightTying = WeightTying::Untied;
    
    // Derived (SHAPE/DERIVED from tensor directory)
    uint64_t exactParams = 0;
    uint64_t encodedWeightBytes = 0;
    double effectiveBpw = 0.0;
    
    // Physical GGUF Info
    uint64_t fileBytes = 0;
    uint32_t ggufVersion = 0;
    uint32_t tensorCount = 0;
    uint32_t alignment = 0;
    uint64_t dataStart = 0;
    
    // Tensor Directory (all 377 tensors)
    std::vector<TensorDescriptor> tensors;
    
    // Block Genomes (27 blocks)
    std::vector<BlockGenome> blocks;
    
    // Expert Banks (26 MoE blocks)
    std::vector<ExpertBank> expertBanks;
    
    // Execution IR
    std::vector<OperationIR> executionOps;
    
    // Capability Manifest
    CapabilityManifest capabilities;
    
    // Residency Bounds
    ResidencyBounds residencyBounds;
    
    // Validation
    bool genomeInputValid = false;
    bool tensorCountMatch = false;
    bool blockCountMatch = false;
    bool blockGrammarMatch = false;
    bool romOffsetsPreserved = false;
    bool romByteLengthsPreserved = false;
    bool residencyBoundsPreserved = false;
    
    ModelGenome() = default;
    
    // Canonical hash for round-trip verification
    std::string computeCanonicalHash() const;
};

} // namespace ModelGenie
} // namespace Deep2
} // namespace RawrXD