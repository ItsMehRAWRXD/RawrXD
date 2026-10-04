#pragma once
// ============================================================================
// PolyKernel.hpp — RAWRXD_POLYKERNEL_SOURCELESS_AUTHORITY_001
//
// A kernel-generation authority that emits MACHINE CODE, not source text.
//
// The previous generator (PolyKernelGenerator) produced a C++ string and invoked
// cl.exe. That is CPP_KERNEL_SOURCE_GENERATION=1 and an external compiler
// dependency. This one produces a KernelIR and an X64Emitter produces the
// bytes. No compiler, no generated source, no per-quant hand-written route.
//
// THE POLYMORPHIC BOUNDARY — KernelRequest deliberately carries no model
// identity. Absent by construction:
//
//     modelName   GGUF filename   layer pointer   WeightTensor*
//
// A kernel cache hit therefore means "these execution shapes are equivalent",
// not "this model has already been seen".
//
// GENERATION knows WHAT must happen. BINDING knows WHERE the bytes are NOW.
// EXECUTION joins them temporarily. A kernel identity never contains a pointer.
// ============================================================================

#include <cstdint>
#include <string>
#include <vector>

namespace Deep2 {
namespace poly {

// ---------------------------------------------------------------------------
// Operations. Every compute path in the engine becomes one of these, including
// the ones that used to be separate kingdoms (grouped GPU GEMV, MoE experts).
// ---------------------------------------------------------------------------
enum class PolyOp : std::uint8_t {
    GEMV = 0,
    GEMM = 1,
    GroupedGEMV = 2,
    MoEExperts = 3,
    Router = 4,
    RMSNorm = 5,
    RoPE = 6,
    Attention = 7,
    CopyTransform = 8,
    INVALID = 0xFF,
};

const char* polyOpName(PolyOp op);

// ---------------------------------------------------------------------------
// The request. Geometry and semantics only.
//
// KERNEL_IDENTITY_DEPENDS_ON_POINTER      = 0
// KERNEL_IDENTITY_DEPENDS_ON_MODEL_PATH   = 0
// KERNEL_IDENTITY_DEPENDS_ON_RESIDENCY    = 0
// ---------------------------------------------------------------------------
struct KernelRequest {
    PolyOp    op = PolyOp::GEMV;

    std::uint32_t quantType   = 0;   // GGML type id
    std::uint32_t inputType   = 0;   // element type of the activation
    std::uint32_t outputType  = 0;

    std::uint64_t M = 0, N = 0, K = 0;

    std::uint32_t groupSize   = 0;   // GroupedGEMV: how many projections
    std::uint32_t expertCount = 0;   // MoEExperts
    std::uint32_t activeExperts = 0;

    std::uint64_t hardwareSignature = 0;
    std::uint64_t layoutSignature  = 0;

    bool gpu = false;

    bool operator==(const KernelRequest&) const noexcept = default;
};

// ---------------------------------------------------------------------------
// Hardware reality. Facts only, published from real CPUID / real device query.
// ---------------------------------------------------------------------------
struct HardwareDescriptor {
    bool avx2    = false;
    bool avx512f = false;
    bool avx512vnni = false;
    bool fma     = false;
    std::uint32_t maxVectorWidth = 8;
    bool gpu     = false;
    std::uint32_t subgroupSize = 0;
};

HardwareDescriptor describeHardware();

// ---------------------------------------------------------------------------
// KernelKey — the cache key. Excludes model identity by construction.
// ---------------------------------------------------------------------------
struct KernelKey {
    PolyOp    op;
    std::uint32_t quant, inputType, outputType;
    std::uint64_t geometryHash;
    std::uint64_t layoutHash;
    std::uint64_t hardwareHash;
    std::uint32_t generatorVersion;

    bool operator==(const KernelKey&) const noexcept = default;
};

KernelKey makeKey(const KernelRequest& r);

// ---------------------------------------------------------------------------
// KernelIR — the instruction graph. This is what "sourceless" means: the
// generator emits THESE, and a backend lowers them to bytes.
// ---------------------------------------------------------------------------
enum class KOp : std::uint8_t {
    Nop = 0,
    // memory
    LoadF32,        // dst = *(float*)(src + imm*4)          (one float)
    LoadF32x4,      // dst[0..3] = *(float*)(src + imm*4)
    LoadF32x8,      // dst[0..7]
    LoadF32x16,     // dst[0..15]
    LoadU8x16,      // dst[0..15] bytes widened to i32
    LoadU8x4,       // 4 bytes
    LoadU16,        // one u16 (for fp16 scale fields)
    StoreF32,       // *(float*)(dst + imm*4) = src
    // integer / nibble
    And,            // dst = src0 & src1
    ShiftRightLogical,
    ShiftLeft,
    Or,
    Xor,
    // float conversion
    I32ToF32,
    F16ToF32,
    // float arithmetic
    Mul, Add, Sub, Fma, Div,
    Broadcast,
    Dot,
    HorizontalSum,
    Negate,
    Select,
    Barrier,
};

struct KInst {
    KOp op = KOp::Nop;
    std::uint16_t dst = 0;
    std::uint16_t src0 = 0;
    std::uint16_t src1 = 0;
    std::uint32_t imm = 0;
};

struct KernelIR {
    std::vector<KInst> code;

    std::uint32_t vectorWidth   = 0;
    std::uint32_t accumulators  = 1;
    std::uint32_t unroll        = 1;

    std::uint64_t scratchBytes  = 0;

    // Registers the IR expects to be bound at execution. Indices refer to the
    // ABI positions the emitter assigns, not to machine registers.
    std::uint32_t inWeight  = 0;
    std::uint32_t inX       = 0;
    std::uint32_t inOut     = 0;
    std::uint32_t rows      = 0;
    std::uint32_t cols      = 0;
    std::uint32_t xStride   = 0;   // elements
    std::uint32_t outStride = 0;   // elements
};

// ---------------------------------------------------------------------------
// Planner — hardware mutates the REALIZATION; the operation stays invariant.
// ---------------------------------------------------------------------------
struct KernelPlan {
    KernelIR ir;
    bool     supported = false;
    std::string rejectReason;
};

KernelPlan planGEMV(const KernelRequest& req, const HardwareDescriptor& hw);

// ---------------------------------------------------------------------------
// The emitted artifact.
// ---------------------------------------------------------------------------
struct KernelBlob {
    bool         ok = false;
    std::vector<std::uint8_t> bytes;
    std::uint64_t digest = 0;
    std::uint32_t entryOffset = 0;
    std::string   rejectReason;
};

std::uint64_t fnv1a64(const void* p, std::size_t n);

// Lower a KernelIR to x86-64 machine code. No compiler is invoked and no source
// text exists at any point.
KernelBlob emitX64(const KernelIR& ir, const KernelRequest& req,
                   const HardwareDescriptor& hw);

// ---------------------------------------------------------------------------
// Binding — supplied AFTER generation, never part of identity.
// ---------------------------------------------------------------------------
struct KernelBinding {
    const float* weight = nullptr;   // already-quantized-or-f32 per request
    const float* x      = nullptr;
    float*       y      = nullptr;
    std::uint32_t rows = 0;
    std::uint32_t cols = 0;
};

// ---------------------------------------------------------------------------
// The authority. Cache keyed on KernelKey; binds per call.
// ---------------------------------------------------------------------------
class PolyKernelAuthority {
public:
    static PolyKernelAuthority& Instance();

    // Returns a handle index, or -1 with a reason.
    long acquire(const KernelRequest& req, std::string* why = nullptr);

    // Execute a previously acquired handle against a binding.
    bool execute(long handle, const KernelBinding& b);

    struct Stats {
        std::uint64_t requests = 0;
        std::uint64_t cacheHits = 0;
        std::uint64_t generated = 0;
        std::uint64_t rejected = 0;
        std::uint64_t executions = 0;
    };
    static Stats stats();

    void clear();

private:
    PolyKernelAuthority() = default;
};

} // namespace poly
} // namespace Deep2