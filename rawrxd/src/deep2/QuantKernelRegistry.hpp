#pragma once
// ============================================================================
// QuantKernelRegistry.hpp — Production header for the quantization-agnostic
// kernel dispatch table.
//
// Must stay in lock-step with QuantKernelRegistry.cpp.
// ============================================================================

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <sstream>
#include <unordered_map>
#include <vector>
#include <atomic>
#include "ExecutionView.hpp"

#ifdef _MSC_VER
#define RESTRICT __restrict
#else
#define RESTRICT __restrict__
#endif

namespace Deep2 {

// ---------------------------------------------------------------------------
// GGML quant type enum is defined in GGUFLoader.hpp (single source of truth).
// ---------------------------------------------------------------------------
// #include "GGUFLoader.hpp" before including this header if you need GGMLType.
// ---------------------------------------------------------------------------

// ---------------------------------------------------------------------------
// Block struct definitions — layouts match ggml reference exactly.
// ---------------------------------------------------------------------------

// Q4_0: 32 weights, 1 fp16 scale — 18 bytes total (2+16)
struct block_q4_0 {
    uint16_t d;           // fp16 scale
    uint8_t  qs[16];      // 32 nibbles
};

// Q4_1: 32 weights, 1 fp16 scale + 1 fp16 min — 20 bytes total (2+2+16)
struct block_q4_1 {
    uint16_t d;           // fp16 scale
    uint16_t m;           // fp16 min
    uint8_t  qs[16];      // 32 nibbles
};

// Q5_0: 32 weights, 1 fp16 scale, 4-byte qh — 22 bytes total (2+4+16)
struct block_q5_0 {
    uint16_t d;
    uint8_t  qh[4];
    uint8_t  qs[16];
};

// Q5_1: 32 weights, 1 fp16 scale + 1 fp16 min, 4-byte qh — 24 bytes total
struct block_q5_1 {
    uint16_t d;
    uint16_t m;
    uint8_t  qh[4];
    uint8_t  qs[16];
};

// Q8_0: 32 int8 weights, 1 fp16 scale — 34 bytes total (2+32)
struct block_q8_0 {
    uint16_t d;           // fp16 scale
    int8_t   qs[32];      // int8 quantized values
};

// Q2_K: 256 weights, 16 scales — 84 bytes
//
// RAWRXD_Q2K_FIELD_ORDER_002 — THIS IS THE ON-DISK ORDER. d/dmin ARE LAST.
//
// ggml-common.h declares block_q2_K as:
//   { uint8_t scales[QK_K/16];  // @ 0
//     uint8_t qs[QK_K/4];       // @ 16
//     ggml_half d;              // @ 80
//     ggml_half dmin; }         // @ 82
// with static_assert(sizeof == 2*sizeof(ggml_half) + QK_K/16 + QK_K/4).
//
// block_q2_K is the ONLY block_* in ggml-common.h whose fp16 super-block
// scales are not first. A Q4_K-shaped reading (d@0, dmin@2, scales@4,
// qs@20) satisfies every structural check — the block is 84 bytes either way,
// and queryTypeGeometry reports the same geometry — while reading its fp16
// scales out of 2-bit quant data. Size checks cannot see this class of defect;
// only a value check can.
//
// MEASURED — tools/quant_block_oracle.cpp (RAWRXD_QUANT_BLOCK_ORACLE_002),
// model G:\~dev\rawrxd\models\llama3.2-3b-Q2_K.gguf, tensor
// blk.0.ffn_gate.weight, 256 blocks, bit-exact comparison (no tolerance):
//   BEFORE  FIRST_DIFF element=0   65535 of 65536 elements differ (99.9985%)
//           max|reference| = 0.157207489    max|production| = 3173056
//           fp16 probe of block 0: offset 0 = 45344, offset 2 = -0.088623,
//           offset 80 = 0.00190926, offset 82 = 0.00398254
//           -> the sane scale words are at 80/82; production was reading 0/2.
//   AFTER   PARITY, 0 mismatched, max_abs_diff 0
// The same run measured Q3_K, Q6_K and F32 PARITY on the same tensor table, so
// the loader, the striding, the registry geometry and the fp16 conversion were
// never involved. Q2_K was the only mismatching type, and it carried 42.6% of
// the file's bytes.
//
// RAWRXD_Q2K_FIELD_ORDER_001 IS RETRACTED. It moved this struct FROM the
// on-disk order TO the Q4_K-shaped order, reporting that the on-disk order
// "read d/dmin from quant data". It did — and so does this one. The field order
// and the decode were wrong simultaneously; the experiment changed one of them
// while reading the other's symptom as the verdict. That is the same shape as
// the rejected Q4_0 zero-point experiment below, and the two were committed
// together.
struct block_q2_K {
    uint8_t  scales[16];  // 4-bit scale/min pairs @ offset 0
    uint8_t  qs[64];      // 2-bit weights (256 values) @ offset 16
    uint16_t d;           // fp16 super-scale    @ offset 80
    uint16_t dmin;        // fp16 super-min      @ offset 82
};
static_assert(sizeof(block_q2_K) == 84, "GGUF block_q2_K must be 84 bytes");

// Q3_K: 256 weights, 32-byte hmask, 64-byte qs, 12-byte scales, fp16 d — 110 bytes
// Field order is load-bearing: it must match the GGUF on-disk layout exactly, or
// `d` is decoded from quant bytes and every output is garbage.
struct block_q3_K {
    // Field order is load-bearing: it must match the GGUF on-disk layout
    // exactly, or `d` is decoded from quant bytes and every output is garbage.
    // RAWRXD_Q3K_FIELD_ORDER_001: a reorder to scales@0/hmask@12/qs@44 was
    // attempted and REVERTED, and a `uint16_t dmin` member added during that
    // attempt was REVERTED too — it made the struct 112 bytes and broke this
    // assert. Not shipping an unverified Q3_K layout.
    uint8_t  hmask[32];   // high-bit mask
    uint8_t  qs[64];      // 3-bit weights
    uint8_t  scales[12];  // packed scales
    uint16_t d;           // fp16 super-scale
};
static_assert(sizeof(block_q3_K) == 110, "GGUF block_q3_K must be 110 bytes");

// Q4_K: 256 weights, 12-byte scales, 128-byte qs — 144 bytes
struct block_q4_K {
    uint16_t d;           // fp16 scale
    uint16_t dmin;        // fp16 min
    uint8_t  scales[12];  // packed scales/mins
    uint8_t  qs[128];     // 4-bit weights
};
static_assert(sizeof(block_q4_K) == 144, "GGUF block_q4_K must be 144 bytes");

// Q5_K: 256 weights, 12-byte scales, 32-byte qh, 128-byte qs, fp16 d/dmin — 176 bytes
//
// RAWRXD_Q5K_FIELD_ORDER_001 — d/dmin ARE FIRST. The order below was WRONG on
// disk, and it is the same defect as RAWRXD_Q2K_FIELD_ORDER_002 in the opposite
// direction.
//
// ggml-common.h declares block_q5_K as:
//   { ggml_half d;                     // @ 0
//     ggml_half dmin;                  // @ 2
//     uint8_t scales[K_SCALE_SIZE];    // @ 4,  12 B
//     uint8_t qh[QK_K/8];              // @ 16, 32 B
//     uint8_t qs[QK_K/2]; }            // @ 48, 128 B
// with static_assert(sizeof == 2*sizeof(ggml_half) + K_SCALE_SIZE + QK_K/2
//                                      + QK_K/8)
//
// This header previously declared scales FIRST and d/dmin LAST, i.e. the Q2_K
// shape, on a block whose upstream shape is the Q4_K one. The two K-quants that
// carry both a scale and a min therefore disagreed with each other, and each
// disagreed with upstream in a different direction:
//
//   type   upstream             this header, before this fix
//   Q2_K   scales,qs,d,dmin    d,dmin,scales,qs        <-- inverted
//   Q5_K   d,dmin,scales,qh,qs  scales,qh,qs,d,dmin    <-- inverted
//   Q4_K   d,dmin,scales,qs     d,dmin,scales,qs        correct throughout
//
// MEASURED — tools/quant_block_oracle.cpp, Codestral-22B-v0.1-Q4_K_M.gguf,
// tensor blk.0.ffn_down.weight, 128 blocks, bit-exact comparison:
//   BEFORE  FIRST_DIFF element=0, 32768/32768 elements differ (100.0000%)
//           reference = 0.0107433917   max|reference| = 0.0388633683
//           production= 49425.75      max|production|= 83703656
//           fp16 probe of block 0: offset 0 = 1.16825e-05 and offset 2 =
//           0.000191092, both plausible scales, while offsets 4..126 hold
//           -56768, 15720, 20208, 30688 — quant bytes read as scales.
//   AFTER   PARITY, 0 mismatched
//
// The block is 176 bytes in every one of those orders and queryTypeGeometry
// agrees in every one of them. Only the values see it. Field order and `qs`
// width are both load-bearing (see block_q3_K) — and the load-bearing part that
// matters is WHICH BYTE each field starts at, not how wide it is.
struct block_q5_K {
    uint16_t d;           // fp16 super-scale    @ offset 0
    uint16_t dmin;        // fp16 super-min      @ offset 2
    uint8_t  scales[12];  // packed scales/mins  @ offset 4
    uint8_t  qh[32];      // 5th bit of each weight @ offset 16
    uint8_t  qs[128];     // low 4 bits of each weight @ offset 48
};
static_assert(sizeof(block_q5_K) == 176, "GGUF block_q5_K must be 176 bytes");

// Q6_K: 256 weights, 16 signed scales, 128-byte ql, 64-byte qh, fp16 d — 210 bytes
struct block_q6_K {
    uint8_t  ql[128];     // low 4 bits
    uint8_t  qh[64];      // high 2 bits
    int8_t   scales[16];  // signed scales
    uint16_t d;           // fp16 scale
};
static_assert(sizeof(block_q6_K) == 210, "GGUF block_q6_K must be 210 bytes");

// Q8_K: 256 int8 weights, 1 fp32 scale, 16 int16 block sums — 292 bytes
struct block_q8_K {
    float   d;            // fp32 scale
    int8_t  qs[256];      // int8 quantized values
    int16_t bsums[16];    // block sums for vec_dot correction
};

// ---------------------------------------------------------------------------
// Quant type descriptor (lookup table used by geometry / name queries)
// ---------------------------------------------------------------------------
struct QuantTypeDesc {
    uint32_t typeId;
    const char* name;
    size_t blockBytes;
    size_t blockElements;
    bool   hasScales;
    bool   hasMin;
    bool   isQuantized;
};

const QuantTypeDesc* LookupQuantType(uint32_t type);
const char*          QuantTypeName(uint32_t type);
bool                 QuantTypeIsQuantized(uint32_t type);

// ---------------------------------------------------------------------------
// Block geometry (bytes per block, elements per block, flags)
// ---------------------------------------------------------------------------
struct BlockGeometry {
    size_t blockBytes;
    size_t blockElements;
    bool   hasScales;
    bool   hasMin;
};

BlockGeometry GetBlockGeometryForType(int quantType);
const char*   GGMLTypeName(int type);

// ---------------------------------------------------------------------------
// RAWRXD_CPU_FULL_MODEL_INFERENCE_001: dispatch telemetry
//
// Counts actual invocations of the admitted vector kernels and their scalar
// references. A receipt needs to PROVE which path ran during a real generation;
// reading the registry's table only shows what was registered, not what executed.
struct GemvDispatchCounters {
    uint64_t q4k_vector = 0;
    uint64_t q4k_scalar = 0;
    uint64_t q6k_vector = 0;
    uint64_t q6k_scalar = 0;
    uint64_t q5k_vector = 0;
    uint64_t q5k_scalar = 0;
};

void ResetGemvDispatchCounters();
GemvDispatchCounters GetGemvDispatchCounters();

// ---------------------------------------------------------------------------
// Kernel function-pointer types
// ---------------------------------------------------------------------------
using GEMVKernelFn = void (*)(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
);

// RAWRXD_SPACELESS_EXECUTION_VIEW_GEMV_002
// ExecutionView-aware GEMV kernel signature. The kernel receives an
// ExecutionView that carries TensorIdentity + transient address, rather
// than a raw pointer. This is the production adoption path.
using GEMVKernelFnEV = void (*)(
    const ExecutionView& ev,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
);

using DequantKernelFn = void (*)(
    const uint8_t* src,
    float*         dst,
    size_t         n
);

// ---------------------------------------------------------------------------
// UniversalTensorProxy — resolved once per tensor, zero branches in hot path
// ---------------------------------------------------------------------------
struct UniversalTensorProxy {
    const uint8_t* mmapBase   = nullptr;
    size_t         byteOffset = 0;
    size_t         totalBytes = 0;
    int            quantType  = 0;
    size_t         rows       = 0;
    size_t         cols       = 0;

    GEMVKernelFn    gemvKernel    = nullptr;
    DequantKernelFn dequantKernel = nullptr;
    BlockGeometry   geometry      = {};

    bool        IsQuantized() const;
    const char* TypeName() const;
};

// ---------------------------------------------------------------------------
// CPU feature flags
// ---------------------------------------------------------------------------
struct CPUFeatures {
    bool fma        = false;
    bool f16c       = false;
    bool avx2       = false;
    bool avx512f    = false;
    bool avx512dq   = false;
    bool avx512bw   = false;
    bool avx512vl   = false;
    bool avx512vnni = false;
};

// ---------------------------------------------------------------------------
// QuantKernelRegistry — singleton dispatch table
// ---------------------------------------------------------------------------
class QuantKernelRegistry {
public:
    static QuantKernelRegistry& Instance();

    void ProbeCPU();
    void Initialize();

    void RegisterGEMV   (int quantType, GEMVKernelFn    kernel);
    void RegisterGEMVEV  (int quantType, GEMVKernelFnEV   kernel);
    void RegisterDequant(int quantType, DequantKernelFn kernel);
    void RegisterGeometry(int quantType, const BlockGeometry& geom);

    void RegisterBuiltins();

    UniversalTensorProxy Resolve(
        const uint8_t* mmapBase,
        size_t byteOffset,
        size_t totalBytes,
        int quantType,
        size_t rows,
        size_t cols
    ) const;

    GEMVKernelFn    GetGEMV    (int quantType) const;
    GEMVKernelFnEV  GetGEMVEV  (int quantType) const;
    DequantKernelFn GetDequant (int quantType) const;
    BlockGeometry   GetGeometry(int quantType) const;

    // RAWRXD_REVERSE_001: read-only view of the flags ProbeCPU() actually set.
    // The Heartbeat publishes these as the CPU half of execution reality. It
    // is a VIEW, not a setter: no path may turn a feature on from outside, so
    // a form can never be selected for an instruction set this CPU lacks.
    const CPUFeatures& cpuFeatures() const { return cpu_; }

    std::string DumpTable() const;
    void        PrintBatch21Report() const;

private:
    CPUFeatures cpu_;

    std::unordered_map<int, GEMVKernelFn>    gemvTable_;
    std::unordered_map<int, GEMVKernelFnEV>   gemvEvTable_;
    std::unordered_map<int, DequantKernelFn> dequantTable_;
    std::unordered_map<int, BlockGeometry>   geometryTable_;

    struct Batch21Counters {
        std::atomic<uint64_t> registryHits{0};
        std::atomic<uint64_t> registryMisses{0};
        std::atomic<uint64_t> scalarFallbacks{0};
        std::atomic<uint64_t> kernelInvocations{0};
        std::atomic<uint64_t> vulkanComputeSubmissions{0};
        std::atomic<uint64_t> vulkanComputeFailures{0};
    } batch21_;
};

} // namespace Deep2
