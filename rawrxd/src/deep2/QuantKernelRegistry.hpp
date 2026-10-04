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
// Field order is load-bearing: d/dmin MUST be first to match GGUF on-disk
// layout. A previous order (scales@0, qs@16, d@80, dmin@82) read d/dmin from
// quant data and produced garbage output — RAWRXD_Q2K_FIELD_ORDER_001.
struct block_q2_K {
    uint16_t d;           // fp16 super-scale    @ offset 0
    uint16_t dmin;        // fp16 super-min      @ offset 2
    uint8_t  scales[16];  // 4-bit scale/min pairs @ offset 4
    uint8_t  qs[64];      // 2-bit weights (256 values) @ offset 20
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
// Field order and `qs` width are both load-bearing (see block_q3_K).
struct block_q5_K {
    uint8_t  scales[12];  // packed scales/mins
    uint8_t  qh[32];      // 5th bit of each weight
    uint8_t  qs[128];     // low 4 bits of each weight
    uint16_t d;           // fp16 super-scale
    uint16_t dmin;        // fp16 super-min
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
