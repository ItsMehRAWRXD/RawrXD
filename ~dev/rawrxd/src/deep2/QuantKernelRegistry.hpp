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
struct block_q2_K {
    uint16_t d;           // fp16 super-scale
    uint16_t dmin;        // fp16 super-min
    uint8_t  scales[16];  // 4-bit scale/min pairs
    uint8_t  qs[64];      // 2-bit weights (256 values)
};

// Q3_K: 256 weights, 12-byte scale packing, hmask — 110 bytes
struct block_q3_K {
    uint16_t d;
    uint8_t  hmask[32];   // high-bit mask
    uint8_t  qs[64];      // 3-bit weights
    uint8_t  scales[12];  // packed scales
};

// Q4_K: 256 weights, 12-byte scales, 128-byte qs — 144 bytes
struct block_q4_K {
    uint16_t d;           // fp16 scale
    uint16_t dmin;        // fp16 min
    uint8_t  scales[12];  // packed scales/mins
    uint8_t  qs[128];     // 4-bit weights
};

// Q5_K: 256 weights, 12-byte scales, 64-byte qs, 32-byte qh — 176 bytes
struct block_q5_K {
    uint16_t d;
    uint16_t dmin;
    uint8_t  scales[12];
    uint8_t  qs[64];
    uint8_t  qh[32];      // high bits for 5th bit
};

// Q6_K: 256 weights, 16 signed scales, 128-byte ql, 64-byte qh, fp16 d — 210 bytes
struct block_q6_K {
    uint8_t  ql[128];     // low 4 bits
    uint8_t  qh[64];      // high 2 bits
    int8_t   scales[16];  // signed scales
    uint16_t d;           // fp16 scale
};

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
// Kernel function-pointer types
// ---------------------------------------------------------------------------
using GEMVKernelFn = void (*)(
    const uint8_t* RESTRICT w,
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

    GEMVKernelFn    GetGEMV   (int quantType) const;
    DequantKernelFn GetDequant(int quantType) const;
    BlockGeometry   GetGeometry(int quantType) const;

    std::string DumpTable() const;
    void        PrintBatch21Report() const;

private:
    CPUFeatures cpu_;

    std::unordered_map<int, GEMVKernelFn>    gemvTable_;
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
