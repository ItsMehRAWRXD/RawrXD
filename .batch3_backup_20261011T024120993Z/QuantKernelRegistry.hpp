// ============================================================================
// QuantKernelRegistry.hpp - Quantization-agnostic kernel dispatch table.
//
// Replaces the hardcoded if/else/switch chains in Deep2Engine::LinearW with
// a function-pointer table resolved once at loader init.  The execution
// graph calls proxy.dispatch_kernel(...) with zero branches in the hot path.
//
// Supported quant types (resolved at runtime from GGUF tensor metadata):
//   F32, F16, Q4_0, Q4_1, Q5_0, Q5_1, Q8_0, Q8_K,
//   Q2_K, Q3_K, Q4_K, Q5_K, Q6_K,
//   IQ2_XXS, IQ2_XS, IQ3_XXS, IQ3_S, IQ2_S, IQ4_NL, IQ4_XS
//
// Each type maps to:
//   1. A dequant+FMA kernel (AVX-512 preferred, AVX2 fallback, scalar fallback)
//   2. Block geometry (block size, elements per block)
//   3. A stride calculator
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#ifndef DEEP2_QUANT_KERNEL_REGISTRY_HPP
#define DEEP2_QUANT_KERNEL_REGISTRY_HPP

#include "QuantTypeTable.hpp"

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <unordered_map>
#include <atomic>

namespace Deep2 {

// GGMLType is defined in QuantTypeTable.hpp (canonical ggml IDs).

// ---------------------------------------------------------------------------
// Block type structs — must match GGML layout byte-for-byte.
// These are used by the K-quant GEMV kernels in QuantKernelRegistry_K.h.
// ---------------------------------------------------------------------------
#pragma pack(push, 1)

// Q4_0: 32 weights, 1 fp16 scale — 18 bytes total (2+16)
struct block_q4_0 {
    uint16_t d;           // fp16 scale
    uint8_t  qs[16];      // 4-bit weights (32 values, packed 2/byte)
};

// Q4_1: 32 weights, fp16 scale + fp16 min — 20 bytes (2+2+16)
struct block_q4_1 {
    uint16_t d;           // fp16 scale
    uint16_t m;           // fp16 min
    uint8_t  qs[16];      // 4-bit weights
};

// Q5_0: 32 weights, 1 fp16 scale, 4-bit high bit mask — 22 bytes (2+16+4+1... no, actual is 2+4+16+128 bits=4 bytes, total 90? Let me check)
// Actually Q5_0: 32 values, 5 bits each = 160 bits, d (2 bytes), 4 bytes high bits, 16 bytes qs = 22 bytes
struct block_q5_0 {
    uint16_t d;           // fp16 scale
    uint8_t  qh[4];       // high bits (1 per value, 32 bits = 4 bytes)
    uint8_t  qs[16];      // 4 low bits of each value
};

// Q5_1: 32 weights, fp16 scale + fp16 min, 5 bits — 24 bytes
struct block_q5_1 {
    uint16_t d;           // fp16 scale
    uint16_t m;           // fp16 min
    uint8_t  qh[4];       // high bits
    uint8_t  qs[16];      // low 4 bits
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

#pragma pack(pop)

// QK_K: number of weights per K-quant block (256 for llama.cpp K-quants)
constexpr size_t QK_K = 256;

static_assert(sizeof(block_q8_0) == 34, "block_q8_0 must be 34 bytes");
static_assert(sizeof(block_q8_K) == 292, "block_q8_K must be 292 bytes");

// ---------------------------------------------------------------------------
// Universal GEMV kernel signature.
//
//   weight_block_ptr  - raw mmap pointer to the packed weight data
//   activation_ptr    - float* input vector (already dequantized if needed)
//   accumulator_ptr   - float* output vector (accumulated, not overwritten)
//   rows              - number of output rows
//   cols              - number of input columns (inner dimension)
//
// The kernel is responsible for:
//   - iterating over rows
//   - dequantizing each block on the fly
//   - computing the dot product
//   - accumulating into the output
//
// Zero branches in the caller: the function pointer is resolved once.
// ---------------------------------------------------------------------------
#ifdef _MSC_VER
#define RESTRICT __restrict
#else
#define RESTRICT __restrict__
#endif

using GEMVKernelFn = void(*)(
    const uint8_t* RESTRICT weight_block_ptr,
    const float*  RESTRICT activation_ptr,
    float*        RESTRICT accumulator_ptr,
    size_t                        rows,
    size_t                        cols
);

// ---------------------------------------------------------------------------
// Dequantize-only kernel (for embeddings, norms, and non-GEMV paths)
// ---------------------------------------------------------------------------
using DequantKernelFn = void(*)(
    const uint8_t* RESTRICT src,
    float*         RESTRICT dst,
    size_t                        num_elements
);

// ---------------------------------------------------------------------------
// Block geometry descriptor
// ---------------------------------------------------------------------------
struct BlockGeometry {
    size_t blockSize   = 0;  // bytes per block
    size_t elemsPerBlock = 0; // weights per block
    bool   hasScales   = false;
    bool   hasMin      = false;
};

// ---------------------------------------------------------------------------
// UniversalTensorProxy - the normalized execution descriptor.
//
// Created during mmap/load phase.  Carries:
//   - raw pointer into the mmap region
//   - quant type tag
//   - resolved kernel function pointers
//   - block geometry
//
// The execution graph never inspects quant_type; it calls dispatch_kernel.
// ---------------------------------------------------------------------------
struct UniversalTensorProxy {
    const uint8_t* mmapBase    = nullptr;
    size_t         byteOffset  = 0;
    size_t         totalBytes  = 0;
    int            quantType   = 0;  // GGMLType as int
    size_t         rows        = 0;
    size_t         cols        = 0;

    GEMVKernelFn   gemvKernel  = nullptr;
    DequantKernelFn dequantKernel = nullptr;
    BlockGeometry  geometry;

    // Convenience: is this a quantized tensor?
    bool IsQuantized() const;

    // Convenience: get a human-readable type name
    const char* TypeName() const;
};

// ---------------------------------------------------------------------------
// CPU feature flags detected at init
// ---------------------------------------------------------------------------
struct CPUFeatures {
    bool avx512f  = false;
    bool avx512bw = false;
    bool avx512dq = false;
    bool avx512vl = false;
    bool avx512vnni = false;
    bool avx2     = false;
    bool fma      = false;
    bool f16c     = false;
};

// ---------------------------------------------------------------------------
// QuantKernelRegistry - singleton dispatch table
//
// Populated once at engine init by probing CPUID and binding the best
// available kernel for each GGML type.
// ---------------------------------------------------------------------------
class QuantKernelRegistry {
public:
    static QuantKernelRegistry& Instance();

    // Initialize: probe CPU features and populate the dispatch table.
    void Initialize();

    // Register a kernel for a specific quant type
    void RegisterGEMV(int quantType, GEMVKernelFn kernel);
    void RegisterDequant(int quantType, DequantKernelFn kernel);
    void RegisterGeometry(int quantType, const BlockGeometry& geom);

    // Resolve a proxy from raw tensor metadata
    UniversalTensorProxy Resolve(
        const uint8_t* mmapBase,
        size_t byteOffset,
        size_t totalBytes,
        int quantType,
        size_t rows,
        size_t cols
    ) const;

    // Lookup
    GEMVKernelFn   GetGEMV(int quantType) const;
    DequantKernelFn GetDequant(int quantType) const;
    BlockGeometry  GetGeometry(int quantType) const;

    // Diagnostics
    const CPUFeatures& GetCPUFeatures() const { return cpu_; }
    size_t GetRegisteredCount() const { return gemvTable_.size(); }
    std::string DumpTable() const;

    // Batch 21 telemetry counters (thread-safe)
    struct Batch21Counters {
        std::atomic<uint64_t> registryHits{0};
        std::atomic<uint64_t> registryMisses{0};
        std::atomic<uint64_t> scalarFallbacks{0};
        std::atomic<uint64_t> kernelInvocations{0};
        std::atomic<uint64_t> vulkanComputeSubmissions{0};
        std::atomic<uint64_t> vulkanComputeFailures{0};

        void Reset() {
            registryHits = 0;
            registryMisses = 0;
            scalarFallbacks = 0;
            kernelInvocations = 0;
            vulkanComputeSubmissions = 0;
            vulkanComputeFailures = 0;
        }
    };

    Batch21Counters& GetBatch21Counters() { return batch21_; }
    const Batch21Counters& GetBatch21Counters() const { return batch21_; }
    void PrintBatch21Report() const;
    void ResetBatch21Counters() { batch21_.Reset(); }

private:
    QuantKernelRegistry() = default;
    ~QuantKernelRegistry() = default;
    QuantKernelRegistry(const QuantKernelRegistry&) = delete;
    QuantKernelRegistry& operator=(const QuantKernelRegistry&) = delete;

    void ProbeCPU();
    void RegisterBuiltins();

    CPUFeatures cpu_;
    std::unordered_map<int, GEMVKernelFn>     gemvTable_;
    std::unordered_map<int, DequantKernelFn>  dequantTable_;
    std::unordered_map<int, BlockGeometry>   geometryTable_;
    mutable Batch21Counters batch21_;
};

// ---------------------------------------------------------------------------
// Helper: convert GGMLType enum to string
// ---------------------------------------------------------------------------
const char* GGMLTypeName(int type);

// ---------------------------------------------------------------------------
// Helper: get block geometry for a type (static, no registry needed)
// ---------------------------------------------------------------------------
BlockGeometry GetBlockGeometryForType(int quantType);

} // namespace Deep2

#endif // DEEP2_QUANT_KERNEL_REGISTRY_HPP
