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

#include <cstdint>
#include <cstddef>
#include <functional>
#include <string>
#include <unordered_map>

namespace Deep2 {

// ---------------------------------------------------------------------------
// Forward-declare GGMLType to avoid header coupling.
// The underlying type MUST match the definition in GGUFLoader.hpp / MoEWeightsLoader.hpp
// (enum class GGMLType : uint32_t).  A mismatch causes a redefinition error.
// ---------------------------------------------------------------------------
enum class GGMLType : uint32_t;

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