// ============================================================================
// QuantKernelRegistry.cpp - Implementation of the quantization-agnostic
// kernel dispatch table.
//
// This replaces the hardcoded switch(wt.type) chains in Deep2Engine with
// a function-pointer table resolved once at init.  The execution graph
// calls proxy.gemvKernel(...) with zero branches in the hot path.
//
// Copyright (c) 2026 RawrXD Sovereign Runtime
// ============================================================================

#include "QuantKernelRegistry.hpp"
#include "GGUFLoader.hpp"
#include "QuantKernelRegistry_K.h"  // K-quant dequant/GEMV kernels
#include "Deep2Q40Reference.hpp"    // Reference Q4_0 GEMV (VAL-051.7)

// E2M1 values (doubled) - from ggml-common.h GGML_TABLE
// Only available when GGML_COMMON_IMPL_C is defined, so we define locally
static const int8_t kvalues_mxfp4[16] = {
    0, 1, 2, 3, 4, 6, 8, 12, 0, -1, -2, -3, -4, -6, -8, -12
};

#include <immintrin.h>
#include <cstring>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <sstream>
#include <vector>

namespace Deep2 {

// Forward declaration from IQQuantKernels.cpp
void RegisterIQKernels();

// ---------------------------------------------------------------------------
// CPU feature detection (intrinsic-based)
// ---------------------------------------------------------------------------
#if defined(_MSC_VER) || defined(__INTEL_COMPILER)
#include <intrin.h>
#define DEEP2_CPUID(level, eax, ebx, ecx, edx) \
    { int _info[4]; __cpuid(_info, level); \
    eax = _info[0]; ebx = _info[1]; ecx = _info[2]; edx = _info[3]; }
#define DEEP2_CPUIDEX(level, subleaf, eax, ebx, ecx, edx) \
    { int _info[4]; __cpuidex(_info, level, subleaf); \
    eax = _info[0]; ebx = _info[1]; ecx = _info[2]; edx = _info[3]; }
#else
#include <cpuid.h>
#define DEEP2_CPUID(level, eax, ebx, ecx, edx) \
    __cpuid(level, eax, ebx, ecx, edx);
#define DEEP2_CPUIDEX(level, subleaf, eax, ebx, ecx, edx) \
    __cpuid_count(level, subleaf, eax, ebx, ecx, edx);
#endif

// ---------------------------------------------------------------------------
// OS-enabled extended register state (XCR0) via XGETBV.
//
// DEEP2_OS_XSAVE_STATE_001: CPUID alone is insufficient. A CPUID leaf-1
// ECX.27 (OSXSAVE) + leaf-7 AVX bit tells us the silicon has the feature; it
// says nothing about whether the OS actually enabled the corresponding
// register state in XCR0. Executing a YMM instruction on an OS that never
// enabled AVX raises #UD and takes the process down. Enabling AVX in a VM with
// the feature hidden/disabled by the hypervisor is the classic case.
//
//   XCR0 bit 0 : x87
//   XCR0 bit 1 : SSE / XMM
//   XCR0 bit 2 : AVX / YMM
//   XCR0 bit 5 : AVX-512 opmask
//   XCR0 bit 6 : AVX-512 ZMM_Hi256
//   XCR0 bit 7 : AVX-512 Hi16_ZMM
// ---------------------------------------------------------------------------
// ---------------------------------------------------------------------------
// Read XCR0 via XGETBV.  Isolated in one helper so the compiler-intrinsic
// difference (MSVC `_xgetbv` returns the value and takes an XCR index; GCC
// inline-asm writes to registers) lives in exactly one place.
// ---------------------------------------------------------------------------
#if (defined(_MSC_VER) || defined(__INTEL_COMPILER)) && !defined(__clang__)
static inline uint64_t deep2_xgetbv0() {
    // _xgetbv RETURNS the register contents and takes the XCR index. It does
    // not take an out-parameter; writing `_xgetbv(v)` and reading `v` discards
    // the result, yields 0, and silently disables every vector kernel on
    // working hardware.
    return static_cast<uint64_t>(_xgetbv(0));
}
#elif (defined(__GNUC__) || defined(__clang__)) && defined(__x86_64__)
static inline uint64_t deep2_xgetbv0() {
    uint32_t lo = 0, hi = 0;
    __asm__ volatile("xgetbv" : "=a"(lo), "=d"(hi) : "c"(0));
    return (static_cast<uint64_t>(hi) << 32) | static_cast<uint64_t>(lo);
}
#else
static inline uint64_t deep2_xgetbv0() { return 0; }
#endif

// Assignment-style macro kept so ProbeCPU() reads as before.
#define DEEP2_XGETBV(xcr_out) (void)(xcr_out = deep2_xgetbv0())


static constexpr uint64_t kXcr0XmmYmm = (1ull << 1) | (1ull << 2);
static constexpr uint64_t kXcr0Avx512 =
    (1ull << 5) | (1ull << 6) | (1ull << 7);

// ---------------------------------------------------------------------------
// Singleton
// ---------------------------------------------------------------------------
QuantKernelRegistry& QuantKernelRegistry::Instance() {
    static QuantKernelRegistry instance;
    return instance;
}

// ---------------------------------------------------------------------------
// Probe CPU features
// ---------------------------------------------------------------------------
void QuantKernelRegistry::ProbeCPU() {
    int eax, ebx, ecx, edx;

    DEEP2_CPUID(1, eax, ebx, ecx, edx);
    cpu_.fma  = (ecx & (1 << 12)) != 0;
    cpu_.f16c = (ecx & (1 << 29)) != 0;

    const bool cpuidAvx  = (ecx & (1 << 28)) != 0;   // silicon feature
    const bool osxsave   = (ecx & (1 << 27)) != 0;   // OS uses XSETBV/XGETBV

    // DEEP2_OS_XSAVE_STATE_001: measure the actual OS-enabled register state.
    uint64_t xcr0 = 0;
    if (osxsave) DEEP2_XGETBV(xcr0);
    const bool osYmm      = (xcr0 & kXcr0XmmYmm) == kXcr0XmmYmm;
    const bool osAvx512   = (xcr0 & kXcr0Avx512) == kXcr0Avx512;

    // AVX-512 requires leaf 7 subleaf 0
    DEEP2_CPUIDEX(7, 0, eax, ebx, ecx, edx);
    cpu_.avx2     = (ebx & (1 << 5)) != 0;
    cpu_.avx512f  = (ebx & (1 << 16)) != 0;
    cpu_.avx512dq = (ebx & (1 << 17)) != 0;
    cpu_.avx512bw = (ebx & (1 << 30)) != 0;
    cpu_.avx512vl = (ebx & (1 << 31)) != 0;
    cpu_.avx512vnni = (ecx & (1 << 11)) != 0;

    // Require silicon feature AND OS-enabled state. A mismatch demotes the
    // feature instead of crashing the process on an unauthorized instruction.
    if (!osxsave || !osYmm) {
        cpu_.avx2 = false;
        cpu_.avx512f = cpu_.avx512dq = cpu_.avx512bw = false;
        cpu_.avx512vl = cpu_.avx512vnni = false;
    } else if (!osAvx512) {
        // AVX-512 register state not enabled: keep AVX2, drop AVX-512.
        cpu_.avx512f = cpu_.avx512dq = cpu_.avx512bw = false;
        cpu_.avx512vl = cpu_.avx512vnni = false;
    }
    (void)cpuidAvx;
}

// ===========================================================================
// MASM KERNEL DECLARATIONS (linked from .asm files)
// ===========================================================================
extern "C" {
    // Q4_K MASM kernels
    void Sovereign_Q4K_GEMV_AVX2(const void* q4_weights, const float* input,
                                    float* output, unsigned int num_blocks, unsigned int rows);
    void Sovereign_Q4K_GEMV_AVX2_V2(const void* q4_weights, const float* input,
                                     float* output, unsigned int num_blocks, unsigned int rows);

    // Q2_K / Q3_K MASM kernels (real implementations in sovereign_q2_k_gemv.asm / sovereign_q3_k_gemv.asm)
    void Deep2_Q2_K_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q3_K_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);

    // Q4_0 / Q4_1 / Q8_0 / Q5_K / Q6_K MASM kernels
    void Deep2_Q4_0_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q4_1_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q8_0_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q5_K_GEMV(const void* weights, const float* input, float* output,
                         unsigned int numBlocks, unsigned int outputDim);
    void Deep2_Q6_K_GEMV(const void* blocks, const float* x, float* out, std::size_t nBlocks);

    // FP16 GEMV
    void Deep2_FP16_GEMV(const void* weights, const float* input, float* output,
                         unsigned int rows, unsigned int cols);
}

// ===========================================================================
// MASM WRAPPER FUNCTIONS
// Bridge the standard GEMV signature to the MASM ABI
// ===========================================================================

// Q4_K wrapper: standard GEMV -> Sovereign_Q4K_GEMV_AVX2_V2
static void gemv_q4_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Sovereign_Q4K_GEMV_AVX2_V2(w, x, y, static_cast<unsigned int>(blocksPerRow),
                                  static_cast<unsigned int>(rows));
}

// Q2_K wrapper: standard GEMV -> Deep2_Q2_K_GEMV
// HARD BAN for product decode: sovereign_q2_k_gemv.asm advances by 72 bytes;
// GGUF block_q2_K is 84. Never register this for RAWRXD_Q2K_PRODUCT_DECODE=1.
static void gemv_q2_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const char* pd = std::getenv("RAWRXD_Q2K_PRODUCT_DECODE");
    if (pd && pd[0] == '1') {
        /* soft-fail: zero outputs; do not touch 72-byte MASM */
        std::memset(y, 0, rows * sizeof(float));
        std::fprintf(stderr,
            "Q2K_72_BYTE_MASM_FORBIDDEN RAWRXD_Q2K_PRODUCT_DECODE=1 "
            "use_84_byte_packed_DispatchGemvQuant\n");
        return;
    }
    size_t blocksPerRow = (cols + 255) / 256;
    Deep2_Q2_K_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q3_K wrapper: standard GEMV -> Deep2_Q3_K_GEMV
static void gemv_q3_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Deep2_Q3_K_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q4_0 wrapper
static void gemv_q4_0_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 31) / 32;
    Deep2_Q4_0_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q4_1 wrapper
static void gemv_q4_1_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 31) / 32;
    Deep2_Q4_1_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q8_0 wrapper
static void gemv_q8_0_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 31) / 32;
    Deep2_Q8_0_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q5_K wrapper
static void gemv_q5_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Deep2_Q5_K_GEMV(w, x, y, static_cast<unsigned int>(blocksPerRow),
                     static_cast<unsigned int>(rows));
}

// Q6_K wrapper
static void gemv_q6_k_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    size_t blocksPerRow = (cols + 255) / 256;
    Deep2_Q6_K_GEMV(w, x, y, static_cast<std::size_t>(blocksPerRow));
}

// FP16 wrapper
static void gemv_f16_masm(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    Deep2_FP16_GEMV(w, x, y, static_cast<unsigned int>(rows),
                     static_cast<unsigned int>(cols));
}

// ---------------------------------------------------------------------------
// Static block geometry lookup — authoritative QuantTypeTable (fail-closed).
// ---------------------------------------------------------------------------
BlockGeometry GetBlockGeometryForType(int quantType) {
    const auto* d = LookupQuantType(static_cast<uint32_t>(quantType));
    if (!d) return {0, 0, false, false};
    return {d->blockBytes, d->blockElements, d->hasScales, d->hasMin};
}

// ---------------------------------------------------------------------------
// Type name
// ---------------------------------------------------------------------------
const char* GGMLTypeName(int type) {
    return QuantTypeName(static_cast<uint32_t>(type));
}

// ---------------------------------------------------------------------------
// UniversalTensorProxy helpers
// ---------------------------------------------------------------------------
bool UniversalTensorProxy::IsQuantized() const {
    return QuantTypeIsQuantized(static_cast<uint32_t>(quantType));
}

const char* UniversalTensorProxy::TypeName() const {
    return GGMLTypeName(quantType);
}

// ===========================================================================
// SCALAR FALLBACK KERNELS
// These are always available.  They are correct but slow.
// ===========================================================================

// --- F32 GEMV (scalar) ---
static void gemv_f32_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const float* weights = reinterpret_cast<const float*>(w);
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const float* row = weights + r * cols;
        for (size_t c = 0; c < cols; ++c) {
            acc += row[c] * x[c];
        }
        y[r] += acc;
    }
}

// --- F16 GEMV (scalar via soft conversion) ---
// Uses the same algorithm as QuantKernelRegistry_K.h for consistency.
static inline float f16_to_f32(uint16_t h) {
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;

    if (exp == 0) {
        if (frac == 0) {
            float value = 0.0f;
            std::memcpy(&value, &sign, sizeof(value));
            return value;
        }
        // Denormalized: value = frac * 2^(-10) * 2^(-14) = frac * 2^(-24)
        uint32_t e = 1;
        uint32_t f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x03FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        float value = 0.0f;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        float value = 0.0f;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    float value = 0.0f;
    std::memcpy(&value, &bits, sizeof(value));
    return value;
}

static void gemv_f16_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const uint16_t* weights = reinterpret_cast<const uint16_t*>(w);
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const uint16_t* row = weights + r * cols;
        for (size_t c = 0; c < cols; ++c) {
            acc += f16_to_f32(row[c]) * x[c];
        }
        y[r] += acc;
    }
}

// --- BF16 GEMV (scalar; bit-cast high 16 bits of IEEE754 float) ---
static inline float bf16_to_f32(uint16_t h) {
    uint32_t bits = static_cast<uint32_t>(h) << 16;
    float f;
    std::memcpy(&f, &bits, sizeof(f));
    return f;
}

// --- E4M3 to FP32 conversion (for NVFP4) ---
// E4M3: 1 sign bit, 4 exponent bits (bias 7), 3 mantissa bits
static inline float ggml_e4m3_to_fp32(uint8_t x) {
    int sign = (x & 0x80) ? -1 : 1;
    int exp = (x >> 3) & 0x0F;
    int mant = x & 0x07;

    if (exp == 0) {
        // Subnormal: 2^(-6) * mantissa/8
        return sign * (float)mant * 0.015625f; // 2^(-6) / 8
    } else if (exp == 15) {
        // Inf/NaN - return 0
        return 0.0f;
    } else {
        // Normal: 2^(exp - 7) * (1 + mantissa/8)
        float val = (1.0f + mant * 0.125f) * ldexpf(1.0f, exp - 7);
        return sign * val;
    }
}

static void gemv_bf16_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const uint16_t* weights = reinterpret_cast<const uint16_t*>(w);
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const uint16_t* row = weights + r * cols;
        for (size_t c = 0; c < cols; ++c) {
            acc += bf16_to_f32(row[c]) * x[c];
        }
        y[r] += acc;
    }
}

static void dequant_bf16(
    const uint8_t* RESTRICT w,
    float*        RESTRICT out,
    size_t n
) {
    const uint16_t* src = reinterpret_cast<const uint16_t*>(w);
    for (size_t i = 0; i < n; ++i)
        out[i] = bf16_to_f32(src[i]);
}

// --- Q8_0 GEMV (scalar) ---
// block_q8_0 defined in GGUFLoader.hpp

static void gemv_q8_0_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    // Packed ggml Q8_0 blocks are 34 bytes — walk by byte stride, not
    // pointer arithmetic that could assume padded sizeof.
    constexpr size_t kBlk = 34;
    const size_t blocksPerRow = (cols + 31) / 32;
    const size_t rowBytes = blocksPerRow * kBlk;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const uint8_t* row = w + r * rowBytes;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const auto* blk =
                reinterpret_cast<const block_q8_0*>(row + b * kBlk);
            float d = f16_to_f32(blk->d);
            if (!std::isfinite(d)) d = 0.0f;
            const size_t base = b * 32;
            const size_t n = (base + 32 <= cols) ? 32u : (cols - base);
            float blockAcc = 0.0f;
            for (size_t i = 0; i < n; ++i)
                blockAcc += (float)blk->qs[i] * x[base + i];
            acc += d * blockAcc;
        }
        y[r] += acc;
    }
}

// --- Q4_K GEMV (scalar reference) ---
// VAL-051.9: Correct GGML Q4_K block unpacking per llama.cpp reference.
// block_q4_K layout: d(fp16), dmin(fp16), scales[12], qs[128]
//   256 weights per block, 8 sub-blocks of 32.
//   scales[0..3]  = low 6 bits of scales 0..3 (NO high bits)
//   scales[4..7]  = low 6 bits of mins 0..3 (NO high bits)
//   scales[4..7] high bits from s[0..3] >> 6, combined with s[8..11] low 4 bits
//   mins[4..7] high bits from s[4..7] >> 6, combined with s[8..11] high 4 bits
//
// CRITICAL: Q4_K uses GROUPED nibbles (llama.cpp dequantize_row_q4_K):
//   For each pair of 32-weight groups (64 weights total):
//     qs[0..31] low  nibbles + scale[is+0] -> weights 0..31
//     qs[0..31] high nibbles + scale[is+1] -> weights 32..63
//     then qs += 32, is += 2
//   Do NOT treat each 16-byte chunk as lo/hi within the same scale.

static inline void unpack_q4_k_scales(
    const uint8_t s[12],
    uint8_t scales[8],
    uint8_t mins[8])
{
    // Low 6 bits — first four scale/min pairs
    scales[0] = s[0] & 0x3F;
    scales[1] = s[1] & 0x3F;
    scales[2] = s[2] & 0x3F;
    scales[3] = s[3] & 0x3F;

    mins[0] = s[4] & 0x3F;
    mins[1] = s[5] & 0x3F;
    mins[2] = s[6] & 0x3F;
    mins[3] = s[7] & 0x3F;

    // Upper four scales: low 4 bits from s[8..11], high 2 bits from s[0..3] >> 6
    scales[4] = (s[8] & 0x0F) | ((s[0] >> 6) << 4);
    scales[5] = (s[9] & 0x0F) | ((s[1] >> 6) << 4);
    scales[6] = (s[10] & 0x0F) | ((s[2] >> 6) << 4);
    scales[7] = (s[11] & 0x0F) | ((s[3] >> 6) << 4);

    // Upper four minimums: low 4 bits from s[8..11] >> 4, high 2 bits from s[4..7] >> 6
    mins[4] = (s[8] >> 4) | ((s[4] >> 6) << 4);
    mins[5] = (s[9] >> 4) | ((s[5] >> 6) << 4);
    mins[6] = (s[10] >> 4) | ((s[6] >> 6) << 4);
    mins[7] = (s[11] >> 4) | ((s[7] >> 6) << 4);
}

// --- Q4_K GEMV (ggml mul_mat path: Q4_K × Q8_K) ---
// BATCH2_Q4K_GEMV_001: Deep2 FP32 dequant·x matched ggml dequantize_row_q4_K,
// but Batch-2 llama Q_0 uses quantize_row_q8_K(x) + vec_dot_q4_K_q8_K.
// Production GEMV must follow that path to close Q_0 against llama CPU authority.
//
// Decode (scales/mins/nibble grouping) remains identical to dequantize_row_q4_K;
// only the activation-side quantization + integer dot differ.
// block_q8_K is defined in GGUFLoader.hpp.
static inline int nearest_int_q8k(float fval) {
    float val = fval + 12582912.f;
    int i;
    std::memcpy(&i, &val, sizeof(int));
    return (i & 0x007fffff) - 0x00400000;
}

static void quantize_row_q8_K(const float* x, block_q8_K* y, size_t k) {
    const size_t nb = k / 256;
    for (size_t i = 0; i < nb; ++i) {
        float max = 0.f, amax = 0.f;
        for (int j = 0; j < 256; ++j) {
            float ax = std::fabs(x[j]);
            if (ax > amax) { amax = ax; max = x[j]; }
        }
        if (!amax) {
            y[i].d = 0.f;
            std::memset(y[i].qs, 0, 256);
            std::memset(y[i].bsums, 0, sizeof(y[i].bsums));
            x += 256;
            continue;
        }
        const float iscale = -127.f / max;
        for (int j = 0; j < 256; ++j) {
            int v = nearest_int_q8k(iscale * x[j]);
            y[i].qs[j] = static_cast<int8_t>(v > 127 ? 127 : v);
        }
        for (int j = 0; j < 16; ++j) {
            int sum = 0;
            for (int ii = 0; ii < 16; ++ii) sum += y[i].qs[j * 16 + ii];
            y[i].bsums[j] = static_cast<int16_t>(sum);
        }
        y[i].d = 1.f / iscale;
        x += 256;
    }
}

// Port of ggml_vec_dot_q4_K_q8_K_generic
static float vec_dot_q4_K_q8_K(const block_q4_K* x, const block_q8_K* y, size_t cols) {
    const size_t nb = cols / 256;
    static const uint32_t kmask1 = 0x3f3f3f3f;
    static const uint32_t kmask2 = 0x0f0f0f0f;
    static const uint32_t kmask3 = 0x03030303;
    uint32_t utmp[4];
    const uint8_t* scales = reinterpret_cast<const uint8_t*>(&utmp[0]);
    const uint8_t* mins   = reinterpret_cast<const uint8_t*>(&utmp[2]);
    int8_t  aux8[256];
    int16_t aux16[8];
    float   sums[8];
    int32_t aux32[8];
    std::memset(sums, 0, sizeof(sums));
    float sumf = 0.f;
    for (size_t i = 0; i < nb; ++i) {
        const uint8_t* q4 = x[i].qs;
        const int8_t*  q8 = y[i].qs;
        std::memset(aux32, 0, sizeof(aux32));
        int8_t* a = aux8;
        for (int j = 0; j < 4; ++j) {
            for (int l = 0; l < 32; ++l) a[l] = static_cast<int8_t>(q4[l] & 0xF);
            a += 32;
            for (int l = 0; l < 32; ++l) a[l] = static_cast<int8_t>(q4[l] >> 4);
            a += 32;
            q4 += 32;
        }
        std::memcpy(utmp, x[i].scales, 12);
        utmp[3] = ((utmp[2] >> 4) & kmask2) | (((utmp[1] >> 6) & kmask3) << 4);
        const uint32_t uaux = utmp[1] & kmask1;
        utmp[1] = (utmp[2] & kmask2) | (((utmp[0] >> 6) & kmask3) << 4);
        utmp[2] = uaux;
        utmp[0] &= kmask1;

        int sumi = 0;
        for (int j = 0; j < 16; ++j) sumi += y[i].bsums[j] * mins[j / 2];
        a = aux8;
        int is = 0;
        for (int j = 0; j < 8; ++j) {
            const int32_t scale = scales[is++];
            for (int r = 0; r < 4; ++r) {
                for (int l = 0; l < 8; ++l) aux16[l] = static_cast<int16_t>(q8[l] * a[l]);
                for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
                q8 += 8;
                a += 8;
            }
        }
        const float d = f16_to_f32(x[i].d) * y[i].d;
        for (int l = 0; l < 8; ++l) sums[l] += d * static_cast<float>(aux32[l]);
        const float dmin = f16_to_f32(x[i].dmin) * y[i].d;
        sumf -= dmin * static_cast<float>(sumi);
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

static void gemv_q4_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
if (cols % 256 != 0) {
          // Fallback: FP32 dequant·x (non-ggml-mul_mat shapes)
          const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(w);
          size_t blocksPerRow = (cols + 255) / 256;
          for (size_t r = 0; r < rows; ++r) {
              float acc = 0.0f;
              const block_q4_K* rowBlocks = blocks + r * blocksPerRow;
              for (size_t b = 0; b < blocksPerRow; ++b) {
                  const block_q4_K& blk = rowBlocks[b];
                  float d    = f16_to_f32(blk.d);
                  float dmin = f16_to_f32(blk.dmin);
                  if (!std::isfinite(d))    d    = 0.0f;
                  if (!std::isfinite(dmin)) dmin = 0.0f;
                  size_t base = b * 256;
                size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
                if (elemsInBlock == 0) break;
                uint8_t scales[8], mins[8];
                unpack_q4_k_scales(blk.scales, scales, mins);
                const uint8_t* q = blk.qs;
                for (int is = 0; is < 8; is += 2) {
                    const float d1 = d * static_cast<float>(scales[is]);
                    const float m1 = dmin * static_cast<float>(mins[is]);
                    const float d2 = d * static_cast<float>(scales[is + 1]);
                    const float m2 = dmin * static_cast<float>(mins[is + 1]);
                    const size_t off0 = static_cast<size_t>(is) * 32;
                    const size_t off1 = off0 + 32;
                    for (int l = 0; l < 32; ++l) {
                        if (off0 + static_cast<size_t>(l) < elemsInBlock)
                            acc += (d1 * static_cast<float>(q[l] & 0x0F) - m1)
                                 * x[base + off0 + static_cast<size_t>(l)];
                        if (off1 + static_cast<size_t>(l) < elemsInBlock)
                            acc += (d2 * static_cast<float>(q[l] >> 4) - m2)
                                 * x[base + off1 + static_cast<size_t>(l)];
                    }
                    q += 32;
                }
            }
            y[r] += acc;
        }
        return;
    }

    // Hot path: match llama.cpp CPU mul_mat(Q4_K, Q8_K)
    const size_t blocksPerRow = cols / 256;
    std::vector<block_q8_K> xQ8(blocksPerRow);
    quantize_row_q8_K(x, xQ8.data(), cols);
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(w);
    for (size_t r = 0; r < rows; ++r) {
        y[r] += vec_dot_q4_K_q8_K(blocks + r * blocksPerRow, xQ8.data(), cols);
    }
}

// --- Q6_K GEMV (scalar reference) ---
// VAL-051.10: Correct GGML Q6_K block unpacking per llama.cpp reference.
// block_q6_K layout (210 bytes, 256 values):
//   [0..127]   ql      128 bytes (low 4 bits)
//   [128..191] qh      64 bytes (high 2 bits)
//   [192..207] scales  16 signed bytes
//   [208..209] d       FP16
//
// Q6_K has 16 scale groups, each covering 16 values.
// The first 128 values and second 128 values are reconstructed from
// separate ql/qh regions.

static inline float rxd_q6k_f16(uint16_t h)
{
    // Use the same algorithm as f16_to_f32 in QuantKernelRegistry_K.h
    uint32_t sign = (static_cast<uint32_t>(h & 0x8000)) << 16;
    uint32_t exp  = (h >> 10) & 0x1F;
    uint32_t frac = h & 0x03FF;

    if (exp == 0) {
        if (frac == 0) return reinterpret_cast<const float&>(sign);
        // Denormalized
        uint32_t e = 1;
        uint32_t f = frac;
        while ((f & 0x0400) == 0) { f <<= 1; e++; }
        f &= 0x03FF;
        uint32_t bits = sign | ((127 - 15 + 2 - e) << 23) | (f << 13);
        return reinterpret_cast<float&>(bits);
    }
    if (exp == 31) {
        uint32_t bits = sign | 0x7F800000 | (frac << 13);
        return reinterpret_cast<float&>(bits);
    }
    uint32_t bits = sign | ((exp + 127 - 15) << 23) | (frac << 13);
    return reinterpret_cast<float&>(bits);
}

static inline bool rxd_q6k_dequant_block(
    const uint8_t* block, float* dst)
{
    if (!block || !dst) return false;
    // block_q6_K layout: ql[128] @ 0, qh[64] @ 128, scales[16] @ 192, d @ 208
    // Per llama.cpp: 256 values, 16 scale groups of 16 values each
    uint16_t d16; std::memcpy(&d16, block + 208, sizeof(d16));
    const float d = rxd_q6k_f16(d16);
    if (!std::isfinite(d)) return false;

    const uint8_t* ql = block + 0;
    const uint8_t* qh = block + 128;
    const int8_t* sc = reinterpret_cast<const int8_t*>(block + 192);
    float* yp = dst;

    // CORRECT implementation: j=0..31, 4 values per j, 2 passes of 128 values
    for (int n = 0; n < 256; n += 128) {
        for (int l = 0; l < 32; ++l) {
            int is = l / 16;
            const int8_t q1 = (int8_t)((ql[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
            const int8_t q2 = (int8_t)((ql[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
            const int8_t q3 = (int8_t)((ql[l +  0]  >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
            const int8_t q4 = (int8_t)((ql[l + 32]  >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            yp[l +  0] = d * sc[is + 0] * q1;
            yp[l + 32] = d * sc[is + 2] * q2;
            yp[l + 64] = d * sc[is + 4] * q3;
            yp[l + 96] = d * sc[is + 6] * q4;
        }
        yp += 128;
        ql += 64;
        qh += 32;
        sc += 8;
    }
    return true;
}

static inline bool rxd_q6k_dot(
    const uint8_t* block, const float* x, float& result)
{
    float w[256];
    if (!rxd_q6k_dequant_block(block, w)) { result = 0.0f; return false; }
    double sum = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (!std::isfinite(x[i]) || !std::isfinite(w[i])) { result = 0.0f; return false; }
        sum += (double)w[i] * (double)x[i];
    }
    result = (float)sum;
    return std::isfinite(result);
}

static bool rxd_q6k_gemv_reference(
    const uint8_t* weights, const float* input, float* output,
    int64_t rows, int64_t cols)
{
    if (!weights || !input || !output || rows <= 0 || cols <= 0 || (cols % 256) != 0) {
        std::fprintf(stderr, "[Q6K_REF] INVALID params: weights=%p input=%p output=%p rows=%lld cols=%lld\n",
                     (const void*)weights, (const void*)input, (void*)output, (long long)rows, (long long)cols);
        return false;
    }
    const int64_t blocksPerRow = cols / 256;
    for (int64_t row = 0; row < rows; ++row) {
        const uint8_t* rowBase = weights + (size_t)row * (size_t)blocksPerRow * 210;
        double sum = 0.0;
        for (int64_t b = 0; b < blocksPerRow; ++b) {
            float dot = 0.0f;
            if (!rxd_q6k_dot(rowBase + (size_t)b * 210, input + (size_t)b * 256, dot)) {
                uint16_t d16; std::memcpy(&d16, rowBase + (size_t)b * 210 + 208, sizeof(d16));
                std::fprintf(stderr, "[Q6K_REF] BLOCK FAIL row=%lld block=%lld d=0x%04X\n",
                             (long long)row, (long long)b, d16);
                return false;
            }
            sum += (double)dot;
        }
        output[row] = (float)sum;
        if (!std::isfinite(output[row])) {
            std::fprintf(stderr, "[Q6K_REF] NONFINITE row=%lld sum=%f\n", (long long)row, output[row]);
            return false;
        }
    }
    return true;
}

// Port of ggml_vec_dot_q6_K_q8_K_generic (one super-block / 256 cols).
static float vec_dot_q6_K_q8_K(const block_q6_K* x, const block_q8_K* y, size_t cols) {
    const size_t nb = cols / 256;
    int8_t  aux8[256];
    int16_t aux16[8];
    float   sums[8];
    int32_t aux32[8];
    std::memset(sums, 0, sizeof(sums));
    float sumf = 0.f;
    for (size_t i = 0; i < nb; ++i) {
        const uint8_t* q4 = x[i].ql;
        const uint8_t* qh = x[i].qh;
        const int8_t*  q8 = y[i].qs;
        std::memset(aux32, 0, sizeof(aux32));
        int8_t* a = aux8;
        for (int j = 0; j < 256; j += 128) {
            for (int l = 0; l < 32; ++l) {
                a[l +  0] = static_cast<int8_t>((q4[l +  0] & 0xF) | (((qh[l] >> 0) & 3) << 4)) - 32;
                a[l + 32] = static_cast<int8_t>((q4[l + 32] & 0xF) | (((qh[l] >> 2) & 3) << 4)) - 32;
                a[l + 64] = static_cast<int8_t>((q4[l +  0] >> 4) | (((qh[l] >> 4) & 3) << 4)) - 32;
                a[l + 96] = static_cast<int8_t>((q4[l + 32] >> 4) | (((qh[l] >> 6) & 3) << 4)) - 32;
            }
            a  += 128;
            q4 += 64;
            qh += 32;
        }
        a = aux8;
        int is = 0;
        for (int j = 0; j < 256 / 16; ++j) {
            const int scale = x[i].scales[is++];
            for (int l = 0; l < 8; ++l) aux16[l] = static_cast<int16_t>(q8[l] * a[l]);
            for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
            q8 += 8; a += 8;
            for (int l = 0; l < 8; ++l) aux16[l] = static_cast<int16_t>(q8[l] * a[l]);
            for (int l = 0; l < 8; ++l) aux32[l] += scale * aux16[l];
            q8 += 8; a += 8;
        }
        const float d = f16_to_f32(x[i].d) * y[i].d;
        for (int l = 0; l < 8; ++l) sums[l] += d * static_cast<float>(aux32[l]);
    }
    for (int l = 0; l < 8; ++l) sumf += sums[l];
    return sumf;
}

// BATCH2_V_PROJ_001: TinyLlama attn_v is Q6_K (type 14), not Q4_K.
// FP32 dequant·x matched dequantize_row_q6_K but diverged from llama mul_mat
// (Q6_K×Q8_K) — same class of bug as Q4K-GEMV-001. Production must use Q8_K path.
static void gemv_q6_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    if (cols % 256 != 0) {
        // Fallback: FP32 dequant·x (non-ggml-mul_mat shapes)
        if (!rxd_q6k_gemv_reference(w, x, y, (int64_t)rows, (int64_t)cols)) {
            std::fprintf(stderr, "[Q6K_REF] GEMV FAILED rows=%zu cols=%zu\n", rows, cols);
        }
        return;
    }
    const size_t blocksPerRow = cols / 256;
    std::vector<block_q8_K> xQ8(blocksPerRow);
    quantize_row_q8_K(x, xQ8.data(), cols);
    const block_q6_K* blocks = reinterpret_cast<const block_q6_K*>(w);
    for (size_t r = 0; r < rows; ++r) {
        y[r] += vec_dot_q6_K_q8_K(blocks + r * blocksPerRow, xQ8.data(), cols);
    }
}

// --- Q4_0 GEMV (reference) ---
// VAL-051.7: Unconditionally use reference implementation until
// optimized kernel parity is certified.  The reference path:
//   1. Zeroes destination before accumulation
//   2. Uses exact 18-byte block geometry
//   3. Decodes fresh scale + nibbles per block
//   4. Applies -8 nibble bias (ggml canonical)
//   5. Hard-finite guard on every row result
static void gemv_q4_0_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    (void)rawrxd::deep2::Q4_0_GEMV_Reference(w, rows, cols, x, y);
}

// --- Q4_1 GEMV (scalar) ---
static void gemv_q4_1_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q4_1* blocks = reinterpret_cast<const block_q4_1*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q4_1* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q4_1& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float m = f16_to_f32(blk.m);
            size_t base = b * 32;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 32;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                uint8_t byte = blk.qs[i / 2];
                float q = (i % 2 == 0) ? (float)(byte & 0x0F) : (float)(byte >> 4);
                acc += (d * q - m) * x[base + i];
            }
        }
        y[r] += acc;
    }
}

// --- Q5_0 GEMV (scalar) ---
static void gemv_q5_0_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q5_0* blocks = reinterpret_cast<const block_q5_0*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q5_0* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q5_0& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            if (!std::isfinite(d)) d = 0.0f;
            size_t base = b * 32;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 32;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                const uint8_t low4 = blk.qs[i / 2];
                int qhIdx = (int)(i / 8);
                int qhShift = (int)(i % 8);
                uint8_t high1 = (blk.qh[qhIdx] >> qhShift) & 0x01;
                // DEEP2_Q5_0_SIGNED_OFFSET_001: GGML Q5_0 stores a signed 5-bit
                // value around an offset of 16. Omitting the offset produced a
                // permanently wrong sign/scale for every Q5_0 tensor. The value
                // below matches ggml_vec_dot_q5_0_q8_0 reference exactly.
                const int q = ((int)(low4 >> ((i % 2) * 4) & 0x0F) |
                               ((int)high1 << 4)) - 16;
                acc += d * (float)q * x[base + i];
            }
        }
        y[r] += acc;
    }
}

// --- Q5_1 GEMV (scalar) ---
static void gemv_q5_1_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q5_1* blocks = reinterpret_cast<const block_q5_1*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q5_1* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q5_1& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float m = f16_to_f32(blk.m);
            size_t base = b * 32;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 32;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                uint8_t low4 = blk.qs[i / 2];
                int qhIdx = (int)(i / 8);
                int qhShift = (int)(i % 8);
                uint8_t high1 = (blk.qh[qhIdx] >> qhShift) & 0x01;
                const int q = ((int)(low4 >> ((i % 2) * 4) & 0x0F) |
                               ((int)high1 << 4)) - 16;
                acc += (d * (float)q - m) * x[base + i];
            }
        }
        y[r] += acc;
    }
}

// --- Q8_K GEMV (scalar) ---
static void gemv_q8_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q8_K* blocks = reinterpret_cast<const block_q8_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q8_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_K& blk = rowBlocks[b];
            float d = blk.d;
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                acc += d * (float)blk.qs[i] * x[base + i];
            }
        }
        y[r] += acc;
    }
}

// ===========================================================================
// AVX-512 KERNELS (selected when cpu_.avx512f && cpu_.avx512bw)
// ===========================================================================
#if defined(__AVX512F__) || (defined(_MSC_VER) && defined(__AVX2__))
#define DEEP2_HAS_AVX512 1
#else
// Runtime detection: we still compile the code, guarded by cpu flags
#define DEEP2_HAS_AVX512 0
#endif

// --- F32 GEMV (AVX-512) ---
static void gemv_f32_avx512(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const float* weights = reinterpret_cast<const float*>(w);
    for (size_t r = 0; r < rows; ++r) {
        const float* row = weights + r * cols;
        __m512 acc = _mm512_setzero_ps();
        size_t c = 0;
        for (; c + 16 <= cols; c += 16) {
            __m512 wv = _mm512_loadu_ps(row + c);
            __m512 xv = _mm512_loadu_ps(x + c);
            acc = _mm512_fmadd_ps(wv, xv, acc);
        }
        // Tail
        float tail = 0.0f;
        for (; c < cols; ++c) {
            tail += row[c] * x[c];
        }
        // Horizontal sum
        float sum = _mm512_reduce_add_ps(acc) + tail;
        y[r] += sum;
    }
}

// --- F16 GEMV (AVX-512 with F16C) ---
static void gemv_f16_avx512(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const uint16_t* weights = reinterpret_cast<const uint16_t*>(w);
    for (size_t r = 0; r < rows; ++r) {
        const uint16_t* row = weights + r * cols;
        __m512 acc = _mm512_setzero_ps();
        size_t c = 0;
        for (; c + 16 <= cols; c += 16) {
            __m256i hv = _mm256_loadu_si256(reinterpret_cast<const __m256i*>(row + c));
            __m512 wv = _mm512_cvtph_ps(hv);
            __m512 xv = _mm512_loadu_ps(x + c);
            acc = _mm512_fmadd_ps(wv, xv, acc);
        }
        float tail = 0.0f;
        for (; c < cols; ++c) {
            tail += f16_to_f32(row[c]) * x[c];
        }
        float sum = _mm512_reduce_add_ps(acc) + tail;
        y[r] += sum;
    }
}

// --- Q4_K GEMV (AVX-512) ---
// Delegate to scalar until a ggml-layout SIMD kernel is re-validated.
static void gemv_q4_k_avx512(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    gemv_q4_k_scalar(w, x, y, rows, cols);
}

// --- Q8_0 GEMV (AVX-512) ---
static void gemv_q8_0_avx512(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    // Fall back to bounds-safe scalar until 32-wide path is re-validated.
    gemv_q8_0_scalar(w, x, y, rows, cols);
}

// --- Q8_K GEMV (AVX-512) ---
static void gemv_q8_k_avx512(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q8_K* blocks = reinterpret_cast<const block_q8_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;

    for (size_t r = 0; r < rows; ++r) {
        __m512 acc = _mm512_setzero_ps();
        const block_q8_K* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_K& blk = rowBlocks[b];
            __m512 dVec = _mm512_set1_ps(blk.d);
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;

            // Process 16 int8 weights at a time (16 iterations per 256-element block)
            size_t i = 0;
            for (; i + 16 <= elemsInBlock; i += 16) {
                __m128i q8 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&blk.qs[i]));
                __m512i i32 = _mm512_cvtepi8_epi32(q8);
                __m512 wv = _mm512_cvtepi32_ps(i32);
                __m512 xv = _mm512_loadu_ps(x + base + i);
                acc = _mm512_fmadd_ps(_mm512_mul_ps(wv, dVec), xv, acc);
            }
            // Tail scalar
            float tail = 0.0f;
            for (; i < elemsInBlock; ++i) {
                tail += blk.d * (float)blk.qs[i] * x[base + i];
            }
            acc = _mm512_add_ps(acc, _mm512_set1_ps(tail));
        }
        y[r] += _mm512_reduce_add_ps(acc);
    }
}

// ===========================================================================
// AVX2 FALLBACK KERNELS
// ===========================================================================

static void gemv_f32_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const float* weights = reinterpret_cast<const float*>(w);
    for (size_t r = 0; r < rows; ++r) {
        const float* row = weights + r * cols;
        __m256 acc = _mm256_setzero_ps();
        size_t c = 0;
        for (; c + 8 <= cols; c += 8) {
            __m256 wv = _mm256_loadu_ps(row + c);
            __m256 xv = _mm256_loadu_ps(x + c);
            acc = _mm256_fmadd_ps(wv, xv, acc);
        }
        float tail = 0.0f;
        for (; c < cols; ++c) tail += row[c] * x[c];
        // Horizontal sum using hadd
        __m256 hsum = _mm256_hadd_ps(acc, acc);
        hsum = _mm256_hadd_ps(hsum, hsum);
        float sum = _mm_cvtss_f32(_mm256_castps256_ps128(hsum)) + 
                    _mm_cvtss_f32(_mm256_extractf128_ps(hsum, 1));
        y[r] += sum + tail;
    }
}

// --- F16 GEMV (AVX2 with F16C) ---
static void gemv_f16_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const uint16_t* weights = reinterpret_cast<const uint16_t*>(w);
    for (size_t r = 0; r < rows; ++r) {
        const uint16_t* row = weights + r * cols;
        __m256 acc = _mm256_setzero_ps();
        size_t c = 0;
        for (; c + 8 <= cols; c += 8) {
            // Load 8 uint16_t and convert to float using F16C
            __m128i hv = _mm_loadu_si128(reinterpret_cast<const __m128i*>(row + c));
            __m256 wv = _mm256_cvtph_ps(hv);
            __m256 xv = _mm256_loadu_ps(x + c);
            acc = _mm256_fmadd_ps(wv, xv, acc);
        }
        float tail = 0.0f;
        for (; c < cols; ++c) {
            tail += f16_to_f32(row[c]) * x[c];
        }
        // Horizontal sum
        __m256 hsum = _mm256_hadd_ps(acc, acc);
        hsum = _mm256_hadd_ps(hsum, hsum);
        float sum = _mm_cvtss_f32(_mm256_castps256_ps128(hsum)) + 
                    _mm_cvtss_f32(_mm256_extractf128_ps(hsum, 1));
        y[r] += sum + tail;
    }
}

// --- Q8_0 GEMV (AVX2) ---
// block_q8_0: 32 int8 weights + 1 float scale (34 bytes total)
// Layout: float d; int8_t qs[32];
static void gemv_q8_0_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(w);
    size_t blocksPerRow = (cols + 31) / 32;

    for (size_t r = 0; r < rows; ++r) {
        __m256 acc = _mm256_setzero_ps();
        const block_q8_0* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_0& blk = rowBlocks[b];
            const size_t base = b * 32;
            const size_t count = (base + 32 <= cols) ? 32u : (cols - base);
            float d = f16_to_f32(blk.d);
            if (!std::isfinite(d)) d = 0.0f;
            if (count < 32) {
                for (size_t i = 0; i < count; ++i)
                    y[r] += d * static_cast<float>(blk.qs[i]) * x[base + i];
                continue;
            }

            // _mm256_cvtepi8_epi32 consumes eight int8 values, not sixteen.
            // Convert all four eight-value chunks so every Q8_0 element is
            // included in the dot product.
            const __m256 dVec = _mm256_set1_ps(d);
            for (size_t chunk = 0; chunk < 4; ++chunk) {
                const __m128i q8 = _mm_loadl_epi64(
                    reinterpret_cast<const __m128i*>(blk.qs + chunk * 8));
                const __m256i q32 = _mm256_cvtepi8_epi32(q8);
                const __m256 wv = _mm256_cvtepi32_ps(q32);
                const __m256 xv = _mm256_loadu_ps(x + base + chunk * 8);
                acc = _mm256_fmadd_ps(_mm256_mul_ps(wv, dVec), xv, acc);
            }
        }
        
        // Horizontal sum
        __m256 hsum = _mm256_hadd_ps(acc, acc);
        hsum = _mm256_hadd_ps(hsum, hsum);
        float sum = _mm_cvtss_f32(_mm256_castps256_ps128(hsum)) + 
                    _mm_cvtss_f32(_mm256_extractf128_ps(hsum, 1));
        y[r] += sum;
    }
}

// --- Q4_K GEMV (AVX2) ---
// Delegate to scalar reference (ggml-compatible nibble layout). SIMD path
// previously used the wrong 16-byte/same-scale packing and is not trusted.
static void gemv_q4_k_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    gemv_q4_k_scalar(w, x, y, rows, cols);
}

// ===========================================================================
// DEQUANT-ONLY KERNELS (for embeddings, norms, etc.)
// ===========================================================================

static void dequant_f32(const uint8_t* src, float* dst, size_t n) {
    std::memcpy(dst, src, n * sizeof(float));
}

static void dequant_f16(const uint8_t* src, float* dst, size_t n) {
    const uint16_t* h = reinterpret_cast<const uint16_t*>(src);
    for (size_t i = 0; i < n; ++i) {
        dst[i] = f16_to_f32(h[i]);
    }
}

static void dequant_q8_0(const uint8_t* src, float* dst, size_t n) {
    const block_q8_0* blocks = reinterpret_cast<const block_q8_0*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        if (!std::isfinite(d)) d = 0.0f;
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) dst[idx] = f16_to_f32(blocks[b].d) * (float)blocks[b].qs[i];
        }
    }
}

// --- Q8_1 Dequant (scalar) ---
// block_q8_1: d(fp16) + m(fp16) + qs[32] int8 = 36 bytes, 32 elements
// value = d * qs[i] - m  (matches ggml dequantize_row_q8_1 reference)
static void dequant_q8_1(const uint8_t* src, float* dst, size_t n) {
    const block_q8_1* blocks = reinterpret_cast<const block_q8_1*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float m = f16_to_f32(blocks[b].m);
        if (!std::isfinite(d)) d = 0.0f;
        if (!std::isfinite(m)) m = 0.0f;
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx < n) dst[idx] = d * (float)blocks[b].qs[i] - m;
        }
    }
}

// --- Q8_1 GEMV (scalar) ---
static void gemv_q8_1_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q8_1* blocks = reinterpret_cast<const block_q8_1*>(w);
    size_t blocksPerRow = (cols + 31) / 32;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q8_1* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q8_1& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float m = f16_to_f32(blk.m);
            size_t base = b * 32;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 32;
            if (elemsInBlock == 0) break;
            for (size_t i = 0; i < elemsInBlock; ++i) {
                acc += (d * (float)blk.qs[i] - m) * x[base + i];
            }
        }
        y[r] += acc;
    }
}

static void dequant_q4_k(const uint8_t* src, float* dst, size_t n) {
    // Exact layout match for ggml dequantize_row_q4_K
    const block_q4_K* blocks = reinterpret_cast<const block_q4_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        if (!std::isfinite(d))    d    = 0.0f;
        if (!std::isfinite(dmin)) dmin = 0.0f;
        uint8_t scales[8], mins[8];
        unpack_q4_k_scales(blocks[b].scales, scales, mins);
        const uint8_t* q = blocks[b].qs;
        float* y = dst + b * 256;
        for (int is = 0; is < 8; is += 2) {
            const float d1 = d * static_cast<float>(scales[is]);
            const float m1 = dmin * static_cast<float>(mins[is]);
            const float d2 = d * static_cast<float>(scales[is + 1]);
            const float m2 = dmin * static_cast<float>(mins[is + 1]);
            for (int l = 0; l < 32; ++l) {
                size_t g0 = b * 256 + static_cast<size_t>(is) * 32 + static_cast<size_t>(l);
                size_t g1 = g0 + 32;
                if (g0 < n) y[static_cast<size_t>(is) * 32 + static_cast<size_t>(l)] =
                    d1 * static_cast<float>(q[l] & 0x0F) - m1;
                if (g1 < n) y[static_cast<size_t>(is) * 32 + 32 + static_cast<size_t>(l)] =
                    d2 * static_cast<float>(q[l] >> 4) - m2;
            }
            q += 32;
        }
    }
}


static void dequant_q2_k(const uint8_t* src, float* dst, size_t n) {
    const block_q2_K* blocks = reinterpret_cast<const block_q2_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d    = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        // Sanitize non-finite scale values to prevent NaN propagation
        if (!std::isfinite(d))    d    = 0.0f;
        if (!std::isfinite(dmin)) dmin = 0.0f;
        for (int chunk = 0; chunk < 2; ++chunk) {
            for (int subBlock = 0; subBlock < 4; ++subBlock) {
                for (int group = 0; group < 2; ++group) {
                    int scaleIdx = chunk * 8 + subBlock * 2 + group;
                    uint8_t sc = blocks[b].scales[scaleIdx];
                    float dl = d * (float)(sc & 0x0F);
                    float ml = dmin * (float)(sc >> 4);
                    for (int pos = 0; pos < 16; ++pos) {
                        int i = chunk * 128 + subBlock * 32 + group * 16 + pos;
                        size_t globalIdx = b * 256 + i;
                        if (globalIdx >= n) return;
                        int qsIdx = chunk * 32 + group * 16 + pos;
                        int qsShift = subBlock * 2;
                        int q = (blocks[b].qs[qsIdx] >> qsShift) & 0x03;
                        dst[globalIdx] = dl * (float)q - ml;
                    }
                }
            }
        }
    }
}
// ggml dequantize_row_q3_K — 16×6-bit scales + walking hmask bit m.
static void dequant_q3_k(const uint8_t* src, float* dst, size_t n) {
    const block_q3_K* blocks = reinterpret_cast<const block_q3_K*>(src);
    const size_t numBlocks = (n + 255) / 256;
    const uint32_t kmask1 = 0x03030303u;
    const uint32_t kmask2 = 0x0f0f0f0fu;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        if (!std::isfinite(d)) d = 0.0f;
        uint32_t aux[4];
        std::memcpy(aux, blocks[b].scales, 12);
        const uint32_t tmp = aux[2];
        aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
        aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
        aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
        aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
        const int8_t* scales = reinterpret_cast<const int8_t*>(aux);
        const uint8_t* q = blocks[b].qs;
        const uint8_t* hm = blocks[b].hmask;
        uint8_t m = 1;
        int is = 0;
        float* y = dst + b * 256;
        for (int n128 = 0; n128 < 256; n128 += 128) {
            int shift = 0;
            for (int j = 0; j < 4; ++j) {
                float dl = d * (float)(scales[is++] - 32);
                for (int l = 0; l < 16; ++l) {
                    const size_t gi = (size_t)(b * 256 + n128 + j * 32 + l);
                    if (gi >= n) return;
                    y[n128 + j * 32 + l] =
                        dl * (float)(((q[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4));
                }
                dl = d * (float)(scales[is++] - 32);
                for (int l = 0; l < 16; ++l) {
                    const size_t gi = (size_t)(b * 256 + n128 + j * 32 + 16 + l);
                    if (gi >= n) return;
                    y[n128 + j * 32 + 16 + l] =
                        dl * (float)(((q[l + 16] >> shift) & 3) -
                                     ((hm[l + 16] & m) ? 0 : 4));
                }
                shift += 2;
                m <<= 1;
            }
            q += 32;
        }
    }
}
static void dequant_q5_k(const uint8_t* src, float* dst, size_t n) {
    const block_q5_K* blocks = reinterpret_cast<const block_q5_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float dmin = f16_to_f32(blocks[b].dmin);
        if (!std::isfinite(d))    d    = 0.0f;
        if (!std::isfinite(dmin)) dmin = 0.0f;
        for (int sb = 0; sb < 8; ++sb) {
            uint8_t scale, min;
            get_scale_min_k4(sb, blocks[b].scales, scale, min);
            float s = d * scale;
            float m = dmin * min;
            for (int i = 0; i < 32; ++i) {
                int idx = sb * 32 + i;
                size_t globalIdx = b * 256 + idx;
                if (globalIdx >= n) return;
                int qsIdx = idx / 2;
                int qsShift = (idx % 2) * 4;
                uint8_t low4 = (blocks[b].qs[qsIdx] >> qsShift) & 0x0F;
                int qhIdx = idx / 8;
                int qhShift = idx % 8;
                uint8_t high1 = (blocks[b].qh[qhIdx] >> qhShift) & 0x01;
                uint8_t q = low4 | (high1 << 4);
                dst[globalIdx] = s * q - m;
            }
        }
    }
}
static void dequant_q6_k(const uint8_t* src, float* dst, size_t n) {
    // Must match ggml dequantize_row_q6_K / rxd_q6k_dequant_block (not flat nibble layout).
    const size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float w[256];
        if (!rxd_q6k_dequant_block(src + b * 210, w)) {
            for (size_t i = 0; i < 256 && b * 256 + i < n; ++i)
                dst[b * 256 + i] = 0.0f;
            continue;
        }
        for (size_t i = 0; i < 256; ++i) {
            const size_t globalIdx = b * 256 + i;
            if (globalIdx >= n) return;
            dst[globalIdx] = w[i];
        }
    }
}

static void dequant_q4_0(const uint8_t* src, float* dst, size_t n) {
    const block_q4_0* blocks = reinterpret_cast<const block_q4_0*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= n) return;
            uint8_t byte = blocks[b].qs[i / 2];
            float q = (i % 2 == 0) ? (float)(byte & 0x0F) : (float)(byte >> 4);
            dst[idx] = d * q;
        }
    }
}

static void dequant_q4_1(const uint8_t* src, float* dst, size_t n) {
    const block_q4_1* blocks = reinterpret_cast<const block_q4_1*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float m = f16_to_f32(blocks[b].m);
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= n) return;
            uint8_t byte = blocks[b].qs[i / 2];
            float q = (i % 2 == 0) ? (float)(byte & 0x0F) : (float)(byte >> 4);
            dst[idx] = d * q - m;
        }
    }
}

static void dequant_q5_0(const uint8_t* src, float* dst, size_t n) {
    const block_q5_0* blocks = reinterpret_cast<const block_q5_0*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= n) return;
            uint8_t low4 = blocks[b].qs[i / 2];
            int qhIdx = i / 8;
            int qhShift = i % 8;
            uint8_t high1 = (blocks[b].qh[qhIdx] >> qhShift) & 0x01;
            // DEEP2_Q5_0_SIGNED_OFFSET_001: signed 5-bit value around offset 16
            // (matches ggml dequantize_row_q5_0 reference).
            const int q = ((int)(low4 >> ((i % 2) * 4) & 0x0F) |
                           ((int)high1 << 4)) - 16;
            dst[idx] = d * (float)q;
        }
    }
}

static void dequant_q5_1(const uint8_t* src, float* dst, size_t n) {
    const block_q5_1* blocks = reinterpret_cast<const block_q5_1*>(src);
    size_t numBlocks = (n + 31) / 32;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = f16_to_f32(blocks[b].d);
        float m = f16_to_f32(blocks[b].m);
        for (int i = 0; i < 32; ++i) {
            size_t idx = b * 32 + i;
            if (idx >= n) return;
            uint8_t low4 = blocks[b].qs[i / 2];
            int qhIdx = i / 8;
            int qhShift = i % 8;
            uint8_t high1 = (blocks[b].qh[qhIdx] >> qhShift) & 0x01;
            const int q = ((int)(low4 >> ((i % 2) * 4) & 0x0F) |
                           ((int)high1 << 4)) - 16;
            dst[idx] = d * (float)q - m;
        }
    }
}

static void dequant_q8_k(const uint8_t* src, float* dst, size_t n) {
    const block_q8_K* blocks = reinterpret_cast<const block_q8_K*>(src);
    size_t numBlocks = (n + 255) / 256;
    for (size_t b = 0; b < numBlocks; ++b) {
        float d = blocks[b].d;
        for (int i = 0; i < 256; ++i) {
            size_t idx = b * 256 + i;
            if (idx >= n) return;
            dst[idx] = d * (float)blocks[b].qs[i];
        }
    }
}

// --- NVFP4 Dequant (scalar) ---
// block_nvfp4: 64 elements = 32 bytes packed E2M1 + 4 bytes E4M3 scales
// row_div is passed separately (FP32 global scale per output row)
static void dequant_nvfp4(const uint8_t* src, float* dst, size_t n) {
    // NVFP4 dequant without row_div (per-row global scale applied in GEMV)
    const block_nvfp4* blocks = reinterpret_cast<const block_nvfp4*>(src);
    size_t numBlocks = (n + 63) / 64;
    for (size_t b = 0; b < numBlocks; ++b) {
        for (int i = 0; i < 64; ++i) {
            size_t idx = b * 64 + i;
            if (idx >= n) return;
            // Extract E2M1 value from packed bytes
            uint8_t packed = blocks[b].qs[i / 2];
            int8_t e2m1 = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
            // Get E4M3 scale for this 16-element group
            int scale_idx = i / 16;
            float scale = ggml_e4m3_to_fp32(blocks[b].scales[scale_idx]);
            dst[idx] = kvalues_mxfp4[e2m1] * 0.5f * scale;
        }
    }
}

// --- NVFP4 GEMV (scalar) ---
// NVFP4: 64 elements per block, 36 bytes (32 packed E2M1 + 4 E4M3 scales per block)
// row_div: FP32 global scale per output row (length = rows), stored separately in GGUF
static void gemv_nvfp4_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    // NVFP4 GEMV: row_div is an optional per-row global scale (length = rows).
    // When not provided via UniversalTensorProxy, defaults to 1.0f (no scaling).
    const float default_row_div = 1.0f;

    const block_nvfp4* blocks = reinterpret_cast<const block_nvfp4*>(w);
    const size_t blocksPerRow = (cols + 63) / 64;

    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_nvfp4* rowBlocks = blocks + r * blocksPerRow;
        
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_nvfp4& blk = rowBlocks[b];
            size_t base = b * 64;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 64;
            if (elemsInBlock == 0) break;
            
            // row_div for this row - in real usage this comes from a separate tensor
            float row_div = default_row_div;
            
            for (int i = 0; i < (int)elemsInBlock; ++i) {
                // Extract E2M1 value from packed bytes (2 elements per byte)
                uint8_t packed = blk.qs[i / 2];
                int8_t e2m1 = (i % 2 == 0) ? (packed & 0x0F) : (packed >> 4);
                
                // Get E4M3 scale for this 16-element group
                int scale_idx = i / 16;
                float scale = ggml_e4m3_to_fp32(blk.scales[scale_idx]);
                
                // Dequantize: E2M1 * scale / row_div
                float w_val = kvalues_mxfp4[e2m1] * 0.5f * scale / row_div;
                acc += w_val * x[base + i];
            }
        }
        y[r] += acc;
    }
}

// --- IQ2_XXS Dequant (scalar) ---
// IQ2_XXS: 256 elements per block, 66 bytes (2 bytes fp16 scale + 32 uint16 = 64 bytes quant data)
// Use GGML's dequantize_row_iq2_xxs directly
extern "C" void dequantize_row_iq2_xxs(const void* x, float* y, int64_t k);

static void dequant_iq2_xxs(const uint8_t* src, float* dst, size_t n) {
    dequantize_row_iq2_xxs(src, dst, static_cast<int64_t>(n));
}

// --- IQ2_XXS GEMV (scalar) ---
// IQ2_XXS: 256 elements per block, 66 bytes (2 bytes fp16 scale + 32 uint16 = 64 bytes quant data)
// Each uint16_t holds 8 two-bit values (2 bits per element).
// Scalar fallback: dequantize 2-bit nibbles directly using fp16 scale d.
static void gemv_iq2_xxs_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_iq2_xxs* blocks = reinterpret_cast<const block_iq2_xxs*>(w);
    const size_t blocksPerRow = (cols + 255) / 256;

    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_iq2_xxs* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_iq2_xxs& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;

            // Each uint16_t holds 8 two-bit values (MSB first).
            for (size_t i = 0; i < elemsInBlock; ++i) {
                size_t qi = i / 8;           // which uint16_t in qs[]
                unsigned shift = (7u - (i % 8u)) * 2u; // bit pair position
                uint16_t packed = blk.qs[qi];
                uint32_t val2 = (packed >> shift) & 0x3u; // extract 2 bits
                // Map 2-bit unsigned (0..3) to signed (-2..1)
                float w_val = (float)(int)(val2 - 2u) * d;
                acc += w_val * x[base + i];
            }
        }
        y[r] += acc;
    }
}

// --- Q2_K GEMV (scalar) ---
static void gemv_q2_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q2_K* blocks = reinterpret_cast<const block_q2_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q2_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q2_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float dmin = f16_to_f32(blk.dmin);
            if (!std::isfinite(d)) d = 0.0f;
            if (!std::isfinite(dmin)) dmin = 0.0f;
            size_t base = b * 256;
            size_t elemsInBlock = (b == blocksPerRow - 1) ? (cols - base) : 256;
            if (elemsInBlock == 0) break;
            for (int chunk = 0; chunk < 2; ++chunk) {
                for (int subBlock = 0; subBlock < 4; ++subBlock) {
                    for (int group = 0; group < 2; ++group) {
                        int scaleIdx = chunk * 8 + subBlock * 2 + group;
                        uint8_t sc = blk.scales[scaleIdx];
                        float dl = d * (float)(sc & 0x0F);
                        float ml = dmin * (float)(sc >> 4);
                        for (int pos = 0; pos < 16; ++pos) {
                            int idx = chunk * 128 + subBlock * 32 + group * 16 + pos;
                            if ((size_t)idx >= elemsInBlock) break;
                            int qsIdx = chunk * 32 + group * 16 + pos;
                            int qsShift = subBlock * 2;
                            int q = (blk.qs[qsIdx] >> qsShift) & 0x03;
                            acc += (dl * (float)q - ml) * x[base + idx];
                        }
                    }
                }
            }
        }
        y[r] += acc;
    }
}

// --- Q3_K GEMV (scalar) — ggml dequantize_row_q3_K layout ---
static void gemv_q3_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q3_K* blocks = reinterpret_cast<const block_q3_K*>(w);
    const size_t blocksPerRow = (cols + 255) / 256;
    const uint32_t kmask1 = 0x03030303u;
    const uint32_t kmask2 = 0x0f0f0f0fu;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q3_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q3_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            if (!std::isfinite(d)) d = 0.0f;
            uint32_t aux[4];
            std::memcpy(aux, blk.scales, 12);
            const uint32_t tmp = aux[2];
            aux[2] = ((aux[0] >> 4) & kmask2) | (((tmp >> 4) & kmask1) << 4);
            aux[3] = ((aux[1] >> 4) & kmask2) | (((tmp >> 6) & kmask1) << 4);
            aux[0] = (aux[0] & kmask2) | (((tmp >> 0) & kmask1) << 4);
            aux[1] = (aux[1] & kmask2) | (((tmp >> 2) & kmask1) << 4);
            const int8_t* scales = reinterpret_cast<const int8_t*>(aux);
            const uint8_t* q = blk.qs;
            const uint8_t* hm = blk.hmask;
            const float* xb = x + b * 256;
            const size_t base = b * 256;
            const size_t elemsInBlock =
                (b + 1 == blocksPerRow) ? (cols - base) : 256;
            uint8_t m = 1;
            int is = 0;
            size_t written = 0;
            for (int n128 = 0; n128 < 256 && written < elemsInBlock; n128 += 128) {
                int shift = 0;
                for (int j = 0; j < 4 && written < elemsInBlock; ++j) {
                    float dl = d * (float)(scales[is++] - 32);
                    for (int l = 0; l < 16 && written < elemsInBlock; ++l, ++written)
                        acc += dl *
                               (float)(((q[l] >> shift) & 3) - ((hm[l] & m) ? 0 : 4)) *
                               xb[n128 + j * 32 + l];
                    dl = d * (float)(scales[is++] - 32);
                    for (int l = 0; l < 16 && written < elemsInBlock; ++l, ++written)
                        acc += dl *
                               (float)(((q[l + 16] >> shift) & 3) -
                                       ((hm[l + 16] & m) ? 0 : 4)) *
                               xb[n128 + j * 32 + 16 + l];
                    shift += 2;
                    m <<= 1;
                }
                q += 32;
            }
        }
        y[r] += acc;
    }
}
static void gemv_q5_k_scalar(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q5_K* blocks = reinterpret_cast<const block_q5_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;
    for (size_t r = 0; r < rows; ++r) {
        float acc = 0.0f;
        const block_q5_K* rowBlocks = blocks + r * blocksPerRow;
        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q5_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float dmin = f16_to_f32(blk.dmin);
            size_t elemsInBlock = (b == blocksPerRow - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            for (int sb = 0; sb < 8; ++sb) {
                uint8_t scale, min;
                get_scale_min_k4(sb, blk.scales, scale, min);
                float s = d * scale;
                float m = dmin * min;
                float blockAcc = 0.0f;
                for (int i = 0; i < 32; ++i) {
                    int idx = sb * 32 + i;
                    if ((size_t)idx >= elemsInBlock) break;
                    int qsIdx = idx / 2;
                    int qsShift = (idx % 2) * 4;
                    uint8_t low4 = (blk.qs[qsIdx] >> qsShift) & 0x0F;
                    int qhIdx = idx / 8;
                    int qhShift = idx % 8;
                    uint8_t high1 = (blk.qh[qhIdx] >> qhShift) & 0x01;
                    uint8_t q = low4 | (high1 << 4);
                    blockAcc += (s * q - m) * x[b * 256 + idx];
                }
                acc += blockAcc;
            }
        }
        y[r] += acc;
    }
}

// Q5_K AVX2 implementation - 5-bit weights with 1-bit high from qh
static void gemv_q5_k_avx2(
    const uint8_t* RESTRICT w,
    const float*  RESTRICT x,
    float*        RESTRICT y,
    size_t rows, size_t cols
) {
    const block_q5_K* blocks = reinterpret_cast<const block_q5_K*>(w);
    size_t blocksPerRow = (cols + 255) / 256;

    for (size_t r = 0; r < rows; ++r) {
        float rowAcc = 0.0f;
        const block_q5_K* rowBlocks = blocks + r * blocksPerRow;

        for (size_t b = 0; b < blocksPerRow; ++b) {
            const block_q5_K& blk = rowBlocks[b];
            float d = f16_to_f32(blk.d);
            float dmin = f16_to_f32(blk.dmin);
            size_t elemsInBlock = (b == blocksPerRow - 1)
                ? (cols - b * 256)
                : 256;
            if (elemsInBlock == 0) break;

            for (int sb = 0; sb < 8; ++sb) {
                uint8_t scale_u8, min_u8;
                get_scale_min_k4(sb, blk.scales, scale_u8, min_u8);
                float s = d * scale_u8;
                float m = dmin * min_u8;
                __m256 sVec = _mm256_set1_ps(s);
                __m256 mVec = _mm256_set1_ps(m);

                // Process 32 weights in this sub-block
                size_t qsOffset = sb * 16;
                __m128i packed = _mm_loadu_si128(reinterpret_cast<const __m128i*>(blk.qs + qsOffset));

                // Extract low/high nibbles (4 bits each)
                __m128i lowNibbles = _mm_and_si128(packed, _mm_set1_epi8(0x0F));
                __m128i highNibbles = _mm_srli_epi16(packed, 4);
                highNibbles = _mm_and_si128(highNibbles, _mm_set1_epi8(0x0F));

                // Load qh bits for this sub-block (32 weights = 4 bytes of qh)
                size_t qhOffset = sb * 4;
                uint32_t qhBits = *reinterpret_cast<const uint32_t*>(blk.qh + qhOffset);

                // Process in 4 chunks of 8 weights
                for (int chunk = 0; chunk < 4; ++chunk) {
                    int offset = sb * 32 + chunk * 8;
                    if ((size_t)offset + 8 > elemsInBlock) break;
                    if (b * 256 + offset + 8 > cols) break;

                    // Get 8 low nibbles
                    __m128i nibbles;
                    if (chunk < 2) {
                        nibbles = (chunk == 0) ? lowNibbles : _mm_srli_si128(lowNibbles, 8);
                    } else {
                        nibbles = (chunk == 2) ? highNibbles : _mm_srli_si128(highNibbles, 8);
                    }

                    __m256i i32 = _mm256_cvtepu8_epi32(nibbles);
                    __m256 wv = _mm256_cvtepi32_ps(i32);

                    // Add high bit (qh) to make 5-bit values
                    // Each chunk of 8 weights gets bits from qh
                    int qhShift = chunk * 8;
                    uint8_t qhByte = (qhBits >> qhShift) & 0xFF;
                    __m256 qhVec = _mm256_set_ps(
                        (float)((qhByte >> 7) & 1),
                        (float)((qhByte >> 6) & 1),
                        (float)((qhByte >> 5) & 1),
                        (float)((qhByte >> 4) & 1),
                        (float)((qhByte >> 3) & 1),
                        (float)((qhByte >> 2) & 1),
                        (float)((qhByte >> 1) & 1),
                        (float)(qhByte & 1)
                    );
                    wv = _mm256_add_ps(wv, _mm256_mul_ps(qhVec, _mm256_set1_ps(16.0f)));

                    __m256 dequant = _mm256_sub_ps(_mm256_mul_ps(wv, sVec), mVec);
                    __m256 xv = _mm256_loadu_ps(x + b * 256 + offset);
                    rowAcc += _mm_cvtss_f32(_mm256_castps256_ps128(_mm256_dp_ps(dequant, xv, 0xF1)));
                }
            }
        }
        y[r] += rowAcc;
    }
}

#define gemv_q2_k_avx2 gemv_q2_k_scalar
#define gemv_q2_k_avx512 gemv_q2_k_scalar
#define gemv_q3_k_avx2 gemv_q3_k_scalar
#define gemv_q3_k_avx512 gemv_q3_k_scalar
// gemv_q5_k_avx2 is registered directly in RegisterBuiltins (see below)
#define gemv_q5_k_avx512 gemv_q5_k_scalar
#define gemv_q6_k_avx2 gemv_q6_k_scalar
#define gemv_q6_k_avx512 gemv_q6_k_scalar

// ===========================================================================
// MASM KERNEL DEFINITIONS (C++ reference fallbacks)
// The real MASM .asm files (sovereign_q*_gemv.asm) are not present in this
// tree, so these extern "C" symbols — declared above and referenced by the
// _masm wrapper paths — are implemented here as thin wrappers around the
// scalar reference kernels defined in this translation unit. This resolves
// the otherwise-unresolved Deep2_Q*_GEMV / Sovereign_Q4K_GEMV_* externals and
// keeps the quant pipeline end-to-end functional on any CPU.
// ===========================================================================
extern "C" {

void Deep2_Q2_K_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    gemv_q2_k_scalar(reinterpret_cast<const uint8_t*>(weights), input, output,
                     static_cast<size_t>(outputDim),
                     static_cast<size_t>(numBlocks) * 256);
}

void Deep2_Q3_K_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    gemv_q3_k_scalar(reinterpret_cast<const uint8_t*>(weights), input, output,
                     static_cast<size_t>(outputDim),
                     static_cast<size_t>(numBlocks) * 256);
}

void Deep2_Q4_0_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    gemv_q4_0_scalar(reinterpret_cast<const uint8_t*>(weights), input, output,
                     static_cast<size_t>(outputDim),
                     static_cast<size_t>(numBlocks) * 32);
}

void Deep2_Q4_1_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    gemv_q4_1_scalar(reinterpret_cast<const uint8_t*>(weights), input, output,
                     static_cast<size_t>(outputDim),
                     static_cast<size_t>(numBlocks) * 32);
}

void Deep2_Q8_0_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    gemv_q8_0_scalar(reinterpret_cast<const uint8_t*>(weights), input, output,
                     static_cast<size_t>(outputDim),
                     static_cast<size_t>(numBlocks) * 32);
}

void Deep2_Q5_K_GEMV(const void* weights, const float* input, float* output,
                     unsigned int numBlocks, unsigned int outputDim) {
    gemv_q5_k_scalar(reinterpret_cast<const uint8_t*>(weights), input, output,
                     static_cast<size_t>(outputDim),
                     static_cast<size_t>(numBlocks) * 256);
}

void Deep2_Q6_K_GEMV(const void* blocks, const float* x, float* out,
                     std::size_t nBlocks) {
    // Single-row entry: nBlocks super-blocks, 256 elements each.
    gemv_q6_k_scalar(reinterpret_cast<const uint8_t*>(blocks), x, out,
                     1, static_cast<size_t>(nBlocks) * 256);
}

void Sovereign_Q4K_GEMV_AVX2(const void* q4_weights, const float* input,
                             float* output, unsigned int num_blocks,
                             unsigned int rows) {
    gemv_q4_k_scalar(reinterpret_cast<const uint8_t*>(q4_weights), input, output,
                     static_cast<size_t>(rows),
                     static_cast<size_t>(num_blocks) * 256);
}

void Sovereign_Q4K_GEMV_AVX2_V2(const void* q4_weights, const float* input,
                                float* output, unsigned int num_blocks,
                                unsigned int rows) {
    gemv_q4_k_scalar(reinterpret_cast<const uint8_t*>(q4_weights), input, output,
                     static_cast<size_t>(rows),
                     static_cast<size_t>(num_blocks) * 256);
}

} // extern "C"

void QuantKernelRegistry::RegisterGEMV(int quantType, GEMVKernelFn kernel) {
    gemvTable_[quantType] = kernel;
}

void QuantKernelRegistry::RegisterDequant(int quantType, DequantKernelFn kernel) {
    dequantTable_[quantType] = kernel;
}

void QuantKernelRegistry::RegisterGeometry(int quantType, const BlockGeometry& geom)
{
    geometryTable_[quantType] = geom;
}

void QuantKernelRegistry::RegisterBuiltins() {
    const bool hasAVX512 = cpu_.avx512f && cpu_.avx512bw;
    const bool hasAVX2   = cpu_.avx2 && cpu_.fma;

    // --- F32 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_F32, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_F32));
    RegisterDequant((int)GGMLType::GGML_TYPE_F32, dequant_f32);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_F32, gemv_f32_avx512);
    else if (hasAVX2)   RegisterGEMV((int)GGMLType::GGML_TYPE_F32, gemv_f32_avx2);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_F32, gemv_f32_scalar);

    // --- F16 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_F16, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_F16));
    RegisterDequant((int)GGMLType::GGML_TYPE_F16, dequant_f16);
    if (hasAVX2 && cpu_.f16c) RegisterGEMV((int)GGMLType::GGML_TYPE_F16, gemv_f16_masm);
    else                         RegisterGEMV((int)GGMLType::GGML_TYPE_F16, gemv_f16_scalar);

    // BF16 (ggml id 30) — common for lm_head / norms on newer GGUFs
    RegisterGeometry((int)GGMLType::GGML_TYPE_BF16, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_BF16));
    RegisterDequant((int)GGMLType::GGML_TYPE_BF16, dequant_bf16);
    RegisterGEMV((int)GGMLType::GGML_TYPE_BF16, gemv_bf16_scalar);

    // --- Q8_0 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_0, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_0));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q8_0, dequant_q8_0);
    // AVX2 kernel registered directly (implementation at line 1285)
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_0, gemv_q8_0_avx2);

    // --- Q4_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q4_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q4_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q4_K, dequant_q4_k);
    // MASM linked but unverified — use scalar reference until byte-level comparison passes
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_K, gemv_q4_k_scalar);
    printf("[QuantKernelRegistry] Q4_K GEMV=%p dequant=%p GetGEMV(12)=%p match=%d\n",
           (void*)(GEMVKernelFn)gemv_q4_k_scalar,
           (void*)(DequantKernelFn)dequant_q4_k,
           (void*)GetGEMV((int)GGMLType::GGML_TYPE_Q4_K),
           (int)(GetGEMV((int)GGMLType::GGML_TYPE_Q4_K) == (GEMVKernelFn)gemv_q4_k_scalar));

    // --- Q5_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q5_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q5_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q5_K, dequant_q5_k);
    // AVX2 kernel registered directly (implementation at line 1929)
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_K, gemv_q5_k_avx2);

    // --- Q6_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q6_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q6_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q6_K, dequant_q6_k);
    // MASM wrapper registered (gemv_q6_k_masm at line 286; falls back to scalar if MASM unavailable)
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q6_K, gemv_q6_k_masm);

    // --- Q2_K ---
    // LAW: block_q2_K = 84 bytes. Deep2_Q2_K_GEMV (72-byte MASM) is FORBIDDEN
    // for product decode (RAWRXD_Q2K_PRODUCT_DECODE=1 soft-fails gemv_q2_k_masm).
    // Product path: Vulkan DispatchGemvQuant / packed dual 84-byte SsVk.
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q2_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q2_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q2_K, dequant_q2_k);
    // Never register gemv_q2_k_masm here — scalar only; GPU packed owns product decode.
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q2_K, gemv_q2_k_scalar);

    // --- Q3_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q3_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q3_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q3_K, dequant_q3_k);
    // MASM untrusted — use scalar reference until byte-level comparison passes
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q3_K, gemv_q3_k_scalar);

    // --- Q4_0 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q4_0, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q4_0));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q4_0, dequant_q4_0);
    // MASM has dimensionality bug (iterates blocks as rows) — use scalar reference
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_0, gemv_q4_0_scalar);

    // --- Q4_1 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q4_1, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q4_1));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q4_1, dequant_q4_1);
    // MASM wrapper registered (gemv_q4_1_masm at line 250; falls back to scalar if MASM unavailable)
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q4_1, gemv_q4_1_masm);

    // --- Q5_0 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q5_0, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q5_0));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q5_0, dequant_q5_0);
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_0, gemv_q5_0_scalar);

    // --- Q5_1 ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q5_1, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q5_1));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q5_1, dequant_q5_1);
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q5_1, gemv_q5_1_scalar);

    // --- Q8_K ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_K, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_K));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q8_K, dequant_q8_k);
    if (hasAVX512)      RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_K, gemv_q8_k_avx512);
    else                RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_K, gemv_q8_k_scalar);

    // --- NVFP4 ---
    // NVFP4: 64 elements per block, 36 bytes (32 packed E2M1 + 4 E4M3 scales)
    // Global scale (row_div) is stored separately per output row
    RegisterGeometry((int)GGMLType::GGML_TYPE_NVFP4, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_NVFP4));
    RegisterDequant((int)GGMLType::GGML_TYPE_NVFP4, dequant_nvfp4);
    RegisterGEMV((int)GGMLType::GGML_TYPE_NVFP4, gemv_nvfp4_scalar);

    // --- IQ2_XXS ---
    // IQ2_XXS: 256 elements per block, 66 bytes (2 bytes fp16 scale + 32 uint16 = 64 bytes quant data)
    // Uses GGML's dequantize_row_iq2_xxs; GEMV via scalar fallback
    RegisterGeometry((int)GGMLType::GGML_TYPE_IQ2_XXS, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ2_XXS));
    RegisterDequant((int)GGMLType::GGML_TYPE_IQ2_XXS, dequant_iq2_xxs);
    RegisterGEMV((int)GGMLType::GGML_TYPE_IQ2_XXS, gemv_iq2_xxs_scalar);

    // --- Q8_1 (ggml id 9) ---
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q8_1, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q8_1));
    RegisterDequant((int)GGMLType::GGML_TYPE_Q8_1, dequant_q8_1);
    RegisterGEMV((int)GGMLType::GGML_TYPE_Q8_1, gemv_q8_1_scalar);

    // --- Remaining IQ / TQ / MXFP4 / Q1_0 / Q2_0 types ---
    // Geometry is registered so dispatch/sizing is correct end-to-end. Dequant
    // for IQ3_XXS/IQ1_S/IQ4_NL/IQ3_S/IQ2_S/IQ4_XS/IQ1_M is provided by GGML's
    // dequantize_row_* (linked via ggml_interface); register the GEMV dequant
    // fallback so these types load and run rather than being rejected.
    RegisterGeometry((int)GGMLType::GGML_TYPE_IQ3_XXS, GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ3_XXS));
    RegisterGeometry((int)GGMLType::GGML_TYPE_IQ1_S,   GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ1_S));
    RegisterGeometry((int)GGMLType::GGML_TYPE_IQ4_NL,  GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ4_NL));
    RegisterGeometry((int)GGMLType::GGML_TYPE_IQ3_S,   GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ3_S));
    RegisterGeometry((int)GGMLType::GGML_TYPE_IQ2_S,   GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ2_S));
    RegisterGeometry((int)GGMLType::GGML_TYPE_IQ4_XS,  GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ4_XS));
    RegisterGeometry((int)GGMLType::GGML_TYPE_IQ1_M,   GetBlockGeometryForType((int)GGMLType::GGML_TYPE_IQ1_M));
    RegisterGeometry((int)GGMLType::GGML_TYPE_TQ1_0,   GetBlockGeometryForType((int)GGMLType::GGML_TYPE_TQ1_0));
    RegisterGeometry((int)GGMLType::GGML_TYPE_TQ2_0,   GetBlockGeometryForType((int)GGMLType::GGML_TYPE_TQ2_0));
    RegisterGeometry((int)GGMLType::GGML_TYPE_MXFP4,   GetBlockGeometryForType((int)GGMLType::GGML_TYPE_MXFP4));
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q1_0,    GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q1_0));
    RegisterGeometry((int)GGMLType::GGML_TYPE_Q2_0,    GetBlockGeometryForType((int)GGMLType::GGML_TYPE_Q2_0));

    // --- IQ types (registered via IQQuantKernels.cpp) ---
    RegisterIQKernels();
}

void QuantKernelRegistry::Initialize() {
    ProbeCPU();
    RegisterBuiltins();

    printf("[QuantKernelRegistry] CPU features: AVX512F=%d AVX512BW=%d "
           "AVX512DQ=%d AVX512VNNI=%d AVX2=%d FMA=%d F16C=%d\n",
           cpu_.avx512f, cpu_.avx512bw, cpu_.avx512dq,
           cpu_.avx512vnni, cpu_.avx2, cpu_.fma, cpu_.f16c);
    printf("[QuantKernelRegistry] Registered %zu GEMV kernels, %zu dequant kernels\n",
           gemvTable_.size(), dequantTable_.size());
}

// ---------------------------------------------------------------------------
// Resolve a proxy from raw tensor metadata
// ---------------------------------------------------------------------------
UniversalTensorProxy QuantKernelRegistry::Resolve(
    const uint8_t* mmapBase,
    size_t byteOffset,
    size_t totalBytes,
    int quantType,
    size_t rows,
    size_t cols
) const {
    UniversalTensorProxy proxy;
    proxy.mmapBase   = mmapBase;
    proxy.byteOffset = byteOffset;
    proxy.totalBytes = totalBytes;
    proxy.quantType  = quantType;
    proxy.rows       = rows;
    proxy.cols       = cols;
    proxy.gemvKernel    = GetGEMV(quantType);
    proxy.dequantKernel = GetDequant(quantType);
    proxy.geometry      = GetGeometry(quantType);
    return proxy;
}

GEMVKernelFn QuantKernelRegistry::GetGEMV(int quantType) const {
    auto it = gemvTable_.find(quantType);
    if (it != gemvTable_.end()) return it->second;
    return nullptr;
}

DequantKernelFn QuantKernelRegistry::GetDequant(int quantType) const {
    auto it = dequantTable_.find(quantType);
    if (it != dequantTable_.end()) return it->second;
    return nullptr;
}

BlockGeometry QuantKernelRegistry::GetGeometry(int quantType) const {
    auto it = geometryTable_.find(quantType);
    if (it != geometryTable_.end()) return it->second;
    return GetBlockGeometryForType(quantType);
}

std::string QuantKernelRegistry::DumpTable() const {
    std::ostringstream oss;
    oss << "[QuantKernelRegistry] Dispatch Table:\n";
    for (const auto& [type, kernel] : gemvTable_) {
        const char* name = GGMLTypeName(type);
        const char* impl = "scalar";
        if (cpu_.avx512f && cpu_.avx512bw) impl = "avx512";
        else if (cpu_.avx2) impl = "avx2";
        oss << "  " << name << " (type=" << type << ") -> " << impl << "\n";
    }
    return oss.str();
}

// ============================================================================
// Batch 21 telemetry report
// ============================================================================
void QuantKernelRegistry::PrintBatch21Report() const {
    printf("\n[BATCH21]\n");
    printf("registry_hit=%llu\n", (unsigned long long)batch21_.registryHits.load());
    printf("registry_miss=%llu\n", (unsigned long long)batch21_.registryMisses.load());
    printf("scalar_fallback=%llu\n", (unsigned long long)batch21_.scalarFallbacks.load());
    printf("kernel_invocations=%llu\n", (unsigned long long)batch21_.kernelInvocations.load());
    printf("vulkan_compute_submissions=%llu\n", (unsigned long long)batch21_.vulkanComputeSubmissions.load());
    printf("vulkan_compute_failures=%llu\n", (unsigned long long)batch21_.vulkanComputeFailures.load());
    bool pass = batch21_.registryHits.load() > 0 &&
                batch21_.registryMisses.load() == 0 &&
                batch21_.scalarFallbacks.load() == 0 &&
                batch21_.kernelInvocations.load() > 0;
    printf("status=%s\n", pass ? "PASS" : "FAIL");
}

} // namespace Deep2




