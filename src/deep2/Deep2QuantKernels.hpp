// ============================================================================
// Deep2QuantKernels.hpp — K-quant super-block layouts only
//
// Engine/k_quant_kernels.h is the authoritative source for these GGML block
// structures and asserts each one to its exact byte size. It also declares
// ggml_rxd_type and the AVX2 kernel entry points, which pulls in
// engine/common_types.h — a header whose ggml_type enum carries obsolete
// Q2_K/Q3_K/Q4_K/Q5_K/Q6_K ids and does not match the canonical
// Deep2::GGMLType. Deep2Engine.cpp needs only the block definitions, so they
// are mirrored here.
//
// These MUST stay byte-identical to engine/k_quant_kernels.h; the static_asserts
// below enforce that.
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

namespace rawrxd {
namespace kquant {

static constexpr int QK_K = 256;

#pragma pack(push, 1)

// Q2_K super-block: 256 weights, 84 bytes
struct block_q2_K {
    uint8_t  scales[QK_K / 16]; // scale/min pairs (12 bytes)
    uint8_t  qs[QK_K / 4];      // 2-bit quantized values packed (256 x 2 bits)
    uint16_t d;
    uint16_t dmin;
};
static_assert(sizeof(block_q2_K) == 84, "block_q2_K size mismatch");

// Q3_K super-block: 256 weights, 110 bytes
// Layout follows ggml's dequantize_row_q3_K: hmask (high bits), qs (low 2
// bits), scales (12 packed bytes -> 16 int8 via the bit unpack below) and d.
struct block_q3_K {
    uint8_t  hmask[QK_K / 8];  // high bit of each 3-bit weight (32 bytes)
    uint8_t  qs[QK_K / 4];     // low 2 bits (64 bytes)
    uint8_t  scales[12];       // 6-bit scale/min pairs
    uint16_t d;
};
static_assert(sizeof(block_q3_K) == 110, "block_q3_K size mismatch");

// Q4_K super-block: 256 weights, 144 bytes
struct block_q4_K {
    uint16_t d;          // fp16 super-block scale
    uint16_t dmin;       // fp16 super-block min
    uint8_t  scales[12]; // 6-bit sub-scales (8 sub-blocks x 6 bits = 48 bits)
    uint8_t  qs[128];    // 4-bit quantized values packed (256 nibbles in 128 bytes)
};
static_assert(sizeof(block_q4_K) == 144, "block_q4_K size mismatch");

// Q5_K super-block: 256 weights, 176 bytes
struct block_q5_K {
    uint16_t d;          // fp16 scale
    uint16_t dmin;       // fp16 min
    uint8_t  scales[12]; // 6-bit sub-scales (same packing as Q4_K)
    uint8_t  qh[32];     // high bits: bit i of element j is (qh[j/8] >> (j%8)) & 1
    uint8_t  qs[128];    // low 4 bits
};
static_assert(sizeof(block_q5_K) == 176, "block_q5_K size mismatch");

// Q6_K super-block: 256 weights, 210 bytes
struct block_q6_K {
    uint8_t  ql[128];    // low 4 bits of each 6-bit weight
    uint8_t  qh[64];     // high 2 bits packed (4 per byte)
    int8_t   scales[16]; // per-16-element scale factors
    uint16_t d;          // fp16 super-block scale
};
static_assert(sizeof(block_q6_K) == 210, "block_q6_K size mismatch");

// Q8_K super-block: 256 weights, 292 bytes
// Unlike the K-quant super-blocks above, Q8_K stores its scale as a native
// float (not fp16), and has no separate min.
struct block_q8_K {
    float    d;          // fp32 scale
    int8_t   qs[QK_K];   // 256 quantized weights
    uint16_t bsums[QK_K / 16]; // per-16-element bit sums
};
static_assert(sizeof(block_q8_K) == 292, "block_q8_K size mismatch");

#pragma pack(pop)

// ---------------------------------------------------------------------------
// Legacy (pre-K) block layouts.
//
// ggml's non-K formats are 32-element blocks:
//   Q4_0 / Q8_0 : fp16 scale + nibble/byte payloads
//   Q4_1 / Q5_1 : fp16 scale + fp16 min + payloads
//   Q5_0        : fp16 scale + payload + 4-bit high-bit plane
// Byte sizes are asserted below and match engine/common_types.h exactly.
// ---------------------------------------------------------------------------
#pragma pack(push, 1)

// Q4_0: 32 weights, 18 bytes
struct block_q4_0 {
    uint16_t d;         // fp16 scale
    uint8_t  qs[16];    // 32 4-bit weights packed
};
static_assert(sizeof(block_q4_0) == 18, "block_q4_0 size mismatch");

// Q4_1: 32 weights, 20 bytes
struct block_q4_1 {
    uint16_t d;         // fp16 scale
    uint16_t m;         // fp16 min
    uint8_t  qs[16];    // 32 4-bit weights packed
};
static_assert(sizeof(block_q4_1) == 20, "block_q4_1 size mismatch");

// Q5_0: 32 weights, 22 bytes
struct block_q5_0 {
    uint16_t d;         // fp16 scale
    uint8_t  qh[4];     // high bit of each 5-bit weight
    uint8_t  qs[16];    // low 4 bits
};
static_assert(sizeof(block_q5_0) == 22, "block_q5_0 size mismatch");

// Q5_1: 32 weights, 24 bytes
struct block_q5_1 {
    uint16_t d;         // fp16 scale
    uint16_t m;         // fp16 min
    uint8_t  qh[4];     // high bit of each 5-bit weight
    uint8_t  qs[16];    // low 4 bits
};
static_assert(sizeof(block_q5_1) == 24, "block_q5_1 size mismatch");

// Q8_0: 32 weights, 34 bytes
struct block_q8_0 {
    uint16_t d;         // fp16 scale
    int8_t   qs[32];    // 32 quantized weights
};
static_assert(sizeof(block_q8_0) == 34, "block_q8_0 size mismatch");

#pragma pack(pop)

} // namespace kquant
} // namespace rawrxd
