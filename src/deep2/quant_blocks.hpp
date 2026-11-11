// Canonical Deep2 quantization block layouts. Single source of truth for the
// mapped GGUF reader and the quant kernel registry; both include this header
// and declare nothing themselves. Layouts mirror ggml-common.h; the
// static_asserts below are the ABI contract (sizeof and field offsets).
#pragma once
#include <cstdint>
#include <cstddef>

namespace Deep2 {

#pragma pack(push, 1)
struct block_q4_0 { uint16_t d; uint8_t qs[16]; }; // 18 bytes, 32 elements
struct block_q4_1 { uint16_t d; uint16_t m; uint8_t qs[16]; }; // 20 bytes
struct block_q5_0 { uint16_t d; uint8_t qh[4]; uint8_t qs[16]; }; // 22 bytes
struct block_q5_1 { uint16_t d; uint16_t m; uint8_t qh[4]; uint8_t qs[16]; }; // 24 bytes
struct block_q8_0 { uint16_t d; int8_t qs[32]; }; // 34 bytes
struct block_q8_1 { uint16_t d; uint16_t s; int8_t qs[32]; }; // 36 bytes
// ggml-common.h layout: scales + qs FIRST, then d/dmin at end (NOT d-first).
struct block_q2_K { uint8_t scales[16]; uint8_t qs[64]; uint16_t d; uint16_t dmin; }; // 84 bytes
struct block_q3_K { uint8_t hmask[32]; uint8_t qs[64]; uint8_t scales[12]; uint16_t d; }; // 110 bytes
struct block_q4_K { uint16_t d; uint16_t dmin; uint8_t scales[12]; uint8_t qs[128]; }; // 144 bytes, 256 elements
struct block_q5_K { uint16_t d; uint16_t dmin; uint8_t scales[12]; uint8_t qh[32]; uint8_t qs[128]; }; // 176 bytes
struct block_q6_K { uint8_t ql[128]; uint8_t qh[64]; int8_t scales[16]; uint16_t d; }; // 210 bytes
struct block_q8_K { float d; int8_t qs[256]; int16_t bsums[16]; }; // 292 bytes
// IQ / modern formats (canonical ggml sizes)
struct block_iq2_xxs { uint16_t d; uint8_t qs[64]; }; // 66 bytes (== ggml uint16 qs[32])
struct block_iq2_xs  { uint16_t d; uint8_t qs[64]; uint8_t scales[8]; }; // 74 bytes
struct block_iq2_s   { uint16_t d; uint8_t qs[64]; uint8_t qh[8]; uint8_t scales[8]; }; // 82 bytes
struct block_iq3_xxs { uint16_t d; uint8_t qs[96]; }; // 98 bytes
struct block_iq3_s   { uint16_t d; uint8_t qs[64]; uint8_t qh[8]; uint8_t signs[32]; uint8_t scales[4]; }; // 110
struct block_iq1_s   { uint16_t d; uint8_t qs[32]; uint16_t qh[8]; }; // 50 bytes, 256 elems
struct block_iq1_m   { uint8_t qs[32]; uint8_t qh[16]; uint8_t scales[8]; }; // 56 bytes
struct block_iq4_nl  { uint16_t d; uint8_t qs[16]; }; // 18 bytes, 32 elems (NOT 132/256)
struct block_iq4_xs  {
    uint16_t d;
    union {
        struct { uint16_t scales_h; uint8_t scales_l[4]; };
        uint8_t scales[6]; // legacy kernel access (same 6 bytes)
    };
    uint8_t qs[128];
}; // 136 bytes
struct block_tq1_0   { uint8_t qs[48]; uint8_t qh[4]; uint16_t d; }; // 54 bytes
struct block_tq2_0   { uint8_t qs[64]; uint16_t d; }; // 66 bytes
struct block_mxfp4   { uint8_t e; uint8_t qs[16]; }; // 17 bytes, 32 elems
struct block_nvfp4   { uint8_t d[4]; uint8_t qs[32]; }; // 36 bytes, 64 elems
struct block_q1_0    { uint16_t d; uint8_t qs[16]; }; // 18 bytes, 128 elems
struct block_bf16    { uint16_t bits; }; // 2 bytes, 1 elem
#pragma pack(pop)

// ABI contract: sizes and offsets must match the ggml-common.h reference.
static_assert(sizeof(block_q4_0) == 18, "block_q4_0 size");
static_assert(offsetof(block_q4_0, qs) == 2, "block_q4_0 qs offset");
static_assert(sizeof(block_q4_1) == 20, "block_q4_1 size");
static_assert(sizeof(block_q5_0) == 22, "block_q5_0 size");
static_assert(sizeof(block_q5_1) == 24, "block_q5_1 size");
static_assert(sizeof(block_q8_0) == 34, "block_q8_0 size");
static_assert(sizeof(block_q8_1) == 36, "block_q8_1 size");
static_assert(sizeof(block_q2_K) == 84, "block_q2_K size");
static_assert(offsetof(block_q2_K, qs) == 16, "block_q2_K qs offset");
static_assert(sizeof(block_q3_K) == 110, "block_q3_K size");
static_assert(sizeof(block_q4_K) == 144, "block_q4_K size");
static_assert(offsetof(block_q4_K, qs) == 16, "block_q4_K qs offset");
static_assert(sizeof(block_q5_K) == 176, "block_q5_K size");
static_assert(sizeof(block_q6_K) == 210, "block_q6_K size");
static_assert(sizeof(block_q8_K) == 292, "block_q8_K size");
static_assert(sizeof(block_iq2_xxs) == 66, "block_iq2_xxs size");
static_assert(sizeof(block_iq2_xs) == 74, "block_iq2_xs size");
static_assert(sizeof(block_iq2_s) == 82, "block_iq2_s size");
static_assert(sizeof(block_iq3_xxs) == 98, "block_iq3_xxs size");
static_assert(sizeof(block_iq3_s) == 110, "block_iq3_s size");
static_assert(sizeof(block_iq1_s) == 50, "block_iq1_s size");
static_assert(sizeof(block_iq1_m) == 56, "block_iq1_m size");

} // namespace Deep2