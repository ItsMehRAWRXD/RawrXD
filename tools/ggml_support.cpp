// Minimal ggml support functions.
//
// ggml.c is deliberately NOT linked: it pulls in graph/backend machinery that a
// dequantizer does not need (ggml_backend_tensor_set, critical sections, ...).
// These are the small lookup helpers ggml-quants.c references. They are NOT
// substitutes for the code under test - the dequantizers come from the real
// ggml-quants.c in this repository.
//
// ggml_fp16_to_fp32 is written from the IEEE 754 binary16 specification so the
// FP16 path is an independent implementation, not a copy of ggml's own.
#include "ggml.h"
#include <cstdarg>
#include <cstdio>
#include <cstdlib>
#include <cstring>

extern "C" {

// Signature per ggml.h: (file, line, printf-format, ...).
void ggml_abort(const char* file, int line, const char* fmt, ...) {
    std::fprintf(stderr, "ggml_abort: %s:%d ", file ? file : "?", line);
    if (fmt) {
        va_list ap;
        va_start(ap, fmt);
        std::vfprintf(stderr, fmt, ap);
        va_end(ap);
    }
    std::fprintf(stderr, "\n");
    std::abort();
}

static const size_t kTypeSize[] = {
    sizeof(float),       // 0  F32
    sizeof(ggml_fp16_t), // 1  F16
    18, 20, 0, 0,        // 2-5 Q4_0, Q4_1, (removed Q4_2/Q4_3)
    22, 24,              // 6  Q5_0, 7 Q5_1
    34, 36,              // 8  Q8_0, 9 Q8_1
    84, 110, 144,        // 10-12 Q2_K, Q3_K, Q4_K
    176, 210, 256        // 13-15 Q5_K, Q6_K, Q8_K
};
static const int64_t kBlckSize[] = { 1, 1, 32, 32, 0, 0, 32, 32, 32, 32, 16, 16, 32, 32, 16, 32 };

size_t ggml_type_size(enum ggml_type type) {
    const int t = (int)type;
    if (t < 0 || t >= (int)(sizeof(kTypeSize) / sizeof(kTypeSize[0]))) return 0;
    return kTypeSize[t];
}

int64_t ggml_blck_size(enum ggml_type type) {
    const int t = (int)type;
    if (t < 0 || t >= (int)(sizeof(kBlckSize) / sizeof(kBlckSize[0]))) return 0;
    return kBlckSize[t];
}

size_t ggml_row_size(enum ggml_type type, int64_t n) {
    const size_t bs = (size_t)ggml_blck_size(type);
    if (bs == 0) return 0;
    return ggml_type_size(type) * ((size_t)n / bs);
}

float ggml_fp16_to_fp32(ggml_fp16_t h) {
    const uint32_t sign = (uint32_t)(h >> 15) & 1u;
    const uint32_t exp  = (uint32_t)(h >> 10) & 0x1Fu;
    const uint32_t mant = (uint32_t)h & 0x3FFu;
    uint32_t bits;
    if (exp == 0) {
        if (mant == 0) { bits = sign << 31; }
        else {
            int e = -1; uint32_t m = mant;
            do { m <<= 1; ++e; } while ((m & 0x400u) == 0);
            m &= 0x3FFu;
            bits = (sign << 31) | ((127u - 15u - (uint32_t)e) << 23) | (m << 13);
        }
    } else if (exp == 0x1Fu) {
        bits = (sign << 31) | (0xFFu << 23) | (mant << 13);
    } else {
        bits = (sign << 31) | ((exp + 127u - 15u) << 23) | (mant << 13);
    }
    float out; std::memcpy(&out, &bits, sizeof(out)); return out;
}

// ---- to_float: wired to the REAL dequantizers in this repository's
// ggml-quants.c, not to anything written here.
//
// A previous version left to_float null for every type. That made
// DequantPrefix() return 0 for every non-F32/F16 tensor, so the Q5_0 embedding
// row dequantized to nothing and the executor failed with
// "embedding: dequant short" - a silent inability to read weights.
//
// ggml-quants.c is compiled into the same binary, so these are the genuine
// ggml decoders. ggml_to_float_t is void(const void*, float*, int64_t).
extern "C" {
void dequantize_row_q4_0(const void*, float*, int64_t);
void dequantize_row_q4_1(const void*, float*, int64_t);
void dequantize_row_q5_0(const void*, float*, int64_t);
void dequantize_row_q5_1(const void*, float*, int64_t);
void dequantize_row_q8_0(const void*, float*, int64_t);
void dequantize_row_q2_K(const void*, float*, int64_t);
void dequantize_row_q3_K(const void*, float*, int64_t);
void dequantize_row_q4_K(const void*, float*, int64_t);
void dequantize_row_q5_K(const void*, float*, int64_t);
void dequantize_row_q6_K(const void*, float*, int64_t);
void dequantize_row_q8_K(const void*, float*, int64_t);

static void to_f32_(const void* x, float* y, int64_t k) { std::memcpy(y, x, (size_t)k * 4); }
static void to_f16_(const void* x, float* y, int64_t k) {
    for (int64_t i = 0; i < k; ++i) {
        uint16_t h; std::memcpy(&h, (const char*)x + i * 2, 2);
        y[i] = ggml_fp16_to_fp32((ggml_fp16_t)h);
    }
}
}  // extern "C"

#define GGML_DEQ(lower) \
    static void to_##lower##_(const void* x, float* y, int64_t k) { \
        dequantize_row_##lower(x, y, k); \
    }

GGML_DEQ(q4_0)
GGML_DEQ(q4_1)
GGML_DEQ(q5_0)
GGML_DEQ(q5_1)
GGML_DEQ(q8_0)
GGML_DEQ(q2_K)
GGML_DEQ(q3_K)
GGML_DEQ(q4_K)
GGML_DEQ(q5_K)
GGML_DEQ(q6_K)
GGML_DEQ(q8_K)

// Field order per ggml.h: type_name, blck_size, blck_size_interleave,
// type_size, is_quantized, to_float, from_float_ref.
static const ggml_type_traits kTraits[] = {
    /* F32  */ { "F32",  false, 1,  sizeof(float),       false, to_f32_,     nullptr },
    /* F16  */ { "F16",  false, 1,  sizeof(ggml_fp16_t), false, to_f16_,     nullptr },
    /* Q4_0 */ { "Q4_0", true,  32, 18,                  true,  to_q4_0_,    nullptr },
    /* Q4_1 */ { "Q4_1", true,  32, 20,                  true,  to_q4_1_,    nullptr },
    /* ?    */ { "?",    false, 1,  0,                   false, nullptr,     nullptr },
    /* ?    */ { "?",    false, 1,  0,                   false, nullptr,     nullptr },
    /* Q5_0 */ { "Q5_0", true,  32, 22,                  true,  to_q5_0_,    nullptr },
    /* Q5_1 */ { "Q5_1", true,  32, 24,                  true,  to_q5_1_,    nullptr },
    /* Q8_0 */ { "Q8_0", true,  32, 34,                  true,  to_q8_0_,    nullptr },
    /* Q8_1 */ { "Q8_1", true,  32, 36,                  true,  to_q8_0_,    nullptr },
    /* Q2_K */ { "Q2_K", true,  16, 84,                  true,  to_q2_K_,    nullptr },
    /* Q3_K */ { "Q3_K", true,  16, 110,                 true,  to_q3_K_,    nullptr },
    /* Q4_K */ { "Q4_K", true,  256, 144,                true,  to_q4_K_,    nullptr },
    /* Q5_K */ { "Q5_K", true,  256, 176,                true,  to_q5_K_,    nullptr },
    /* Q6_K */ { "Q6_K", true,  256, 210,                true,  to_q6_K_,    nullptr },
    /* Q8_K */ { "Q8_K", true,  256, 256,                true,  to_q8_K_,    nullptr }
};

const struct ggml_type_traits* ggml_get_type_traits(enum ggml_type type) {
    const int t = (int)type;
    if (t < 0 || t >= (int)(sizeof(kTraits) / sizeof(kTraits[0]))) return nullptr;
    return &kTraits[t];
}

const char* ggml_type_name(enum ggml_type type) {
    static const char* names[] = {
        "F32", "F16", "Q4_0", "Q4_1", "?", "?",
        "Q5_0", "Q5_1", "Q8_0", "Q8_1",
        "Q2_K", "Q3_K", "Q4_K", "Q5_K", "Q6_K", "Q8_K"
    };
    const int t = (int)type;
    if (t < 0 || t >= (int)(sizeof(names) / sizeof(names[0]))) return "?";
    return names[t];
}

}  // extern "C"
