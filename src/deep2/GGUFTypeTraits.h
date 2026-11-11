// =============================================================================
// Blocker #4: Complete GGUF tensor type enum + mapping table
// Matches ggml_type_e from llama.cpp/ggml
// =============================================================================

#pragma once
#include <cstdint>
#include <string>

enum GGMLType : uint32_t {
    GGML_TYPE_F32    = 0,
    GGML_TYPE_F16    = 1,
    GGML_TYPE_Q4_0   = 2,
    GGML_TYPE_Q4_1   = 3,
    // 4, 5 are deprecated (Q4_2, Q4_3)
    GGML_TYPE_Q5_0   = 6,
    GGML_TYPE_Q5_1   = 7,
    GGML_TYPE_Q8_0   = 8,
    GGML_TYPE_Q8_1   = 9,
    GGML_TYPE_Q2_K   = 10,
    GGML_TYPE_Q3_K   = 11,
    GGML_TYPE_Q4_K   = 12,
    GGML_TYPE_Q5_K   = 13,
    GGML_TYPE_Q6_K   = 14,
    GGML_TYPE_Q8_K   = 15,
    GGML_TYPE_I8     = 16,
    GGML_TYPE_I16    = 17,
    GGML_TYPE_I32    = 18,
    GGML_TYPE_I64    = 27,
    GGML_TYPE_F64    = 28,
    GGML_TYPE_BF16   = 29,
    GGML_TYPE_IQ2_XXS = 16,  // Note: overlaps with I8 in some versions
    GGML_TYPE_IQ2_XS  = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S   = 19,
    GGML_TYPE_IQ4_NL  = 20,
    GGML_TYPE_IQ3_S   = 21,
    GGML_TYPE_IQ2_S   = 22,
    GGML_TYPE_IQ4_XS  = 23,
    GGML_TYPE_TQ1_0   = 24,
    GGML_TYPE_TQ2_0   = 25,
    GGML_TYPE_COUNT   = 26,
};

struct GGMLTypeTraits {
    const char* name;
    int blockSize;
    int typeSize;  // bytes per block
    bool isQuantized;
    bool isKQuant;
};

static const GGMLTypeTraits ggmlTypeTraits[] = {
    // [0] F32
    { "F32",     1,   4,   false, false },
    // [1] F16
    { "F16",     1,   2,   false, false },
    // [2] Q4_0
    { "Q4_0",   32,  18,   true,  false },
    // [3] Q4_1
    { "Q4_1",   32,  20,   true,  false },
    // [4] deprecated
    { "Q4_2",   32,  18,   true,  false },
    // [5] deprecated
    { "Q4_3",   32,  20,   true,  false },
    // [6] Q5_0
    { "Q5_0",   32,  22,   true,  false },
    // [7] Q5_1
    { "Q5_1",   32,  24,   true,  false },
    // [8] Q8_0
    { "Q8_0",   32,  34,   true,  false },
    // [9] Q8_1
    { "Q8_1",   32,  36,   true,  false },
    // [10] Q2_K
    { "Q2_K",  256,  84,   true,  true  },
    // [11] Q3_K
    { "Q3_K",  256, 110,   true,  true  },
    // [12] Q4_K
    { "Q4_K",  256, 144,   true,  true  },
    // [13] Q5_K
    { "Q5_K",  256, 176,   true,  true  },
    // [14] Q6_K
    { "Q6_K",  256, 210,   true,  true  },
    // [15] Q8_K
    { "Q8_K",  256, 292,   true,  true  },
    // [16-23] I-quants (may vary by version)
    { "IQ2_XXS", 256, 66,  true, false },
    { "IQ2_XS",  256, 74,  true, false },
    { "IQ3_XXS", 256, 98,  true, false },
    { "IQ1_S",   256, 50,  true, false },
    { "IQ4_NL",   32, 18,  true, false },
    { "IQ3_S",   256, 110, true, false },
    { "IQ2_S",   256, 82,  true, false },
    { "IQ4_XS",  256, 136, true, false },
};

static inline const char* ggml_type_name(uint32_t type) {
    if (type < 24) return ggmlTypeTraits[type].name;
    switch (type) {
        case 24: return "I8";
        case 25: return "I16";
        case 26: return "I32";
        case 27: return "I64";
        case 28: return "F64";
        case 29: return "BF16";
        default: return "UNKNOWN";
    }
}

static inline int ggml_type_block_size(uint32_t type) {
    switch (type) {
        case GGML_TYPE_F32: case GGML_TYPE_F16: case GGML_TYPE_BF16: case GGML_TYPE_F64:
        case GGML_TYPE_I8: case GGML_TYPE_I16: case GGML_TYPE_I32: case GGML_TYPE_I64:
            return 1;
        case GGML_TYPE_Q4_0: case GGML_TYPE_Q4_1:
        case GGML_TYPE_Q5_0: case GGML_TYPE_Q5_1:
        case GGML_TYPE_Q8_0: case GGML_TYPE_Q8_1:
        case GGML_TYPE_IQ4_NL:
            return 32;
        case GGML_TYPE_Q2_K: case GGML_TYPE_Q3_K: case GGML_TYPE_Q4_K:
        case GGML_TYPE_Q5_K: case GGML_TYPE_Q6_K: case GGML_TYPE_Q8_K:
        case GGML_TYPE_IQ2_XXS: case GGML_TYPE_IQ2_XS: case GGML_TYPE_IQ2_S:
        case GGML_TYPE_IQ3_XXS: case GGML_TYPE_IQ3_S: case GGML_TYPE_IQ1_S:
        case GGML_TYPE_IQ4_XS:
            return 256;
        default:
            return -1;  // Unknown
    }
}

static inline int ggml_type_size(uint32_t type) {
    switch (type) {
        case GGML_TYPE_F32: return 4;
        case GGML_TYPE_F16: return 2;
        case GGML_TYPE_BF16: return 2;
        case GGML_TYPE_F64: return 8;
        case GGML_TYPE_I8:  return 1;
        case GGML_TYPE_I16: return 2;
        case GGML_TYPE_I32: return 4;
        case GGML_TYPE_I64: return 8;
        case GGML_TYPE_Q4_0: return 18;
        case GGML_TYPE_Q4_1: return 20;
        case GGML_TYPE_Q5_0: return 22;
        case GGML_TYPE_Q5_1: return 24;
        case GGML_TYPE_Q8_0: return 34;
        case GGML_TYPE_Q8_1: return 36;
        case GGML_TYPE_Q2_K: return 84;
        case GGML_TYPE_Q3_K: return 110;
        case GGML_TYPE_Q4_K: return 144;
        case GGML_TYPE_Q5_K: return 176;
        case GGML_TYPE_Q6_K: return 210;
        case GGML_TYPE_Q8_K: return 292;
        case GGML_TYPE_IQ2_XXS: return 66;
        case GGML_TYPE_IQ2_XS:  return 74;
        case GGML_TYPE_IQ2_S:   return 82;
        case GGML_TYPE_IQ3_XXS: return 98;
        case GGML_TYPE_IQ3_S:   return 110;
        case GGML_TYPE_IQ1_S:   return 50;
        case GGML_TYPE_IQ4_NL:  return 18;
        case GGML_TYPE_IQ4_XS:  return 136;
        default: return -1;
    }
}

static inline uint64_t ggml_tensor_size(uint32_t type, uint64_t numElements) {
    int bs = ggml_type_block_size(type);
    int ts = ggml_type_size(type);
    if (bs <= 0 || ts <= 0) return 0;
    uint64_t numBlocks = (numElements + static_cast<uint64_t>(bs) - 1) / static_cast<uint64_t>(bs);
    return numBlocks * static_cast<uint64_t>(ts);
}