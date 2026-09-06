// ============================================================================
// QuantTypeTable.hpp — SINGLE authoritative GGUF/GGML type descriptor table
//
// QUANT-COVERAGE-001 / P0:
//   - Canonical ggml_type numeric IDs (llama.cpp ggml.h, COUNT=43)
//   - Block geometry (elems + bytes) for sizing / mmap / dispatch
//   - Fail-closed for unknown / zero-geometry types (no silent {4,1})
//
// Loader sizing, registry geometry, diagnostics, and ABI asserts MUST
// consume this table — do not reintroduce parallel switch statements.
// ============================================================================
#pragma once

#include <cstdint>
#include <cstddef>
#include <cstdio>

namespace Deep2 {

// Canonical ggml_type IDs (must match ggml-org/llama.cpp ggml/include/ggml.h)
enum class GGMLType : uint32_t {
    GGML_TYPE_F32     = 0,
    GGML_TYPE_F16     = 1,
    GGML_TYPE_Q4_0    = 2,
    GGML_TYPE_Q4_1    = 3,
    // 4,5 removed (Q4_2/Q4_3)
    GGML_TYPE_Q5_0    = 6,
    GGML_TYPE_Q5_1    = 7,
    GGML_TYPE_Q8_0    = 8,
    GGML_TYPE_Q8_1    = 9,
    GGML_TYPE_Q2_K    = 10,
    GGML_TYPE_Q3_K    = 11,
    GGML_TYPE_Q4_K    = 12,
    GGML_TYPE_Q5_K    = 13,
    GGML_TYPE_Q6_K    = 14,
    GGML_TYPE_Q8_K    = 15,
    GGML_TYPE_IQ2_XXS = 16,
    GGML_TYPE_IQ2_XS  = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S   = 19,
    GGML_TYPE_IQ4_NL  = 20,
    GGML_TYPE_IQ3_S   = 21,
    GGML_TYPE_IQ2_S   = 22,
    GGML_TYPE_IQ4_XS  = 23,
    GGML_TYPE_I8      = 24,
    GGML_TYPE_I16     = 25,
    GGML_TYPE_I32     = 26,
    GGML_TYPE_I64     = 27,
    GGML_TYPE_F64     = 28,
    GGML_TYPE_IQ1_M   = 29,
    GGML_TYPE_BF16    = 30,
    // 31-33 removed (Q4_0_x_x)
    GGML_TYPE_TQ1_0   = 34,
    GGML_TYPE_TQ2_0   = 35,
    // 36-38 removed (IQ4_NL_x_x)
    GGML_TYPE_MXFP4   = 39,
    GGML_TYPE_NVFP4   = 40,
    GGML_TYPE_Q1_0    = 41,
    GGML_TYPE_Q2_0    = 42,
    GGML_TYPE_COUNT   = 43,
};

// Drift → compile failure (not silent inference corruption).
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_Q8_0)    == 8);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_Q8_1)    == 9);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_Q2_K)    == 10);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_Q4_K)    == 12);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_Q8_K)    == 15);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ2_XXS) == 16);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ2_XS)  == 17);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ3_XXS) == 18);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ1_S)   == 19);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ4_NL)  == 20);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ3_S)   == 21);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ2_S)   == 22);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ4_XS)  == 23);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_I8)      == 24);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_F64)     == 28);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_IQ1_M)   == 29);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_BF16)    == 30);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_TQ1_0)   == 34);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_TQ2_0)   == 35);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_MXFP4)   == 39);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_NVFP4)   == 40);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_Q1_0)    == 41);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_Q2_0)    == 42);
static_assert(static_cast<uint32_t>(GGMLType::GGML_TYPE_COUNT)   == 43);

struct QuantTypeDescriptor {
    uint32_t    ggmlId;
    const char* name;
    uint32_t    blockElements; // 0 = unknown / fail-closed
    uint32_t    blockBytes;    // 0 = unknown / fail-closed
    bool        isQuantized;
    bool        hasScales;
    bool        hasMin;
    bool        persistedGGUF; // may appear as weight storage in GGUF
    bool        kernelReady;   // Deep2 has registered dequant+GEMV today
};

// Indexed by ggmlId. Unused / removed IDs have blockElements=0 → fail-closed.
inline const QuantTypeDescriptor* QuantTypeTable() {
    static const QuantTypeDescriptor kTable[static_cast<size_t>(GGMLType::GGML_TYPE_COUNT)] = {
        // id, name, elems, bytes, quant, scales, min, persist, kernel
        { 0,  "F32",     1,   4, false, false, false, true,  true  },
        { 1,  "F16",     1,   2, false, false, false, true,  true  },
        { 2,  "Q4_0",   32,  18, true,  true,  false, true,  true  },
        { 3,  "Q4_1",   32,  20, true,  true,  true,  true,  true  },
        { 4,  "Q4_2",    0,   0, true,  false, false, false, false }, // removed
        { 5,  "Q4_3",    0,   0, true,  false, false, false, false }, // removed
        { 6,  "Q5_0",   32,  22, true,  true,  false, true,  true  },
        { 7,  "Q5_1",   32,  24, true,  true,  true,  true,  true  },
        { 8,  "Q8_0",   32,  34, true,  true,  false, true,  true  },
        { 9,  "Q8_1",   32,  36, true,  true,  false, true,  false }, // P2
        {10,  "Q2_K",  256,  84, true,  true,  true,  true,  true  },
        {11,  "Q3_K",  256, 110, true,  true,  false, true,  true  },
        {12,  "Q4_K",  256, 144, true,  true,  true,  true,  true  },
        {13,  "Q5_K",  256, 176, true,  true,  true,  true,  true  },
        {14,  "Q6_K",  256, 210, true,  true,  true,  true,  true  },
        {15,  "Q8_K",  256, 292, true,  true,  false, true,  true  }, // was wrongly 29
        {16,  "IQ2_XXS",256, 66, true,  true,  false, true,  true  },
        {17,  "IQ2_XS", 256, 74, true,  true,  false, true,  true  },
        {18,  "IQ3_XXS",256, 98, true,  true,  false, true,  true  },
        {19,  "IQ1_S",  256, 50, true,  true,  false, true,  true  }, // was wrongly 34
        {20,  "IQ4_NL",  32, 18, true,  true,  false, true,  true  }, // was wrongly 132/256
        {21,  "IQ3_S",  256,110, true,  true,  false, true,  true  },
        {22,  "IQ2_S",  256, 82, true,  true,  false, true,  true  },
        {23,  "IQ4_XS", 256,136, true,  true,  false, true,  true  },
        {24,  "I8",      1,   1, false, false, false, true,  false },
        {25,  "I16",     1,   2, false, false, false, true,  false },
        {26,  "I32",     1,   4, false, false, false, true,  false },
        {27,  "I64",     1,   8, false, false, false, true,  false },
        {28,  "F64",     1,   8, false, false, false, true,  false },
        {29,  "IQ1_M",  256, 56, true,  true,  false, true,  false }, // P2
        {30,  "BF16",    1,   2, false, false, false, true,  false }, // P2
        {31,  "Q4_0_4_4",0,   0, true,  false, false, false, false },
        {32,  "Q4_0_4_8",0,   0, true,  false, false, false, false },
        {33,  "Q4_0_8_8",0,   0, true,  false, false, false, false },
        {34,  "TQ1_0",  256, 54, true,  true,  false, true,  false }, // P2
        {35,  "TQ2_0",  256, 66, true,  true,  false, true,  false }, // P2
        {36,  "IQ4_NL_4_4",0, 0, true,  false, false, false, false },
        {37,  "IQ4_NL_4_8",0, 0, true,  false, false, false, false },
        {38,  "IQ4_NL_8_8",0, 0, true,  false, false, false, false },
        {39,  "MXFP4",   32, 17, true,  true,  false, true,  false }, // P2 HIGH
        {40,  "NVFP4",   64, 36, true,  true,  false, true,  false }, // P2 HIGH
        {41,  "Q1_0",   128, 18, true,  true,  false, true,  false }, // P2
        {42,  "Q2_0",    32, 17, true,  true,  false, true,  false }, // P2 (provisional)
    };
    return kTable;
}

inline const QuantTypeDescriptor* LookupQuantType(uint32_t ggmlId) {
    if (ggmlId >= static_cast<uint32_t>(GGMLType::GGML_TYPE_COUNT))
        return nullptr;
    const QuantTypeDescriptor* d = &QuantTypeTable()[ggmlId];
    if (d->blockElements == 0 || d->blockBytes == 0)
        return nullptr; // fail-closed (removed / unknown)
    return d;
}

inline const QuantTypeDescriptor* LookupQuantType(GGMLType t) {
    return LookupQuantType(static_cast<uint32_t>(t));
}

inline bool QuantTypeIsKnown(uint32_t ggmlId) {
    return LookupQuantType(ggmlId) != nullptr;
}

inline const char* QuantTypeName(uint32_t ggmlId) {
    if (ggmlId >= static_cast<uint32_t>(GGMLType::GGML_TYPE_COUNT))
        return "UNKNOWN";
    return QuantTypeTable()[ggmlId].name;
}

inline size_t QuantTypeBlockBytes(uint32_t ggmlId) {
    const auto* d = LookupQuantType(ggmlId);
    return d ? d->blockBytes : 0;
}

inline size_t QuantTypeBlockElements(uint32_t ggmlId) {
    const auto* d = LookupQuantType(ggmlId);
    return d ? d->blockElements : 0;
}

inline bool QuantTypeIsQuantized(uint32_t ggmlId) {
    const auto* d = LookupQuantType(ggmlId);
    return d ? d->isQuantized : false;
}

// Coverage counters for cert harnesses
struct QuantCoverageStats {
    int knownTypes = 0;
    int persistedTypes = 0;
    int kernelReady = 0;
    int missingKernels = 0;
};

inline QuantCoverageStats ComputeQuantCoverageStats() {
    QuantCoverageStats s{};
    for (uint32_t i = 0; i < static_cast<uint32_t>(GGMLType::GGML_TYPE_COUNT); ++i) {
        const auto& d = QuantTypeTable()[i];
        if (d.blockElements == 0) continue;
        ++s.knownTypes;
        if (d.persistedGGUF) ++s.persistedTypes;
        if (d.kernelReady) ++s.kernelReady;
        else if (d.persistedGGUF) ++s.missingKernels;
    }
    return s;
}

} // namespace Deep2
