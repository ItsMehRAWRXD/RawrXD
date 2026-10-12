// ============================================================================
// gguf_compat.h — bridges this repo's GGUFLoader to the ggml gguf.h vocabulary
// ============================================================================
// The Deep2 GGUFLoader (src/deep2/GGUFLoader.cpp) was written against a
// *different* gguf.h dialect than the one vendored now:
//
//   * it expects `enum class GGUFValueType { UINT8, INT8, ... }` with
//     enumerators named `GGUFValueType::UINT8`, whereas the vendored gguf.h
//     declares `enum gguf_type { GGUF_TYPE_UINT8, ... }`;
//   * it compares against `GGUF_MAGIC` as a 32-bit integer, whereas the
//     vendored header defines it as the C string "GGUF" (which made
//     `reader.magic != GGUF_MAGIC` fail with C2446: no conversion from
//     const char[5] to uint32_t).
//
// Rather than edit ~2000 call sites across GGUFLoader.cpp,
// QuantKernelRegistry_K.h and MoEWeightsLoader.cpp, this header supplies the
// missing names as aliases. Including gguf.h first keeps the canonical
// definitions authoritative.
// ============================================================================
#pragma once

// ggml-common.h emits NOTHING unless one of the GGML_COMMON_DECL_* macros is
// defined first. Without it, every block_q2_K / block_q6_K / block_q8_K type
// is silently absent, which is why QuantKernelRegistry_K.h failed with
// "block_q2_K: undeclared identifier" even though the header was correctly
// included. Pick the C++ dialect for a C++ TU.
#ifndef GGML_COMMON_DECL_C
#ifndef GGML_COMMON_DECL_CPP
#ifndef GGML_COMMON_DECL_METAL
#ifndef GGML_COMMON_DECL_CUDA
#ifndef GGML_COMMON_DECL_HIP
#ifndef GGML_COMMON_DECL_SYCL
#ifndef GGML_COMMON_DECL_OPENCL
#ifndef GGML_COMMON_DECL_VULKAN
#ifdef __cplusplus
#define GGML_COMMON_DECL_CPP
#else
#define GGML_COMMON_DECL_C
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif
#endif

#include "gguf.h"

// ggml-common.h defines ggml_half, block_q2_K, block_q6_K, block_q8_K and QK_K
// (all at global scope). It must come after the GGML_COMMON_DECL_* selection
// above, otherwise it expands to nothing.
#if __has_include("ggml-common.h")
#include "ggml-common.h"      // IWYU pragma: export
#elif __has_include("../src/ggml-common.h")
#include "../src/ggml-common.h" // IWYU pragma: export
#endif

// --- enum class aliases (GGUFValueType::UINT8 == GGUF_TYPE_UINT8) ----------
enum class GGUFValueType : int32_t {
    UINT8     = GGUF_TYPE_UINT8,
    INT8      = GGUF_TYPE_INT8,
    UINT16    = GGUF_TYPE_UINT16,
    INT16     = GGUF_TYPE_INT16,
    UINT32    = GGUF_TYPE_UINT32,
    INT32     = GGUF_TYPE_INT32,
    FLOAT32   = GGUF_TYPE_FLOAT32,
    BOOL      = GGUF_TYPE_BOOL,
    STRING    = GGUF_TYPE_STRING,
    ARRAY     = GGUF_TYPE_ARRAY,
    UINT64    = GGUF_TYPE_UINT64,
    INT64     = GGUF_TYPE_INT64,
    FLOAT64   = GGUF_TYPE_FLOAT64,
};

// --- integer GGUF_MAGIC ----------------------------------------------------
// gguf.h defines GGUF_MAGIC as "GGUF"; this repo compares it as a uint32_t.
// The first four bytes of a GGUF file are exactly those characters, so the
// little-endian comparison below is equivalent to the byte sequence.
#ifdef _MSC_VER
#define GG4(a,b,c,d) ((uint32_t)(unsigned char)(a) | ((uint32_t)(unsigned char)(b) << 8) | \
                      ((uint32_t)(unsigned char)(c) << 16) | ((uint32_t)(unsigned char)(d) << 24))
#undef GGUF_MAGIC
#define GGUF_MAGIC GG4('G','G','U','F')
#endif

#ifndef GGUF_VERSION
#define GGUF_VERSION 3u
#endif

// --- K-quant scale access, flat --------------------------------------------
// ggml-common.h declares the K-quant scales inside an anonymous union whose
// field name is fixed by GGML_COMMON_AGGR_S/U (`data` in C++ dialects), so the
// memory layout is correct but the field path is block.data.d, not block.d.
// Defining both macros empty makes the union and its inner struct anonymous,
// which promotes `d`/`dmin` (and `dm`) to the enclosing struct WITHOUT
// changing the layout - the union is still a union, so `dm` still overlaps
// `d`/`dmin` exactly as intended. This repo's kernels then compile unchanged.
#ifndef GGML_COMMON_AGGR_S
#define GGML_COMMON_AGGR_S
#endif
#ifndef GGML_COMMON_AGGR_U
#define GGML_COMMON_AGGR_U
#endif


