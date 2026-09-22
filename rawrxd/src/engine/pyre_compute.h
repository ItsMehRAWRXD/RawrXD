// ============================================================================
// pyre_compute.h — Pyre Engine compute types and layer configuration
//
// Provides:
//   - PyreLayerConfig     : per-model architecture config (used by LayerOffloadManager)
//   - PyreDataType        : enumeration of tensor element types
//   - PyreTensor          : lightweight tensor descriptor
//
// Design:
//   - Header-only, no link dependency
//   - Plain structs with default member initializers (C++17 compatible)
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
// Forward declaration — defined in patch_result.hpp
struct PatchResult;
namespace RawrXD {

// ============================================================================
// PyreDataType — GGML-style type enum
// ============================================================================
enum class PyreDataType : uint32_t {
    F32  = 0,   // 32-bit float
    F16  = 1,   // 16-bit float
    Q4_0 = 2,   // 4-bit quantization (block 32)
    Q4_1 = 3,   // 4-bit quantization with min (block 32)
    Q5_0 = 6,   // 5-bit quantization
    Q5_1 = 7,   // 5-bit quantization with min
    Q8_0 = 8,   // 8-bit quantization (block 32)
    Q8_1 = 9,   // 8-bit quantization with min
    Q2_K = 10,  // K-quants 2-bit
    Q3_K = 11,  // K-quants 3-bit
    Q4_K = 12,  // K-quants 4-bit
    Q5_K = 13,  // K-quants 5-bit
    Q6_K = 14,  // K-quants 6-bit
    Q8_K = 15,  // K-quants 8-bit
    I8   = 16,  // 8-bit integer
    I16  = 17,  // 16-bit integer
    I32  = 18,  // 32-bit integer
    COUNT
};

// ============================================================================
// PyreLayerConfig — Model architecture configuration
// ============================================================================
struct PyreLayerConfig {
    uint32_t numLayers          = 0;    // Number of transformer layers
    uint32_t numHeads           = 0;    // Attention heads
    uint32_t numKVHeads         = 0;    // Key/Value heads (GQA)
    uint32_t embeddingDim       = 0;    // Hidden size (e.g. 4096)
    uint32_t intermediateSize   = 0;    // FFN intermediate dimension
    uint32_t vocabSize          = 0;    // Vocabulary size
    uint32_t contextLength      = 0;    // Max context length
    uint32_t headDim            = 0;    // embeddingDim / numHeads
    float    rmsNormEps         = 1e-5f;
    float    ropeTheta          = 10000.0f;
    float    ropeScale          = 1.0f;
    PyreDataType weightType     = PyreDataType::Q4_0; // Default quantization
    bool     useGQA             = false; // Grouped Query Attention
    bool     useSlidingWindow   = false; // Sliding window attention
    uint32_t slidingWindowSize  = 0;

    // Compute derived headDim automatically when heads > 0
    void finalize() {
        if (numHeads > 0 && embeddingDim > 0 && headDim == 0) {
            headDim = embeddingDim / numHeads;
        }
    }
};

// ============================================================================
// PyreTensor — Lightweight tensor descriptor (no ownership of data)
// ============================================================================
struct PyreTensor {
    const char* name      = nullptr;
    void*       data      = nullptr;
    uint64_t    byteSize  = 0;
    uint32_t    dims      = 0;
    uint64_t    shape[4]  = {0,0,0,0};
    PyreDataType dtype    = PyreDataType::F32;

    uint64_t elementCount() const {
        uint64_t n = 1;
        for (uint32_t i = 0; i < dims; ++i) n *= shape[i];
        return n;
    }

    size_t elementSize() const {
        switch (dtype) {
            case PyreDataType::F32: return 4;
            case PyreDataType::F16: return 2;
            case PyreDataType::Q4_0:
            case PyreDataType::Q4_1: return 1; // per-element average
            case PyreDataType::Q8_0:
            case PyreDataType::Q8_1: return 1;
            case PyreDataType::I8:   return 1;
            case PyreDataType::I16:  return 2;
            case PyreDataType::I32:  return 4;
            default: return 1;
        }
    }
};

// ============================================================================
// PyreModelHeader — File header for .pyre model containers
// ============================================================================
struct PyreModelHeader {
    uint32_t magic       = 0x45525950; // 'PYRE'
    uint32_t version     = 1;
    uint32_t numLayers   = 0;
    uint32_t numTensors  = 0;
    uint64_t dataOffset  = 0; // byte offset to tensor blob area
    uint64_t metadataOffset = 0;
};

// ============================================================================
// PyreWeightEntry — Directory entry for one tensor inside a .pyre file
// ============================================================================
struct PyreWeightEntry {
    char     name[128]   = {};
    uint32_t ndim        = 0;
    uint64_t dims[4]     = {0,0,0,0};
    uint64_t offset      = 0; // relative to dataOffset
    uint64_t byteSize    = 0;
    PyreDataType dtype   = PyreDataType::F32;
};

} // namespace RawrXD

