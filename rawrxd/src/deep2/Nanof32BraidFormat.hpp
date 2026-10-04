#pragma once
// ============================================================================
// Nanof32BraidFormat.hpp — On-disk layout for nanof32braidQuantless models
// ============================================================================
// Format: reverse-streamed, sub-1-bit compressed, bfloat16 output
// Effective: 1.15 bits/weight for 671B params → ~98 GB on disk
//
// Stream direction: BACKWARD (read footer first, then data)
// Eliminates forward-parse stalls and NaN propagation from misaligned headers.
// ============================================================================

#include <cstdint>
#include <cstddef>

namespace Deep2 {

// ----------------------------------------------------------------------------
// Magic and version
// ----------------------------------------------------------------------------
constexpr uint32_t NANO_F32_BRAID_MAGIC      = 0x4E513252; // 'NQ2R'
constexpr uint32_t NANO_F32_BRAID_VERSION    = 1;

// ----------------------------------------------------------------------------
// Global file header (at byte 0 of the file)
// ----------------------------------------------------------------------------
struct alignas(64) Nanof32BraidHeader {
    uint32_t magic;           // NQ2R
    uint32_t version;       // 1
    uint64_t paramCount;      // total parameters (e.g. 671000000000)
    uint32_t bitsPerWeight;   // fixed-point: 115 = 1.15 bits/weight
    uint32_t numTensors;      // tensor count
    uint64_t tensorDirOffset; // absolute offset to tensor directory footer
    uint64_t fileSize;        // total file size in bytes
    uint64_t reserved[4];     // padding to 64 bytes
};

// ----------------------------------------------------------------------------
// Architecture metadata (stored at byte 64, immediately after header)
// Required for Deep2Engine to configure geometry without a GGUF loader.
// ----------------------------------------------------------------------------
struct alignas(64) Nanof32BraidArchMeta {
    char     modelName[32];      // e.g. "DeepSeek-R1-671B"
    char     archName[16];       // e.g. "deepseek2"
    uint32_t numLayers;          // total transformer layers
    uint32_t numExperts;           // total experts (0 for dense)
    uint32_t activeExperts;        // routed per token (0 for dense)
    uint32_t hiddenDim;            // hidden dimension
    uint32_t numHeads;             // attention heads
    uint32_t numKVHeads;           // GQA / MLA kv heads
    uint32_t headDim;              // dimension per head
    uint32_t intermediateDim;      // FFN intermediate dimension
    uint32_t vocabSize;            // vocabulary size
    uint32_t contextLength;        // max context length
    uint32_t ropeType;             // 0=none, 1=NeoX, 2=GPT-J, 3=MLA
    float    normEps;              // RMSNorm epsilon
    uint32_t moeGateDim;           // MoE gate dimension
    uint32_t hasSharedExperts;     // 1 if shared expert present
    uint32_t reserved[3];            // padding
};

// ----------------------------------------------------------------------------
// Per-tensor footer (read FIRST when reverse-streaming)
// Appended at the end of each tensor's data block.
// ----------------------------------------------------------------------------
struct alignas(32) Nanof32BraidTensorFooter {
    uint32_t magic;           // NQ2R (validates structural integrity)
    uint32_t quantType;       // decompression dispatch index
    float    scaleMin;        // global floor (prevents NaN dispatch)
    float    scaleMax;        // global ceiling
    uint64_t rows;            // output dimension
    uint64_t cols;            // input dimension
    uint64_t dataBytes;       // compressed byte count
    uint32_t expertIndex;     // 0xFFFFFFFF for dense, else expert id
    char     name[64];        // tensor name (null-terminated, e.g. "blk.0.attn_q.weight")
};

// Quant type dispatch indices
constexpr uint32_t NQBRAID_DENSE_F32      = 0;  // uncompressed float32
constexpr uint32_t NQBRAID_DENSE_BF16     = 1;  // uncompressed bfloat16
constexpr uint32_t NQBRAID_CODEBOOK_1BIT  = 2;  // 1-bit codebook (2 centroids)
constexpr uint32_t NQBRAID_CODEBOOK_2BIT  = 3;  // 2-bit codebook (4 centroids)
constexpr uint32_t NQBRAID_CODEBOOK_3BIT  = 4;  // 3-bit codebook (8 centroids)
constexpr uint32_t NQBRAID_BRAID_115      = 5;  // 1.15-bit braid (sub-1-bit)
constexpr uint32_t NQBRAID_COUNT          = 6;

// ----------------------------------------------------------------------------
// Block constants
// ----------------------------------------------------------------------------
constexpr size_t NQBRAID_BLOCK_SIZE = 4096;       // disk read granularity
constexpr size_t NQBRAID_CACHE_BLOCKS = 256;     // in-memory cache size

} // namespace Deep2
