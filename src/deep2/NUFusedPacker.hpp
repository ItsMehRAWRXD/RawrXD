// ============================================================================
// NUFusedPacker.hpp - NU Fused Compression / Decompression Engine
//
// VAL-000 Component: Compression Engine → NU Fused Packing
//
// NU (Non-Uniform) Fused packing combines multiple quantization formats into
// a single contiguous byte stream with a runtime decompression layer. This
// enables:
//   - Mixed-precision tensors (different layers at different precisions)
//   - 215XVA resource packing (aligned to cache lines)
//   - Multi-nibble layouts (2-bit, 3-bit, 4-bit, 6-bit in one stream)
//   - GGUF-independent execution (decompress to F32 on the fly)
//   - Runtime block translation (no compile-time format assumptions)
//
// Architecture:
//   Packed Stream: [Header][Block0][Block1]...[BlockN]
//   Header: format table + block offsets
//   Block: [formatTag][scale][packedData]
//
// Copyright (c) 2026 RawrXD Sovereign Runtime - VAL-000 Phase 3
// ============================================================================

#ifndef DEEP2_NU_FUSED_PACKER_HPP
#define DEEP2_NU_FUSED_PACKER_HPP

#include <cstddef>
#include <cstdint>
#include <vector>
#include <cstring>
#include <cmath>
#include <cstdio>

namespace Deep2 {

// ---------------------------------------------------------------------------
// NU Fused format tags
// ---------------------------------------------------------------------------
enum class NUFormatTag : uint8_t {
    NU_F32      = 0,   // Uncompressed F32
    NU_F16      = 1,   // Half precision
    NU_Q8_0     = 2,   // 8-bit quantized
    NU_Q4_0     = 3,   // 4-bit quantized
    NU_Q4_K     = 4,   // 4-bit K-quant
    NU_Q2_K     = 5,   // 2-bit K-quant
    NU_IQ2_XXS  = 6,   // 2-bit importance matrix
    NU_IQ3_S    = 7,   // 3-bit importance matrix
    NU_IQ4_NL   = 8,   // 4-bit non-linear
    NU_NIBBLE2  = 9,   // Raw 2-bit packed
    NU_NIBBLE3  = 10,  // Raw 3-bit packed
    NU_NIBBLE4  = 11,  // Raw 4-bit packed
    NU_NIBBLE6  = 12,  // Raw 6-bit packed
    NU_XVA      = 13,  // 215XVA resource packed
    NU_FUSED    = 14,  // Fused multi-format block
};

// ---------------------------------------------------------------------------
// Block format descriptor
// ---------------------------------------------------------------------------
struct NUBlockFormat {
    NUFormatTag tag;
    size_t      blockSize;     // Bytes per block
    size_t      elemsPerBlock; // Elements per block
    float       bitsPerWeight; // Compression density
};

// ---------------------------------------------------------------------------
// 215XVA Resource Packing Header
// Aligns packed data to 64-byte cache lines for zero-pollution loads
// ---------------------------------------------------------------------------
struct XVAHeader {
    uint32_t magic;          // 0x41585632 = "2VXA"
    uint16_t version;        // Format version
    uint16_t numBlocks;      // Number of packed blocks
    uint32_t totalElements;  // Total elements in tensor
    uint32_t totalBytes;     // Total packed bytes
    uint32_t cacheLineSize;  // 64 (standard) or 128 (AVX-512)
    uint32_t reserved[8];    // Future use
};

// ---------------------------------------------------------------------------
// NU Fused Stream Header
// ---------------------------------------------------------------------------
struct NUStreamHeader {
    uint32_t magic;          // 0x46554E00 = "NU\0"
    uint16_t version;
    uint16_t numFormats;     // Number of distinct formats used
    uint32_t numBlocks;      // Total blocks in stream
    uint32_t totalElements;  // Total elements
    uint32_t totalBytes;     // Total packed bytes
    uint32_t formatTable[16]; // Format tags used (up to 16)
    uint32_t blockOffsets[1]; // Variable-length block offset table
};

// ---------------------------------------------------------------------------
// NU Fused Packer Configuration
// ---------------------------------------------------------------------------
struct NUPackerConfig {
    bool    enableXVAAlignment = true;   // 215XVA cache-line alignment
    size_t  cacheLineSize = 64;          // 64 for AVX2, 128 for AVX-512
    bool    enableMultiNibble = true;     // Mixed nibble widths
    float   targetBitsPerWeight = 4.0f;   // Target compression density
    bool    enableRuntimeTranslation = true; // Decompress at runtime
};

// ---------------------------------------------------------------------------
// NUFusedPacker - Compression / Decompression engine
// ---------------------------------------------------------------------------
class NUFusedPacker {
public:
    NUFusedPacker();
    ~NUFusedPacker();

    // Initialize with config
    bool initialize(const NUPackerConfig& config);

    // Pack a float tensor into NU Fused format
    // Returns packed byte stream
    std::vector<uint8_t> packTensor(
        const float* data,
        size_t numElements,
        NUFormatTag targetFormat = NUFormatTag::NU_Q4_K
    );

    // Unpack a NU Fused stream to F32
    // Returns number of elements decompressed
    size_t unpackTensor(
        const uint8_t* packedData,
        size_t packedSize,
        float* output,
        size_t maxElements
    );

    // Pack with 215XVA cache-line alignment
    std::vector<uint8_t> packXVA(
        const float* data,
        size_t numElements,
        NUFormatTag targetFormat = NUFormatTag::NU_Q4_K
    );

    // Unpack 215XVA-aligned stream
    size_t unpackXVA(
        const uint8_t* packedData,
        size_t packedSize,
        float* output,
        size_t maxElements
    );

    // Multi-nibble packing: pack different blocks at different bit widths
    // based on dynamic range analysis
    std::vector<uint8_t> packMultiNibble(
        const float* data,
        size_t numElements
    );

    // Runtime block translation: decompress a single block
    // Used for on-the-fly dequantization in GEMV kernels
    size_t translateBlock(
        const uint8_t* blockData,
        NUFormatTag format,
        float* output,
        size_t maxElements
    );

    // Get compression statistics
    struct Stats {
        size_t totalPacked = 0;
        size_t totalUnpacked = 0;
        size_t bytesPacked = 0;
        size_t bytesUnpacked = 0;
        double avgCompressionRatio = 0.0;
    };
    const Stats& getStats() const { return stats_; }

    // Get format info
    static NUBlockFormat getFormatInfo(NUFormatTag tag);

private:
    NUPackerConfig config_;
    Stats stats_;

    // Per-format packing functions
    void packQ8_0(const float* src, uint8_t* dst, size_t n);
    void unpackQ8_0(const uint8_t* src, float* dst, size_t n);
    void packQ4_0(const float* src, uint8_t* dst, size_t n);
    void unpackQ4_0(const uint8_t* src, float* dst, size_t n);
    void packQ4_K(const float* src, uint8_t* dst, size_t n);
    void unpackQ4_K(const uint8_t* src, float* dst, size_t n);
    void packF16(const float* src, uint8_t* dst, size_t n);
    void unpackF16(const uint8_t* src, float* dst, size_t n);

    // Multi-nibble helpers
    uint8_t packNibble2(const float values[4], float scale);
    void    unpackNibble2(uint8_t packed, float scale, float out[4]);
    uint8_t packNibble3(const float values[8], float scale);
    void    unpackNibble3(const uint8_t packed[3], float scale, float out[8]);

    // XVA alignment helper
    size_t alignToCacheLine(size_t offset) const;
};

} // namespace Deep2

#endif // DEEP2_NU_FUSED_PACKER_HPP
