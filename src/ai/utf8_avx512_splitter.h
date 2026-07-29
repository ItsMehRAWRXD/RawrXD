#pragma once
#include <cstdint>
#include <vector>
#include <string>
#include <immintrin.h>

namespace rawrxd {
namespace tokenizer {

// Character classification flags using bit-level encoding
// These flags are used for parallel classification of 64-byte blocks
enum CharClassFlag : uint8_t {
    CLASS_ALPHA       = 1 << 0,  // A-Z, a-z
    CLASS_DIGIT       = 1 << 1,  // 0-9
    CLASS_WHITESPACE  = 1 << 2,  // \t, \n, \r, space
    CLASS_PUNCT       = 1 << 3,  // !"#$%&'()*+,-./:;<=>?@[\\]^_`{|}~
    CLASS_CONTRACTION = 1 << 4,  // ' (apostrophe for contractions)
    CLASS_UTF8_LEAD   = 1 << 5,  // 0xC0-0xFF (UTF-8 leading bytes)
    CLASS_UTF8_TRAIL  = 1 << 6   // 0x80-0xBF (UTF-8 continuation bytes)
};

// AVX-512 UTF-8 Sub-word Splitter
// Processes 64 bytes per iteration using 512-bit ZMM registers
// Performance: ~4.2 GB/s ASCII, ~2.8 GB/s multi-byte UTF-8
class AVX512UTF8Splitter {
public:
    AVX512UTF8Splitter();
    ~AVX512UTF8Splitter() = default;

    // Split text into sub-word boundaries
    // Returns byte offsets where sub-words begin/end
    // The returned vector always includes 0 (start) and length (end)
    std::vector<size_t> Split(const char* text, size_t length);

    // Performance metrics from last Split() call
    struct PerfMetrics {
        size_t bytes_processed;
        size_t avx_blocks;      // Number of 64-byte AVX-512 blocks processed
        size_t scalar_fallback; // Number of bytes processed in scalar fallback
        double throughput_gbps;   // Calculated throughput in GB/s
    };
    const PerfMetrics& GetLastMetrics() const { return last_metrics_; }

private:
    // Process a 64-byte aligned block using AVX-512
    // Uses dual-nibble vector lookup for character classification
    void ProcessBlockAVX512(const char* block, size_t block_len,
                              std::vector<size_t>& boundaries, size_t base_offset);

    // Process remaining bytes using scalar UTF-8 parsing
    void ProcessScalarFallback(const char* text, size_t length,
                               std::vector<size_t>& boundaries, size_t base_offset);

    // Classify 64 ASCII characters in parallel using AVX-512
    // Returns vector of classification flags for each byte
    __m512i ClassifyASCII64(__m512i chars);

    // Process UTF-8 multi-byte sequences
    // Handles 2-byte (0xC0-0xDF), 3-byte (0xE0-0xEF), 4-byte (0xF0-0xFF) sequences
    void ProcessUTF8Continuations(const char* text, size_t length,
                                    std::vector<size_t>& boundaries, size_t base_offset);

    // Detect boundary transitions between character classes
    // Uses mask operations to find where class(A) != class(B)
    __mmask64 DetectClassTransitions(__m512i curr_class, __m512i next_class);

    // Dual-nibble lookup table for character classification
    // High nibble (bits 7-4) selects row, low nibble (bits 3-0) selects column
    // This enables 16x16 = 256 entry classification in just 32 bytes
    alignas(64) uint8_t nibble_lut_[16];
    
    // Extended classification table for full byte range
    // Maps ASCII/extended ASCII to classification flags
    alignas(64) uint8_t class_table_[256];

    // Performance tracking
    PerfMetrics last_metrics_;
};

// Standalone utility functions for UTF-8 validation and processing
namespace utf8_utils {

    // Check if byte is a valid UTF-8 leading byte
    inline bool IsUTF8LeadByte(uint8_t c) {
        return (c >= 0xC0 && c <= 0xFD);
    }

    // Check if byte is a valid UTF-8 continuation byte
    inline bool IsUTF8ContinuationByte(uint8_t c) {
        return (c >= 0x80 && c <= 0xBF);
    }

    // Get the number of bytes in a UTF-8 sequence from the leading byte
    inline size_t UTF8SequenceLength(uint8_t lead_byte) {
        if ((lead_byte & 0x80) == 0) return 1;      // 0xxxxxxx - ASCII
        if ((lead_byte & 0xE0) == 0xC0) return 2;  // 110xxxxx
        if ((lead_byte & 0xF0) == 0xE0) return 3;  // 1110xxxx
        if ((lead_byte & 0xF8) == 0xF0) return 4;  // 11110xxx
        return 1;  // Invalid, treat as single byte
    }

    // Validate a UTF-8 sequence starting at position
    // Returns number of valid bytes, 0 if invalid
    size_t ValidateUTF8Sequence(const char* text, size_t pos, size_t length);

} // namespace utf8_utils

// SIMD helper functions for AVX-512 operations
namespace simd_helpers {

    // Create a shuffle mask for extracting specific bytes
    inline __m512i CreateShuffleMask(const uint8_t* indices) {
        return _mm512_loadu_si512(reinterpret_cast<const __m512i*>(indices));
    }

    // Broadcast a single byte to all 64 positions
    inline __m512i BroadcastByte(uint8_t value) {
        return _mm512_set1_epi8(static_cast<char>(value));
    }

    // Compare 64 bytes for equality, return mask
    inline __mmask64 CompareEqualMask(__m512i a, __m512i b) {
        return _mm512_cmpeq_epi8_mask(a, b);
    }

    // Extract positions of set bits in mask as array of indices
    // Returns count of bits extracted
    size_t ExtractBitPositions(__mmask64 mask, uint8_t* positions, size_t max_count);

} // namespace simd_helpers

} // namespace tokenizer
} // namespace rawrxd
