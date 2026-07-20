//=============================================================================
// Q4_0 Weight Preprocessor
// Converts nibble-interleaved GGUF format to byte-planar for fast AVX-512
//
// GGUF Q4_0 layout (64 bytes):
//   [0:1]   scale (fp16)
//   [2:33]  32 packed nibbles (64 weights)
//
// Preprocessed layout (128 bytes):
//   [0:1]   scale (fp16)
//   [2:65]  64 bytes, low nibble of each weight (0-15)
//   [66:129] 64 bytes, high nibble (unused, reserved)
//
// Actually simpler: just expand to 64 bytes of contiguous weights
// Each weight is stored as one byte (0-15), no packing
//=============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <vector>
#include <memory>

namespace RawrXD {
namespace Memory {

// Q4PreparedBlock header - explicit metadata for version safety
struct alignas(8) Q4BlockHeader {
    uint32_t magic;           // 'Q4P0' = 0x51345030
    uint32_t version;         // Layout version (1 = current)
    uint32_t block_count;     // Total blocks in tensor
    uint32_t original_elements; // Original element count
    
    static constexpr uint32_t MAGIC = 0x51345030;  // 'Q4P0'
    static constexpr uint32_t VERSION = 1;
    
    bool validate() const {
        return magic == MAGIC && version == VERSION;
    }
};

// Preprocessed Q4_0 block (expanded for fast access)
// Layout: header (16 bytes) + scale (4 bytes) + weights (64 bytes) + padding
struct alignas(64) PreprocessedQ4Block {
    Q4BlockHeader header;     // Metadata for safety
    float scale;              // fp32 scale (converted from fp16)
    int8_t weights[64];       // 64 unpacked weights (-8 to +7)
    
    // Padding to 128 bytes for cache line alignment
    uint8_t padding[44];
    
    static constexpr size_t SIZE = 128;  // Aligned size
    
    // Validate block integrity
    bool validate() const {
        return header.validate();
    }
    
    // Initialize header for new block
    void init_header(uint32_t count, uint32_t elements) {
        header.magic = Q4BlockHeader::MAGIC;
        header.version = Q4BlockHeader::VERSION;
        header.block_count = count;
        header.original_elements = elements;
    }
};

// Preprocessor for Q4_0 weights
class Q4WeightPreprocessor {
public:
    Q4WeightPreprocessor();
    ~Q4WeightPreprocessor();
    
    // Preprocess a single GGUF Q4_0 block
    // Input: 64 bytes (GGUF format)
    // Output: 128 bytes (preprocessed, aligned)
    static void PreprocessBlock(
        const void* gguf_block,
        PreprocessedQ4Block* output_block,
        uint32_t block_index = 0,
        uint32_t total_blocks = 1,
        uint32_t total_elements = 64
    );
    
    // Preprocess entire tensor
    // Returns preprocessed blocks, ready for AVX-512 kernel
    static std::vector<PreprocessedQ4Block> PreprocessTensor(
        const void* gguf_tensor_data,
        size_t num_blocks
    );
    
    // Get scale from preprocessed block (fp16 -> fp32)
    static float ExtractScale(const PreprocessedQ4Block* block);
    
    // Validate preprocessing (compare against reference dequantization)
    static bool ValidateBlock(
        const void* gguf_block,
        const PreprocessedQ4Block* preprocessed_block
    );
};

// Fast AVX-512 kernel using preprocessed weights
extern "C" {
    // Dot product of 64 preprocessed weights with 64 activations
    // Input: preprocessed block (128 bytes), activations (64 x fp32)
    // Output: dot product (fp32)
    float q4_preprocessed_dot_avx512(
        const PreprocessedQ4Block* block,
        const float* activations
    );
    
    // Batch process multiple blocks
    // Output: accumulator for each output element
    void q4_preprocessed_gemm_avx512(
        const PreprocessedQ4Block* blocks,  // Column-major blocks
        const float* activations,            // Input activations
        float* output,                       // Output accumulators
        size_t num_blocks,                   // K dimension in blocks
        size_t num_outputs                   // N dimension
    );
}

} // namespace Memory
} // namespace RawrXD
