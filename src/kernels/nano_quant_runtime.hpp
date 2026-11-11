//============================================================================
// nano_quant_runtime.hpp
// RawrXD NanoQuant Runtime - Complete Implementation
// Zero dependencies, pure x64 MASM kernels
//============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

// Platform export macros
#if defined(_MSC_VER)
    #define RAWRXD_KERNEL_API extern "C" __declspec(dllexport)
#else
    #define RAWRXD_KERNEL_API extern "C" __attribute__((visibility("default")))
#endif

namespace RawrXD {
namespace NanoQuant {

//============================================================================
// Format Constants (from nano_format.inc)
//============================================================================
constexpr uint32_t NANO_MAGIC = 0x52415752;  // "RAWR"
constexpr uint32_t NANO_VERSION = 0x00010000;

enum class NanoCodec : uint32_t {
    RAW = 0,        // FP16
    Q8 = 1,         // 8-bit
    Q4 = 2,         // 4-bit
    Q2 = 3,         // 2-bit LUT
    BINARY = 4      // 0.5-bit XNOR
};

//============================================================================
// File Header (64 bytes)
//============================================================================
#pragma pack(push, 1)
struct NanoHeader {
    uint32_t magic;              // "RAWR"
    uint32_t version;            // 1.0
    uint64_t tensor_count;       // Number of tensors
    uint64_t codebook_offset;    // Codebook section
    uint64_t tensor_dir_offset;  // Tensor directory
    uint64_t data_offset;        // Packed data start
    uint64_t metadata_size;      // Metadata section
    uint32_t flags;              // Format flags
    uint32_t reserved;           // Padding
    uint64_t checksum;           // CRC64
};

struct NanoTensorEntry {
    char name[32];               // Tensor name
    uint32_t shape[4];           // Dimensions
    uint32_t codec_type;         // Compression codec
    uint64_t data_offset;        // Data location
    uint64_t data_size;          // Data size
    uint32_t codebook_id;        // Codebook index
    uint32_t importance;         // Importance score
    uint64_t residual_offset;    // Residuals
    uint64_t residual_size;
};

struct NanoCodebookHeader {
    uint32_t entry_count;
    uint32_t entry_size;
    uint64_t data_offset;
    uint64_t data_size;
};
#pragma pack(pop)

//============================================================================
// Kernel Function Declarations (MASM)
//============================================================================

// LUT-2 (2-bit) matrix multiplication
// Unpacks 2-bit indices, looks up in 4-entry codebook, FMA with activations
RAWRXD_KERNEL_API void NanoMatMul_LUT2(
    const uint8_t* packed_indices,   // 2-bit packed weights (64 bytes per 256 weights)
    const float* activations,        // FP32 activations
    float* output,                   // FP32 output accumulator
    const float* codebook,           // 4-entry codebook
    uint64_t element_count           // Must be multiple of 256
);

// XNOR (0.5-bit binary) matrix multiplication
// Binary weights {-1, +1}, binary activations, popcount for dot product
RAWRXD_KERNEL_API void NanoMatMul_XNOR(
    const uint8_t* packed_weights,   // 1 bit per weight
    const uint8_t* packed_activations, // 1 bit per activation
    float* output,                   // Single float result
    uint64_t element_count           // Must be multiple of 512
);

//============================================================================
// Runtime Classes
//============================================================================

class NanoTensorView {
public:
    const char* name;
    uint32_t shape[4];
    NanoCodec codec;
    
    // Data pointers
    const uint8_t* packed_data;
    uint64_t packed_size;
    
    // Codebook (for Q2, Q4)
    const float* codebook;
    uint32_t codebook_entries;
    
    // Residuals (for high-precision correction)
    const float* residuals;
    uint64_t residual_count;
    
    // Importance for adaptive precision
    uint32_t importance_score;
    
    // Execution
    void Execute(const float* activations, float* output, uint64_t count) const;
};

class NanoQuantRuntime {
public:
    // Load .nano file from disk (memory-mapped)
    bool Load(const char* filepath);
    
    // Get tensor by name
    const NanoTensorView* GetTensor(const char* name) const;
    
    // Execute tensor operation
    bool Execute(const char* tensor_name, 
                 const float* activations, 
                 float* output,
                 uint64_t count);
    
    // Adaptive precision control
    void SetPrecisionLevel(uint32_t level);  // 0=brutal, 3=precise
    
private:
    void* mapped_file;
    size_t file_size;
    
    NanoHeader* header;
    NanoTensorEntry* tensor_dir;
    NanoCodebookHeader* codebooks;
    
    uint32_t current_precision = 2;  // Default: balanced
};

} // namespace NanoQuant
} // namespace RawrXD
