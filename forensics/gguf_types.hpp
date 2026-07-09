/**
 * GGUF Type Definitions and Utilities
 * 
 * Complete mapping of GGUF format types for forensics and runtime use.
 */

#ifndef GGUF_TYPES_HPP
#define GGUF_TYPES_HPP

#include <cstdint>
#include <cstddef>
#include <string>

namespace gguf {

// ============================================================================
// Magic and Version
// ============================================================================

static constexpr uint32_t MAGIC = 0x46554747;  // "GGUF" in little-endian
static constexpr uint32_t VERSION_MIN = 2;
static constexpr uint32_t VERSION_MAX = 3;
static constexpr size_t ALIGNMENT = 64;  // Tensor data alignment

// ============================================================================
// Tensor Types (GGML types)
// ============================================================================

enum class TensorType : uint32_t {
    // Floating point
    F32     = 0,
    F16     = 1,
    BF16    = 30,  // Added in newer versions
    F64     = 28,
    
    // Quantized - legacy
    Q4_0    = 2,
    Q4_1    = 3,
    Q5_0    = 6,
    Q5_1    = 7,
    Q8_0    = 8,
    Q8_1    = 9,
    
    // Quantized - K-quants (Kobold)
    Q2_K    = 10,
    Q3_K    = 11,
    Q4_K    = 12,
    Q5_K    = 13,
    Q6_K    = 14,
    Q8_K    = 15,
    
    // Quantized - I-quants (Imatrix)
    IQ2_XXS = 16,
    IQ2_XS  = 17,
    IQ3_XXS = 18,
    IQ1_S   = 19,
    IQ4_NL  = 20,
    IQ3_S   = 21,
    IQ2_S   = 22,
    IQ4_XS  = 23,
    IQ1_M   = 29,
    
    // Integer types
    I8      = 24,
    I16     = 25,
    I32     = 26,
    I64     = 27,
    
    COUNT
};

// ============================================================================
// Metadata Value Types
// ============================================================================

enum class ValueType : uint32_t {
    UINT8   = 0,
    INT8    = 1,
    UINT16  = 2,
    INT16   = 3,
    UINT32  = 4,
    INT32   = 5,
    FLOAT32 = 6,
    BOOL    = 7,
    STRING  = 8,
    ARRAY   = 9,
    UINT64  = 10,
    INT64   = 11,
    FLOAT64 = 12,
    COUNT
};

// ============================================================================
// Type Information
// ============================================================================

struct TensorTypeInfo {
    const char* name;
    size_t size;           // Size per element (or block for quantized)
    bool is_quantized;
    uint32_t block_size;   // Elements per block (1 for non-quantized)
    const char* description;
};

// Get type information
const TensorTypeInfo* GetTensorTypeInfo(TensorType type);
const char* GetTensorTypeName(TensorType type);
const char* GetValueTypeName(ValueType type);

// Type properties
bool IsQuantized(TensorType type);
bool IsFloatingPoint(TensorType type);
bool IsInteger(TensorType type);
size_t GetTensorSize(TensorType type, uint64_t num_elements);

// ============================================================================
// Block Structure Definitions (for forensics)
// ============================================================================

// Q4_K block structure (256 elements)
struct Q4KBlock {
    // Scales (6-bit packed)
    uint8_t scales[12];      // 12 bytes for 16 scales (6-bit each, packed)
    
    // Minimum values (F16)
    uint16_t dmin;           // Scale for min values
    
    // Quantized weights (4-bit)
    uint8_t qs[128];         // 256 nibbles = 128 bytes
    
    // Block scale (F16)
    uint16_t d;              // Scale for this block
    
    // Total: 144 bytes per 256 elements = 0.5625 bits/weight
};

// Q2_K block structure (256 elements)
struct Q2KBlock {
    uint16_t d;              // F16 scale
    uint16_t dmin;           // F16 min scale
    uint8_t scales[4];       // 6-bit scales packed
    uint8_t qs[64];          // 256 2-bit weights
    // Total: 72 bytes per 256 elements = 2.25 bits/weight
};

// Q6_K block structure (256 elements)
struct Q6KBlock {
    uint8_t ql[128];         // Low 4 bits of each weight
    uint8_t qh[64];          // High 2 bits of each weight
    uint8_t scales[64];       // 8-bit scales
    uint16_t d;              // F16 super-scale
    // Total: 258 bytes per 256 elements = 8.06 bits/weight
};

// Q8_0 block structure (32 elements)
struct Q8_0Block {
    uint16_t d;              // F16 scale
    int8_t qs[32];           // 8-bit quantized values
    // Total: 34 bytes per 32 elements = 8.5 bits/weight
};

// Q8_K block structure (256 elements)
struct Q8KBlock {
    uint16_t d;              // F16 scale
    uint16_t dmin;           // F16 min scale
    uint8_t scales[64];       // 8-bit scales
    int8_t qs[256];          // 8-bit quantized values
    // Total: 324 bytes per 256 elements = 10.125 bits/weight
};

// ============================================================================
// Forensics Utilities
// ============================================================================

// Calculate expected tensor size based on type and dimensions
uint64_t CalculateTensorDataSize(TensorType type, const uint64_t* dims, uint32_t n_dims);

// Verify if a tensor type is valid/supported
bool IsValidTensorType(uint32_t type_id);

// Get quantization bits per weight
float GetBitsPerWeight(TensorType type);

// Format dimension string
std::string FormatDimensions(const uint64_t* dims, uint32_t n_dims);

// Format byte size with units (B, KB, MB, GB)
std::string FormatBytes(uint64_t bytes);

// ============================================================================
// Alignment Utilities
// ============================================================================

template<typename T>
constexpr T AlignUp(T value, T alignment) {
    return (value + alignment - 1) & ~(alignment - 1);
}

template<typename T>
constexpr bool IsAligned(T value, T alignment) {
    return (value & (alignment - 1)) == 0;
}

// GGUF uses 64-byte alignment for tensor data
constexpr size_t GGUF_ALIGNMENT = 64;

} // namespace gguf

#endif // GGUF_TYPES_HPP
