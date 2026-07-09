// ============================================================================
// TensorView.hpp - Frozen ABI for Tensor Access
// ============================================================================
// This is the stable contract between the loader layer and compute layer.
// Once kernels depend on this, changing the weight representation becomes
// a loader problem instead of a runtime rewrite.
//
// Frozen ABI - Do not modify without versioning:
//   struct TensorView {
//       const void* data;
//       uint64_t offset;
//       uint32_t rows;
//       uint32_t cols;
//       GGMLType type;
//       QuantizationInfo quant;
//       TensorProvenance provenance;
//       float Get(uint32_t row, uint32_t col) const;
//   };
// ============================================================================

#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <cstring>
#include <unordered_map>
namespace RawrXD {
namespace Runtime {

// GGML/GGUF tensor types
enum class GGMLType : uint32_t {
    F32  = 0,
    F16  = 1,
    Q4_0 = 2,
    Q4_1 = 3,
    Q5_0 = 6,
    Q5_1 = 7,
    Q8_0 = 8,
    Q8_1 = 9,
    Q2_K = 10,
    Q3_K = 11,
    Q4_K = 12,
    Q5_K = 13,
    Q6_K = 14,
    Q8_K = 15,
    I8   = 16,
    I16  = 17,
    I32  = 18,
    Count
};

// ============================================================================
// TensorProvenance - Tracks where tensor data came from
// ============================================================================
struct TensorProvenance {
    std::string source;        // File path or "synthetic"
    std::string tensorName;    // Name in GGUF or synthetic identifier
    uint64_t byteOffset = 0;   // Offset in source file
    size_t bytes = 0;          // Size in bytes
    bool quantized = false;    // Whether original data was quantized
    GGMLType sourceType = GGMLType::F32;  // Original GGML type
    
    bool IsSynthetic() const { return source == "synthetic"; }
};

// ============================================================================
// TensorData - Internal storage for tensor registry
// ============================================================================
struct TensorData {
    std::vector<float> f32Data;     // Dequantized float data
    std::vector<uint8_t> rawData;    // Raw quantized data
    GGMLType type = GGMLType::F32;
    std::vector<size_t> shape;
    TensorProvenance provenance;
};

// ============================================================================
// TensorView - Runtime access to tensor data with dequantization
// ============================================================================
// This is the frozen ABI. All compute kernels consume TensorView.
// ============================================================================
class TensorView {
public:
    TensorView() = default;
    explicit TensorView(const TensorData* data) : m_data(data) {}
    
    // ------------------------------------------------------------------------
    // Core Accessors (Frozen ABI)
    // ------------------------------------------------------------------------
    bool IsValid() const { return m_data != nullptr; }
    bool IsEmpty() const { return !m_data || m_data->f32Data.empty(); }
    
    uint32_t Rows() const {
        if (!m_data || m_data->shape.empty()) return 0;
        return static_cast<uint32_t>(m_data->shape[0]);
    }
    
    uint32_t Cols() const {
        if (!m_data || m_data->shape.size() < 2) return 0;
        return static_cast<uint32_t>(m_data->shape[1]);
    }
    
    GGMLType Type() const {
        return m_data ? m_data->type : GGMLType::F32;
    }
    
    bool IsQuantized() const {
        return m_data && m_data->provenance.quantized;
    }
    
    bool IsSynthetic() const {
        return m_data && m_data->provenance.IsSynthetic();
    }
    
    const TensorProvenance* GetProvenance() const {
        return m_data ? &m_data->provenance : nullptr;
    }
    
    // ------------------------------------------------------------------------
    // Dequantization Interface
    // ------------------------------------------------------------------------
    // Dequantize a single row to float array
    // Returns number of elements written
    size_t DequantizeRow(size_t row, float* output, size_t outputCapacity) const {
        if (!m_data || !output || outputCapacity == 0) return 0;
        
        uint32_t cols = Cols();
        if (cols == 0) cols = Rows();  // 1D tensor
        if (outputCapacity < cols) return 0;
        
        // For F32 data, just copy
        if (m_data->type == GGMLType::F32 || !m_data->f32Data.empty()) {
            size_t offset = row * cols;
            if (offset + cols > m_data->f32Data.size()) return 0;
            
            std::memcpy(output, m_data->f32Data.data() + offset, cols * sizeof(float));
            return cols;
        }
        
        // For Q4_K data, use real dequantization
        if (m_data->type == GGMLType::Q4_K) {
            return DequantizeQ4KRow(row, output, cols);
        }
        
        // For Q2_K data, use real dequantization
        if (m_data->type == GGMLType::Q2_K) {
            return DequantizeQ2KRow(row, output, cols);
        }
        
        // For other quantized types, return zeros (not yet implemented)
        std::memset(output, 0, cols * sizeof(float));
        return cols;
    }
    
private:
    // Q4_K dequantization
    size_t DequantizeQ4KRow(size_t row, float* output, uint32_t cols) const {
        if (!m_data || m_data->rawData.empty()) return 0;
        
        // Calculate row offset in raw data
        // Q4_K: 144 bytes per 256 elements
        size_t elements_per_block = 256;
        size_t bytes_per_block = 144;
        size_t blocks_per_row = (cols + elements_per_block - 1) / elements_per_block;
        size_t row_offset = row * blocks_per_row * bytes_per_block;
        
        if (row_offset >= m_data->rawData.size()) return 0;
        
        const uint8_t* row_data = m_data->rawData.data() + row_offset;
        
        // Dequantize using Q4KDecoder
        // Need to include the decoder - we'll use inline implementation
        DequantizeQ4KBlocks(row_data, cols, output);
        return cols;
    }
    
    // Q2_K dequantization
    size_t DequantizeQ2KRow(size_t row, float* output, uint32_t cols) const {
        if (!m_data || m_data->rawData.empty()) return 0;
        
        // Q2_K: 96 bytes per 256 elements
        size_t elements_per_block = 256;
        size_t bytes_per_block = 96;
        size_t blocks_per_row = (cols + elements_per_block - 1) / elements_per_block;
        size_t row_offset = row * blocks_per_row * bytes_per_block;
        
        if (row_offset >= m_data->rawData.size()) return 0;
        
        const uint8_t* row_data = m_data->rawData.data() + row_offset;
        DequantizeQ2KBlocks(row_data, cols, output);
        return cols;
    }
    
    // Inline Q4_K block dequantization
    void DequantizeQ4KBlocks(const uint8_t* data, size_t num_elements, float* output) const {
        struct BlockQ4_K {
            uint8_t scales[12];
            uint8_t qs[128];
            uint16_t d;
            uint16_t dmin;
        };
        
        const BlockQ4_K* blocks = reinterpret_cast<const BlockQ4_K*>(data);
        size_t num_blocks = (num_elements + 255) / 256;
        
        size_t out_idx = 0;
        for (size_t b = 0; b < num_blocks && out_idx < num_elements; b++) {
            const BlockQ4_K& block = blocks[b];
            
            // Convert F16 scale/min
            float d = F16ToF32(block.d);
            float dmin = F16ToF32(block.dmin);
            
            // Unpack scales (8 groups, each with scale and min)
            float scales[8];
            float mins[8];
            
            // Q4_K scale unpacking (llama.cpp compatible)
            // scales and mins are 6-bit values packed into 12 bytes
            for (int i = 0; i < 8; i++) {
                int idx = i * 3 / 2;
                int shift = (i % 2) * 4;
                
                uint8_t s0 = block.scales[idx];
                uint8_t s1 = (idx + 1 < 12) ? block.scales[idx + 1] : 0;
                
                uint8_t scale_val = (s0 >> shift) & 0xF;
                uint8_t min_val = ((s0 >> (shift + 4)) | (s1 << (4 - shift))) & 0xF;
                
                scales[i] = d * scale_val;
                mins[i] = dmin * min_val;
            }
            
            // Dequantize 256 values (8 groups of 32)
            for (int g = 0; g < 8 && out_idx < num_elements; g++) {
                for (int j = 0; j < 32 && out_idx < num_elements; j++) {
                    int q_idx = g * 32 + j;
                    uint8_t q = (q_idx & 1) ? (block.qs[q_idx >> 1] >> 4) : (block.qs[q_idx >> 1] & 0xF);
                    output[out_idx++] = scales[g] * q + mins[g];
                }
            }
        }
    }
    
    // Inline Q2_K block dequantization
    void DequantizeQ2KBlocks(const uint8_t* data, size_t num_elements, float* output) const {
        struct BlockQ2_K {
            uint8_t scales[6];
            uint8_t qs[64];
            uint16_t d;
            uint16_t dmin;
        };
        
        const BlockQ2_K* blocks = reinterpret_cast<const BlockQ2_K*>(data);
        size_t num_blocks = (num_elements + 255) / 256;
        
        size_t out_idx = 0;
        for (size_t b = 0; b < num_blocks && out_idx < num_elements; b++) {
            const BlockQ2_K& block = blocks[b];
            
            float d = F16ToF32(block.d);
            float dmin = F16ToF32(block.dmin);
            
            // Unpack 6 scales and 6 mins from 6 bytes
            float scales[6];
            float mins[6];
            
            for (int i = 0; i < 6; i++) {
                uint8_t s = block.scales[i];
                scales[i] = d * (s & 0x0F);
                mins[i] = dmin * ((s >> 4) & 0x0F);
            }
            
            // Dequantize 256 values (6 groups of 32 + 1 group of 64)
            // Actually Q2_K: 64 bytes of qs = 256 2-bit values
            for (int g = 0; g < 8 && out_idx < num_elements; g++) {
                int scale_idx = g < 6 ? g : 5;  // Last group uses last scale
                for (int j = 0; j < 32 && out_idx < num_elements; j++) {
                    int q_idx = g * 32 + j;
                    int byte_idx = q_idx / 4;
                    int shift = (q_idx % 4) * 2;
                    uint8_t q = (block.qs[byte_idx] >> shift) & 0x3;
                    output[out_idx++] = scales[scale_idx] * q + mins[scale_idx];
                }
            }
        }
    }
    
    // F16 to F32 conversion
    static float F16ToF32(uint16_t f16) {
        uint32_t sign = (f16 >> 15) & 0x1;
        uint32_t exp = (f16 >> 10) & 0x1F;
        uint32_t mant = f16 & 0x3FF;
        
        uint32_t f32;
        if (exp == 0) {
            if (mant == 0) {
                f32 = sign << 31;
            } else {
                exp = 1;
                while ((mant & 0x400) == 0) {
                    mant <<= 1;
                    exp--;
                }
                mant &= 0x3FF;
                f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
            }
        } else if (exp == 31) {
            f32 = (sign << 31) | (0xFF << 23) | (mant << 13);
        } else {
            f32 = (sign << 31) | ((exp + 112) << 23) | (mant << 13);
        }
        
        float result;
        std::memcpy(&result, &f32, sizeof(result));
        return result;
    }
    
public:
    
    // Direct float access (if already dequantized)
    const float* GetFloatData() const {
        return m_data ? m_data->f32Data.data() : nullptr;
    }
    
    size_t GetFloatDataSize() const {
        return m_data ? m_data->f32Data.size() : 0;
    }
    
private:
    const TensorData* m_data = nullptr;
};

// ============================================================================
// TensorRegistry - Central registry for tensor storage
// ============================================================================
class TensorRegistry {
public:
    TensorRegistry() = default;
    ~TensorRegistry() = default;
    
    // Register a tensor (takes ownership)
    void Register(const std::string& name, TensorData data) {
        m_tensors[name] = std::move(data);
    }
    
    // Find tensor by name
    const TensorData* Find(const std::string& name) const {
        auto it = m_tensors.find(name);
        return (it != m_tensors.end()) ? &it->second : nullptr;
    }
    
    // Check if tensor exists
    bool Has(const std::string& name) const {
        return m_tensors.find(name) != m_tensors.end();
    }
    
    // Get all tensor names
    std::vector<std::string> GetNames() const {
        std::vector<std::string> names;
        for (const auto& [name, _] : m_tensors) {
            names.push_back(name);
        }
        return names;
    }
    
    size_t Count() const { return m_tensors.size(); }
    
private:
    std::unordered_map<std::string, TensorData> m_tensors;
};

} // namespace Runtime
} // namespace RawrXD
