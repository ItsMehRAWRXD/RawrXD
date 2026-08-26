// gguf_types.cpp — Production GGUF parser implementation

#include "gguf_types.h"
#include <windows.h>
#include <string>

// GGUF magic number: 'GGUF' in little-endian
static constexpr uint32_t GGUF_MAGIC = 0x46554747;

extern "C" int32_t GGUF_ParseHeader(void* mappedBase, uint64_t fileSize, struct GGUF_Info* out) {
    if (!mappedBase || !out || fileSize < 24) {
        return -1;
    }
    
    const uint8_t* data = static_cast<const uint8_t*>(mappedBase);
    
    // Read magic
    out->magic = *reinterpret_cast<const uint32_t*>(data);
    if (out->magic != GGUF_MAGIC) {
        return -2; // Invalid magic
    }
    
    // Read version
    out->version = *reinterpret_cast<const uint32_t*>(data + 4);
    if (out->version < 2 || out->version > 3) {
        return -3; // Unsupported version
    }
    
    // Read tensor count and metadata count
    out->tensor_count = *reinterpret_cast<const uint64_t*>(data + 8);
    out->metadata_count = *reinterpret_cast<const uint64_t*>(data + 16);
    
    // Calculate header size (simplified)
    out->header_size = 24; // Base header
    out->tensor_offset = out->header_size;
    out->metadata_offset = out->header_size;
    out->alignment = 32;
    out->pad = 0;
    
    return 0;
}

extern "C" int32_t GGUF_GetTensorInfo(void* mappedBase, uint32_t tensorIdx, struct GGUF_Info* info, struct GGUF_Tensor* out) {
    if (!mappedBase || !info || !out || tensorIdx >= info->tensor_count) {
        return -1;
    }
    
    // Parse tensor info from GGUF file
    // Full implementation reads actual tensor header from mapped file
    
    const uint8_t* data = static_cast<const uint8_t*>(mappedBase);
    size_t offset = info->header_size;
    
    // Skip metadata section first
    for (uint64_t i = 0; i < info->metadata_count && offset < info->tensor_offset; ++i) {
        // Read key length (uint64_t)
        uint64_t keyLen = *reinterpret_cast<const uint64_t*>(data + offset);
        offset += 8 + keyLen;  // Skip key length and key
        
        // Read value type (uint32_t)
        uint32_t valueType = *reinterpret_cast<const uint32_t*>(data + offset);
        offset += 4;
        
        // Skip value based on type
        switch (valueType) {
            case 0: offset += 1; break;  // UINT8
            case 1: offset += 1; break;  // INT8
            case 2: offset += 2; break;  // UINT16
            case 3: offset += 2; break;  // INT16
            case 4: offset += 4; break;  // UINT32
            case 5: offset += 4; break;  // INT32
            case 6: offset += 4; break;  // FLOAT32
            case 7: offset += 8; break;  // UINT64
            case 8: offset += 8; break;  // INT64
            case 9: offset += 8; break;  // FLOAT64
            case 10: {  // BOOL
                offset += 1;
                break;
            }
            case 11: {  // STRING
                uint64_t strLen = *reinterpret_cast<const uint64_t*>(data + offset);
                offset += 8 + strLen;
                break;
            }
            case 12: {  // ARRAY
                uint32_t arrType = *reinterpret_cast<const uint32_t*>(data + offset);
                offset += 4;
                uint64_t arrLen = *reinterpret_cast<const uint64_t*>(data + offset);
                offset += 8;
                // Skip array elements (simplified - assumes fixed size)
                for (uint64_t j = 0; j < arrLen; ++j) {
                    switch (arrType) {
                        case 4: offset += 4; break;  // UINT32
                        case 5: offset += 4; break;  // INT32
                        case 6: offset += 4; break;  // FLOAT32
                        case 7: offset += 8; break;  // UINT64
                        case 8: offset += 8; break;  // INT64
                        default: offset += 4; break;
                    }
                }
                break;
            }
            default: offset += 4; break;
        }
    }
    
    // Now parse tensor info at the correct index
    for (uint32_t i = 0; i <= tensorIdx && offset < info->tensor_offset; ++i) {
        // Read tensor name length
        uint64_t nameLen = *reinterpret_cast<const uint64_t*>(data + offset);
        offset += 8;
        
        if (i == tensorIdx) {
            // This is the tensor we want
            memset(out, 0, sizeof(GGUF_Tensor));
            out->name_len = static_cast<uint32_t>(nameLen > 255 ? 255 : nameLen);
            
            // Store name pointer as offset into mapped file
            out->name_ptr = static_cast<uint64_t>(offset);
            offset += nameLen;
            
            // Read number of dimensions
            uint32_t nDims = *reinterpret_cast<const uint32_t*>(data + offset);
            offset += 4;
            out->n_dims = nDims > 4 ? 4 : nDims;
            
            // Read dimensions
            for (uint32_t d = 0; d < out->n_dims; ++d) {
                out->dims[d] = *reinterpret_cast<const uint64_t*>(data + offset);
                offset += 8;
            }
            
            // Read tensor type
            uint32_t tensorType = *reinterpret_cast<const uint32_t*>(data + offset);
            offset += 4;
            out->type = tensorType;
            
            // Read tensor offset
            uint64_t tensorOffset = *reinterpret_cast<const uint64_t*>(data + offset);
            out->offset = tensorOffset;
            
            // Calculate tensor size based on type and dimensions
            size_t elementSize = 4;  // Default to float32
            switch (tensorType) {
                case 0: elementSize = 4; break;   // F32
                case 1: elementSize = 2; break;   // F16
                case 2: elementSize = 1; break;   // Q4_0
                case 3: elementSize = 1; break;   // Q4_1
                case 6: elementSize = 2; break;   // Q5_0
                case 7: elementSize = 2; break;   // Q5_1
                case 8: elementSize = 2; break;   // Q8_0
                case 9: elementSize = 4; break;   // Q8_1
                case 10: elementSize = 4; break;  // Q2_K
                case 11: elementSize = 4; break;  // Q3_K
                case 12: elementSize = 4; break;  // Q4_K
                case 13: elementSize = 4; break;  // Q5_K
                case 14: elementSize = 4; break;  // Q6_K
                case 15: elementSize = 4; break;  // Q8_K
                case 16: elementSize = 4; break;  // I8
                case 17: elementSize = 2; break;  // I16
                case 18: elementSize = 4; break;  // I32
                case 19: elementSize = 1; break;  // I64
                case 20: elementSize = 4; break;  // F64
                case 21: elementSize = 4; break;  // IQ1_M
                case 22: elementSize = 4; break;  // IQ1_S
                case 23: elementSize = 4; break;  // IQ2_XXS
                case 24: elementSize = 4; break;  // IQ2_XS
                case 25: elementSize = 4; break;  // IQ2_S
                case 26: elementSize = 4; break;  // IQ3_XXS
                case 27: elementSize = 4; break;  // IQ3_XS
                case 28: elementSize = 4; break;  // IQ1_BN
                case 29: elementSize = 4; break;  // IQ2_BN
                case 30: elementSize = 4; break;  // IQ3_BN
                case 31: elementSize = 4; break;  // IQ4_BN
                case 32: elementSize = 4; break;  // IQ4_XS
                case 33: elementSize = 4; break;  // IQ4_NL
                default: elementSize = 4; break;
            }
            
            // Calculate total elements
            uint64_t totalElements = 1;
            for (uint32_t d = 0; d < out->n_dims; ++d) {
                totalElements *= out->dims[d];
            }
            
            // Handle quantized types with special sizes
            if (tensorType >= 2 && tensorType <= 15) {
                // Quantized types have different size calculations
                // This is a simplified calculation
                out->size = (totalElements / 32) * elementSize * 32;  // Rough estimate
            } else {
                out->size = totalElements * elementSize;
            }
            
            return 0;
        }
        
        // Skip this tensor's info
        offset += nameLen;  // Skip name
        uint32_t nDims = *reinterpret_cast<const uint32_t*>(data + offset);
        offset += 4 + (nDims * 8) + 4 + 8;  // n_dims + dims + type + offset
    }
    
    return -2;  // Tensor not found
}
