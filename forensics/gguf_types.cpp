/**
 * GGUF Type Implementation
 */

#include "gguf_types.hpp"
#include <map>
#include <string>
#include <sstream>
#include <iomanip>

namespace gguf {

// Type info lookup table
static const std::map<TensorType, TensorTypeInfo> kTensorTypeInfo = {
    // Floating point
    {TensorType::F32,  {"F32",  4,  false, 1, "32-bit floating point"}},
    {TensorType::F16,  {"F16",  2,  false, 1, "16-bit floating point (IEEE 754)"}},
    {TensorType::BF16, {"BF16", 2,  false, 1, "16-bit brain floating point"}},
    {TensorType::F64,  {"F64",  8,  false, 1, "64-bit floating point"}},
    
    // Legacy quantized
    {TensorType::Q4_0, {"Q4_0", 18, true,  32, "4-bit quantization, type-0"}},
    {TensorType::Q4_1, {"Q4_1", 20, true,  32, "4-bit quantization, type-1"}},
    {TensorType::Q5_0, {"Q5_0", 22, true,  32, "5-bit quantization, type-0"}},
    {TensorType::Q5_1, {"Q5_1", 24, true,  32, "5-bit quantization, type-1"}},
    {TensorType::Q8_0, {"Q8_0", 34, true,  32, "8-bit quantization, type-0"}},
    {TensorType::Q8_1, {"Q8_1", 36, true,  32, "8-bit quantization, type-1"}},
    
    // K-quants
    {TensorType::Q2_K, {"Q2_K", 0,  true,  256, "2-bit K-quantization"}},
    {TensorType::Q3_K, {"Q3_K", 0,  true,  256, "3-bit K-quantization"}},
    {TensorType::Q4_K, {"Q4_K", 0,  true,  256, "4-bit K-quantization"}},
    {TensorType::Q5_K, {"Q5_K", 0,  true,  256, "5-bit K-quantization"}},
    {TensorType::Q6_K, {"Q6_K", 0,  true,  256, "6-bit K-quantization"}},
    {TensorType::Q8_K, {"Q8_K", 0,  true,  256, "8-bit K-quantization"}},
    
    // I-quants
    {TensorType::IQ2_XXS, {"IQ2_XXS", 0, true, 256, "2-bit importance-aware quant (XXS)"}},
    {TensorType::IQ2_XS,  {"IQ2_XS",  0, true, 256, "2-bit importance-aware quant (XS)"}},
    {TensorType::IQ3_XXS, {"IQ3_XXS", 0, true, 256, "3-bit importance-aware quant (XXS)"}},
    {TensorType::IQ1_S,   {"IQ1_S",   0, true, 256, "1-bit importance-aware quant (S)"}},
    {TensorType::IQ4_NL,  {"IQ4_NL",  0, true, 256, "4-bit importance-aware quant (NL)"}},
    {TensorType::IQ3_S,   {"IQ3_S",   0, true, 256, "3-bit importance-aware quant (S)"}},
    {TensorType::IQ2_S,   {"IQ2_S",   0, true, 256, "2-bit importance-aware quant (S)"}},
    {TensorType::IQ4_XS,  {"IQ4_XS",  0, true, 256, "4-bit importance-aware quant (XS)"}},
    {TensorType::IQ1_M,   {"IQ1_M",   0, true, 256, "1-bit importance-aware quant (M)"}},
    
    // Integer types
    {TensorType::I8,  {"I8",  1, false, 1, "8-bit signed integer"}},
    {TensorType::I16, {"I16", 2, false, 1, "16-bit signed integer"}},
    {TensorType::I32, {"I32", 4, false, 1, "32-bit signed integer"}},
    {TensorType::I64, {"I64", 8, false, 1, "64-bit signed integer"}},
};

const TensorTypeInfo* GetTensorTypeInfo(TensorType type) {
    auto it = kTensorTypeInfo.find(type);
    return (it != kTensorTypeInfo.end()) ? &it->second : nullptr;
}

const char* GetTensorTypeName(TensorType type) {
    auto info = GetTensorTypeInfo(type);
    return info ? info->name : "UNKNOWN";
}

const char* GetValueTypeName(ValueType type) {
    switch (type) {
        case ValueType::UINT8:   return "uint8";
        case ValueType::INT8:    return "int8";
        case ValueType::UINT16:  return "uint16";
        case ValueType::INT16:   return "int16";
        case ValueType::UINT32:  return "uint32";
        case ValueType::INT32:   return "int32";
        case ValueType::FLOAT32: return "float32";
        case ValueType::BOOL:    return "bool";
        case ValueType::STRING:  return "string";
        case ValueType::ARRAY:   return "array";
        case ValueType::UINT64:  return "uint64";
        case ValueType::INT64:   return "int64";
        case ValueType::FLOAT64: return "float64";
        default: return "unknown";
    }
}

bool IsQuantized(TensorType type) {
    auto info = GetTensorTypeInfo(type);
    return info ? info->is_quantized : false;
}

bool IsFloatingPoint(TensorType type) {
    return type == TensorType::F32 || 
           type == TensorType::F16 || 
           type == TensorType::BF16 || 
           type == TensorType::F64;
}

bool IsInteger(TensorType type) {
    return type == TensorType::I8 || 
           type == TensorType::I16 || 
           type == TensorType::I32 || 
           type == TensorType::I64;
}

uint64_t CalculateTensorDataSize(TensorType type, const uint64_t* dims, uint32_t n_dims) {
    // Calculate total elements
    uint64_t num_elements = 1;
    for (uint32_t i = 0; i < n_dims; i++) {
        num_elements *= dims[i];
    }
    
    switch (type) {
        case TensorType::F32:
            return num_elements * 4;
        case TensorType::F16:
        case TensorType::BF16:
            return num_elements * 2;
        case TensorType::F64:
            return num_elements * 8;
            
        case TensorType::Q4_0:
            return (num_elements / 32) * 18 + ((num_elements % 32) ? 18 : 0);
        case TensorType::Q4_1:
            return (num_elements / 32) * 20 + ((num_elements % 32) ? 20 : 0);
        case TensorType::Q5_0:
            return (num_elements / 32) * 22 + ((num_elements % 32) ? 22 : 0);
        case TensorType::Q5_1:
            return (num_elements / 32) * 24 + ((num_elements % 32) ? 24 : 0);
        case TensorType::Q8_0:
            return (num_elements / 32) * 34 + ((num_elements % 32) ? 34 : 0);
        case TensorType::Q8_1:
            return (num_elements / 32) * 36 + ((num_elements % 32) ? 36 : 0);
            
        case TensorType::Q2_K:
            return (num_elements / 256) * 72 + ((num_elements % 256) ? 72 : 0);
        case TensorType::Q3_K:
            return (num_elements / 256) * 110 + ((num_elements % 256) ? 110 : 0);
        case TensorType::Q4_K:
            return (num_elements / 256) * 144 + ((num_elements % 256) ? 144 : 0);
        case TensorType::Q5_K:
            return (num_elements / 256) * 176 + ((num_elements % 256) ? 176 : 0);
        case TensorType::Q6_K:
            return (num_elements / 256) * 210 + ((num_elements % 256) ? 210 : 0);
        case TensorType::Q8_K:
            return (num_elements / 256) * 324 + ((num_elements % 256) ? 324 : 0);
            
        case TensorType::I8:
            return num_elements;
        case TensorType::I16:
            return num_elements * 2;
        case TensorType::I32:
            return num_elements * 4;
        case TensorType::I64:
            return num_elements * 8;
            
        default:
            return num_elements; // Unknown type, assume 1 byte per element
    }
}

bool IsValidTensorType(uint32_t type_id) {
    return type_id < static_cast<uint32_t>(TensorType::COUNT);
}

float GetBitsPerWeight(TensorType type) {
    switch (type) {
        case TensorType::F32:  return 32.0f;
        case TensorType::F16:  return 16.0f;
        case TensorType::BF16: return 16.0f;
        case TensorType::F64:  return 64.0f;
        case TensorType::Q4_0: return 4.5f;   // 18 bytes / 32 elements = 4.5 bits
        case TensorType::Q4_1: return 5.0f;   // 20 bytes / 32 elements = 5 bits
        case TensorType::Q5_0: return 5.5f;
        case TensorType::Q5_1: return 6.0f;
        case TensorType::Q8_0: return 8.5f;
        case TensorType::Q8_1: return 9.0f;
        case TensorType::Q2_K: return 2.25f;  // 72 bytes / 256 elements = 2.25 bits
        case TensorType::Q3_K: return 3.44f;
        case TensorType::Q4_K: return 4.5f;
        case TensorType::Q5_K: return 5.5f;
        case TensorType::Q6_K: return 6.56f;
        case TensorType::Q8_K: return 10.125f;
        case TensorType::I8:   return 8.0f;
        case TensorType::I16:  return 16.0f;
        case TensorType::I32:  return 32.0f;
        case TensorType::I64:  return 64.0f;
        default: return 0.0f;
    }
}

std::string FormatDimensions(const uint64_t* dims, uint32_t n_dims) {
    std::ostringstream oss;
    oss << "[";
    for (uint32_t i = 0; i < n_dims; i++) {
        if (i > 0) oss << ", ";
        oss << dims[i];
    }
    oss << "]";
    return oss.str();
}

std::string FormatBytes(uint64_t bytes) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2);
    
    if (bytes >= 1024ULL * 1024 * 1024 * 1024) {
        oss << (bytes / (1024.0 * 1024 * 1024 * 1024)) << " TB";
    } else if (bytes >= 1024ULL * 1024 * 1024) {
        oss << (bytes / (1024.0 * 1024 * 1024)) << " GB";
    } else if (bytes >= 1024ULL * 1024) {
        oss << (bytes / (1024.0 * 1024)) << " MB";
    } else if (bytes >= 1024ULL) {
        oss << (bytes / 1024.0) << " KB";
    } else {
        oss << bytes << " B";
    }
    
    return oss.str();
}

} // namespace gguf
