// ============================================================================
// TensorView Implementation — Minimal tensor access for runtime kernels
// ============================================================================

#include "tensor_view.hpp"
#include <cstring>
#include <cmath>

namespace RawrXD {
namespace CLI {

// ============================================================================
// Constructors
// ============================================================================

TensorView::TensorView(const TensorEntry* entry, const void* tensorData) {
    if (entry && tensorData) {
        data = tensorData;
        type = entry->type;
        shape = entry->shape.dimensions;
        byte_size = entry->size;
    }
}

// ============================================================================
// Status
// ============================================================================

TensorViewStatus TensorView::GetStatus() const {
    if (data == nullptr) return TensorViewStatus::NULL_DATA;
    if (shape.empty()) return TensorViewStatus::INVALID_SHAPE;
    if (!IsDirectlyReadable()) return TensorViewStatus::UNSUPPORTED_TYPE;
    return TensorViewStatus::OK;
}

bool TensorView::IsSupported() const {
    return IsDirectlyReadable();
}

std::string TensorView::GetUnsupportedReason() const {
    if (data == nullptr) return "Null data pointer";
    if (shape.empty()) return "Empty shape";
    if (!IsDirectlyReadable()) {
        return "Quantized type " + TypeName() + " not yet supported (requires dequantization)";
    }
    return "";
}

// ============================================================================
// Type checking
// ============================================================================

bool TensorView::IsDirectlyReadable() const {
    return type == TensorType::F32 || type == TensorType::F16;
}

std::string TensorView::TypeName() const {
    switch (type) {
        case TensorType::F32: return "F32";
        case TensorType::F16: return "F16";
        case TensorType::Q4_0: return "Q4_0";
        case TensorType::Q4_1: return "Q4_1";
        case TensorType::Q5_0: return "Q5_0";
        case TensorType::Q5_1: return "Q5_1";
        case TensorType::Q8_0: return "Q8_0";
        case TensorType::Q8_1: return "Q8_1";
        case TensorType::Q2_K: return "Q2_K";
        case TensorType::Q3_K: return "Q3_K";
        case TensorType::Q4_K: return "Q4_K";
        case TensorType::Q5_K: return "Q5_K";
        case TensorType::Q6_K: return "Q6_K";
        case TensorType::Q8_K: return "Q8_K";
        case TensorType::I8: return "I8";
        case TensorType::I16: return "I16";
        case TensorType::I32: return "I32";
        default: return "UNKNOWN";
    }
}

// ============================================================================
// Shape helpers
// ============================================================================

uint64_t TensorView::RowWidth() const {
    if (shape.empty()) return 0;
    if (shape.size() == 1) return shape[0];
    return shape[1];
}

uint64_t TensorView::NumElements() const {
    uint64_t n = 1;
    for (auto dim : shape) n *= dim;
    return n;
}

// ============================================================================
// Element/Row reading
// ============================================================================

bool TensorView::ReadElement(size_t index, float& out) const {
    if (!IsDirectlyReadable()) return false;
    if (index >= NumElements()) return false;
    
    if (type == TensorType::F32) {
        const float* ptr = static_cast<const float*>(data);
        out = ptr[index];
        return true;
    }
    
    if (type == TensorType::F16) {
        // Simple F16 to F32 conversion
        const uint16_t* ptr = static_cast<const uint16_t*>(data);
        uint16_t h = ptr[index];
        
        // Extract F16 components
        uint32_t sign = (h >> 15) & 0x1;
        uint32_t exp = (h >> 10) & 0x1F;
        uint32_t mant = h & 0x3FF;
        
        if (exp == 0) {
            // Zero or denormal
            out = sign ? -0.0f : 0.0f;
        } else if (exp == 31) {
            // Infinity or NaN
            out = sign ? -INFINITY : INFINITY;
        } else {
            // Normal number: convert to F32
            int32_t e = static_cast<int32_t>(exp) - 15 + 127;  // Adjust bias
            uint32_t f32 = (sign << 31) | (static_cast<uint32_t>(e) << 23) | (mant << 13);
            memcpy(&out, &f32, sizeof(float));
        }
        return true;
    }
    
    return false;
}

bool TensorView::ReadRow(size_t row, float* dst, size_t count) const {
    if (!IsDirectlyReadable()) return false;
    if (shape.empty()) return false;
    if (row >= shape[0]) return false;
    
    uint64_t row_width = RowWidth();
    if (count > row_width) return false;
    
    size_t row_offset = row * row_width;
    
    if (type == TensorType::F32) {
        const float* src = static_cast<const float*>(data);
        memcpy(dst, src + row_offset, count * sizeof(float));
        return true;
    }
    
    if (type == TensorType::F16) {
        // Convert F16 row to F32
        const uint16_t* src = static_cast<const uint16_t*>(data);
        for (size_t i = 0; i < count; ++i) {
            float val;
            if (!ReadElement(row_offset + i, val)) return false;
            dst[i] = val;
        }
        return true;
    }
    
    return false;
}

// ============================================================================
// Telemetry
// ============================================================================

std::string TensorExecutionInfo::ToString() const {
    std::string result = "Tensor: " + tensor_name + "\n";
    result += "  Source: " + source + "\n";
    result += "  Type: " + type_name + "\n";
    result += "  Synthetic: " + std::string(synthetic ? "true" : "false") + "\n";
    
    switch (status) {
        case TensorViewStatus::OK: result += "  Status: OK\n"; break;
        case TensorViewStatus::UNSUPPORTED_TYPE: result += "  Status: UNSUPPORTED_TYPE\n"; break;
        case TensorViewStatus::INVALID_SHAPE: result += "  Status: INVALID_SHAPE\n"; break;
        case TensorViewStatus::OUT_OF_BOUNDS: result += "  Status: OUT_OF_BOUNDS\n"; break;
        case TensorViewStatus::NULL_DATA: result += "  Status: NULL_DATA\n"; break;
    }
    
    return result;
}

} // namespace CLI
} // namespace RawrXD
