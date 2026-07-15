// ============================================================================
// GGUF Adapter C++ Bridge
// Header-only interface to MASM GGUF loader
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <stdexcept>

// ============================================================================
// C Linkage for MASM Functions
// ============================================================================
extern "C" {
    // Initialization
    int64_t GGUF_Init(const char* filename);
    void GGUF_Cleanup(void);
    
    // Tensor iteration
    int64_t GGUF_NextTensor(void);
    uint64_t GGUF_GetTensorCount(void);
    
    // Current tensor info
    const char* GGUF_GetCurrentTensorName(void);
    uint32_t GGUF_GetCurrentTensorType(void);
    const uint64_t* GGUF_GetCurrentTensorShape(void);
    uint32_t GGUF_GetCurrentTensorNDims(void);
    uint64_t GGUF_GetCurrentTensorDataSize(void);
    const void* GGUF_GetCurrentTensorDataPtr(void);
    
    // Data loading
    int64_t GGUF_LoadTensorData(void* buffer, uint64_t bufferSize);
    const char* GGUF_GetTypeName(uint32_t type);
}

namespace sovereign {

// ============================================================================
// GGML Type Enum (matches MASM constants)
// ============================================================================
enum class GGMLType : uint32_t {
    F32 = 0,
    F16 = 1,
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
    IQ2_XXS = 16,
    IQ2_XS = 17,
    IQ3_XXS = 18,
    IQ1_S = 19,
    IQ4_NL = 20,
    IQ3_S = 21,
    IQ2_S = 22,
    IQ4_XS = 23,
    I8 = 24,
    I16 = 25,
    I32 = 26,
    I64 = 27
};

// ============================================================================
// Tensor Info Structure
// ============================================================================
struct TensorInfo {
    std::string name;
    GGMLType type;
    std::vector<uint64_t> shape;
    uint64_t dataSize;
    const void* dataPtr;
    
    // Helper to calculate total elements
    uint64_t numElements() const {
        if (shape.empty()) return 1;
        uint64_t total = 1;
        for (auto dim : shape) total *= dim;
        return total;
    }
    
    // Check if this is a quantized type
    bool isQuantized() const {
        return type >= GGMLType::Q4_0 && type <= GGMLType::Q8_K;
    }
    
    // Get type name
    std::string typeName() const {
        const char* name = GGUF_GetTypeName(static_cast<uint32_t>(type));
        return name ? name : "UNKNOWN";
    }
};

// ============================================================================
// GGUF Loader Class
// ============================================================================
class GGUFLoader {
public:
    GGUFLoader() = default;
    ~GGUFLoader() { close(); }
    
    // Non-copyable
    GGUFLoader(const GGUFLoader&) = delete;
    GGUFLoader& operator=(const GGUFLoader&) = delete;
    
    // Movable
    GGUFLoader(GGUFLoader&& other) noexcept 
        : isOpen_(other.isOpen_), tensorCount_(other.tensorCount_) {
        other.isOpen_ = false;
        other.tensorCount_ = 0;
    }
    
    GGUFLoader& operator=(GGUFLoader&& other) noexcept {
        if (this != &other) {
            close();
            isOpen_ = other.isOpen_;
            tensorCount_ = other.tensorCount_;
            other.isOpen_ = false;
            other.tensorCount_ = 0;
        }
        return *this;
    }
    
    // Open GGUF file
    void open(const std::string& filename) {
        int64_t result = GGUF_Init(filename.c_str());
        if (result != 0) {
            throw std::runtime_error("Failed to open GGUF file: " + filename);
        }
        isOpen_ = true;
        tensorCount_ = GGUF_GetTensorCount();
    }
    
    // Close file
    void close() {
        if (isOpen_) {
            GGUF_Cleanup();
            isOpen_ = false;
            tensorCount_ = 0;
        }
    }
    
    // Get number of tensors
    uint64_t tensorCount() const { return tensorCount_; }
    
    // Iterate to next tensor
    // Returns: 0 = tensor available, 1 = end of stream, <0 = error
    int64_t nextTensor() {
        if (!isOpen_) return -1;
        return GGUF_NextTensor();
    }
    
    // Get current tensor info (without loading data)
    TensorInfo getTensorInfo() const {
        if (!isOpen_) throw std::runtime_error("No file open");
        
        TensorInfo info;
        const char* name = GGUF_GetCurrentTensorName();
        if (name) info.name = name;
        
        info.type = static_cast<GGMLType>(GGUF_GetCurrentTensorType());
        
        uint32_t nDims = GGUF_GetCurrentTensorNDims();
        const uint64_t* shape = GGUF_GetCurrentTensorShape();
        if (shape && nDims > 0) {
            info.shape.assign(shape, shape + nDims);
        }
        
        info.dataSize = GGUF_GetCurrentTensorDataSize();
        info.dataPtr = GGUF_GetCurrentTensorDataPtr();
        
        return info;
    }
    
    // Load current tensor data into buffer
    // Returns true on success
    bool loadTensorData(std::vector<uint8_t>& buffer) {
        if (!isOpen_) return false;
        
        uint64_t size = GGUF_GetCurrentTensorDataSize();
        buffer.resize(size);
        
        int64_t result = GGUF_LoadTensorData(buffer.data(), size);
        return result == 0;
    }
    
    // Convenience: Get all tensor infos without loading data
    std::vector<TensorInfo> getAllTensorInfos() {
        std::vector<TensorInfo> infos;
        infos.reserve(tensorCount_);
        
        // Reset iteration by re-opening file
        // (In production, add a reset function to MASM)
        
        while (true) {
            int64_t result = nextTensor();
            if (result == 1) break;  // End of stream
            if (result < 0) throw std::runtime_error("Error reading tensor");
            
            infos.push_back(getTensorInfo());
        }
        
        return infos;
    }
    
private:
    bool isOpen_ = false;
    uint64_t tensorCount_ = 0;
};

// ============================================================================
// Type Conversion Helpers
// ============================================================================

// Convert GGML type to element size in bytes (for dequantized data)
inline size_t GetElementSize(GGMLType type) {
    switch (type) {
        case GGMLType::F32: return 4;
        case GGMLType::F16: return 2;
        case GGMLType::I8:  return 1;
        case GGMLType::I16: return 2;
        case GGMLType::I32: return 4;
        case GGMLType::I64: return 8;
        default: return 0;  // Quantized types have variable size
    }
}

// Get block size info for quantized types
struct BlockInfo {
    size_t weightsPerBlock;
    size_t bytesPerBlock;
};

inline BlockInfo GetBlockInfo(GGMLType type) {
    switch (type) {
        case GGMLType::Q4_0: return {32, 18};
        case GGMLType::Q4_1: return {32, 20};
        case GGMLType::Q5_0: return {32, 22};
        case GGMLType::Q5_1: return {32, 24};
        case GGMLType::Q8_0: return {32, 34};
        case GGMLType::Q8_1: return {32, 36};
        case GGMLType::Q2_K: return {256, 256};
        case GGMLType::Q3_K: return {256, 384};
        case GGMLType::Q4_K: return {256, 144};
        case GGMLType::Q5_K: return {256, 176};
        case GGMLType::Q6_K: return {256, 210};
        case GGMLType::Q8_K: return {256, 292};
        default: return {0, 0};
    }
}

} // namespace sovereign
