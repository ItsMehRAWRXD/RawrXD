// ============================================================================
// GGUF Adapter C++ Bridge v2 - Tight Integration Edition
// Enhanced for Streaming Runtime and SEG Integration
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <stdexcept>
#include <memory>
#include <functional>
#include <optional>

#ifdef _WIN32
#include <windows.h>
#else
using HANDLE = void*;
#endif

// ============================================================================
// C Linkage for MASM Functions
// ============================================================================
extern "C" {
    // Initialization
    int64_t GGUF_Init(const char* filename);
    int64_t GGUF_InitFromHandle(HANDLE file);
    void GGUF_Cleanup(void);
    
    // Tensor iteration
    int64_t GGUF_NextTensor(void);
    int64_t GGUF_Reset(void);
    uint64_t GGUF_GetTensorCount(void);
    uint64_t GGUF_GetCurrentTensorIndex(void);
    
    // Current tensor info
    const char* GGUF_GetCurrentTensorName(void);
    uint32_t GGUF_GetCurrentTensorType(void);
    const uint64_t* GGUF_GetCurrentTensorShape(void);
    uint32_t GGUF_GetCurrentTensorNDims(void);
    uint64_t GGUF_GetCurrentTensorDataSize(void);
    uint64_t GGUF_GetCurrentTensorOffset(void);
    const void* GGUF_GetCurrentTensorDataPtr(void);
    
    // Data loading
    int64_t GGUF_LoadTensorData(void* buffer, uint64_t bufferSize);
    int64_t GGUF_LoadTensorDataAsync(void* buffer, uint64_t bufferSize, void* completionEvent);
    const char* GGUF_GetTypeName(uint32_t type);
    
    // Metadata
    uint64_t GGUF_GetDataSectionOffset(void);
    uint64_t GGUF_GetFileSize(void);
}

namespace sovereign {

// ============================================================================
// GGML Type Enum (complete mapping)
// ============================================================================
enum class GGMLType : uint32_t {
    F32 = 0, F16 = 1,
    Q4_0 = 2, Q4_1 = 3,
    Q5_0 = 6, Q5_1 = 7,
    Q8_0 = 8, Q8_1 = 9,
    Q2_K = 10, Q3_K = 11, Q4_K = 12, Q5_K = 13, Q6_K = 14, Q8_K = 15,
    IQ2_XXS = 16, IQ2_XS = 17, IQ3_XXS = 18, IQ1_S = 19,
    IQ4_NL = 20, IQ3_S = 21, IQ2_S = 22, IQ4_XS = 23,
    I8 = 24, I16 = 25, I32 = 26, I64 = 27
};

// ============================================================================
// Tensor Info Structure (Enhanced)
// ============================================================================
struct TensorInfo {
    std::string name;
    GGMLType type;
    std::vector<uint64_t> shape;
    uint64_t dataSize;
    uint64_t offset;
    const void* dataPtr;
    uint64_t tensorIndex;
    
    // Calculate total elements
    [[nodiscard]] uint64_t numElements() const {
        if (shape.empty()) return 1;
        uint64_t total = 1;
        for (auto dim : shape) total *= dim;
        return total;
    }
    
    // Check if quantized
    [[nodiscard]] bool isQuantized() const {
        return type >= GGMLType::Q4_0 && type <= GGMLType::Q8_K;
    }
    
    // Get type name
    [[nodiscard]] std::string typeName() const {
        const char* n = GGUF_GetTypeName(static_cast<uint32_t>(type));
        return n ? n : "UNKNOWN";
    }
    
    // Format shape as string
    [[nodiscard]] std::string shapeStr() const {
        if (shape.empty()) return "scalar";
        std::string s;
        for (size_t i = 0; i < shape.size(); i++) {
            if (i > 0) s += "x";
            s += std::to_string(shape[i]);
        }
        return s;
    }
    
    // Check if this is a weight tensor
    [[nodiscard]] bool isWeight() const {
        return name.find("weight") != std::string::npos ||
               name.find("bias") != std::string::npos;
    }
    
    // Check if this is an embedding tensor
    [[nodiscard]] bool isEmbedding() const {
        return name.find("embed") != std::string::npos ||
               name == "token_embd.weight" ||
               name == "output.weight";
    }
};

// ============================================================================
// Tensor View (Non-owning reference to tensor data)
// ============================================================================
class TensorView {
public:
    TensorView() = default;
    TensorView(const TensorInfo& info, void* data = nullptr)
        : info_(info), data_(data) {}
    
    [[nodiscard]] const TensorInfo& info() const { return info_; }
    [[nodiscard]] const void* data() const { return data_; }
    [[nodiscard]] void* mutableData() { return data_; }
    
    [[nodiscard]] bool isLoaded() const { return data_ != nullptr; }
    
    // Typed data access
    template<typename T>
    [[nodiscard]] const T* typedData() const {
        return static_cast<const T*>(data_);
    }
    
    template<typename T>
    [[nodiscard]] T* mutableTypedData() {
        return static_cast<T*>(data_);
    }
    
private:
    TensorInfo info_;
    void* data_ = nullptr;
};

// ============================================================================
// GGUF Adapter - Core Interface
// ============================================================================
class GGUFAdapter {
public:
    GGUFAdapter() = default;
    ~GGUFAdapter() { cleanup(); }
    
    // Non-copyable
    GGUFAdapter(const GGUFAdapter&) = delete;
    GGUFAdapter& operator=(const GGUFAdapter&) = delete;
    
    // Movable
    GGUFAdapter(GGUFAdapter&& other) noexcept
        : isOpen_(other.isOpen_), tensorCount_(other.tensorCount_) {
        other.isOpen_ = false;
        other.tensorCount_ = 0;
    }
    
    GGUFAdapter& operator=(GGUFAdapter&& other) noexcept {
        if (this != &other) {
            cleanup();
            isOpen_ = other.isOpen_;
            tensorCount_ = other.tensorCount_;
            other.isOpen_ = false;
            other.tensorCount_ = 0;
        }
        return *this;
    }
    
    // Initialize from file path
    bool init(const std::string& filename) {
        int64_t result = GGUF_Init(filename.c_str());
        if (result == 0) {
            isOpen_ = true;
            tensorCount_ = GGUF_GetTensorCount();
            return true;
        }
        return false;
    }
    
    // Initialize from existing file handle
    bool initFromHandle(HANDLE file) {
        int64_t result = GGUF_InitFromHandle(file);
        if (result == 0) {
            isOpen_ = true;
            tensorCount_ = GGUF_GetTensorCount();
            return true;
        }
        return false;
    }
    
    // Cleanup
    void cleanup() {
        if (isOpen_) {
            GGUF_Cleanup();
            isOpen_ = false;
            tensorCount_ = 0;
        }
    }
    
    // Reset iteration to beginning
    bool reset() {
        if (!isOpen_) return false;
        return GGUF_Reset() == 0;
    }
    
    // Get next tensor info
    [[nodiscard]] std::optional<TensorInfo> nextTensor() {
        if (!isOpen_) return std::nullopt;
        
        int64_t result = GGUF_NextTensor();
        if (result != 0) return std::nullopt;  // End or error
        
        return buildTensorInfo();
    }
    
    // Get current tensor info without advancing
    [[nodiscard]] std::optional<TensorInfo> currentTensor() const {
        if (!isOpen_) return std::nullopt;
        return buildTensorInfo();
    }
    
    // Load current tensor data into buffer
    [[nodiscard]] bool loadTensorData(std::vector<uint8_t>& buffer) {
        if (!isOpen_) return false;
        
        uint64_t size = GGUF_GetCurrentTensorDataSize();
        buffer.resize(size);
        
        return GGUF_LoadTensorData(buffer.data(), size) == 0;
    }
    
    // Load and return tensor view
    [[nodiscard]] std::optional<TensorView> loadCurrentTensor() {
        auto info = currentTensor();
        if (!info) return std::nullopt;
        
        // For now, return view without data (data loaded separately)
        return TensorView(*info);
    }
    
    // Getters
    [[nodiscard]] bool isOpen() const { return isOpen_; }
    [[nodiscard]] uint64_t tensorCount() const { return tensorCount_; }
    [[nodiscard]] uint64_t currentIndex() const { return GGUF_GetCurrentTensorIndex(); }
    [[nodiscard]] uint64_t dataSectionOffset() const { return GGUF_GetDataSectionOffset(); }
    [[nodiscard]] uint64_t fileSize() const { return GGUF_GetFileSize(); }
    
private:
    [[nodiscard]] TensorInfo buildTensorInfo() const {
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
        info.offset = GGUF_GetCurrentTensorOffset();
        info.dataPtr = GGUF_GetCurrentTensorDataPtr();
        info.tensorIndex = GGUF_GetCurrentTensorIndex();
        
        return info;
    }
    
    bool isOpen_ = false;
    uint64_t tensorCount_ = 0;
};

// ============================================================================
// Streaming GGUF Loader - High-level interface
// ============================================================================
class StreamingGGUFLoader {
public:
    using TensorCallback = std::function<void(const TensorView&)>;
    using FilterFn = std::function<bool(const TensorInfo&)>;
    
    StreamingGGUFLoader() = default;
    explicit StreamingGGUFLoader(const std::string& filename) {
        open(filename);
    }
    
    ~StreamingGGUFLoader() = default;
    
    // Open file
    bool open(const std::string& filename) {
        return adapter_.init(filename);
    }
    
    // Open from handle
    bool open(HANDLE file) {
        return adapter_.initFromHandle(file);
    }
    
    // Iterate all tensors with callback
    void forEachTensor(TensorCallback callback) {
        adapter_.reset();
        while (auto info = adapter_.nextTensor()) {
            TensorView view(*info);
            callback(view);
        }
    }
    
    // Iterate with filter
    void forEachTensor(FilterFn filter, TensorCallback callback) {
        adapter_.reset();
        while (auto info = adapter_.nextTensor()) {
            if (filter(*info)) {
                TensorView view(*info);
                callback(view);
            }
        }
    }
    
    // Find specific tensor by name
    [[nodiscard]] std::optional<TensorInfo> findTensor(const std::string& name) {
        adapter_.reset();
        while (auto info = adapter_.nextTensor()) {
            if (info->name == name) {
                return info;
            }
        }
        return std::nullopt;
    }
    
    // Load specific tensor by name
    [[nodiscard]] std::optional<std::vector<uint8_t>> loadTensor(const std::string& name) {
        auto info = findTensor(name);
        if (!info) return std::nullopt;
        
        // Seek to tensor
        adapter_.reset();
        while (auto curr = adapter_.nextTensor()) {
            if (curr->name == name) {
                std::vector<uint8_t> data;
                if (adapter_.loadTensorData(data)) {
                    return data;
                }
                break;
            }
        }
        return std::nullopt;
    }
    
    // Get all tensor infos (metadata only)
    [[nodiscard]] std::vector<TensorInfo> getTensorList() {
        std::vector<TensorInfo> list;
        list.reserve(adapter_.tensorCount());
        
        adapter_.reset();
        while (auto info = adapter_.nextTensor()) {
            list.push_back(*info);
        }
        
        return list;
    }
    
    // Load only weight tensors
    [[nodiscard]] std::vector<std::pair<TensorInfo, std::vector<uint8_t>>> loadWeights() {
        std::vector<std::pair<TensorInfo, std::vector<uint8_t>>> weights;
        
        adapter_.reset();
        while (auto info = adapter_.nextTensor()) {
            if (info->isWeight()) {
                std::vector<uint8_t> data;
                if (adapter_.loadTensorData(data)) {
                    weights.emplace_back(*info, std::move(data));
                }
            }
        }
        
        return weights;
    }
    
    // Getters
    [[nodiscard]] bool isOpen() const { return adapter_.isOpen(); }
    [[nodiscard]] uint64_t tensorCount() const { return adapter_.tensorCount(); }
    
private:
    GGUFAdapter adapter_;
};

// ============================================================================
// Convenience Functions
// ============================================================================

// Quick load tensor list
[[nodiscard]] inline std::vector<TensorInfo> ListGGUFTensors(const std::string& filename) {
    StreamingGGUFLoader loader(filename);
    return loader.getTensorList();
}

// Quick load specific tensor
[[nodiscard]] inline std::optional<std::vector<uint8_t>> LoadGGUFTensor(
    const std::string& filename, 
    const std::string& tensorName) {
    StreamingGGUFLoader loader(filename);
    return loader.loadTensor(tensorName);
}

// Print tensor info
inline void PrintTensorInfo(const TensorInfo& info) {
    printf("%-50s %-10s %-20s %12llu bytes\n",
           info.name.c_str(),
           info.typeName().c_str(),
           info.shapeStr().c_str(),
           (unsigned long long)info.dataSize);
}

} // namespace sovereign
