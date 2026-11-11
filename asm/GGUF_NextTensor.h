// ============================================================================
// GGUF_NextTensor.h - C++ Runtime Bridge Interface
// ============================================================================
// Header file for integrating the MASM GGUF tensor iterator with C++ runtime
//
// Usage:
//   #include "GGUF_NextTensor.h"
//   
//   // Create context from loaded GGUF data
//   auto ctx = GGUF_CreateContext(gguf_data, data_size);
//   
//   // Iterate tensors
//   GGUF_Tensor tensor;
//   while (GGUF_NextTensor(ctx, &tensor)) {
//       printf("Tensor: %s, Type: %s, Size: %zu bytes\n",
//              tensor.name, GGUF_GetTypeName(tensor.type), tensor.size_bytes);
//   }
//
//   // Cleanup
//   GGUF_DestroyContext(ctx);
// ============================================================================

#pragma once

#include <cstdint>
#include <cstddef>

#ifdef __cplusplus
extern "C" {
#endif

// ----------------------------------------------------------------------------
// Constants
// ----------------------------------------------------------------------------
#define GGUF_MAX_DIMS           4
#define GGUF_MAX_NAME_LEN       256
#define GGUF_MAX_TENSORS        65536

// GGML Types (0-27)
typedef enum {
    GGML_TYPE_F32     = 0,
    GGML_TYPE_F16     = 1,
    GGML_TYPE_Q4_0    = 2,
    GGML_TYPE_Q4_1    = 3,
    GGML_TYPE_Q4_2    = 4,   // Deprecated
    GGML_TYPE_Q4_3    = 5,   // Deprecated
    GGML_TYPE_Q5_0    = 6,
    GGML_TYPE_Q5_1    = 7,
    GGML_TYPE_Q8_0    = 8,
    GGML_TYPE_Q8_1    = 9,
    GGML_TYPE_Q2_K    = 10,
    GGML_TYPE_Q3_K    = 11,
    GGML_TYPE_Q4_K    = 12,
    GGML_TYPE_Q5_K    = 13,
    GGML_TYPE_Q6_K    = 14,
    GGML_TYPE_Q8_K    = 15,
    GGML_TYPE_IQ2_XXS = 16,
    GGML_TYPE_IQ2_XS  = 17,
    GGML_TYPE_IQ3_XXS = 18,
    GGML_TYPE_IQ1_S   = 19,
    GGML_TYPE_IQ4_NL  = 20,
    GGML_TYPE_IQ3_S   = 21,
    GGML_TYPE_IQ2_S   = 22,
    GGML_TYPE_IQ4_XS  = 23,
    GGML_TYPE_I8      = 24,
    GGML_TYPE_I16     = 25,
    GGML_TYPE_I32     = 26,
    GGML_TYPE_I64     = 27,
    GGML_TYPE_COUNT   = 28
} ggml_type;

// ----------------------------------------------------------------------------
// Structures
// ----------------------------------------------------------------------------

// Tensor information structure
#pragma pack(push, 1)
typedef struct {
    uint32_t    name_len;                       // Length of tensor name
    char        name[GGUF_MAX_NAME_LEN];        // Tensor name (null-terminated)
    uint32_t    n_dims;                         // Number of dimensions (0-4)
    uint64_t    dims[GGUF_MAX_DIMS];            // Dimension sizes
    uint32_t    type;                           // GGML type enum
    uint64_t    offset;                         // Offset in data section
    void*       data_ptr;                       // Pointer to tensor data
    uint64_t    size_bytes;                     // Total size in bytes
} GGUF_Tensor;
#pragma pack(pop)

// GGUF Context structure (opaque, use accessor functions)
typedef struct {
    uint64_t    tensor_count;                   // Total number of tensors
    void*       tensor_info;                    // Pointer to tensor info array
    void*       data_base;                      // Pointer to tensor data section
    uint64_t    current_idx;                    // Iterator position
    uint32_t    error_code;                     // Last error code
    uint32_t    reserved[7];                    // Padding
} GGUF_Context;

// Error codes
typedef enum {
    GGUF_ERROR_NONE         = 0,
    GGUF_ERROR_INVALID_TYPE = 1,
    GGUF_ERROR_INVALID_DIM  = 2,
    GGUF_ERROR_EOS          = 3,
    GGUF_ERROR_MEMORY       = 4
} gguf_error;

// ----------------------------------------------------------------------------
// Core API Functions (implemented in MASM)
// ----------------------------------------------------------------------------

/**
 * @brief Create a GGUF context from loaded file data
 * @param gguf_data Pointer to loaded GGUF file data
 * @param size Size of the data in bytes
 * @return Pointer to context, or NULL on failure
 */
void* GGUF_CreateContext(void* gguf_data, size_t size);

/**
 * @brief Destroy a GGUF context and free resources
 * @param ctx Context pointer
 */
void GGUF_DestroyContext(void* ctx);

/**
 * @brief Get the next tensor from the iterator
 * @param ctx Context pointer
 * @param tensor Output tensor structure (must be allocated by caller)
 * @return 1 on success, 0 on end-of-stream, -1 on error
 */
int GGUF_NextTensor(void* ctx, GGUF_Tensor* tensor);

/**
 * @brief Get total tensor count
 * @param ctx Context pointer
 * @return Number of tensors in the file
 */
uint64_t GGUF_GetTensorCount(void* ctx);

/**
 * @brief Reset tensor iterator to beginning
 * @param ctx Context pointer
 */
void GGUF_ResetIterator(void* ctx);

/**
 * @brief Get the last error code
 * @param ctx Context pointer
 * @return Error code
 */
static inline uint32_t GGUF_GetError(void* ctx) {
    if (!ctx) return GGUF_ERROR_NONE;
    return ((GGUF_Context*)ctx)->error_code;
}

// ----------------------------------------------------------------------------
// Utility Functions (implemented in MASM)
// ----------------------------------------------------------------------------

/**
 * @brief Get element size for a GGML type
 * @param type GGML type enum
 * @return Element size in bytes, or 0 for unknown types
 */
size_t GGUF_GetTypeSize(uint32_t type);

/**
 * @brief Get string name for a GGML type
 * @param type GGML type enum
 * @return Pointer to type name string
 */
const char* GGUF_GetTypeName(uint32_t type);

/**
 * @brief Check if a type is quantized
 * @param type GGML type enum
 * @return 1 if quantized, 0 otherwise
 */
int GGUF_IsTypeQuantized(uint32_t type);

/**
 * @brief Calculate total element count from dimensions
 * @param n_dims Number of dimensions
 * @param dims Array of dimension sizes
 * @return Total element count
 */
uint64_t GGUF_CalculateElementCount(uint32_t n_dims, const uint64_t* dims);

// ----------------------------------------------------------------------------
// C++ Wrapper Classes (optional)
// ----------------------------------------------------------------------------

#ifdef __cplusplus

/**
 * @brief RAII wrapper for GGUF context
 */
class GGUFReader {
public:
    GGUFReader(void* data, size_t size) 
        : ctx_(GGUF_CreateContext(data, size)) {}
    
    ~GGUFReader() {
        if (ctx_) GGUF_DestroyContext(ctx_);
    }
    
    // Disable copy
    GGUFReader(const GGUFReader&) = delete;
    GGUFReader& operator=(const GGUFReader&) = delete;
    
    // Enable move
    GGUFReader(GGUFReader&& other) noexcept : ctx_(other.ctx_) {
        other.ctx_ = nullptr;
    }
    
    GGUFReader& operator=(GGUFReader&& other) noexcept {
        if (this != &other) {
            if (ctx_) GGUF_DestroyContext(ctx_);
            ctx_ = other.ctx_;
            other.ctx_ = nullptr;
        }
        return *this;
    }
    
    bool IsValid() const { return ctx_ != nullptr; }
    
    uint64_t GetTensorCount() const {
        return ctx_ ? GGUF_GetTensorCount(ctx_) : 0;
    }
    
    bool NextTensor(GGUF_Tensor* tensor) {
        return ctx_ && GGUF_NextTensor(ctx_, tensor) == 1;
    }
    
    void Reset() {
        if (ctx_) GGUF_ResetIterator(ctx_);
    }
    
    uint32_t GetError() const {
        return ctx_ ? GGUF_GetError(ctx_) : GGUF_ERROR_NONE;
    }
    
private:
    void* ctx_;
};

/**
 * @brief Tensor iterator for range-based for loops
 */
class GGUFTensorIterator {
public:
    using iterator_category = std::input_iterator_tag;
    using value_type = GGUF_Tensor;
    using difference_type = std::ptrdiff_t;
    using pointer = GGUF_Tensor*;
    using reference = GGUF_Tensor&;
    
    GGUFTensorIterator(void* ctx, GGUF_Tensor* tensor) 
        : ctx_(ctx), tensor_(tensor), valid_(false) {
        if (ctx_ && tensor_) {
            valid_ = GGUF_NextTensor(ctx_, tensor_) == 1;
        }
    }
    
    bool operator!=(const GGUFTensorIterator& other) const {
        return valid_ != other.valid_;
    }
    
    GGUFTensorIterator& operator++() {
        if (ctx_ && tensor_) {
            valid_ = GGUF_NextTensor(ctx_, tensor_) == 1;
        }
        return *this;
    }
    
    GGUF_Tensor& operator*() { return *tensor_; }
    GGUF_Tensor* operator->() { return tensor_; }
    
private:
    void* ctx_;
    GGUF_Tensor* tensor_;
    bool valid_;
};

/**
 * @brief Range-based for loop support
 */
class GGUFRange {
public:
    GGUFRange(void* ctx) : ctx_(ctx) {}
    
    GGUFTensorIterator begin() {
        if (ctx_) GGUF_ResetIterator(ctx_);
        return GGUFTensorIterator(ctx_, &tensor_);
    }
    
    GGUFTensorIterator end() {
        return GGUFTensorIterator(nullptr, nullptr);
    }
    
private:
    void* ctx_;
    GGUF_Tensor tensor_;
};

#endif // __cplusplus

#ifdef __cplusplus
} // extern "C"
#endif

// ----------------------------------------------------------------------------
// Build Configuration
// ----------------------------------------------------------------------------

// Link against the MASM object file
// In your CMakeLists.txt or build script:
//   target_link_libraries(your_target GGUF_NextTensor.obj)

// Or use LoadLibrary/GetProcAddress for dynamic loading:
//   HMODULE hMod = LoadLibraryA("GGUF_NextTensor.dll");
//   auto pfnCreate = (decltype(&GGUF_CreateContext))GetProcAddress(hMod, "GGUF_CreateContext");

// ============================================================================
// End of Header
// ============================================================================
