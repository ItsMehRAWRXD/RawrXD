// L4_2_0_TensorRuntime.h
// L4.2.0 Tensor Runtime - Weight Access Abstraction Layer
// Frozen dependency: L4.1 GGUF Weight Access Layer

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>

namespace RawrXD {
namespace L4 {

// Forward declarations
class FileReader;

// ============================================================================
// Type Definitions
// ============================================================================

// GGML quantization types (subset for L4.2.0)
enum class QuantType : uint32_t {
    Q4_0 = 2,   // 4-bit quantization, type 0
    Q8_0 = 8,   // 8-bit quantization, type 0 (future)
    F32  = 0,   // 32-bit float (future)
};

// Tensor view - lightweight handle to tensor data
struct TensorView {
    std::string name;
    std::vector<uint64_t> dims;
    QuantType type;
    uint64_t data_offset;      // Absolute file offset to tensor data
    uint64_t tensor_data_start; // Base of tensor data section
    size_t element_size;       // Bytes per element (for quantized: block size)
    
    // Computed properties
    uint64_t num_elements() const;
    uint64_t num_rows() const;
    uint64_t row_size() const;
};

// Weight buffer - owning container for dequantized weights
struct WeightBuffer {
    std::vector<float> data;
    std::vector<uint64_t> shape;
    
    float* ptr() { return data.data(); }
    const float* ptr() const { return data.data(); }
    size_t size() const { return data.size(); }
};

// ============================================================================
// Tensor Runtime Interface
// ============================================================================

class ITensorRuntime {
public:
    virtual ~ITensorRuntime() = default;
    
    // Initialize with GGUF file path
    virtual bool Initialize(const std::string& gguf_path) = 0;
    
    // Shutdown and release resources
    virtual void Shutdown() = 0;
    
    // Get tensor by name (lookup in registry)
    virtual TensorView GetTensor(const std::string& name) = 0;
    
    // Check if tensor exists
    virtual bool HasTensor(const std::string& name) const = 0;
    
    // Read a single row from quantized tensor
    // Output buffer must hold at least tensor.dims[0] floats
    virtual bool ReadRow(
        const TensorView& tensor,
        uint64_t row_index,
        float* output
    ) = 0;
    
    // Read entire tensor (for small weights like biases)
    virtual WeightBuffer ReadTensor(const TensorView& tensor) = 0;
    
    // Get list of available tensors
    virtual std::vector<std::string> ListTensors() const = 0;
    
    // Get runtime statistics
    struct Stats {
        uint64_t bytes_read;
        uint64_t rows_read;
        uint64_t cache_hits;
        uint64_t cache_misses;
    };
    virtual Stats GetStats() const = 0;
};

// ============================================================================
// Kernel Dispatch Interface
// ============================================================================

// Kernel types for weight operations
enum class KernelType {
    Q4_0_DECODE_ROW,      // Decode single row from Q4_0
    Q4_0_GEMV,            // Matrix-vector multiply with Q4_0 weights
    Q8_0_DECODE_ROW,      // Future: Q8_0 support
};

// Kernel dispatch interface
class IKernelDispatch {
public:
    virtual ~IKernelDispatch() = default;
    
    // Execute kernel by type
    virtual bool Execute(
        KernelType type,
        const void* input,
        void* output,
        size_t count
    ) = 0;
    
    // Check if kernel is available
    virtual bool HasKernel(KernelType type) const = 0;
};

// ============================================================================
// Concrete Implementation
// ============================================================================

class TensorRuntime : public ITensorRuntime {
public:
    TensorRuntime();
    ~TensorRuntime() override;
    
    // ITensorRuntime implementation
    bool Initialize(const std::string& gguf_path) override;
    void Shutdown() override;
    TensorView GetTensor(const std::string& name) override;
    bool HasTensor(const std::string& name) const override;
    bool ReadRow(const TensorView& tensor, uint64_t row_index, float* output) override;
    WeightBuffer ReadTensor(const TensorView& tensor) override;
    std::vector<std::string> ListTensors() const override;
    Stats GetStats() const override;
    
    // Extended: Set kernel dispatch (for fused operations)
    void SetKernelDispatch(std::shared_ptr<IKernelDispatch> dispatch);
    
    // Extended: Execute GEMV with fused kernel
    bool ExecuteGEMV(
        const TensorView& weights,
        const float* input,
        float* output,
        uint64_t row_count
    );

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// Factory
// ============================================================================

std::unique_ptr<ITensorRuntime> CreateTensorRuntime();

} // namespace L4
} // namespace RawrXD
