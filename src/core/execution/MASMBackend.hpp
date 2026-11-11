//==============================================================================
// MASMBackend.hpp
// Thin adapter for MASM kernel execution via Sovereign_KernelDispatch
//
// Phase 7C.2 - MASM Backend Integration
// Implements IKernelBackend interface for MASM kernels
//==============================================================================

#pragma once

#include "IKernelBackend.hpp"
#include "SovereignKernelTypes.hpp"
#include <cstdint>
#include <vector>
#include <string>

// Include C API from Sovereign_KernelDispatch
extern "C" {
    #include "../../../../src/asm/Sovereign_KernelDispatch.h"
}

namespace sovereign {

//==============================================================================
// MASM Backend Implementation
//==============================================================================
class MASMBackend : public IKernelBackend {
public:
    // Constructor initializes kernel table
    MASMBackend();
    ~MASMBackend() override;

    // IKernelBackend interface
    BackendInfo GetInfo() const override;
    bool Initialize() override;
    void Shutdown() override;
    bool IsInitialized() const override { return initialized_; }
    
    // Capabilities
    bool SupportsKernel(KernelId id) const override;
    bool SupportsDataType(TensorDesc::DataType dtype) const override;

    // Core operations
    bool MatMul(const TensorDesc& A, const TensorDesc& B, TensorDesc& C,
                  const MatMulParams& params, ExecutionStats* stats) override;
    bool FlashAttention(const TensorDesc& Q, const TensorDesc& K, const TensorDesc& V,
                        TensorDesc& output, const AttentionParams& params,
                        ExecutionStats* stats) override;
    bool RMSNorm(const TensorDesc& input, const TensorDesc& weight, TensorDesc& output,
                 float epsilon, ExecutionStats* stats) override;
    bool LayerNorm(const TensorDesc& input, const TensorDesc& weight, const TensorDesc& bias,
                   TensorDesc& output, float epsilon, ExecutionStats* stats) override;
    bool RoPE(const TensorDesc& input, TensorDesc& output, const float* cosTable,
              const float* sinTable, uint32_t seqLen, uint32_t headDim,
              ExecutionStats* stats) override;
    bool SiLU(const TensorDesc& input, TensorDesc& output, ExecutionStats* stats) override;
    bool Softmax(const TensorDesc& input, TensorDesc& output, int32_t axis,
                 ExecutionStats* stats) override;
    bool ResidualAdd(const TensorDesc& input, const TensorDesc& residual,
                     TensorDesc& output, ExecutionStats* stats) override;
    bool Quantize(const TensorDesc& input, TensorDesc& output, const QuantParams& params,
                  ExecutionStats* stats) override;
    bool Dequantize(const TensorDesc& input, TensorDesc& output, const QuantParams& params,
                    ExecutionStats* stats) override;
    bool Copy(const TensorDesc& source, TensorDesc& dest, size_t sizeBytes,
              ExecutionStats* stats) override;

private:
    bool initialized_;
    Sovereign_KernelTable kernelTable_;
    
    // Supported kernels cache
    std::vector<KernelId> supportedKernels_;
    
    // Helper to populate supported kernels
    void PopulateSupportedKernels();
    
    // Timing helper
    uint64_t NowUs() const;
};

} // namespace sovereign
