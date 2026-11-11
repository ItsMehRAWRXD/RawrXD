// ============================================================================
// Tree Attention AVX-512 Wrapper
// C++ interface to the MASM kernel
// ============================================================================

#include "RawrXD_TreeAttention.hpp"
#include <Windows.h>
#include <iostream>

namespace RawrXD {
namespace Inference {

// External ASM functions
extern "C" {
    int TreeVerify_Batch_4x4_AVX512(
        const float* Q,      // RCX
        const float* K,      // RDX
        const float* V,      // R8
        const uint8_t* mask, // R9
        float* output,       // [RSP+40]
        uint32_t headDim,    // [RSP+48]
        float softmaxScale   // [RSP+56]
    );
    
    bool TreeAttention_HasAVX512();
    uint32_t TreeAttention_GetOptimalThreads();
}

// ============================================================================
// AVX-512 Kernel Wrapper
// ============================================================================

class TreeAttentionAVX512 : public TreeAttentionKernel {
public:
    TreeAttentionAVX512() : hasAVX512_(false) {
        hasAVX512_ = TreeAttention_HasAVX512();
        if (!hasAVX512_) {
            std::cerr << "Warning: AVX-512 not available, falling back to reference\n";
        }
    }
    
    bool Forward(const TreeAttentionParams& params) override {
        if (!hasAVX512_ || params.numNodes != 16) {
            // Fall back to reference implementation
            return TreeAttentionKernel::Forward(params);
        }
        
        // Validate alignment
        if (!IsAligned(params.query, 64) || 
            !IsAligned(params.key, 64) ||
            !IsAligned(params.value, 64) ||
            !IsAligned(params.output, 64)) {
            std::cerr << "Error: Inputs not 64-byte aligned\n";
            return false;
        }
        
        // Call ASM kernel
        int result = TreeVerify_Batch_4x4_AVX512(
            params.query,
            params.key,
            params.value,
            params.causalMask,
            params.output,
            params.headDim,
            params.softmaxScale
        );
        
        return result == 0;
    }
    
    static bool IsSupported() {
        return TreeAttention_HasAVX512();
    }
    
    static uint32_t GetOptimalThreads() {
        return TreeAttention_GetOptimalThreads();
    }

private:
    bool hasAVX512_;
    
    bool IsAligned(const void* ptr, size_t alignment) {
        return (reinterpret_cast<uintptr_t>(ptr) % alignment) == 0;
    }
};

// Factory function
TreeAttentionKernel* CreateTreeAttentionKernel() {
    if (TreeAttentionAVX512::IsSupported()) {
        return new TreeAttentionAVX512();
    }
    return new TreeAttentionKernel();  // Reference implementation
}

} // namespace Inference
} // namespace RawrXD
