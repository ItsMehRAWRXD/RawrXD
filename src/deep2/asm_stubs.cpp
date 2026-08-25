// ============================================================================
// asm_stubs.cpp — Stub implementations for missing ASM symbols
// ============================================================================

#include <cstdint>
#include <cstddef>

extern "C" {

// RMSNorm stubs
void Deep2_RMSNorm_AVX2(const float* /*input*/, float* /*output*/, size_t /*dim*/, float /*eps*/) {}
void rmsnorm_forward_avx2(const float* /*input*/, float* /*output*/, size_t /*dim*/, float /*eps*/) {}

// Softmax stub
void softmax_forward_avx2(const float* /*input*/, float* /*output*/, size_t /*dim*/) {}

// SiLU stub
void silu_activation_avx512(const float* /*input*/, float* /*output*/, size_t /*dim*/) {}

// Dequant stub
void Dequant_Q4_0_AVX2(const uint8_t* /*weights*/, const float* /*input*/, float* /*output*/,
                       size_t /*outDim*/, size_t /*inDim*/) {}

// Flash Attention stub
void flash_attn_asm_avx2(const float* /*Q*/, const float* /*K*/, const float* /*V",
                         float* /*O*/, uint32_t /*seqLen*/, uint32_t /*headDim*/, float /*scale*/) {}

} // extern "C"

namespace Deep2 {
void RegisterIQKernels() {}
}
