#pragma once
#include "ElasticTypes.hpp"
#include "../governance/TLSInstructionGate.hpp"
#include <cstdint>
#include <cstring>

// ============================================================================
// ElasticDecoder
// ============================================================================
// Decodes GGUF-quantized expert weights to FP32 for GPU upload.
// Uses the actual TLSInstructionGate API (path() / allows()), NOT invented
// has_avx512vpopcntdq() methods.
//
// NOTE: This is a functional decoder for standard GGML Q4_K_M blocks.
// The "0.35 effective bpw" claim comes from MoE sparsity (only resident
// experts count), NOT from a custom block codec.  Physical storage is
// standard GGUF quantization (~4.5 bpw for Q4_K_M).
// ============================================================================

namespace RawrXD::Elastic {

class ElasticDecoder {
public:
    // Decode a block of quantized weights to FP32.
    // block_ptr  -> raw GGML-quantized bytes (Q4_K_M, Q8_0, etc.)
    // out_buffer -> FP32 output buffer (must hold num_weights floats)
    // ggml_type  -> GGML type enum (from ExpertMetadata)
    // num_weights-> Number of scalar weights to decode
    static void DecodeExpertBlock(const void* block_ptr, float* out_buffer,
                                   uint32_t ggml_type, uint64_t num_weights);

private:
    // Scalar fallback — always works, always slow
    static void DecodeScalar(const void* block_ptr, float* out_buffer,
                              uint32_t ggml_type, uint64_t num_weights);

    // AVX2 path — 8-wide FP32 decode
    static void DecodeAvx2(const void* block_ptr, float* out_buffer,
                            uint32_t ggml_type, uint64_t num_weights);

    // AVX-512 path — 16-wide FP32 decode
    static void DecodeAvx512(const void* block_ptr, float* out_buffer,
                              uint32_t ggml_type, uint64_t num_weights);

    // Q4_K_M block layout (GGML standard):
    //   256 weights per block
    //   2-bit scales (6 bits) + 4-bit weights (128 bytes) + 2 8-bit scales
    //   Total: ~144 bytes per 256 weights = ~4.5 bpw
    static void DecodeQ4_K_M_Scalar(const uint8_t* src, float* dst, uint64_t count);
    static void DecodeQ8_0_Scalar(const uint8_t* src, float* dst, uint64_t count);
};

} // namespace RawrXD::Elastic
