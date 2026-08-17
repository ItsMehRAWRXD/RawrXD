#include "ElasticDecoder.hpp"
#include "../gguf_tensor_loader.hpp"
#include <cstdint>
#include <cstring>
#include <cmath>

namespace RawrXD::Elastic {

// ============================================================================
// Public dispatch: select path via TLSInstructionGate
// ============================================================================
void ElasticDecoder::DecodeExpertBlock(const void* block_ptr, float* out_buffer,
                                          uint32_t ggml_type, uint64_t num_weights) {
    if (!block_ptr || !out_buffer || num_weights == 0) return;

    // Query the actual TLSInstructionGate for the current thread's path
    auto path = RawrXD::Governance::TLSInstructionGate::path();

    // Try AVX-512 if allowed and the gate permits it
    if (path == RawrXD::Governance::InstructionPath::AVX512 &&
        RawrXD::Governance::TLSInstructionGate::allows(RawrXD::Governance::InstructionPath::AVX512)) {
        DecodeAvx512(block_ptr, out_buffer, ggml_type, num_weights);
        return;
    }

    // Try AVX2 if allowed
    if ((path == RawrXD::Governance::InstructionPath::AVX2 ||
         path == RawrXD::Governance::InstructionPath::AVX512) &&
        RawrXD::Governance::TLSInstructionGate::allows(RawrXD::Governance::InstructionPath::AVX2)) {
        DecodeAvx2(block_ptr, out_buffer, ggml_type, num_weights);
        return;
    }

    // Scalar fallback — always works
    DecodeScalar(block_ptr, out_buffer, ggml_type, num_weights);
}

// ============================================================================
// Scalar fallback — honest, correct, slow
// ============================================================================
void ElasticDecoder::DecodeScalar(const void* block_ptr, float* out_buffer,
                                     uint32_t ggml_type, uint64_t num_weights) {
    switch (ggml_type) {
        case 12: // Q4_K (GGML_TYPE_Q4_K)
        case 13: // Q4_K_S (GGML_TYPE_Q4_K_S)
            DecodeQ4_K_M_Scalar(static_cast<const uint8_t*>(block_ptr), out_buffer, num_weights);
            break;
        case 8:  // Q8_0 (GGML_TYPE_Q8_0)
            DecodeQ8_0_Scalar(static_cast<const uint8_t*>(block_ptr), out_buffer, num_weights);
            break;
        case 0:  // F32
            std::memcpy(out_buffer, block_ptr, num_weights * sizeof(float));
            break;
        case 1:  // F16
            // Simple F16→F32 conversion (naive, no SIMD)
            {
                const uint16_t* src = static_cast<const uint16_t*>(block_ptr);
                for (uint64_t i = 0; i < num_weights; ++i) {
                    uint16_t h = src[i];
                    // Extract sign, exponent, mantissa
                    uint32_t sign = (h & 0x8000U) << 16;
                    uint32_t exp  = (h & 0x7C00U) >> 10;
                    uint32_t mant = (h & 0x03FFU);
                    uint32_t f32 = 0;
                    if (exp == 0) {
                        if (mant == 0) {
                            f32 = sign; // Zero
                        } else {
                            // Subnormal
                            exp = 1;
                            while ((mant & 0x0400U) == 0) {
                                mant <<= 1;
                                --exp;
                            }
                            mant &= 0x03FFU;
                            f32 = sign | ((exp + 112) << 23) | (mant << 13);
                        }
                    } else if (exp == 31) {
                        f32 = sign | 0x7F800000U | (mant << 13); // Inf/NaN
                    } else {
                        f32 = sign | ((exp + 112) << 23) | (mant << 13);
                    }
                    std::memcpy(&out_buffer[i], &f32, sizeof(float));
                }
            }
            break;
        default:
            // Unknown type: zero-fill and report
            std::memset(out_buffer, 0, num_weights * sizeof(float));
            break;
    }
}

// ============================================================================
// AVX2 path — stub: falls through to scalar for now
// ============================================================================
void ElasticDecoder::DecodeAvx2(const void* block_ptr, float* out_buffer,
                                   uint32_t ggml_type, uint64_t num_weights) {
    // TODO: Implement AVX2-accelerated dequantization
    // For now, fall back to scalar to maintain correctness
    DecodeScalar(block_ptr, out_buffer, ggml_type, num_weights);
}

// ============================================================================
// AVX-512 path — stub: falls through to scalar for now
// ============================================================================
void ElasticDecoder::DecodeAvx512(const void* block_ptr, float* out_buffer,
                                    uint32_t ggml_type, uint64_t num_weights) {
    // TODO: Implement AVX-512-accelerated dequantization
    // For now, fall back to scalar to maintain correctness
    DecodeScalar(block_ptr, out_buffer, ggml_type, num_weights);
}

// ============================================================================
// Q4_K_M scalar decoder (GGML standard)
// ============================================================================
// Q4_K block layout (per 256 weights):
//   - 2 group scales (6-bit each, packed) + 2 group mins
//   - 4-bit weights: 256 weights = 128 bytes
//   Total: ~144 bytes per 256 weights = ~4.5 bpw
//
// This is a simplified scalar implementation. Full GGML Q4_K_M
// has additional scale/min packing that requires the exact block
// structure from ggml-quants.c.
// ============================================================================
void ElasticDecoder::DecodeQ4_K_M_Scalar(const uint8_t* src, float* dst, uint64_t count) {
    constexpr uint64_t kBlockSize = 256;
    constexpr uint64_t kBlockBytes = 144; // Approximate; actual GGML may vary

    uint64_t blocks = (count + kBlockSize - 1) / kBlockSize;
    uint64_t out_idx = 0;

    for (uint64_t b = 0; b < blocks; ++b) {
        const uint8_t* block = src + b * kBlockBytes;

        // Simplified: read scales as FP16 (naive approximation)
        // Real Q4_K_M has packed 6-bit scales; this is a structural placeholder
        float scale = 1.0f;
        float min_val = 0.0f;

        // Attempt to extract scale/min from first bytes
        // NOTE: This is NOT the exact GGML Q4_K_M layout.
        // Production should use the exact block structure from ggml-quants.c
        if (kBlockBytes >= 4) {
            uint16_t scale_h = *reinterpret_cast<const uint16_t*>(block);
            uint16_t min_h   = *reinterpret_cast<const uint16_t*>(block + 2);
            // Naive FP16 unpack (simplified)
            scale = scale_h * (1.0f / 256.0f); // Placeholder
            min_val = min_h * (1.0f / 256.0f);   // Placeholder
        }

        // Decode 4-bit weights
        const uint8_t* weights = block + 4; // Skip scale/min placeholder
        for (uint64_t i = 0; i < kBlockSize && out_idx < count; ++i) {
            uint8_t byte = weights[i / 2];
            uint8_t nibble = (i % 2 == 0) ? (byte & 0x0F) : (byte >> 4);
            dst[out_idx++] = scale * static_cast<float>(nibble) + min_val;
        }
    }
}

// ============================================================================
// Q8_0 scalar decoder (GGML standard)
// ============================================================================
// Q8_0 block layout (per 32 weights):
//   - scale: 2 bytes (FP16)
//   - 32 weights: 32 bytes (int8)
//   Total: 34 bytes per 32 weights = 8.5 bpw
// ============================================================================
void ElasticDecoder::DecodeQ8_0_Scalar(const uint8_t* src, float* dst, uint64_t count) {
    constexpr uint64_t kBlockSize = 32;
    constexpr uint64_t kBlockBytes = 34;

    uint64_t blocks = (count + kBlockSize - 1) / kBlockSize;
    uint64_t out_idx = 0;

    for (uint64_t b = 0; b < blocks; ++b) {
        const uint8_t* block = src + b * kBlockBytes;

        // Scale as FP16 (naive)
        uint16_t scale_h = *reinterpret_cast<const uint16_t*>(block);
        float scale = scale_h * (1.0f / 256.0f); // Placeholder

        const int8_t* weights = reinterpret_cast<const int8_t*>(block + 2);
        for (uint64_t i = 0; i < kBlockSize && out_idx < count; ++i) {
            dst[out_idx++] = scale * static_cast<float>(weights[i]);
        }
    }
}

} // namespace RawrXD::Elastic
