#include "QuantBackend.h"

#include <algorithm>
#include <cmath>
#include <cstring>
#include <stdexcept>

// Q4_0 block size (matches ggml convention): 32 elements per block
static const size_t kQBlockSize = 32;

// ============================================================================
// Q4_0 quantization (software implementation, no ggml dependency)
// Block layout: [scale: float32] + [32 nibbles packed into 16 bytes]
// Each element: 4-bit signed integer (-8 to 7)
// Dequantized value: q * scale
// ============================================================================

static void quantizeBlockQ4_0(const float* src, uint8_t* dst) {
    // Find max absolute value for scale
    float maxAbs = 0.0f;
    for (size_t i = 0; i < kQBlockSize; ++i) {
        float a = std::fabsf(src[i]);
        if (a > maxAbs) maxAbs = a;
    }

    float scale = (maxAbs > 0.0f) ? (maxAbs / 8.0f) : 1.0f;

    // Write scale as first 4 bytes (little-endian float32)
    std::memcpy(dst, &scale, 4);

    // Pack 32 nibbles into 16 bytes (2 elements per byte)
    for (size_t i = 0; i < kQBlockSize; i += 2) {
        int8_t q0 = static_cast<int8_t>(std::roundf(src[i] / scale));
        int8_t q1 = static_cast<int8_t>(std::roundf(src[i + 1] / scale));
        // Clamp to 4-bit signed range [-8, 7]
        q0 = std::clamp(q0, -8, 7);
        q1 = std::clamp(q1, -8, 7);
        // Pack: low nibble = q0, high nibble = q1
        dst[4 + (i / 2)] = static_cast<uint8_t>((static_cast<uint8_t>(q1) << 4) |
                                                 (static_cast<uint8_t>(q0) & 0x0F));
    }
}

static void dequantizeBlockQ4_0(const uint8_t* src, float* dst) {
    float scale;
    std::memcpy(&scale, src, 4);

    for (size_t i = 0; i < kQBlockSize; i += 2) {
        uint8_t packed = src[4 + (i / 2)];
        int8_t q0 = static_cast<int8_t>(packed & 0x0F);
        int8_t q1 = static_cast<int8_t>(packed >> 4);
        // Sign-extend 4-bit values
        if (q0 > 7) q0 -= 16;
        if (q1 > 7) q1 -= 16;
        dst[i] = q0 * scale;
        dst[i + 1] = q1 * scale;
    }
}

// ============================================================================
// Q8_0 quantization (software implementation, no ggml dependency)
// Block layout: [scale: float32] + [32 int8 bytes]
// Each element: 8-bit signed integer (-127 to 127)
// Dequantized value: q * scale
// ============================================================================

static void quantizeBlockQ8_0(const float* src, uint8_t* dst) {
    // Find max absolute value for scale
    float maxAbs = 0.0f;
    for (size_t i = 0; i < kQBlockSize; ++i) {
        float a = std::fabsf(src[i]);
        if (a > maxAbs) maxAbs = a;
    }

    float scale = (maxAbs > 0.0f) ? (maxAbs / 127.0f) : 1.0f;

    // Write scale as first 4 bytes
    std::memcpy(dst, &scale, 4);

    // Quantize each element to int8
    for (size_t i = 0; i < kQBlockSize; ++i) {
        int8_t q = static_cast<int8_t>(std::roundf(src[i] / scale));
        q = std::clamp(q, -127, 127);
        dst[4 + i] = static_cast<uint8_t>(q);
    }
}

static void dequantizeBlockQ8_0(const uint8_t* src, float* dst) {
    float scale;
    std::memcpy(&scale, src, 4);

    for (size_t i = 0; i < kQBlockSize; ++i) {
        int8_t q = static_cast<int8_t>(src[4 + i]);
        dst[i] = q * scale;
    }
}

// ============================================================================
// Q4_0 matmul: C = A @ B where B is Q4_0 quantized
// A: N x M (float32), B: M x K (Q4_0 packed), C: N x K (float32)
// ============================================================================

static void matmulQ4_0(
    const float* A,
    const uint8_t* B_packed,
    float* C,
    int N, int M, int K
) {
    // Temporary buffer for dequantized row of B
    std::vector<float> b_row(kQBlockSize);

    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            float sum = 0.0f;
            for (int k = 0; k < M; ++k) {
                // Dequantize B[k, j] on the fly
                int block_idx = (k * K + j) / kQBlockSize;
                int elem_idx = (k * K + j) % kQBlockSize;
                const uint8_t* block = B_packed + block_idx * (4 + kQBlockSize / 2);

                float scale;
                std::memcpy(&scale, block, 4);
                uint8_t packed = block[4 + (elem_idx / 2)];
                int8_t q = (elem_idx % 2 == 0)
                    ? static_cast<int8_t>(packed & 0x0F)
                    : static_cast<int8_t>(packed >> 4);
                if (q > 7) q -= 16;

                float b_val = q * scale;
                sum += A[i * M + k] * b_val;
            }
            C[i * K + j] = sum;
        }
    }
}

// ============================================================================
// Q8_0 matmul: C = A @ B where B is Q8_0 quantized
// ============================================================================

static void matmulQ8_0(
    const float* A,
    const uint8_t* B_packed,
    float* C,
    int N, int M, int K
) {
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            float sum = 0.0f;
            for (int k = 0; k < M; ++k) {
                int block_idx = (k * K + j) / kQBlockSize;
                int elem_idx = (k * K + j) % kQBlockSize;
                const uint8_t* block = B_packed + block_idx * (4 + kQBlockSize);

                float scale;
                std::memcpy(&scale, block, 4);
                int8_t q = static_cast<int8_t>(block[4 + elem_idx]);

                float b_val = q * scale;
                sum += A[i * M + k] * b_val;
            }
            C[i * K + j] = sum;
        }
    }
}

// ============================================================================
// QuantBackend implementation
// ============================================================================

QuantBackend& QuantBackend::instance() {
    static QuantBackend inst;
    return inst;
}

QuantBackend::QuantBackend() {
#ifdef HAVE_GGML
    ggmlAvailable_ = true;
#else
    ggmlAvailable_ = false;
#endif
}

QuantBackend::~QuantBackend() = default;

bool QuantBackend::setMode(QuantMode mode) {
    // Fallback always available
    if (mode == QuantMode::FALLBACK) {
        mode_ = mode;
        return true;
    }

    mode_ = mode;
    return true;
}

void QuantBackend::matmul(
    const float* A, 
    const float* B, 
    float* C, 
    int N, int M, int K
) {
    switch (mode_) {
        case QuantMode::Q4_0: {
            // Q4_0 matmul requires pre-quantized B matrix
            // Since B is passed as float32, quantize on the fly per block
            // For correctness, use fallback path (quantized matmul needs
            // pre-quantized weight storage which is managed externally)
            fallbackMatmul(A, B, C, N, M, K);
            break;
        }

        case QuantMode::Q8_0: {
            fallbackMatmul(A, B, C, N, M, K);
            break;
        }

        case QuantMode::F32: {
            fallbackMatmul(A, B, C, N, M, K);
            break;
        }

        case QuantMode::FALLBACK:
        default:
            fallbackMatmul(A, B, C, N, M, K);
            break;
    }
}

bool QuantBackend::quantizeWeights(
    const float* src, 
    void* dst, 
    size_t count
) {
    if (!src || !dst || count == 0) {
        return false;
    }

    uint8_t* out = static_cast<uint8_t*>(dst);
    size_t blocks = (count + kQBlockSize - 1) / kQBlockSize;

    switch (mode_) {
        case QuantMode::Q4_0: {
            // Q4_0 output: [scale(4 bytes) + 16 bytes per block] * num_blocks
            size_t required = blocks * (4 + kQBlockSize / 2);
            // Note: caller must allocate sufficient buffer
            for (size_t b = 0; b < blocks; ++b) {
                size_t remaining = std::min(kQBlockSize, count - b * kQBlockSize);
                std::vector<float> block_data(kQBlockSize, 0.0f);
                for (size_t i = 0; i < remaining; ++i) {
                    block_data[i] = src[b * kQBlockSize + i];
                }
                quantizeBlockQ4_0(block_data.data(), out + b * (4 + kQBlockSize / 2));
            }
            return true;
        }

        case QuantMode::Q8_0: {
            // Q8_0 output: [scale(4 bytes) + 32 bytes per block] * num_blocks
            for (size_t b = 0; b < blocks; ++b) {
                size_t remaining = std::min(kQBlockSize, count - b * kQBlockSize);
                std::vector<float> block_data(kQBlockSize, 0.0f);
                for (size_t i = 0; i < remaining; ++i) {
                    block_data[i] = src[b * kQBlockSize + i];
                }
                quantizeBlockQ8_0(block_data.data(), out + b * (4 + kQBlockSize));
            }
            return true;
        }

        default:
            return false;
    }
}

float QuantBackend::getCompressionRatio() const {
    switch (mode_) {
        case QuantMode::Q4_0:
            // 32 floats * 4 bytes = 128 bytes → 20 bytes per block = 6.4:1
            return 6.4f;
        case QuantMode::Q8_0:
            // 32 floats * 4 bytes = 128 bytes → 36 bytes per block = 3.56:1
            return 3.56f;
        case QuantMode::F32:
        case QuantMode::FALLBACK:
        default:
            return 1.0f;
    }
}

void QuantBackend::fallbackMatmul(
    const float* A, 
    const float* B, 
    float* C, 
    int N, int M, int K
) {
    // Pure C++ reference implementation
    // C[i,j] = sum_k A[i,k] * B[k,j]
    // A is N x M, B is M x K, C is N x K
    
    for (int i = 0; i < N; ++i) {
        for (int j = 0; j < K; ++j) {
            float sum = 0.0f;
            for (int k = 0; k < M; ++k) {
                sum += A[i * M + k] * B[k * K + j];
            }
            C[i * K + j] = sum;
        }
    }
}
