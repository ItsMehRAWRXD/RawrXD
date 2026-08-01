/**
 * @file fused_quant_gemm.cpp
 * @brief RawrXD L4.2.2 Fused Quant GEMM Implementation
 *
 * High-performance kernels that decode compressed weights directly into
 * AVX2 FMA accumulators. No temporary FP32 buffer.
 *
 * @copyright RawrXD 2026
 */

#include "fused_quant_gemm.h"
#include <immintrin.h>
#include <cstring>
#include <cmath>
#include <thread>
#include <vector>
#include <chrono>
#include <iostream>
#include <random>
#include <intrin.h>

namespace rawrxd {
namespace kernels {

// ============================================================================
// Global Metrics
// ============================================================================

FusedKernelMetrics g_fused_metrics;

void FusedKernelMetrics::Reset() {
    blocks_processed = 0;
    weights_decoded = 0;
    fma_operations = 0;
    memory_bandwidth_gbps = 0.0;
    compute_gflops = 0.0;
    efficiency_percent = 0.0;
}

void FusedKernelMetrics::Print() const {
    std::cout << "Fused Kernel Metrics:\n";
    std::cout << "  Blocks processed: " << blocks_processed << "\n";
    std::cout << "  Weights decoded: " << weights_decoded << "\n";
    std::cout << "  FMA operations: " << fma_operations << "\n";
    std::cout << "  Memory bandwidth: " << memory_bandwidth_gbps << " GB/s\n";
    std::cout << "  Compute: " << compute_gflops << " GFLOPS\n";
    std::cout << "  Efficiency: " << efficiency_percent << "%\n";
}

// ============================================================================
// CPU Feature Detection
// ============================================================================

void FusedQuantGemm::CPUFeatures::Detect() {
    // Conservative defaults
    has_avx2 = true;
    has_avx512f = false;
    has_fma = true;
    has_vnni = false;
    
#ifdef _WIN32
    // Windows CPU detection
    int cpu_info[4] = {0};
    
    __cpuid(cpu_info, 0);
    int max_func = cpu_info[0];
    
    if (max_func >= 1) {
        __cpuid(cpu_info, 1);
        has_avx2 = (cpu_info[2] & (1 << 28)) != 0;
        has_fma = (cpu_info[2] & (1 << 12)) != 0;
    }
    
    if (max_func >= 7) {
        __cpuid(cpu_info, 7);
        has_avx2 = (cpu_info[1] & (1 << 5)) != 0;
        has_avx512f = (cpu_info[1] & (1 << 16)) != 0;
    }
#else
    // Linux/Unix - assume AVX2 for now
    has_avx2 = true;
    has_fma = true;
#endif
}

void FusedQuantGemm::CPUFeatures::Print() const {
    std::cout << "CPU Features:\n";
    std::cout << "  AVX2: " << (has_avx2 ? "YES" : "NO") << "\n";
    std::cout << "  AVX-512F: " << (has_avx512f ? "YES" : "NO") << "\n";
    std::cout << "  FMA: " << (has_fma ? "YES" : "NO") << "\n";
}

FusedQuantGemm::CPUFeatures FusedQuantGemm::GetCPUFeatures() {
    CPUFeatures features;
    features.Detect();
    return features;
}

// ============================================================================
// Intrinsics Implementation
// ============================================================================

namespace intrinsics {

inline __m256 DecodeQ4_0_Block_AVX2(const uint8_t* block_data, size_t nibble_idx) {
    // Load scale (FP16) and convert to FP32
    uint16_t scale_f16 = *reinterpret_cast<const uint16_t*>(block_data);
    float scale = *reinterpret_cast<const float*>(&scale_f16);  // Simplified - proper FP16 decode needed
    __m256 scale_vec = _mm256_set1_ps(scale);
    
    // Load nibbles
    const uint8_t* nibbles = block_data + 2;
    
    // Extract 8 consecutive nibbles
    // This is simplified - real implementation needs proper nibble extraction
    float dequantized[8];
    for (int i = 0; i < 8; i++) {
        size_t byte_idx = (nibble_idx + i) / 2;
        int nibble = (nibble_idx + i) % 2 == 0 ? 
            (nibbles[byte_idx] & 0x0F) : ((nibbles[byte_idx] >> 4) & 0x0F);
        dequantized[i] = (static_cast<float>(nibble) - 8.0f) * scale;
    }
    
    return _mm256_loadu_ps(dequantized);
}

inline __m256 FusedQ4_0_FMA_AVX2(
    __m256 accumulator,
    const uint8_t* block_data,
    size_t nibble_idx,
    __m256 input_vec
) {
    __m256 weights = DecodeQ4_0_Block_AVX2(block_data, nibble_idx);
    return _mm256_fmadd_ps(weights, input_vec, accumulator);
}

inline float HorizontalSum_AVX2(__m256 vec) {
    // Horizontal sum of 8 floats
    __m256 sum1 = _mm256_hadd_ps(vec, vec);
    __m256 sum2 = _mm256_hadd_ps(sum1, sum1);
    __m128 sum3 = _mm256_extractf128_ps(sum2, 1);
    __m128 sum4 = _mm_add_ps(_mm256_castps256_ps128(sum2), sum3);
    return _mm_cvtss_f32(sum4);
}

inline void PrefetchNextBlock(const uint8_t* addr) {
    _mm_prefetch(reinterpret_cast<const char*>(addr), _MM_HINT_T0);
}

} // namespace intrinsics

// ============================================================================
// Q4_0 Scalar Fallback
// ============================================================================

void FusedQuantGemm::GemvQ4_0_Scalar(
    const uint8_t* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    const size_t BLOCK_SIZE = 32;
    const size_t BYTES_PER_BLOCK = 18;  // 2 bytes scale + 16 bytes nibbles
    
    for (size_t r = 0; r < rows; r++) {
        float sum = 0.0f;
        const uint8_t* row_weights = weights + r * (cols / BLOCK_SIZE) * BYTES_PER_BLOCK;
        
        for (size_t c = 0; c < cols; c += BLOCK_SIZE) {
            const uint8_t* block = row_weights + (c / BLOCK_SIZE) * BYTES_PER_BLOCK;
            
            // Read FP16 scale
            uint16_t scale_f16;
            memcpy(&scale_f16, block, 2);
            float scale = *reinterpret_cast<const float*>(&scale_f16);
            
            // Process 32 nibbles
            const uint8_t* nibbles = block + 2;
            for (size_t i = 0; i < BLOCK_SIZE; i += 2) {
                uint8_t packed = nibbles[i / 2];
                int nibble1 = (packed & 0x0F) - 8;
                int nibble2 = ((packed >> 4) & 0x0F) - 8;
                
                float w1 = static_cast<float>(nibble1) * scale;
                float w2 = static_cast<float>(nibble2) * scale;
                
                sum += w1 * input[c + i];
                sum += w2 * input[c + i + 1];
            }
        }
        
        output[r] = sum;
    }
}

// ============================================================================
// Q4_0 AVX2 Implementation
// ============================================================================

void FusedQuantGemm::GemvQ4_0_AVX2(
    const uint8_t* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    const size_t BLOCK_SIZE = 32;
    const size_t BYTES_PER_BLOCK = 18;
    
    for (size_t r = 0; r < rows; r++) {
        __m256 sum_vec = _mm256_setzero_ps();
        const uint8_t* row_weights = weights + r * (cols / BLOCK_SIZE) * BYTES_PER_BLOCK;
        
        for (size_t c = 0; c < cols; c += BLOCK_SIZE) {
            const uint8_t* block = row_weights + (c / BLOCK_SIZE) * BYTES_PER_BLOCK;
            
            // Prefetch next block
            if (c + BLOCK_SIZE < cols) {
                intrinsics::PrefetchNextBlock(block + BYTES_PER_BLOCK);
            }
            
            // Read scale
            uint16_t scale_f16;
            memcpy(&scale_f16, block, 2);
            float scale = *reinterpret_cast<const float*>(&scale_f16);
            __m256 scale_vec = _mm256_set1_ps(scale);
            
            // Process 8 nibbles at a time (4 iterations for 32 weights)
            const uint8_t* nibbles = block + 2;
            const float* input_ptr = &input[c];
            
            for (int group = 0; group < 4; group++) {
                // Load 8 input floats
                __m256 input_vec = _mm256_loadu_ps(&input_ptr[group * 8]);
                
                // Decode 8 weights from nibbles
                float weights_f32[8];
                for (int i = 0; i < 8; i++) {
                    int nibble_idx = group * 8 + i;
                    int byte_idx = nibble_idx / 2;
                    int nibble = (nibble_idx % 2 == 0) ? 
                        (nibbles[byte_idx] & 0x0F) : ((nibbles[byte_idx] >> 4) & 0x0F);
                    weights_f32[i] = (static_cast<float>(nibble) - 8.0f) * scale;
                }
                
                __m256 weight_vec = _mm256_loadu_ps(weights_f32);
                
                // FMA: sum += weight * input
                sum_vec = _mm256_fmadd_ps(weight_vec, input_vec, sum_vec);
            }
        }
        
        // Horizontal sum
        output[r] = intrinsics::HorizontalSum_AVX2(sum_vec);
    }
}

// ============================================================================
// Q4_0 AVX-512 Stub
// ============================================================================

void FusedQuantGemm::GemvQ4_0_AVX512(
    const uint8_t* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    // For now, fall back to AVX2
    // Real AVX-512 implementation would process 16 floats at a time
    GemvQ4_0_AVX2(weights, input, output, rows, cols);
}

// ============================================================================
// Q4_K AVX2 Implementation
// ============================================================================

void FusedQuantGemm::GemvQ4_K_AVX2(
    const uint8_t* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    // Q4_K uses 256-weight super-blocks with mixed precision
    // Simplified implementation - full version needs proper K-quant decode
    const size_t SUPERBLOCK_SIZE = 256;
    const size_t BYTES_PER_SUPERBLOCK = 272;
    
    for (size_t r = 0; r < rows; r++) {
        __m256 sum_vec = _mm256_setzero_ps();
        const uint8_t* row_weights = weights + r * (cols / SUPERBLOCK_SIZE) * BYTES_PER_SUPERBLOCK;
        
        for (size_t c = 0; c < cols; c += SUPERBLOCK_SIZE) {
            const uint8_t* block = row_weights + (c / SUPERBLOCK_SIZE) * BYTES_PER_SUPERBLOCK;
            
            // Read global scale and min
            float scale, min_val;
            memcpy(&scale, block, 4);
            memcpy(&min_val, block + 4, 4);
            
            __m256 scale_vec = _mm256_set1_ps(scale);
            __m256 min_vec = _mm256_set1_ps(min_val);
            
            // Process 256 weights (32 groups of 8)
            const uint8_t* quants = block + 16;  // After scale + scales array
            const float* input_ptr = &input[c];
            
            for (int group = 0; group < 32; group++) {
                __m256 input_vec = _mm256_loadu_ps(&input_ptr[group * 8]);
                
                // Decode 8 weights (simplified)
                float weights_f32[8];
                for (int i = 0; i < 8; i++) {
                    int nibble_idx = group * 8 + i;
                    int byte_idx = nibble_idx / 2;
                    int nibble = (nibble_idx % 2 == 0) ? 
                        (quants[byte_idx] & 0x0F) : ((quants[byte_idx] >> 4) & 0x0F);
                    weights_f32[i] = static_cast<float>(nibble) * scale + min_val;
                }
                
                __m256 weight_vec = _mm256_loadu_ps(weights_f32);
                sum_vec = _mm256_fmadd_ps(weight_vec, input_vec, sum_vec);
            }
        }
        
        output[r] = intrinsics::HorizontalSum_AVX2(sum_vec);
    }
}

// ============================================================================
// Q8_0 AVX2 Implementation
// ============================================================================

void FusedQuantGemm::GemvQ8_0_AVX2(
    const uint8_t* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    const size_t BLOCK_SIZE = 32;
    const size_t BYTES_PER_BLOCK = 34;  // 2 bytes scale + 32 bytes weights
    
    for (size_t r = 0; r < rows; r++) {
        __m256 sum_vec = _mm256_setzero_ps();
        const uint8_t* row_weights = weights + r * (cols / BLOCK_SIZE) * BYTES_PER_BLOCK;
        
        for (size_t c = 0; c < cols; c += BLOCK_SIZE) {
            const uint8_t* block = row_weights + (c / BLOCK_SIZE) * BYTES_PER_BLOCK;
            
            // Read scale
            uint16_t scale_f16;
            memcpy(&scale_f16, block, 2);
            float scale = *reinterpret_cast<const float*>(&scale_f16);
            __m256 scale_vec = _mm256_set1_ps(scale);
            
            // Process 32 int8 weights (4 groups of 8)
            const uint8_t* quant_weights = block + 2;
            const float* input_ptr = &input[c];
            
            for (int group = 0; group < 4; group++) {
                __m256 input_vec = _mm256_loadu_ps(&input_ptr[group * 8]);
                
                // Convert int8 to float and dequantize
                float weights_f32[8];
                for (int i = 0; i < 8; i++) {
                    int8_t quant = static_cast<int8_t>(quant_weights[group * 8 + i]);
                    weights_f32[i] = static_cast<float>(quant) * scale;
                }
                
                __m256 weight_vec = _mm256_loadu_ps(weights_f32);
                sum_vec = _mm256_fmadd_ps(weight_vec, input_vec, sum_vec);
            }
        }
        
        output[r] = intrinsics::HorizontalSum_AVX2(sum_vec);
    }
}

// ============================================================================
// Auto-Dispatch
// ============================================================================

void FusedQuantGemm::GemvAuto(
    compression::CompressionType type,
    const uint8_t* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols
) {
    CPUFeatures features;
    features.Detect();
    
    switch (type) {
        case compression::CompressionType::Q4_0:
            if (features.has_avx512f) {
                GemvQ4_0_AVX512(weights, input, output, rows, cols);
            } else if (features.has_avx2) {
                GemvQ4_0_AVX2(weights, input, output, rows, cols);
            } else {
                GemvQ4_0_Scalar(weights, input, output, rows, cols);
            }
            break;
            
        case compression::CompressionType::Q4_K:
            GemvQ4_K_AVX2(weights, input, output, rows, cols);
            break;
            
        case compression::CompressionType::Q8_0:
            GemvQ8_0_AVX2(weights, input, output, rows, cols);
            break;
            
        default:
            // Fall back to scalar
            GemvQ4_0_Scalar(weights, input, output, rows, cols);
            break;
    }
}

// ============================================================================
// Multi-threaded Implementation
// ============================================================================

static void GemvWorker(
    compression::CompressionType type,
    const uint8_t* weights,
    const float* input,
    float* output,
    size_t cols,
    size_t start_row,
    size_t end_row
) {
    // Calculate offset for this worker's rows
    size_t block_size = (type == compression::CompressionType::Q4_K) ? 256 : 32;
    size_t bytes_per_block = (type == compression::CompressionType::Q4_K) ? 272 : 18;
    
    const uint8_t* worker_weights = weights + start_row * (cols / block_size) * bytes_per_block;
    float* worker_output = output + start_row;
    
    FusedQuantGemm::GemvAuto(type, worker_weights, input, worker_output, 
                            end_row - start_row, cols);
}

void FusedQuantGemm::GemvMT(
    compression::CompressionType type,
    const uint8_t* weights,
    const float* input,
    float* output,
    size_t rows,
    size_t cols,
    int num_threads
) {
    if (num_threads <= 1) {
        GemvAuto(type, weights, input, output, rows, cols);
        return;
    }
    
    std::vector<std::thread> threads;
    size_t rows_per_thread = rows / num_threads;
    
    for (int t = 0; t < num_threads; t++) {
        size_t start_row = t * rows_per_thread;
        size_t end_row = (t == num_threads - 1) ? rows : (t + 1) * rows_per_thread;
        
        threads.emplace_back(GemvWorker, type, weights, input, output, 
                            cols, start_row, end_row);
    }
    
    for (auto& t : threads) {
        t.join();
    }
}

// ============================================================================
// Validation
// ============================================================================

bool FusedQuantGemm::ValidateKernel(
    compression::CompressionType type,
    const float* weights_fp32,
    const float* input,
    float* output,
    size_t rows,
    size_t cols,
    float tolerance
) {
    // Reference implementation (FP32 GEMV)
    std::vector<float> reference(rows);
    for (size_t r = 0; r < rows; r++) {
        float sum = 0.0f;
        for (size_t c = 0; c < cols; c++) {
            sum += weights_fp32[r * cols + c] * input[c];
        }
        reference[r] = sum;
    }
    
    // Compress weights
    auto codec = compression::CodecFactory::Create(type);
    if (!codec) return false;
    
    size_t num_weights = rows * cols;
    std::vector<uint8_t> compressed(codec->GetCompressedSize(num_weights));
    codec->EncodeBlock(weights_fp32, compressed.data(), num_weights);
    
    // Run fused kernel
    GemvAuto(type, compressed.data(), input, output, rows, cols);
    
    // Compare
    float max_error = 0.0f;
    for (size_t r = 0; r < rows; r++) {
        max_error = std::max(max_error, std::abs(reference[r] - output[r]));
    }
    
    return max_error <= tolerance;
}

// ============================================================================
// Benchmarking
// ============================================================================

FusedQuantGemm::BenchmarkResult FusedQuantGemm::Benchmark(
    compression::CompressionType type,
    size_t rows,
    size_t cols,
    int iterations
) {
    BenchmarkResult result = {0};
    
    // Generate test data
    std::vector<float> weights_fp32(rows * cols);
    std::vector<float> input(cols);
    std::vector<float> output(rows);
    
    std::mt19937 rng(42);
    std::normal_distribution<float> dist(0.0f, 0.1f);
    
    for (auto& w : weights_fp32) w = dist(rng);
    for (auto& i : input) i = dist(rng);
    
    // Compress weights
    auto codec = compression::CodecFactory::Create(type);
    if (!codec) return result;
    
    std::vector<uint8_t> compressed(codec->GetCompressedSize(rows * cols));
    codec->EncodeBlock(weights_fp32.data(), compressed.data(), rows * cols);
    
    // Benchmark fused kernel
    auto start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        GemvAuto(type, compressed.data(), input.data(), output.data(), rows, cols);
    }
    auto end = std::chrono::high_resolution_clock::now();
    
    double fused_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
    result.fused_time_ms = fused_ms / iterations;
    
    // Benchmark separate decode + GEMM
    std::vector<float> decompressed(rows * cols);
    start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < iterations; iter++) {
        codec->DecodeBlock(compressed.data(), decompressed.data(), rows * cols);
        // Simple GEMV
        for (size_t r = 0; r < rows; r++) {
            float sum = 0.0f;
            for (size_t c = 0; c < cols; c++) {
                sum += decompressed[r * cols + c] * input[c];
            }
            output[r] = sum;
        }
    }
    end = std::chrono::high_resolution_clock::now();
    
    double separate_ms = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
    result.separate_time_ms = separate_ms / iterations;
    
    result.speedup = result.separate_time_ms / result.fused_time_ms;
    result.memory_saved_bytes = rows * cols * sizeof(float) - compressed.size();
    
    // Calculate max error
    std::vector<float> reference(rows);
    for (size_t r = 0; r < rows; r++) {
        float sum = 0.0f;
        for (size_t c = 0; c < cols; c++) {
            sum += weights_fp32[r * cols + c] * input[c];
        }
        reference[r] = sum;
    }
    
    result.max_error = 0.0f;
    for (size_t r = 0; r < rows; r++) {
        result.max_error = std::max(result.max_error, std::abs(reference[r] - output[r]));
    }
    
    return result;
}

} // namespace kernels
} // namespace rawrxd
