// ============================================================================
// Standalone Benchmark - With Quantized Inference
// ============================================================================

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cmath>
#include <thread>
#include <immintrin.h>
#include <cpuid.h>
#include <cstring>

// ============================================================================
// Quantized Inference (Embedded for Standalone)
// ============================================================================

namespace quantized {

// Q4_0 Block: 18 bytes for 32 weights
struct Q4_0Block {
    uint16_t scale_f16;
    uint8_t quants[16];  // 32 nibbles packed
};

// Q8_0 Block: 34 bytes for 32 weights  
struct Q8_0Block {
    uint16_t scale_f16;
    int8_t quants[32];
};

constexpr size_t Q4_0_BLOCK_SIZE = 32;
constexpr size_t Q8_0_BLOCK_SIZE = 32;

// F16 to F32 conversion
float F16ToF32(uint16_t f16) {
    uint32_t sign = (f16 >> 15) & 0x1;
    uint32_t exp = (f16 >> 10) & 0x1F;
    uint32_t mant = f16 & 0x3FF;
    
    if (exp == 0) {
        if (mant == 0) return sign ? -0.0f : 0.0f;
        float val = mant / 1024.0f;
        return (sign ? -1.0f : 1.0f) * val * std::pow(2.0f, -14);
    }
    if (exp == 31) {
        if (mant == 0) return sign ? -INFINITY : INFINITY;
        return NAN;
    }
    
    float val = 1.0f + mant / 1024.0f;
    int32_t exp32 = exp - 15 + 127;
    uint32_t f32 = (sign << 31) | (exp32 << 23) | (mant << 13);
    float result;
    std::memcpy(&result, &f32, sizeof(result));
    return result;
}

// Quantize F32 to Q4_0
void QuantizeF32ToQ4_0(const float* input, size_t num_elements, std::vector<uint8_t>& output) {
    size_t num_blocks = (num_elements + Q4_0_BLOCK_SIZE - 1) / Q4_0_BLOCK_SIZE;
    output.resize(num_blocks * sizeof(Q4_0Block));
    Q4_0Block* blocks = reinterpret_cast<Q4_0Block*>(output.data());
    
    for (size_t b = 0; b < num_blocks; b++) {
        float max_abs = 0.0f;
        size_t start = b * Q4_0_BLOCK_SIZE;
        size_t end = std::min(start + Q4_0_BLOCK_SIZE, num_elements);
        
        for (size_t i = start; i < end; i++) {
            max_abs = std::max(max_abs, std::abs(input[i]));
        }
        
        float scale = (max_abs > 0.0f) ? (max_abs / 7.0f) : 1.0f;
        
        // Convert scale to F16 (simplified)
        uint32_t scale_f32;
        std::memcpy(&scale_f32, &scale, sizeof(scale));
        uint32_t sign = (scale_f32 >> 31) & 0x1;
        uint32_t exp = (scale_f32 >> 23) & 0xFF;
        uint32_t mant = scale_f32 & 0x7FFFFF;
        uint32_t exp16 = (exp - 127 + 15) & 0x1F;
        uint32_t mant16 = mant >> 13;
        blocks[b].scale_f16 = static_cast<uint16_t>((sign << 15) | (exp16 << 10) | mant16);
        
        for (size_t i = start; i < end; i += 2) {
            int8_t nibble0 = static_cast<int8_t>(std::round(input[i] / scale)) + 8;
            int8_t nibble1 = (i + 1 < end) ? 
                static_cast<int8_t>(std::round(input[i + 1] / scale)) + 8 : 8;
            blocks[b].quants[(i - start) / 2] = 
                (static_cast<uint8_t>(nibble0) & 0x0F) | 
                ((static_cast<uint8_t>(nibble1) & 0x0F) << 4);
        }
    }
}

// Quantized MatMul Q4_0
void MatMulQ4_0(const uint8_t* weight_data, const float* input, float* output,
                size_t batch_size, size_t input_dim, size_t output_dim) {
    const Q4_0Block* blocks = reinterpret_cast<const Q4_0Block*>(weight_data);
    size_t num_blocks_per_row = (input_dim + Q4_0_BLOCK_SIZE - 1) / Q4_0_BLOCK_SIZE;
    
    for (size_t b = 0; b < batch_size; b++) {
        const float* in_batch = input + b * input_dim;
        float* out_batch = output + b * output_dim;
        
        for (size_t o = 0; o < output_dim; o++) {
            float sum = 0.0f;
            
            for (size_t i = 0; i < input_dim; i++) {
                size_t block_idx = (o * input_dim + i) / Q4_0_BLOCK_SIZE;
                size_t idx_in_block = (o * input_dim + i) % Q4_0_BLOCK_SIZE;
                
                float scale = F16ToF32(blocks[block_idx].scale_f16);
                uint8_t byte = blocks[block_idx].quants[idx_in_block / 2];
                int8_t nibble = (idx_in_block % 2 == 0) ? 
                    (byte & 0x0F) - 8 : ((byte >> 4) & 0x0F) - 8;
                
                sum += in_batch[i] * (nibble * scale);
            }
            out_batch[o] = sum;
        }
    }
}

} // namespace quantized

// Simple CPU detection
struct CPUInfo {
    bool has_avx512 = false;
    bool has_avx2 = false;
    bool has_fma = false;
    int cores = 0;
};

CPUInfo DetectCPU() {
    CPUInfo info;
    info.cores = std::thread::hardware_concurrency();
    
    // Check CPU features using CPUID
    unsigned int eax, ebx, ecx, edx;
    
    __get_cpuid(1, &eax, &ebx, &ecx, &edx);
    info.has_avx2 = (ecx & (1 << 28)) != 0;  // AVX bit
    info.has_fma = (ecx & (1 << 12)) != 0;   // FMA bit
    
    __get_cpuid_count(7, 0, &eax, &ebx, &ecx, &edx);
    info.has_avx512 = (ebx & (1 << 16)) != 0;  // AVX512F bit
    
    return info;
}

// Scalar MatMul for benchmarking
double BenchmarkMatMulScalar(size_t M, size_t N, size_t K) {
    std::vector<float> A(M * K, 0.01f);
    std::vector<float> B(K * N, 0.01f);
    std::vector<float> C(M * N, 0.0f);
    
    // Warmup
    for (size_t i = 0; i < M; ++i) {
        for (size_t j = 0; j < N; ++j) {
            float sum = 0.0f;
            for (size_t k = 0; k < K; ++k) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
    
    // Timed run
    auto start = std::chrono::high_resolution_clock::now();
    const int iterations = 10;
    
    for (int iter = 0; iter < iterations; ++iter) {
        for (size_t i = 0; i < M; ++i) {
            for (size_t j = 0; j < N; ++j) {
                float sum = 0.0f;
                for (size_t k = 0; k < K; ++k) {
                    sum += A[i * K + k] * B[k * N + j];
                }
                C[i * N + j] = sum;
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0 / iterations;
    
    // Calculate GFLOPS
    double flops = 2.0 * M * N * K;
    double gflops = flops / (time_ms * 1e6);
    
    return gflops;
}

// AVX-512 MatMul for benchmarking
double BenchmarkMatMulAVX512(size_t M, size_t N, size_t K) {
    std::vector<float> A(M * K, 0.01f);
    std::vector<float> B(K * N, 0.01f);
    std::vector<float> C(M * N, 0.0f);
    
    const size_t simd_width = 16;  // 512 bits / 32 bits per float
    
    // Warmup
    for (size_t i = 0; i < M; ++i) {
        for (size_t j = 0; j < N; ++j) {
            __m512 sum_vec = _mm512_setzero_ps();
            size_t k = 0;
            
            // Process 16 elements at a time
            for (; k + simd_width <= K; k += simd_width) {
                __m512 a_vec = _mm512_loadu_ps(&A[i * K + k]);
                // Load B values - need to gather since B is column-major access
                float b_vals[16];
                for (size_t kk = 0; kk < simd_width; ++kk) {
                    b_vals[kk] = B[(k + kk) * N + j];
                }
                __m512 b_vec = _mm512_loadu_ps(b_vals);
                sum_vec = _mm512_fmadd_ps(a_vec, b_vec, sum_vec);
            }
            
            // Horizontal sum
            float sum = _mm512_reduce_add_ps(sum_vec);
            
            // Handle remaining elements
            for (; k < K; ++k) {
                sum += A[i * K + k] * B[k * N + j];
            }
            
            C[i * N + j] = sum;
        }
    }
    
    // Timed run
    auto start = std::chrono::high_resolution_clock::now();
    const int iterations = 10;
    
    for (int iter = 0; iter < iterations; ++iter) {
        for (size_t i = 0; i < M; ++i) {
            for (size_t j = 0; j < N; ++j) {
                __m512 sum_vec = _mm512_setzero_ps();
                size_t k = 0;
                
                for (; k + simd_width <= K; k += simd_width) {
                    __m512 a_vec = _mm512_loadu_ps(&A[i * K + k]);
                    float b_vals[16];
                    for (size_t kk = 0; kk < simd_width; ++kk) {
                        b_vals[kk] = B[(k + kk) * N + j];
                    }
                    __m512 b_vec = _mm512_loadu_ps(b_vals);
                    sum_vec = _mm512_fmadd_ps(a_vec, b_vec, sum_vec);
                }
                
                float sum = _mm512_reduce_add_ps(sum_vec);
                
                for (; k < K; ++k) {
                    sum += A[i * K + k] * B[k * N + j];
                }
                
                C[i * N + j] = sum;
            }
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0 / iterations;
    
    // Calculate GFLOPS
    double flops = 2.0 * M * N * K;
    double gflops = flops / (time_ms * 1e6);
    
    return gflops;
}

// Simple MatMul wrapper
double BenchmarkMatMul(size_t M, size_t N, size_t K, bool use_avx512 = false) {
    if (use_avx512) {
        return BenchmarkMatMulAVX512(M, N, K);
    }
    return BenchmarkMatMulScalar(M, N, K);
}

// ============================================================================
// Quantized MatMul Benchmark
// ============================================================================

double BenchmarkQuantizedMatMul(size_t M, size_t N, size_t K) {
    using namespace quantized;
    
    // Create and quantize weights
    std::vector<float> B(K * N, 0.01f);
    std::vector<uint8_t> B_quantized;
    QuantizeF32ToQ4_0(B.data(), B.size(), B_quantized);
    
    std::vector<float> A(M * K, 0.01f);
    std::vector<float> C(M * N, 0.0f);
    
    // Warmup
    MatMulQ4_0(B_quantized.data(), A.data(), C.data(), M, K, N);
    
    // Timed run
    auto start = std::chrono::high_resolution_clock::now();
    const int iterations = 10;
    
    for (int iter = 0; iter < iterations; ++iter) {
        MatMulQ4_0(B_quantized.data(), A.data(), C.data(), M, K, N);
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0 / iterations;
    
    // Calculate GFLOPS (same flops as regular MatMul)
    double flops = 2.0 * M * N * K;
    double gflops = flops / (time_ms * 1e6);
    
    return gflops;
}

// Memory bandwidth benchmark
double BenchmarkMemoryBandwidth() {
    const size_t size = 1024 * 1024 * 100;  // 100 MB
    std::vector<float> src(size);
    std::vector<float> dst(size);
    
    // Initialize
    for (size_t i = 0; i < size; i++) {
        src[i] = static_cast<float>(i);
    }
    
    // Warmup
    std::memcpy(dst.data(), src.data(), size * sizeof(float));
    
    // Timed run
    auto start = std::chrono::high_resolution_clock::now();
    const int iterations = 10;
    
    for (int iter = 0; iter < iterations; ++iter) {
        std::memcpy(dst.data(), src.data(), size * sizeof(float));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double time_ms = duration.count() / 1000.0 / iterations;
    
    // Calculate GB/s
    double bytes = size * sizeof(float);
    double gbps = (bytes / (1024.0 * 1024 * 1024)) / (time_ms / 1000.0);
    
    return gbps;
}

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrXD Standalone Benchmark\n";
    std::cout << "========================================\n\n";
    
    // Detect CPU
    CPUInfo cpu = DetectCPU();
    std::cout << "CPU Features:\n";
    std::cout << "  Cores: " << cpu.cores << "\n";
    std::cout << "  AVX512: " << (cpu.has_avx512 ? "Yes" : "No") << "\n";
    std::cout << "  AVX2: " << (cpu.has_avx2 ? "Yes" : "No") << "\n";
    std::cout << "  FMA: " << (cpu.has_fma ? "Yes" : "No") << "\n\n";
    
    // Calculate theoretical max
    double theoretical_max = cpu.has_avx512 ? 3072.0 : (cpu.has_avx2 ? 1536.0 : 384.0);
    std::cout << "Theoretical Max: " << theoretical_max << " GFLOPS\n\n";
    
    // Run benchmarks
    std::cout << "Running MatMul benchmarks...\n";
    
    struct Config {
        size_t M, N, K;
        const char* name;
    };
    
    Config configs[] = {
        {512, 512, 512, "512x512x512"},
        {1024, 1024, 1024, "1024x1024x1024"},
        {4096, 4096, 4096, "4096x4096x4096"}
    };
    
    double best_gflops_scalar = 0.0;
    double best_gflops_avx512 = 0.0;
    double best_gflops_quantized = 0.0;
    
    std::cout << "\nScalar (baseline):\n";
    for (const auto& cfg : configs) {
        double gflops = BenchmarkMatMul(cfg.M, cfg.N, cfg.K, false);
        double efficiency = (gflops / theoretical_max) * 100.0;
        
        std::cout << "  " << cfg.name << ": " 
                  << std::fixed << std::setprecision(1) << gflops << " GFLOPS"
                  << " (" << std::setprecision(1) << efficiency << "% efficiency)\n";
        
        if (gflops > best_gflops_scalar) best_gflops_scalar = gflops;
    }
    
    if (cpu.has_avx512) {
        std::cout << "\nAVX-512:\n";
        for (const auto& cfg : configs) {
            double gflops = BenchmarkMatMul(cfg.M, cfg.N, cfg.K, true);
            double efficiency = (gflops / theoretical_max) * 100.0;
            
            std::cout << "  " << cfg.name << ": " 
                      << std::fixed << std::setprecision(1) << gflops << " GFLOPS"
                      << " (" << std::setprecision(1) << efficiency << "% efficiency)\n";
            
            if (gflops > best_gflops_avx512) best_gflops_avx512 = gflops;
        }
    }
    
    // Quantized benchmark
    std::cout << "\nQ4_0 Quantized:\n";
    for (const auto& cfg : configs) {
        double gflops = BenchmarkQuantizedMatMul(cfg.M, cfg.N, cfg.K);
        double efficiency = (gflops / theoretical_max) * 100.0;
        
        std::cout << "  " << cfg.name << ": " 
                  << std::fixed << std::setprecision(1) << gflops << " GFLOPS"
                  << " (" << std::setprecision(1) << efficiency << "% efficiency)\n";
        
        if (gflops > best_gflops_quantized) best_gflops_quantized = gflops;
    }
    
    // Memory bandwidth
    std::cout << "\nMemory Bandwidth:\n";
    double mem_bw = BenchmarkMemoryBandwidth();
    std::cout << "  " << std::fixed << std::setprecision(1) << mem_bw << " GB/s\n";
    
    // Analysis
    double overall_efficiency_scalar = (best_gflops_scalar / theoretical_max) * 100.0;
    
    std::cout << "\n========================================\n";
    std::cout << "Analysis\n";
    std::cout << "========================================\n";
    std::cout << "Scalar Best: " << std::setprecision(1) << best_gflops_scalar << " GFLOPS (" 
              << std::setprecision(1) << overall_efficiency_scalar << "% efficiency)\n";
    
    if (cpu.has_avx512 && best_gflops_avx512 > 0) {
        double overall_efficiency_avx512 = (best_gflops_avx512 / theoretical_max) * 100.0;
        double speedup = best_gflops_avx512 / best_gflops_scalar;
        std::cout << "AVX-512 Best: " << std::setprecision(1) << best_gflops_avx512 << " GFLOPS (" 
                  << std::setprecision(1) << overall_efficiency_avx512 << "% efficiency)\n";
        std::cout << "Speedup: " << std::setprecision(1) << speedup << "x\n\n";
        
        if (speedup < 2.0) {
            std::cout << "=> AVX-512 underperforming - memory bandwidth bound\n";
            std::cout << "=> Recommendation: Implement Q4_0/Q8_0 quantization\n";
            std::cout << "=> Expected gain: 2-4x additional speedup\n";
        } else if (speedup < 8.0) {
            std::cout << "=> Moderate AVX-512 utilization\n";
            std::cout << "=> Recommendation: Optimize memory access patterns\n";
        } else {
            std::cout << "=> Good AVX-512 utilization\n";
            std::cout << "=> Recommendation: Consider multi-threading\n";
        }
    } else if (overall_efficiency_scalar < 30.0) {
        std::cout << "\n=> Memory bandwidth bound\n";
        std::cout << "=> Recommendation: Implement Q4_0/Q8_0 quantization\n";
        std::cout << "=> Expected gain: 2-4x speedup\n";
    } else if (overall_efficiency_scalar < 60.0) {
        std::cout << "\n=> Partially compute bound\n";
        std::cout << "=> Recommendation: Enable multi-threading across heads\n";
        std::cout << "=> Expected gain: 1.5-2x speedup\n";
    } else {
        std::cout << "\n=> Well optimized\n";
        std::cout << "=> Recommendation: Consider batching for higher throughput\n";
    }
    
    std::cout << "\n========================================\n";
    
    return 0;
}
