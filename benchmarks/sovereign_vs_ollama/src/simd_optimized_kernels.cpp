// simd_optimized_kernels.cpp
// Batch 9: SIMD-Optimized Statistical Kernels
//
// Provides AVX2/AVX-512 optimized implementations of:
// - Sum/Mean calculation
// - Variance/StdDev calculation
// - Min/Max finding
// - Percentile calculation

#include <cstddef>
#include <cstdint>
#include <vector>
#include <algorithm>
#include <cmath>

// SIMD intrinsics
#if defined(__AVX512F__)
    #include <immintrin.h>
    #define HAS_AVX512 1
#elif defined(__AVX2__)
    #include <immintrin.h>
    #define HAS_AVX2 1
#elif defined(__SSE4_2__)
    #include <nmmintrin.h>
    #define HAS_SSE42 1
#endif

namespace Benchmark {
namespace Performance {

// Feature detection
struct SIMDFeatures {
    static bool HasAVX512() {
        #if defined(HAS_AVX512)
        return true;
        #else
        return false;
        #endif
    }
    
    static bool HasAVX2() {
        #if defined(HAS_AVX2)
        return true;
        #else
        return false;
        #endif
    }
    
    static bool HasSSE42() {
        #if defined(HAS_SSE42)
        return true;
        #else
        return false;
        #endif
    }
};

// Optimized sum calculation
inline double SumOptimized(const double* data, size_t count) {
    if (count == 0) return 0.0;
    
    double sum = 0.0;
    size_t i = 0;
    
    #if defined(HAS_AVX512)
    // AVX-512: Process 8 doubles at a time
    __m512d vec_sum = _mm512_setzero_pd();
    
    for (; i + 8 <= count; i += 8) {
        __m512d vec = _mm512_loadu_pd(data + i);
        vec_sum = _mm512_add_pd(vec_sum, vec);
    }
    
    // Horizontal sum
    sum = _mm512_reduce_add_pd(vec_sum);
    
    #elif defined(HAS_AVX2)
    // AVX2: Process 4 doubles at a time
    __m256d vec_sum = _mm256_setzero_pd();
    
    for (; i + 4 <= count; i += 4) {
        __m256d vec = _mm256_loadu_pd(data + i);
        vec_sum = _mm256_add_pd(vec_sum, vec);
    }
    
    // Horizontal sum
    __m256d hsum = _mm256_hadd_pd(vec_sum, vec_sum);
    __m128d sum_low = _mm256_castpd256_pd128(hsum);
    __m128d sum_high = _mm256_extractf128_pd(hsum, 1);
    __m128d result = _mm_add_pd(sum_low, sum_high);
    sum = _mm_cvtsd_f64(result);
    
    #elif defined(HAS_SSE42)
    // SSE4.2: Process 2 doubles at a time
    __m128d vec_sum = _mm_setzero_pd();
    
    for (; i + 2 <= count; i += 2) {
        __m128d vec = _mm_loadu_pd(data + i);
        vec_sum = _mm_add_pd(vec_sum, vec);
    }
    
    sum = _mm_cvtsd_f64(vec_sum) + _mm_cvtsd_f64(_mm_unpackhi_pd(vec_sum, vec_sum));
    #endif
    
    // Scalar remainder
    for (; i < count; ++i) {
        sum += data[i];
    }
    
    return sum;
}

// Optimized mean and variance calculation (single pass)
inline void MeanAndVarianceOptimized(const double* data, size_t count, 
                                    double& mean, double& variance) {
    if (count == 0) {
        mean = 0.0;
        variance = 0.0;
        return;
    }
    
    // Use Welford's online algorithm for numerical stability
    double m = 0.0;
    double s = 0.0;
    
    for (size_t i = 0; i < count; ++i) {
        double x = data[i];
        double delta = x - m;
        m += delta / static_cast<double>(i + 1);
        double delta2 = x - m;
        s += delta * delta2;
    }
    
    mean = m;
    variance = (count > 1) ? s / static_cast<double>(count) : 0.0;
}

// Optimized min/max finding
inline void MinMaxOptimized(const double* data, size_t count, 
                           double& min_val, double& max_val) {
    if (count == 0) {
        min_val = max_val = 0.0;
        return;
    }
    
    min_val = max_val = data[0];
    size_t i = 1;
    
    #if defined(HAS_AVX2)
    // AVX2: Process 4 doubles at a time
    if (count >= 4) {
        __m256d vec_min = _mm256_set1_pd(data[0]);
        __m256d vec_max = _mm256_set1_pd(data[0]);
        
        for (; i + 4 <= count; i += 4) {
            __m256d vec = _mm256_loadu_pd(data + i);
            vec_min = _mm256_min_pd(vec_min, vec);
            vec_max = _mm256_max_pd(vec_max, vec);
        }
        
        // Extract min/max
        double mins[4], maxs[4];
        _mm256_storeu_pd(mins, vec_min);
        _mm256_storeu_pd(maxs, vec_max);
        
        for (int j = 0; j < 4; ++j) {
            if (mins[j] < min_val) min_val = mins[j];
            if (maxs[j] > max_val) max_val = maxs[j];
        }
    }
    #endif
    
    // Scalar remainder
    for (; i < count; ++i) {
        if (data[i] < min_val) min_val = data[i];
        if (data[i] > max_val) max_val = data[i];
    }
}

// Fast percentile approximation using histogram
class FastPercentileCalculator {
public:
    explicit FastPercentileCalculator(size_t num_bins = 1000)
        : num_bins_(num_bins) {}
    
    void Compute(const std::vector<double>& data, 
                 std::vector<double>& percentiles) {
        if (data.empty()) {
            percentiles.assign(percentiles.size(), 0.0);
            return;
        }
        
        // Find min/max
        double min_val = *std::min_element(data.begin(), data.end());
        double max_val = *std::max_element(data.begin(), data.end());
        
        if (min_val == max_val) {
            percentiles.assign(percentiles.size(), min_val);
            return;
        }
        
        // Build histogram
        std::vector<size_t> histogram(num_bins_, 0);
        double bin_width = (max_val - min_val) / num_bins_;
        
        for (double value : data) {
            size_t bin = static_cast<size_t>((value - min_val) / bin_width);
            if (bin >= num_bins_) bin = num_bins_ - 1;
            ++histogram[bin];
        }
        
        // Compute cumulative distribution
        std::vector<double> cdf(num_bins_);
        size_t cumulative = 0;
        for (size_t i = 0; i < num_bins_; ++i) {
            cumulative += histogram[i];
            cdf[i] = static_cast<double>(cumulative) / data.size();
        }
        
        // Find percentiles
        for (size_t p = 0; p < percentiles.size(); ++p) {
            double target = static_cast<double>(p) / (percentiles.size() - 1);
            
            // Find bin containing this percentile
            size_t bin = 0;
            for (; bin < num_bins_; ++bin) {
                if (cdf[bin] >= target) break;
            }
            
            // Linear interpolation within bin
            double bin_start = min_val + bin * bin_width;
            double prev_cdf = (bin > 0) ? cdf[bin - 1] : 0.0;
            double frac = (target - prev_cdf) / (cdf[bin] - prev_cdf);
            
            percentiles[p] = bin_start + frac * bin_width;
        }
    }
    
private:
    size_t num_bins_;
};

// Parallel reduction for large datasets
inline double ParallelSum(const std::vector<double>& data) {
    if (data.empty()) return 0.0;
    
    double sum = 0.0;
    
    #pragma omp parallel for reduction(+:sum)
    for (size_t i = 0; i < data.size(); ++i) {
        sum += data[i];
    }
    
    return sum;
}

// Cache-optimized sort for percentile calculation
inline void CacheOptimizedSort(std::vector<double>& data) {
    // Use introsort (std::sort) which is cache-friendly
    std::sort(data.begin(), data.end());
}

// SIMD-optimized memory copy
inline void FastCopy(double* dst, const double* src, size_t count) {
    size_t i = 0;
    
    #if defined(HAS_AVX512)
    for (; i + 8 <= count; i += 8) {
        _mm512_storeu_pd(dst + i, _mm512_loadu_pd(src + i));
    }
    #elif defined(HAS_AVX2)
    for (; i + 4 <= count; i += 4) {
        _mm256_storeu_pd(dst + i, _mm256_loadu_pd(src + i));
    }
    #elif defined(HAS_SSE42)
    for (; i + 2 <= count; i += 2) {
        _mm_storeu_pd(dst + i, _mm_loadu_pd(src + i));
    }
    #endif
    
    // Remainder
    for (; i < count; ++i) {
        dst[i] = src[i];
    }
}

// Benchmark the SIMD kernels
struct SIMDBenchmarkResult {
    double scalar_time_ms;
    double simd_time_ms;
    double speedup;
};

inline SIMDBenchmarkResult BenchmarkSIMDSum(const std::vector<double>& data) {
    SIMDBenchmarkResult result;
    
    // Scalar sum
    auto start = std::chrono::high_resolution_clock::now();
    double scalar_sum = 0.0;
    for (size_t i = 0; i < data.size(); ++i) {
        scalar_sum += data[i];
    }
    auto end = std::chrono::high_resolution_clock::now();
    result.scalar_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // SIMD sum
    start = std::chrono::high_resolution_clock::now();
    double simd_sum = SumOptimized(data.data(), data.size());
    end = std::chrono::high_resolution_clock::now();
    result.simd_time_ms = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Verify correctness
    if (std::abs(scalar_sum - simd_sum) > 1e-6) {
        result.speedup = -1.0; // Error
    } else {
        result.speedup = result.scalar_time_ms / result.simd_time_ms;
    }
    
    return result;
}

} // namespace Performance
} // namespace Benchmark
