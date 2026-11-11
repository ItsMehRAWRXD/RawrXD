// ============================================================================
// Parallel GEMM with Thread Pool Implementation
// ============================================================================

#include "parallel_gemm.hpp"
#include "quantized_matmul_fast.hpp"
#include "int8_gemm.hpp"
#include <immintrin.h>
#include <algorithm>

namespace SEG {

// ThreadPool implementation
ThreadPool::ThreadPool(size_t num_threads) : num_threads_(num_threads) {
    for (size_t i = 0; i < num_threads; ++i) {
        workers_.emplace_back([this] {
            while (true) {
                std::function<void()> task;
                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    condition_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                    if (stop_ && tasks_.empty()) return;
                    task = std::move(tasks_.front());
                    tasks_.pop();
                    active_tasks_++;
                }
                task();
                {
                    std::unique_lock<std::mutex> lock(queue_mutex_);
                    active_tasks_--;
                    if (active_tasks_ == 0 && tasks_.empty()) {
                        finished_.notify_all();
                    }
                }
            }
        });
    }
}

ThreadPool::~ThreadPool() {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        stop_ = true;
    }
    condition_.notify_all();
    for (std::thread& worker : workers_) {
        worker.join();
    }
}

void ThreadPool::Submit(std::function<void()> task) {
    {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        tasks_.push(std::move(task));
    }
    condition_.notify_one();
}

void ThreadPool::WaitForAll() {
    std::unique_lock<std::mutex> lock(queue_mutex_);
    finished_.wait(lock, [this] { return active_tasks_ == 0 && tasks_.empty(); });
}

// Get optimal thread count
size_t GetOptimalThreadCount() {
    return std::thread::hardware_concurrency();
}

// Parallel FP32 vector-matrix multiplication
void ParallelVecMatMul(const float* input, const float* weights,
                       float* output, size_t N, size_t K,
                       ThreadPool& pool) {
    const size_t num_threads = pool.GetNumThreads();
    const size_t chunk_size = (N + num_threads - 1) / num_threads;
    
    for (size_t t = 0; t < num_threads; ++t) {
        size_t start_n = t * chunk_size;
        size_t end_n = std::min(start_n + chunk_size, N);
        
        if (start_n >= end_n) break;
        
        pool.Submit([=]() {
            // Process this chunk
            for (size_t n = start_n; n < end_n; n++) {
                __m512 sum_vec0 = _mm512_setzero_ps();
                __m512 sum_vec1 = _mm512_setzero_ps();
                __m512 sum_vec2 = _mm512_setzero_ps();
                __m512 sum_vec3 = _mm512_setzero_ps();
                const float* weight_row = weights + n * K;
                
                size_t k = 0;
                for (; k + 64 <= K; k += 64) {
                    __m512 input_vec0 = _mm512_loadu_ps(&input[k]);
                    __m512 input_vec1 = _mm512_loadu_ps(&input[k + 16]);
                    __m512 input_vec2 = _mm512_loadu_ps(&input[k + 32]);
                    __m512 input_vec3 = _mm512_loadu_ps(&input[k + 48]);
                    __m512 weight_vec0 = _mm512_loadu_ps(&weight_row[k]);
                    __m512 weight_vec1 = _mm512_loadu_ps(&weight_row[k + 16]);
                    __m512 weight_vec2 = _mm512_loadu_ps(&weight_row[k + 32]);
                    __m512 weight_vec3 = _mm512_loadu_ps(&weight_row[k + 48]);
                    
                    sum_vec0 = _mm512_fmadd_ps(input_vec0, weight_vec0, sum_vec0);
                    sum_vec1 = _mm512_fmadd_ps(input_vec1, weight_vec1, sum_vec1);
                    sum_vec2 = _mm512_fmadd_ps(input_vec2, weight_vec2, sum_vec2);
                    sum_vec3 = _mm512_fmadd_ps(input_vec3, weight_vec3, sum_vec3);
                }
                
                __m512 sum_vec = _mm512_add_ps(_mm512_add_ps(sum_vec0, sum_vec1),
                                               _mm512_add_ps(sum_vec2, sum_vec3));
                
                for (; k + 16 <= K; k += 16) {
                    __m512 input_vec = _mm512_loadu_ps(&input[k]);
                    __m512 weight_vec = _mm512_loadu_ps(&weight_row[k]);
                    sum_vec = _mm512_fmadd_ps(input_vec, weight_vec, sum_vec);
                }
                
                float sum = _mm512_reduce_add_ps(sum_vec);
                for (; k < K; k++) {
                    sum += input[k] * weight_row[k];
                }
                output[n] = sum;
            }
        });
    }
    
    pool.WaitForAll();
}

// Parallel INT8 vector-matrix multiplication
void ParallelInt8VecMatMul(const float* input, const Q8Matrix& weights,
                           float* output, ThreadPool& pool) {
    const size_t N = weights.N;
    const size_t K = weights.K;
    const size_t num_blocks = weights.num_blocks;
    const size_t num_threads = pool.GetNumThreads();
    const size_t chunk_size = (N + num_threads - 1) / num_threads;
    
    for (size_t t = 0; t < num_threads; ++t) {
        size_t start_n = t * chunk_size;
        size_t end_n = std::min(start_n + chunk_size, N);
        
        if (start_n >= end_n) break;
        
        pool.Submit([=, &weights]() {
            for (size_t n = start_n; n < end_n; n++) {
                __m512 sum_vec = _mm512_setzero_ps();
                
                for (size_t block_idx = 0; block_idx < num_blocks; block_idx++) {
                    const Q8_128_Block& block = *weights.GetBlock(n, block_idx);
                    const float* input_block = input + block_idx * 128;
                    __m512 scale_vec = _mm512_set1_ps(block.d);
                    __m512 block_sum = _mm512_setzero_ps();
                    
                    size_t k = 0;
                    for (; k + 16 <= 128; k += 16) {
                        __m512 input_vec = _mm512_loadu_ps(&input_block[k]);
                        __m128i weight_i8 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(&block.qs[k]));
                        __m512i weight_i32 = _mm512_cvtepi8_epi32(weight_i8);
                        __m512 weight_vec = _mm512_cvtepi32_ps(weight_i32);
                        weight_vec = _mm512_mul_ps(weight_vec, scale_vec);
                        block_sum = _mm512_fmadd_ps(input_vec, weight_vec, block_sum);
                    }
                    
                    sum_vec = _mm512_add_ps(sum_vec, block_sum);
                    
                    for (; k < 128; k++) {
                        sum_vec = _mm512_add_ps(sum_vec, _mm512_set1_ps(input_block[k] * (block.qs[k] * block.d)));
                    }
                }
                
                output[n] = _mm512_reduce_add_ps(sum_vec);
            }
        });
    }
    
    pool.WaitForAll();
}

} // namespace SEG
