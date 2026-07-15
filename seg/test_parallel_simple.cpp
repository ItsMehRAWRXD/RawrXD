// ============================================================================
// Simple Multi-threaded Transformer Test
// ============================================================================

#include "thread_pool.hpp"
#include <iostream>
#include <chrono>
#include <vector>
#include <cmath>

using namespace RawrXD::Inference;

// Simple matrix multiplication for benchmarking
void SimpleMatMul(const float* A, const float* B, float* C, 
                  uint32_t M, uint32_t K, uint32_t N) {
    for (uint32_t i = 0; i < M; i++) {
        for (uint32_t j = 0; j < N; j++) {
            float sum = 0.0f;
            for (uint32_t k = 0; k < K; k++) {
                sum += A[i * K + k] * B[k * N + j];
            }
            C[i * N + j] = sum;
        }
    }
}

// Parallel matrix multiplication using thread pool
void ParallelMatMul(const float* A, const float* B, float* C,
                    uint32_t M, uint32_t K, uint32_t N,
                    ThreadPool& pool, size_t num_threads) {
    // Split M dimension across threads
    size_t chunk_size = M / num_threads;
    size_t remainder = M % num_threads;
    
    std::vector<std::future<void>> futures;
    
    size_t current_row = 0;
    for (size_t t = 0; t < num_threads; t++) {
        size_t local_rows = chunk_size + (t < remainder ? 1 : 0);
        size_t start_row = current_row;
        current_row += local_rows;
        
        futures.push_back(pool.Submit([&, start_row, local_rows]() {
            for (uint32_t i = start_row; i < start_row + local_rows; i++) {
                for (uint32_t j = 0; j < N; j++) {
                    float sum = 0.0f;
                    for (uint32_t k = 0; k < K; k++) {
                        sum += A[i * K + k] * B[k * N + j];
                    }
                    C[i * N + j] = sum;
                }
            }
        }));
    }
    
    // Wait for all tasks
    for (auto& f : futures) {
        f.wait();
    }
}

int main() {
    std::cout << "========================================\n";
    std::cout << "Simple Parallel MatMul Test\n";
    std::cout << "========================================\n\n";
    
    // Test thread pool first
    std::cout << "Testing thread pool...\n";
    ThreadPool pool;
    pool.Initialize(4);
    std::cout << "Thread pool initialized with " << pool.GetNumThreads() << " threads\n\n";
    
    // Simple task test
    std::cout << "Testing simple task submission...\n";
    std::vector<std::future<int>> futures;
    for (int i = 0; i < 4; i++) {
        futures.push_back(pool.Submit([i]() { return i * i; }));
    }
    std::cout << "Results: ";
    for (auto& f : futures) {
        std::cout << f.get() << " ";
    }
    std::cout << "\n\n";
    
    // Matrix sizes for benchmarking
    uint32_t M = 512, K = 512, N = 512;
    
    std::cout << "Matrix multiplication benchmark:\n";
    std::cout << "  Matrix A: " << M << "x" << K << "\n";
    std::cout << "  Matrix B: " << K << "x" << N << "\n";
    std::cout << "  Matrix C: " << M << "x" << N << "\n\n";
    
    // Allocate matrices
    std::vector<float> A(M * K, 0.001f);
    std::vector<float> B(K * N, 0.001f);
    std::vector<float> C(M * N, 0.0f);
    
    // Sequential benchmark
    std::cout << "Sequential MatMul...\n";
    auto start = std::chrono::high_resolution_clock::now();
    for (int iter = 0; iter < 10; iter++) {
        SimpleMatMul(A.data(), B.data(), C.data(), M, K, N);
    }
    auto end = std::chrono::high_resolution_clock::now();
    auto seq_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    std::cout << "  Time: " << seq_time << " ms (10 iterations)\n\n";
    
    // Parallel benchmark with different thread counts
    std::vector<size_t> thread_counts = {1, 2, 4, 8, 16};
    
    for (size_t tc : thread_counts) {
        if (tc > ThreadPool::HardwareConcurrency()) continue;
        
        pool.Shutdown();
        pool.Initialize(tc);
        
        // Warmup
        for (int i = 0; i < 2; i++) {
            ParallelMatMul(A.data(), B.data(), C.data(), M, K, N, pool, tc);
        }
        
        // Benchmark
        start = std::chrono::high_resolution_clock::now();
        for (int iter = 0; iter < 10; iter++) {
            ParallelMatMul(A.data(), B.data(), C.data(), M, K, N, pool, tc);
        }
        end = std::chrono::high_resolution_clock::now();
        auto par_time = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
        
        float speedup = static_cast<float>(seq_time) / par_time;
        std::cout << tc << " threads: " << par_time << " ms, speedup: " << speedup << "x\n";
    }
    
    std::cout << "\nDone!\n";
    return 0;
}
