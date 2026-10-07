/**
 * @file quick_profile.cpp
 * @brief Quick Profiling Tool for RawrXD Components
 *
 * Standalone benchmark that measures key operations without
 * requiring full model loading.
 *
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <cmath>
#include <cstring>
#include <algorithm>
#include <numeric>
#include <immintrin.h>

// Simple profiling timer
class Timer {
public:
    void Start() {
        start_ = std::chrono::high_resolution_clock::now();
    }
    
    double End() {
        auto end = std::chrono::high_resolution_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start_);
        return duration.count() / 1000.0;  // Return milliseconds
    }
    
private:
    std::chrono::high_resolution_clock::time_point start_;
};

// ============================================================================
// Component Benchmarks
// ============================================================================

// 1. Embedding Lookup
double BenchmarkEmbedding(uint32_t vocab_size, uint32_t hidden_size, uint32_t seq_len) {
    // Simulate embedding table
    std::vector<float> embeddings(vocab_size * hidden_size);
    for (auto& e : embeddings) {
        e = static_cast<float>(rand()) / RAND_MAX * 0.02f - 0.01f;
    }
    
    // Simulate token IDs
    std::vector<uint32_t> token_ids(seq_len);
    for (auto& id : token_ids) {
        id = rand() % vocab_size;
    }
    
    Timer timer;
    std::vector<float> output(seq_len * hidden_size);
    
    const int iterations = 100;
    timer.Start();
    
    for (int iter = 0; iter < iterations; ++iter) {
        for (uint32_t s = 0; s < seq_len; ++s) {
            uint32_t id = token_ids[s];
            std::memcpy(&output[s * hidden_size],
                     &embeddings[id * hidden_size],
                     hidden_size * sizeof(float));
        }
    }
    
    double total_ms = timer.End();
    return (total_ms / iterations);  // Time per lookup
}

// 2. RMSNorm
double BenchmarkRMSNorm(uint32_t hidden_size, uint32_t seq_len) {
    std::vector<float> input(seq_len * hidden_size);
    std::vector<float> weight(hidden_size, 1.0f);
    std::vector<float> output(seq_len * hidden_size);
    
    for (auto& i : input) {
        i = static_cast<float>(rand()) / RAND_MAX;
    }
    
    const float eps = 1e-6f;
    const int iterations = 1000;
    
    Timer timer;
    timer.Start();
    
    for (int iter = 0; iter < iterations; ++iter) {
        for (uint32_t s = 0; s < seq_len; ++s) {
            // Calculate RMS
            float sum_sq = 0.0f;
            for (uint32_t h = 0; h < hidden_size; ++h) {
                float v = input[s * hidden_size + h];
                sum_sq += v * v;
            }
            float rms = std::sqrt(sum_sq / hidden_size + eps);
            float scale = 1.0f / rms;
            
            // Apply
            for (uint32_t h = 0; h < hidden_size; ++h) {
                output[s * hidden_size + h] = input[s * hidden_size + h] * scale * weight[h];
            }
        }
    }
    
    double total_ms = timer.End();
    return (total_ms / iterations);
}

// 3. Matrix Multiplication (simulating attention/MLP)
double BenchmarkMatMul(uint32_t M, uint32_t N, uint32_t K) {
    std::vector<float> A(M * K, 0.01f);
    std::vector<float> B(K * N, 0.01f);
    std::vector<float> C(M * N, 0.0f);
    
    const int iterations = 100;
    
    Timer timer;
    timer.Start();
    
    for (int iter = 0; iter < iterations; ++iter) {
        for (uint32_t i = 0; i < M; ++i) {
            for (uint32_t k = 0; k < K; ++k) {
                float a_val = A[i * K + k];
                for (uint32_t j = 0; j < N; ++j) {
                    C[i * N + j] += a_val * B[k * N + j];
                }
            }
        }
    }
    
    double total_ms = timer.End();
    return (total_ms / iterations);
}

// 4. Attention Scores (Q @ K^T)
double BenchmarkAttentionScores(uint32_t seq_len, uint32_t head_dim) {
    std::vector<float> Q(seq_len * head_dim, 0.01f);
    std::vector<float> K(seq_len * head_dim, 0.01f);
    std::vector<float> scores(seq_len * seq_len, 0.0f);
    
    const int iterations = 100;
    float scale = 1.0f / std::sqrt(static_cast<float>(head_dim));
    
    Timer timer;
    timer.Start();
    
    for (int iter = 0; iter < iterations; ++iter) {
        for (uint32_t i = 0; i < seq_len; ++i) {
            for (uint32_t j = 0; j < seq_len; ++j) {
                float dot = 0.0f;
                for (uint32_t d = 0; d < head_dim; ++d) {
                    dot += Q[i * head_dim + d] * K[j * head_dim + d];
                }
                scores[i * seq_len + j] = dot * scale;
            }
        }
    }
    
    double total_ms = timer.End();
    return (total_ms / iterations);
}

// 5. Softmax
double BenchmarkSoftmax(uint32_t seq_len) {
    std::vector<float> scores(seq_len);
    for (auto& s : scores) {
        s = static_cast<float>(rand()) / RAND_MAX * 10.0f - 5.0f;
    }
    
    std::vector<float> probs(seq_len);
    const int iterations = 10000;
    
    Timer timer;
    timer.Start();
    
    for (int iter = 0; iter < iterations; ++iter) {
        float max_val = *std::max_element(scores.begin(), scores.end());
        
        float sum_exp = 0.0f;
        for (uint32_t i = 0; i < seq_len; ++i) {
            probs[i] = std::exp(scores[i] - max_val);
            sum_exp += probs[i];
        }
        
        for (uint32_t i = 0; i < seq_len; ++i) {
            probs[i] /= sum_exp;
        }
    }
    
    double total_ms = timer.End();
    return (total_ms / iterations);
}

// 6. SiLU Activation
double BenchmarkSiLU(uint32_t size) {
    std::vector<float> input(size);
    std::vector<float> output(size);
    
    for (auto& i : input) {
        i = static_cast<float>(rand()) / RAND_MAX * 4.0f - 2.0f;
    }
    
    const int iterations = 10000;
    
    Timer timer;
    timer.Start();
    
    for (int iter = 0; iter < iterations; ++iter) {
        for (uint32_t i = 0; i < size; ++i) {
            // SiLU(x) = x * sigmoid(x)
            output[i] = input[i] / (1.0f + std::exp(-input[i]));
        }
    }
    
    double total_ms = timer.End();
    return (total_ms / iterations);
}

// 7. Top-k Sampling
double BenchmarkTopKSampling(uint32_t vocab_size, uint32_t top_k) {
    std::vector<float> logits(vocab_size);
    for (auto& l : logits) {
        l = static_cast<float>(rand()) / RAND_MAX * 10.0f - 5.0f;
    }
    
    const int iterations = 10000;
    
    Timer timer;
    timer.Start();
    
    for (int iter = 0; iter < iterations; ++iter) {
        // Find top-k
        std::vector<std::pair<float, uint32_t>> indexed;
        for (uint32_t i = 0; i < vocab_size; ++i) {
            indexed.push_back({logits[i], i});
        }
        
        std::partial_sort(indexed.begin(),
                         indexed.begin() + std::min(top_k, vocab_size),
                         indexed.end(),
                         std::greater<std::pair<float, uint32_t>>());
        
        // Sample from top-k
        float sum = 0.0f;
        for (uint32_t i = 0; i < std::min(top_k, vocab_size); ++i) {
            sum += indexed[i].first;
        }
        
        float r = static_cast<float>(rand()) / RAND_MAX * sum;
        float cumsum = 0.0f;
        uint32_t selected = indexed[0].second;
        for (uint32_t i = 0; i < std::min(top_k, vocab_size); ++i) {
            cumsum += indexed[i].first;
            if (r <= cumsum) {
                selected = indexed[i].second;
                break;
            }
        }
    }
    
    double total_ms = timer.End();
    return (total_ms / iterations);
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "RawrXD Quick Profile Tool\n";
    std::cout << "========================================\n\n";
    
    // Model configuration (typical 7B model)
    uint32_t vocab_size = 32000;
    uint32_t hidden_size = 4096;
    uint32_t intermediate_size = 11008;
    uint32_t num_heads = 32;
    uint32_t num_layers = 32;
    uint32_t head_dim = hidden_size / num_heads;
    uint32_t seq_len = 128;
    
    std::cout << "Model Configuration:\n";
    std::cout << "  Vocab size: " << vocab_size << "\n";
    std::cout << "  Hidden size: " << hidden_size << "\n";
    std::cout << "  Intermediate size: " << intermediate_size << "\n";
    std::cout << "  Num heads: " << num_heads << "\n";
    std::cout << "  Num layers: " << num_layers << "\n";
    std::cout << "  Sequence length: " << seq_len << "\n\n";
    
    std::cout << "Running component benchmarks...\n\n";
    
    struct Result {
        const char* name;
        double time_ms;
        const char* unit;
    };
    
    std::vector<Result> results;
    
    // Run benchmarks
    std::cout << "1. Embedding lookup... " << std::flush;
    results.push_back({"Embedding Lookup",
        BenchmarkEmbedding(vocab_size, hidden_size, seq_len), "ms"});
    std::cout << results.back().time_ms << " ms\n";
    
    std::cout << "2. RMSNorm... " << std::flush;
    results.push_back({"RMSNorm",
        BenchmarkRMSNorm(hidden_size, seq_len), "ms"});
    std::cout << results.back().time_ms << " ms\n";
    
    std::cout << "3. MatMul (Q projection)... " << std::flush;
    results.push_back({"MatMul Q Proj",
        BenchmarkMatMul(seq_len, hidden_size, hidden_size), "ms"});
    std::cout << results.back().time_ms << " ms\n";
    
    std::cout << "4. MatMul (FFN up)... " << std::flush;
    results.push_back({"MatMul FFN Up",
        BenchmarkMatMul(seq_len, intermediate_size, hidden_size), "ms"});
    std::cout << results.back().time_ms << " ms\n";
    
    std::cout << "5. Attention scores... " << std::flush;
    results.push_back({"Attention Scores",
        BenchmarkAttentionScores(seq_len, head_dim), "ms"});
    std::cout << results.back().time_ms << " ms\n";
    
    std::cout << "6. Softmax... " << std::flush;
    results.push_back({"Softmax",
        BenchmarkSoftmax(seq_len), "us"});
    std::cout << results.back().time_ms * 1000.0 << " us\n";
    
    std::cout << "7. SiLU activation... " << std::flush;
    results.push_back({"SiLU",
        BenchmarkSiLU(seq_len * intermediate_size), "ms"});
    std::cout << results.back().time_ms << " ms\n";
    
    std::cout << "8. Top-k sampling... " << std::flush;
    results.push_back({"Top-k Sampling",
        BenchmarkTopKSampling(vocab_size, 40), "us"});
    std::cout << results.back().time_ms * 1000.0 << " us\n";
    
    // Calculate estimated throughput
    std::cout << "\n========================================\n";
    std::cout << "Performance Analysis\n";
    std::cout << "========================================\n\n";
    
    // Estimate time per layer
    double time_per_layer =
        results[1].time_ms +                    // RMSNorm
        results[2].time_ms +                    // Q projection
        results[2].time_ms +                    // K projection
        results[2].time_ms +                    // V projection
        results[4].time_ms +                    // Attention scores
        results[5].time_ms / 1000.0 +          // Softmax (convert us to ms)
        results[2].time_ms +                    // O projection
        results[1].time_ms +                    // RMSNorm
        results[3].time_ms +                    // FFN gate
        results[6].time_ms +                    // SiLU
        results[3].time_ms +                    // FFN up
        results[3].time_ms;                     // FFN down
    
    double time_all_layers = time_per_layer * num_layers;
    double time_embedding = results[0].time_ms;
    double time_sampling = results[7].time_ms / 1000.0;  // convert us to ms
    
    double total_time_per_token = time_embedding + time_all_layers + time_sampling;
    double tokens_per_second = 1000.0 / total_time_per_token;
    
    std::cout << "Estimated time per layer: " << std::fixed << std::setprecision(2) 
              << time_per_layer << " ms\n";
    std::cout << "Estimated time for " << num_layers << " layers: " 
              << time_all_layers << " ms\n";
    std::cout << "Embedding lookup: " << time_embedding << " ms\n";
    std::cout << "Sampling: " << time_sampling << " ms\n\n";
    
    std::cout << "ESTIMATED THROUGHPUT:\n";
    std::cout << "  " << std::fixed << std::setprecision(1) 
              << tokens_per_second << " tokens/sec\n";
    std::cout << "  " << total_time_per_token << " ms per token\n\n";
    
    // Identify bottlenecks
    std::cout << "Bottleneck Analysis:\n";
    double total_matmul = results[2].time_ms * 7 + results[3].time_ms * 3;  // 7 attention + 3 FFN projections
    double total_attention = results[4].time_ms;
    
    std::cout << "  MatMul operations: " << (total_matmul / time_per_layer * 100.0) << "% of layer time\n";
    std::cout << "  Attention computation: " << (total_attention / time_per_layer * 100.0) << "% of layer time\n";
    std::cout << "  Other (norm, activations): " << ((time_per_layer - total_matmul - total_attention) / time_per_layer * 100.0) << "% of layer time\n\n";
    
    std::cout << "========================================\n";
    std::cout << "Recommendations:\n";
    std::cout << "========================================\n";
    
    if (tokens_per_second < 10.0) {
        std::cout << "  - Throughput is LOW (< 10 tok/s)\n";
        std::cout << "  - Consider: Quantized MatMul kernels\n";
        std::cout << "  - Consider: Multi-threading across heads\n";
    } else if (tokens_per_second < 30.0) {
        std::cout << "  - Throughput is MODERATE (10-30 tok/s)\n";
        std::cout << "  - Consider: AVX-512 optimization\n";
        std::cout << "  - Consider: FlashAttention-style tiling\n";
    } else {
        std::cout << "  - Throughput is GOOD (> 30 tok/s)\n";
        std::cout << "  - Consider: Speculative decoding for 2x speedup\n";
    }
    
    std::cout << "========================================\n";
    
    return 0;
}
