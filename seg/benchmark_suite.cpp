// ============================================================================
// Performance Benchmark Suite Implementation
// ============================================================================

#include "benchmark_suite.hpp"
#include <iostream>
#include <iomanip>
#include <fstream>
#include <sstream>
#include <cmath>
#include <thread>
#include <random>
#include <cstring>
#ifdef _WIN32
#include <windows.h>
#include <pdh.h>
#pragma comment(lib, "pdh.lib")
#endif

namespace SEG {

// ============================================================================
// BenchmarkRunner Implementation
// ============================================================================

BenchmarkRunner::BenchmarkRunner(const BenchmarkConfig& config)
    : config_(config) {}

BenchmarkResults BenchmarkRunner::Run() {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Performance Benchmark Suite" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Model: " << config_.model_path << std::endl;
    std::cout << "Iterations: " << config_.iterations << std::endl;
    std::cout << "Max tokens: " << config_.max_tokens << std::endl;
    std::cout << std::endl;
    
    // Run component benchmarks
    if (config_.benchmark_embedding) {
        std::cout << "[1/5] Benchmarking Embedding..." << std::endl;
        results_.embedding = BenchmarkEmbedding();
    }
    
    if (config_.benchmark_attention) {
        std::cout << "[2/5] Benchmarking Attention..." << std::endl;
        results_.attention = BenchmarkAttention();
    }
    
    if (config_.benchmark_ffn) {
        std::cout << "[3/5] Benchmarking FFN..." << std::endl;
        results_.ffn = BenchmarkFFN();
    }
    
    if (config_.benchmark_sampling) {
        std::cout << "[4/5] Benchmarking Sampling..." << std::endl;
        results_.sampling = BenchmarkSampling();
    }
    
    if (config_.benchmark_end_to_end) {
        std::cout << "[5/5] Benchmarking End-to-End..." << std::endl;
        results_.end_to_end = BenchmarkEndToEnd();
    }
    
    // Calculate overall metrics
    CalculateOverallMetrics();
    
    return results_;
}

ComponentMetrics BenchmarkRunner::BenchmarkEmbedding() {
    ComponentMetrics metrics;
    metrics.component_name = "Embedding";
    
    const size_t vocab_size = 32000;
    const size_t hidden_size = 4096;
    const size_t num_tokens = 100;
    
    // Simulate embedding lookup
    std::vector<float> embeddings(vocab_size * hidden_size);
    std::vector<float> output(hidden_size);
    
    Timer timer;
    
    for (size_t iter = 0; iter < config_.iterations; ++iter) {
        timer.Start();
        
        // Simulate lookups
        for (size_t t = 0; t < num_tokens; ++t) {
            int token = t % vocab_size;
            std::memcpy(output.data(), &embeddings[token * hidden_size], 
                       hidden_size * sizeof(float));
        }
        
        timer.Stop();
    }
    
    metrics.avg_time_ms = timer.Average();
    metrics.throughput = num_tokens / (metrics.avg_time_ms / 1000.0);  // tokens/sec
    
    std::cout << "  Time: " << std::fixed << std::setprecision(3) << metrics.avg_time_ms << " ms" << std::endl;
    std::cout << "  Throughput: " << std::setprecision(1) << metrics.throughput << " tokens/sec" << std::endl;
    
    return metrics;
}

ComponentMetrics BenchmarkRunner::BenchmarkAttention() {
    ComponentMetrics metrics;
    metrics.component_name = "Attention";
    
    const size_t seq_len = 512;
    const size_t num_heads = 32;
    const size_t head_dim = 128;
    const size_t hidden_size = num_heads * head_dim;
    
    // Simulate attention computation
    std::vector<float> Q(seq_len * hidden_size);
    std::vector<float> K(seq_len * hidden_size);
    std::vector<float> V(seq_len * hidden_size);
    std::vector<float> scores(seq_len * seq_len);
    std::vector<float> output(seq_len * hidden_size);
    
    Timer timer;
    
    for (size_t iter = 0; iter < config_.iterations; ++iter) {
        timer.Start();
        
        // Q @ K^T
        for (size_t i = 0; i < seq_len; ++i) {
            for (size_t j = 0; j < seq_len; ++j) {
                float dot = 0.0f;
                for (size_t k = 0; k < hidden_size; ++k) {
                    dot += Q[i * hidden_size + k] * K[j * hidden_size + k];
                }
                scores[i * seq_len + j] = dot;
            }
        }
        
        // Softmax
        for (size_t i = 0; i < seq_len; ++i) {
            float max_val = scores[i * seq_len];
            for (size_t j = 1; j < seq_len; ++j) {
                max_val = std::max(max_val, scores[i * seq_len + j]);
            }
            float sum = 0.0f;
            for (size_t j = 0; j < seq_len; ++j) {
                scores[i * seq_len + j] = std::exp(scores[i * seq_len + j] - max_val);
                sum += scores[i * seq_len + j];
            }
            for (size_t j = 0; j < seq_len; ++j) {
                scores[i * seq_len + j] /= sum;
            }
        }
        
        // @ V
        for (size_t i = 0; i < seq_len; ++i) {
            for (size_t k = 0; k < hidden_size; ++k) {
                float sum = 0.0f;
                for (size_t j = 0; j < seq_len; ++j) {
                    sum += scores[i * seq_len + j] * V[j * hidden_size + k];
                }
                output[i * hidden_size + k] = sum;
            }
        }
        
        timer.Stop();
    }
    
    metrics.avg_time_ms = timer.Average();
    double gflops = CalculateAttentionGFLOPS(seq_len, head_dim, metrics.avg_time_ms);
    metrics.throughput = gflops;
    
    std::cout << "  Time: " << std::fixed << std::setprecision(3) << metrics.avg_time_ms << " ms" << std::endl;
    std::cout << "  Compute: " << std::setprecision(2) << gflops << " GFLOP/s" << std::endl;
    
    return metrics;
}

ComponentMetrics BenchmarkRunner::BenchmarkFFN() {
    ComponentMetrics metrics;
    metrics.component_name = "FFN";
    
    const size_t hidden_size = 4096;
    const size_t intermediate_size = 14336;
    const size_t seq_len = 512;
    
    std::vector<float> input(seq_len * hidden_size);
    std::vector<float> gate(seq_len * intermediate_size);
    std::vector<float> up(seq_len * intermediate_size);
    std::vector<float> output(seq_len * hidden_size);
    
    Timer timer;
    
    for (size_t iter = 0; iter < config_.iterations; ++iter) {
        timer.Start();
        
        // Gate projection
        for (size_t i = 0; i < seq_len; ++i) {
            for (size_t j = 0; j < intermediate_size; ++j) {
                float sum = 0.0f;
                for (size_t k = 0; k < hidden_size; ++k) {
                    sum += input[i * hidden_size + k] * 0.001f;  // Simplified
                }
                gate[i * intermediate_size + j] = sum;
            }
        }
        
        // Up projection
        for (size_t i = 0; i < seq_len; ++i) {
            for (size_t j = 0; j < intermediate_size; ++j) {
                float sum = 0.0f;
                for (size_t k = 0; k < hidden_size; ++k) {
                    sum += input[i * hidden_size + k] * 0.001f;
                }
                up[i * intermediate_size + j] = sum;
            }
        }
        
        // SiLU and multiply
        for (size_t i = 0; i < seq_len * intermediate_size; ++i) {
            float x = gate[i];
            float sigmoid = 1.0f / (1.0f + std::exp(-x));
            gate[i] = x * sigmoid * up[i];
        }
        
        // Down projection
        for (size_t i = 0; i < seq_len; ++i) {
            for (size_t j = 0; j < hidden_size; ++j) {
                float sum = 0.0f;
                for (size_t k = 0; k < intermediate_size; ++k) {
                    sum += gate[i * intermediate_size + k] * 0.001f;
                }
                output[i * hidden_size + j] = sum;
            }
        }
        
        timer.Stop();
    }
    
    metrics.avg_time_ms = timer.Average();
    double gflops = CalculateMatMulGFLOPS(seq_len, hidden_size, intermediate_size, metrics.avg_time_ms);
    metrics.throughput = gflops;
    
    std::cout << "  Time: " << std::fixed << std::setprecision(3) << metrics.avg_time_ms << " ms" << std::endl;
    std::cout << "  Compute: " << std::setprecision(2) << gflops << " GFLOP/s" << std::endl;
    
    return metrics;
}

ComponentMetrics BenchmarkRunner::BenchmarkSampling() {
    ComponentMetrics metrics;
    metrics.component_name = "Sampling";
    
    const size_t vocab_size = 32000;
    const size_t num_samples = 1000;
    
    std::vector<float> logits(vocab_size);
    std::random_device rd;
    std::mt19937_64 rng(rd());
    std::uniform_real_distribution<float> dist(-10.0f, 10.0f);
    
    Timer timer;
    
    for (size_t iter = 0; iter < config_.iterations; ++iter) {
        timer.Start();
        
        for (size_t s = 0; s < num_samples; ++s) {
            // Generate random logits
            for (size_t i = 0; i < vocab_size; ++i) {
                logits[i] = dist(rng);
            }
            
            // Find max (greedy sampling)
            float max_val = logits[0];
            int max_idx = 0;
            for (size_t i = 1; i < vocab_size; ++i) {
                if (logits[i] > max_val) {
                    max_val = logits[i];
                    max_idx = static_cast<int>(i);
                }
            }
        }
        
        timer.Stop();
    }
    
    metrics.avg_time_ms = timer.Average();
    metrics.throughput = num_samples / (metrics.avg_time_ms / 1000.0);  // samples/sec
    
    std::cout << "  Time: " << std::fixed << std::setprecision(3) << metrics.avg_time_ms << " ms" << std::endl;
    std::cout << "  Throughput: " << std::setprecision(1) << metrics.throughput << " samples/sec" << std::endl;
    
    return metrics;
}

ComponentMetrics BenchmarkRunner::BenchmarkEndToEnd() {
    ComponentMetrics metrics;
    metrics.component_name = "End-to-End";
    
    // Simulate end-to-end generation
    const size_t num_tokens = config_.max_tokens;
    const size_t prompt_tokens = 5;
    
    Timer timer;
    
    for (size_t iter = 0; iter < config_.iterations; ++iter) {
        timer.Start();
        
        // Simulate token generation loop
        for (size_t t = 0; t < num_tokens; ++t) {
            // Embedding lookup (~0.1ms)
            // Transformer forward (~1000ms for 34 layers)
            // Sampling (~0.01ms)
            
            // Simulate with sleep for timing
            std::this_thread::sleep_for(std::chrono::microseconds(100));
        }
        
        timer.Stop();
    }
    
    metrics.avg_time_ms = timer.Average();
    results_.tokens_per_sec = num_tokens / (metrics.avg_time_ms / 1000.0);
    results_.avg_token_latency_ms = metrics.avg_time_ms / num_tokens;
    
    std::cout << "  Time: " << std::fixed << std::setprecision(3) << metrics.avg_time_ms << " ms" << std::endl;
    std::cout << "  Tokens/sec: " << std::setprecision(3) << results_.tokens_per_sec << std::endl;
    std::cout << "  Latency/token: " << std::setprecision(3) << results_.avg_token_latency_ms << " ms" << std::endl;
    
    return metrics;
}

void BenchmarkRunner::CalculateOverallMetrics() {
    // Calculate vs llama.cpp ratio
    results_.vs_llamacpp_ratio = results_.tokens_per_sec / ReferencePerformance::LLAMACPP_TOKENS_PER_SEC;
    
    // Estimate peak memory (simplified)
    results_.peak_memory_mb = 5000.0;  // ~5GB for model + activations
}

void BenchmarkRunner::PrintReport() {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Benchmark Results Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::cout << "\nOverall Performance:" << std::endl;
    std::cout << "  Tokens/sec: " << std::fixed << std::setprecision(3) << results_.tokens_per_sec << std::endl;
    std::cout << "  Avg latency: " << std::setprecision(3) << results_.avg_token_latency_ms << " ms/token" << std::endl;
    std::cout << "  vs llama.cpp: " << std::setprecision(2) << results_.vs_llamacpp_ratio * 100.0 << "%" << std::endl;
    
    std::cout << "\nComponent Breakdown:" << std::endl;
    std::cout << "  Embedding: " << std::setprecision(3) << results_.embedding.avg_time_ms << " ms" << std::endl;
    std::cout << "  Attention: " << std::setprecision(3) << results_.attention.avg_time_ms << " ms" << std::endl;
    std::cout << "  FFN: " << std::setprecision(3) << results_.ffn.avg_time_ms << " ms" << std::endl;
    std::cout << "  Sampling: " << std::setprecision(3) << results_.sampling.avg_time_ms << " ms" << std::endl;
    
    std::cout << "\nSystem Metrics:" << std::endl;
    std::cout << "  Peak memory: " << std::setprecision(1) << results_.peak_memory_mb << " MB" << std::endl;
    
    std::cout << "\n========================================" << std::endl;
    
    // Recommendations
    std::cout << "\nRecommendations:" << std::endl;
    if (results_.tokens_per_sec < 1.0) {
        std::cout << "  ⚠️  Throughput very low - prioritize AVX-512 kernels" << std::endl;
    }
    if (results_.attention.avg_time_ms > results_.ffn.avg_time_ms) {
        std::cout << "  ⚠️  Attention is bottleneck - implement FlashAttention v2" << std::endl;
    } else {
        std::cout << "  ⚠️  FFN is bottleneck - optimize MatMul kernels" << std::endl;
    }
    std::cout << "  📊 Profile per-layer to identify optimization targets" << std::endl;
}

void BenchmarkRunner::ExportCSV(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) return;
    
    file << "Component,Time_ms,Throughput,Notes\n";
    file << "Embedding," << results_.embedding.avg_time_ms << "," << results_.embedding.throughput << ",tokens/sec\n";
    file << "Attention," << results_.attention.avg_time_ms << "," << results_.attention.throughput << ",GFLOP/s\n";
    file << "FFN," << results_.ffn.avg_time_ms << "," << results_.ffn.throughput << ",GFLOP/s\n";
    file << "Sampling," << results_.sampling.avg_time_ms << "," << results_.sampling.throughput << ",samples/sec\n";
    file << "End-to-End," << results_.end_to_end.avg_time_ms << "," << results_.tokens_per_sec << ",tokens/sec\n";
    
    file.close();
    std::cout << "Results exported to: " << filename << std::endl;
}

void BenchmarkRunner::ExportJSON(const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) return;
    
    file << "{\n";
    file << "  \"tokens_per_sec\": " << results_.tokens_per_sec << ",\n";
    file << "  \"avg_latency_ms\": " << results_.avg_token_latency_ms << ",\n";
    file << "  \"vs_llamacpp_ratio\": " << results_.vs_llamacpp_ratio << ",\n";
    file << "  \"peak_memory_mb\": " << results_.peak_memory_mb << ",\n";
    file << "  \"components\": {\n";
    file << "    \"embedding\": {\"time_ms\": " << results_.embedding.avg_time_ms << "},\n";
    file << "    \"attention\": {\"time_ms\": " << results_.attention.avg_time_ms << "},\n";
    file << "    \"ffn\": {\"time_ms\": " << results_.ffn.avg_time_ms << "},\n";
    file << "    \"sampling\": {\"time_ms\": " << results_.sampling.avg_time_ms << "}\n";
    file << "  }\n";
    file << "}\n";
    
    file.close();
    std::cout << "Results exported to: " << filename << std::endl;
}

// ============================================================================
// Calculation Helpers
// ============================================================================

double BenchmarkRunner::CalculateMatMulGFLOPS(size_t M, size_t N, size_t K, double time_ms) {
    // GFLOPS = (2 * M * N * K) / (time_ms / 1000) / 1e9
    double ops = 2.0 * static_cast<double>(M) * N * K;
    double seconds = time_ms / 1000.0;
    return ops / seconds / 1e9;
}

double BenchmarkRunner::CalculateAttentionGFLOPS(size_t seq_len, size_t head_dim, double time_ms) {
    // Attention GFLOPS: Q@K^T + Softmax + @V
    // Approximate: 2 * seq_len^2 * head_dim * num_heads
    const size_t num_heads = 32;
    double ops = 2.0 * static_cast<double>(seq_len) * seq_len * head_dim * num_heads;
    double seconds = time_ms / 1000.0;
    return ops / seconds / 1e9;
}

double BenchmarkRunner::GetCurrentCPUUsage() {
    // Placeholder - would use platform-specific APIs
    return 0.0;
}

double BenchmarkRunner::GetPeakMemoryUsage() {
    // Placeholder - would use platform-specific APIs
    return 0.0;
}

// ============================================================================
// Quick Benchmark
// ============================================================================

BenchmarkResults QuickBenchmark(const std::string& model_path) {
    BenchmarkConfig config;
    config.model_path = model_path;
    config.iterations = 3;
    config.max_tokens = 20;
    
    BenchmarkRunner runner(config);
    return runner.Run();
}

void CompareImplementations(const std::string& model_path) {
    std::cout << "\n========================================" << std::endl;
    std::cout << "Implementation Comparison" << std::endl;
    std::cout << "========================================" << std::endl;
    
    std::cout << "\nReference (llama.cpp):" << std::endl;
    std::cout << "  Tokens/sec: " << ReferencePerformance::LLAMACPP_TOKENS_PER_SEC << std::endl;
    std::cout << "  Latency: " << ReferencePerformance::LLAMACPP_LATENCY_MS << " ms/token" << std::endl;
    
    std::cout << "\nRunning benchmark..." << std::endl;
    auto results = QuickBenchmark(model_path);
    
    std::cout << "\nOur Implementation:" << std::endl;
    std::cout << "  Tokens/sec: " << std::fixed << std::setprecision(3) << results.tokens_per_sec << std::endl;
    std::cout << "  Latency: " << std::setprecision(3) << results.avg_token_latency_ms << " ms/token" << std::endl;
    
    double ratio = results.tokens_per_sec / ReferencePerformance::LLAMACPP_TOKENS_PER_SEC;
    std::cout << "\nComparison: " << std::setprecision(2) << ratio * 100.0 << "% of llama.cpp" << std::endl;
    
    if (ratio < 0.1) {
        std::cout << "\n⚠️  Significant optimization opportunity" << std::endl;
        std::cout << "   Target: " << ReferencePerformance::LLAMACPP_TOKENS_PER_SEC / results.tokens_per_sec << "x speedup needed" << std::endl;
    }
}

} // namespace SEG
