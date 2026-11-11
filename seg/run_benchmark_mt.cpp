// ============================================================================
// Run Benchmark - Multi-Threaded Version
// ============================================================================
// Demonstrates proper thread pool usage for transformer parallelization
// ============================================================================

#include <iostream>
#include <fstream>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <cstring>
#include <memory>
#include <thread>
#include <mutex>
#include <atomic>
#include <future>
#include <queue>
#include <condition_variable>

// Hardware detection for Windows
#ifdef _WIN32
#include <intrin.h>
#include <windows.h>
#else
#include <unistd.h>
#endif

// ============================================================================
// Thread Pool Implementation
// ============================================================================
class ThreadPool {
public:
    ThreadPool(size_t num_threads) : stop_(false), active_tasks_(0) {
        for (size_t i = 0; i < num_threads; ++i) {
            workers_.emplace_back([this]() { WorkerLoop(); });
        }
    }
    
    ~ThreadPool() {
        Shutdown();
    }
    
    void Shutdown() {
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            stop_ = true;
        }
        condition_.notify_all();
        for (auto& worker : workers_) {
            if (worker.joinable()) worker.join();
        }
    }
    
    template<typename F>
    auto Submit(F&& f) -> std::future<decltype(f())> {
        using ReturnType = decltype(f());
        auto task = std::make_shared<std::packaged_task<ReturnType()>>(std::forward<F>(f));
        std::future<ReturnType> result = task->get_future();
        
        {
            std::unique_lock<std::mutex> lock(queue_mutex_);
            if (stop_) throw std::runtime_error("Pool stopped");
            tasks_.emplace([task]() { (*task)(); });
            active_tasks_++;
        }
        condition_.notify_one();
        return result;
    }
    
    void WaitAll() {
        std::unique_lock<std::mutex> lock(queue_mutex_);
        finished_.wait(lock, [this] { return tasks_.empty() && active_tasks_ == 0; });
    }
    
    size_t Size() const { return workers_.size(); }
    
private:
    void WorkerLoop() {
        while (true) {
            std::function<void()> task;
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                condition_.wait(lock, [this] { return stop_ || !tasks_.empty(); });
                if (stop_ && tasks_.empty()) return;
                task = std::move(tasks_.front());
                tasks_.pop();
            }
            task();
            {
                std::unique_lock<std::mutex> lock(queue_mutex_);
                active_tasks_--;
                if (active_tasks_ == 0 && tasks_.empty()) finished_.notify_all();
            }
        }
    }
    
    std::vector<std::thread> workers_;
    std::queue<std::function<void()>> tasks_;
    std::mutex queue_mutex_;
    std::condition_variable condition_;
    std::condition_variable finished_;
    std::atomic<bool> stop_;
    std::atomic<size_t> active_tasks_;
};

// ============================================================================
// Benchmark Configuration
// ============================================================================
struct BenchmarkConfig {
    std::string model_path;
    uint32_t num_tokens = 128;
    uint32_t num_iterations = 3;
    uint32_t batch_size = 1;  // Tokens to process in parallel
    uint32_t num_threads = 0; // 0 = auto
    bool verbose = false;
};

struct BenchmarkResults {
    float tokens_per_sec = 0.0f;
    float avg_latency_ms = 0.0f;
    float total_time_ms = 0.0f;
    float transformer_time_ms = 0.0f;
    uint32_t num_layers = 24;
    uint32_t hidden_size = 2048;
    uint32_t num_heads = 32;
    std::vector<uint32_t> generated_tokens;
};

// ============================================================================
// Simulate Transformer Layer (compute-bound kernel)
// ============================================================================
void SimulateTransformerLayer(uint32_t hidden_size, uint32_t intermediate_size, 
                               uint32_t num_heads, uint32_t seq_len) {
    const uint32_t ITER_SCALE = 4;
    
    // Attention computation
    uint32_t head_dim = hidden_size / num_heads;
    uint32_t scaled_seq = std::min(seq_len, 32u);
    std::vector<float> attn_scores(num_heads * scaled_seq * scaled_seq, 0.0f);
    
    for (uint32_t h = 0; h < num_heads; h++) {
        for (uint32_t i = 0; i < scaled_seq; i++) {
            for (uint32_t j = 0; j < scaled_seq; j++) {
                float dot = 0.0f;
                for (uint32_t d = 0; d < head_dim / ITER_SCALE; d++) {
                    dot += 0.01f;  // Simulated computation
                }
                attn_scores[h * scaled_seq * scaled_seq + i * scaled_seq + j] = dot;
            }
        }
    }
    
    // MLP computation
    uint32_t scaled_intermediate = intermediate_size / ITER_SCALE;
    std::vector<float> mlp_up(scaled_intermediate, 0.1f);
    std::vector<float> mlp_gate(scaled_intermediate, 0.1f);
    
    for (uint32_t i = 0; i < scaled_intermediate; i++) {
        float x = mlp_gate[i];
        mlp_gate[i] = x / (1.0f + std::exp(-x));
    }
    
    for (uint32_t i = 0; i < scaled_intermediate; i++) {
        mlp_up[i] *= mlp_gate[i];
    }
    
    std::vector<float> mlp_down(hidden_size / ITER_SCALE, 0.0f);
    for (uint32_t i = 0; i < hidden_size / ITER_SCALE; i++) {
        float sum = 0.0f;
        for (uint32_t j = 0; j < scaled_intermediate; j++) {
            sum += mlp_up[j] * 0.01f;
        }
        mlp_down[i] = sum;
    }
}

// ============================================================================
// Single-threaded token generation
// ============================================================================
void GenerateTokensST(uint32_t start, uint32_t end,
                       uint32_t hidden_size, uint32_t intermediate_size,
                       uint32_t num_heads, uint32_t num_layers,
                       uint32_t base_seq_len,
                       std::vector<uint32_t>& tokens) {
    for (uint32_t i = start; i < end; i++) {
        uint32_t seq_len = base_seq_len + i + 1;
        for (uint32_t layer = 0; layer < num_layers; layer++) {
            SimulateTransformerLayer(hidden_size, intermediate_size, num_heads, seq_len);
        }
        tokens.push_back(42 + (i % 100));
    }
}

// ============================================================================
// Multi-threaded token generation (parallel across tokens)
// ============================================================================
void GenerateTokensMT(uint32_t start, uint32_t end,
                       uint32_t hidden_size, uint32_t intermediate_size,
                       uint32_t num_heads, uint32_t num_layers,
                       uint32_t base_seq_len,
                       std::vector<uint32_t>& tokens,
                       ThreadPool& pool) {
    uint32_t num_tokens = end - start;
    uint32_t num_threads = static_cast<uint32_t>(pool.Size());
    uint32_t chunk_size = (num_tokens + num_threads - 1) / num_threads;
    
    std::vector<std::future<void>> futures;
    std::vector<std::vector<uint32_t>> thread_tokens(num_threads);
    
    for (uint32_t t = 0; t < num_threads; t++) {
        uint32_t chunk_start = start + t * chunk_size;
        uint32_t chunk_end = std::min(chunk_start + chunk_size, end);
        
        if (chunk_start >= chunk_end) break;
        
        futures.push_back(pool.Submit([&, t, chunk_start, chunk_end]() {
            GenerateTokensST(chunk_start, chunk_end, hidden_size, intermediate_size,
                            num_heads, num_layers, base_seq_len, thread_tokens[t]);
        }));
    }
    
    for (auto& f : futures) f.wait();
    
    // Merge results in order
    for (uint32_t t = 0; t < num_threads; t++) {
        tokens.insert(tokens.end(), thread_tokens[t].begin(), thread_tokens[t].end());
    }
}

// ============================================================================
// Run Benchmark
// ============================================================================
BenchmarkResults RunBenchmark(const BenchmarkConfig& config, ThreadPool& pool) {
    BenchmarkResults results;
    results.num_layers = 24;
    results.hidden_size = 2048;
    results.num_heads = 32;
    uint32_t intermediate_size = 5504;
    uint32_t base_seq_len = 5;  // "The quick brown fox"
    
    auto transformer_start = std::chrono::high_resolution_clock::now();
    
    if (config.batch_size == 1) {
        // Autoregressive: single-threaded (can't parallelize across tokens)
        GenerateTokensST(0, config.num_tokens, results.hidden_size, intermediate_size,
                        results.num_heads, results.num_layers, base_seq_len,
                        results.generated_tokens);
    } else {
        // Batch processing: multi-threaded
        GenerateTokensMT(0, config.num_tokens, results.hidden_size, intermediate_size,
                        results.num_heads, results.num_layers, base_seq_len,
                        results.generated_tokens, pool);
    }
    
    auto transformer_end = std::chrono::high_resolution_clock::now();
    results.transformer_time_ms = std::chrono::duration_cast<std::chrono::microseconds>(
        transformer_end - transformer_start).count() / 1000.0f;
    results.total_time_ms = results.transformer_time_ms;
    
    if (results.total_time_ms > 0) {
        results.tokens_per_sec = (config.num_tokens * 1000.0f) / results.total_time_ms;
        results.avg_latency_ms = results.total_time_ms / config.num_tokens;
    }
    
    return results;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "RawrXD Multi-Threaded Benchmark\n";
    std::cout << "========================================\n\n";
    
    BenchmarkConfig config;
    config.num_threads = std::thread::hardware_concurrency();
    
    // Parse args
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--tokens" && i + 1 < argc) config.num_tokens = std::stoi(argv[++i]);
        else if (arg == "--iterations" && i + 1 < argc) config.num_iterations = std::stoi(argv[++i]);
        else if (arg == "--batch" && i + 1 < argc) config.batch_size = std::stoi(argv[++i]);
        else if (arg == "--threads" && i + 1 < argc) config.num_threads = std::stoi(argv[++i]);
        else if (arg == "--verbose" || arg == "-v") config.verbose = true;
    }
    
    std::cout << "Configuration:\n";
    std::cout << "  Tokens: " << config.num_tokens << "\n";
    std::cout << "  Iterations: " << config.num_iterations << "\n";
    std::cout << "  Batch size: " << config.batch_size << "\n";
    std::cout << "  Threads: " << config.num_threads << "\n\n";
    
    // Create thread pool
    ThreadPool pool(config.num_threads);
    
    // Run iterations
    std::vector<BenchmarkResults> all_results;
    for (uint32_t iter = 0; iter < config.num_iterations; iter++) {
        if (config.verbose) std::cout << "Running iteration " << (iter + 1) << "/" << config.num_iterations << "...\n";
        all_results.push_back(RunBenchmark(config, pool));
    }
    
    // Average results
    BenchmarkResults avg;
    for (const auto& r : all_results) {
        avg.tokens_per_sec += r.tokens_per_sec;
        avg.avg_latency_ms += r.avg_latency_ms;
        avg.total_time_ms += r.total_time_ms;
    }
    avg.tokens_per_sec /= config.num_iterations;
    avg.avg_latency_ms /= config.num_iterations;
    avg.total_time_ms /= config.num_iterations;
    
    // Print results
    std::cout << "\n========================================\n";
    std::cout << "Results (" << (config.batch_size == 1 ? "Single-threaded" : "Multi-threaded") << ")\n";
    std::cout << "========================================\n";
    std::cout << "  Tokens/sec:  " << std::fixed << std::setprecision(2) << avg.tokens_per_sec << "\n";
    std::cout << "  Latency:     " << avg.avg_latency_ms << " ms/token\n";
    std::cout << "  Total time:  " << avg.total_time_ms << " ms\n\n";
    
    // Compare with theoretical
    std::cout << "Analysis:\n";
    if (config.batch_size == 1) {
        std::cout << "  Mode: Autoregressive (single-threaded)\n";
        std::cout << "  Note: Cannot parallelize across tokens in autoregressive generation.\n";
        std::cout << "        Threading overhead would exceed benefit.\n";
    } else {
        std::cout << "  Mode: Batch processing (multi-threaded)\n";
        std::cout << "  Parallel efficiency: " << (avg.tokens_per_sec / (all_results[0].tokens_per_sec * config.num_threads) * 100) << "%\n";
    }
    
    return 0;
}
