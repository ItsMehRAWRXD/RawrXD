/**
 * @file standardized_benchmark.cpp
 * @brief Standardized Benchmark Implementation
 *
 * Provides reproducible performance measurements with per-component profiling.
 *
 * @copyright RawrXD 2026
 */

#include "standardized_benchmark.hpp"
#include "../../rawrxd/src/inference/transformer_layer.h"
#include "../../rawrxd/src/model/model_context.h"
#include <iostream>
#include <iomanip>
#include <sstream>
#include <fstream>
#include <numeric>
#include <cmath>
#include <algorithm>
#include <thread>
#include <intrin.h>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace rawrxd {
namespace benchmark {

// ============================================================================
// Profiler Implementation
// ============================================================================

void Profiler::BeginRegion(const std::string& name) {
    active_regions_[name].start = std::chrono::high_resolution_clock::now();
}

void Profiler::EndRegion(const std::string& name) {
    auto end = std::chrono::high_resolution_clock::now();
    auto it = active_regions_.find(name);
    if (it != active_regions_.end()) {
        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(
            end - it->second.start);
        double ms = duration.count() / 1000.0;
        completed_regions_[name].push_back(ms);
        active_regions_.erase(it);
    }
}

void Profiler::Reset() {
    active_regions_.clear();
    completed_regions_.clear();
}

std::map<std::string, ComponentTiming> Profiler::GetResults() const {
    std::map<std::string, ComponentTiming> results;
    
    // Calculate total time across all regions
    double total_time = 0.0;
    for (const auto& [name, durations] : completed_regions_) {
        for (double d : durations) {
            total_time += d;
        }
    }
    
    for (const auto& [name, durations] : completed_regions_) {
        if (durations.empty()) continue;
        
        ComponentTiming timing;
        timing.name = name;
        timing.call_count = static_cast<uint32_t>(durations.size());
        
        // Calculate statistics
        double sum = std::accumulate(durations.begin(), durations.end(), 0.0);
        timing.total_ms = sum;
        timing.mean_ms = sum / durations.size();
        timing.min_ms = *std::min_element(durations.begin(), durations.end());
        timing.max_ms = *std::max_element(durations.begin(), durations.end());
        
        // Standard deviation
        double sq_sum = 0.0;
        for (double d : durations) {
            sq_sum += (d - timing.mean_ms) * (d - timing.mean_ms);
        }
        timing.stddev_ms = std::sqrt(sq_sum / durations.size());
        
        // Percentage of total
        if (total_time > 0) {
            timing.percentage = (sum / total_time) * 100.0;
        }
        
        results[name] = timing;
    }
    
    return results;
}

// ============================================================================
// StandardizedBenchmark Implementation
// ============================================================================

StandardizedBenchmark::StandardizedBenchmark(const BenchmarkConfig& config)
    : config_(config) {
    
    // Set random seed for reproducibility
    srand(config.seed);
}

StandardizedBenchmark::~StandardizedBenchmark() = default;

void StandardizedBenchmark::DetectSystemInfo() {
    results_.system_info.cpu_cores = std::thread::hardware_concurrency();
    results_.system_info.cpu_threads = results_.system_info.cpu_cores;
    
    // Check CPU features
    int cpuInfo[4] = {0};
    __cpuid(cpuInfo, 1);
    results_.system_info.has_avx2 = (cpuInfo[2] & (1 << 28)) != 0;
    
    __cpuid(cpuInfo, 7);
    results_.system_info.has_avx512 = (cpuInfo[1] & (1 << 16)) != 0;
    
    // Get memory info
    #ifdef _WIN32
    MEMORYSTATUSEX mem_status;
    mem_status.dwLength = sizeof(mem_status);
    if (GlobalMemoryStatusEx(&mem_status)) {
        results_.system_info.total_memory_bytes = mem_status.ullTotalPhys;
        results_.system_info.available_memory_bytes = mem_status.ullAvailPhys;
    }
    #endif
}

bool StandardizedBenchmark::LoadModel() {
    profiler_.BeginRegion("model_load");
    
    // Load model and get info
    model::ModelContext ctx;
    if (!ctx.LoadFromFile(config_.model_path)) {
        results_.failure_reason = "Failed to load model: " + config_.model_path;
        return false;
    }
    
    const auto& arch = ctx.GetArchitecture();
    results_.model_info.path = config_.model_path;
    results_.model_info.vocab_size = arch.vocab_size;
    results_.model_info.hidden_size = arch.embedding_dim;
    results_.model_info.num_layers = arch.layer_count;
    results_.model_info.num_heads = arch.head_count;
    
    // Get file size
    std::ifstream file(config_.model_path, std::ios::binary | std::ios::ate);
    if (file) {
        results_.model_info.file_size_bytes = file.tellg();
        file.close();
    }
    
    profiler_.EndRegion("model_load");
    return true;
}

BenchmarkResults::IterationResult StandardizedBenchmark::RunIteration(uint32_t iter) {
    BenchmarkResults::IterationResult result;
    result.iteration = iter;
    
    // Create inference pipeline
    inference::TransformerModel model;
    
    // Load model
    if (!model.Load(config_.model_path)) {
        result.total_time_ms = -1.0;
        return result;
    }
    
    // Tokenize prompt (simplified)
    std::vector<uint32_t> prompt_tokens;
    // In real implementation, would use tokenizer
    for (char c : config_.prompt) {
        prompt_tokens.push_back(static_cast<uint32_t>(c) % 256);
    }
    result.tokens_generated = 0;
    
    // Warmup
    for (uint32_t w = 0; w < config_.warmup_iterations; ++w) {
        model.GenerateNextToken(prompt_tokens, config_.temperature, config_.top_k);
    }
    
    // Benchmark run
    auto start = std::chrono::high_resolution_clock::now();
    
    std::vector<uint32_t> generated_tokens;
    for (uint32_t i = 0; i < config_.max_tokens; ++i) {
        auto token_start = std::chrono::high_resolution_clock::now();
        
        uint32_t next_token = model.GenerateNextToken(
            prompt_tokens, config_.temperature, config_.top_k);
        
        auto token_end = std::chrono::high_resolution_clock::now();
        auto token_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            token_end - token_start);
        
        generated_tokens.push_back(next_token);
        prompt_tokens.push_back(next_token);
        result.tokens_generated++;
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto total_duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    result.total_time_ms = total_duration.count() / 1000.0;
    result.tokens_per_second = (result.tokens_generated / result.total_time_ms) * 1000.0;
    
    return result;
}

void StandardizedBenchmark::CalculateStatistics() {
    if (results_.iterations.empty()) return;
    
    // Calculate mean TPS
    double sum_tps = 0.0;
    double sum_time = 0.0;
    std::vector<double> tps_values;
    
    for (const auto& iter : results_.iterations) {
        sum_tps += iter.tokens_per_second;
        sum_time += iter.total_time_ms;
        tps_values.push_back(iter.tokens_per_second);
    }
    
    results_.overall.tokens_per_second = sum_tps / results_.iterations.size();
    results_.overall.total_time_ms = sum_time / results_.iterations.size();
    results_.overall.tokens_generated = results_.iterations[0].tokens_generated;
    results_.overall.prompt_tokens = static_cast<uint32_t>(config_.prompt.size());
    results_.overall.avg_latency_per_token_ms = 
        results_.overall.total_time_ms / results_.overall.tokens_generated;
    
    // Min/max/stddev
    results_.overall.tps_min = *std::min_element(tps_values.begin(), tps_values.end());
    results_.overall.tps_max = *std::max_element(tps_values.begin(), tps_values.end());
    
    double sq_sum = 0.0;
    for (double tps : tps_values) {
        sq_sum += (tps - results_.overall.tokens_per_second) * 
                  (tps - results_.overall.tokens_per_second);
    }
    results_.overall.tps_stddev = std::sqrt(sq_sum / tps_values.size());
}

bool StandardizedBenchmark::ValidateResults() {
    // Check for obvious errors
    if (results_.overall.tokens_per_second <= 0) {
        results_.failure_reason = "Invalid tokens/sec (<= 0)";
        return false;
    }
    
    if (results_.overall.total_time_ms <= 0) {
        results_.failure_reason = "Invalid total time (<= 0)";
        return false;
    }
    
    // Check for high variance (indicates instability)
    if (results_.overall.tps_stddev > results_.overall.tokens_per_second * 0.5) {
        results_.failure_reason = "High variance in results (> 50%)";
        return false;
    }
    
    return true;
}

BenchmarkResults StandardizedBenchmark::Run() {
    // Set timestamp
    auto now = std::chrono::system_clock::now();
    auto time_t = std::chrono::system_clock::to_time_t(now);
    std::stringstream ss;
    ss << std::put_time(std::localtime(&time_t), "%Y-%m-%d %H:%M:%S");
    results_.timestamp = ss.str();
    
    // Detect system
    DetectSystemInfo();
    
    // Load model
    if (!LoadModel()) {
        return results_;
    }
    
    // Run benchmark iterations
    std::cout << "Running " << config_.benchmark_iterations << " benchmark iterations...\n";
    for (uint32_t i = 0; i < config_.benchmark_iterations; ++i) {
        std::cout << "  Iteration " << (i + 1) << "/" << config_.benchmark_iterations << "...\n";
        auto iter_result = RunIteration(i);
        results_.iterations.push_back(iter_result);
    }
    
    // Calculate statistics
    CalculateStatistics();
    
    // Get profiling results
    results_.component_timings = profiler_.GetResults();
    
    // Validate
    results_.passed = ValidateResults();
    
    return results_;
}

bool StandardizedBenchmark::ExportJSON(const std::string& path) const {
    std::ofstream file(path);
    if (!file) return false;
    
    file << "{\n";
    file << "  \"timestamp\": \"" << results_.timestamp << "\",\n";
    file << "  \"passed\": " << (results_.passed ? "true" : "false") << ",\n";
    
    if (!results_.failure_reason.empty()) {
        file << "  \"failure_reason\": \"" << results_.failure_reason << "\",\n";
    }
    
    // System info
    file << "  \"system_info\": {\n";
    file << "    \"cpu_cores\": " << results_.system_info.cpu_cores << ",\n";
    file << "    \"cpu_threads\": " << results_.system_info.cpu_threads << ",\n";
    file << "    \"has_avx2\": " << (results_.system_info.has_avx2 ? "true" : "false") << ",\n";
    file << "    \"has_avx512\": " << (results_.system_info.has_avx512 ? "true" : "false") << ",\n";
    file << "    \"total_memory_gb\": " << (results_.system_info.total_memory_bytes / 1e9) << "\n";
    file << "  },\n";
    
    // Model info
    file << "  \"model_info\": {\n";
    file << "    \"path\": \"" << results_.model_info.path << "\",\n";
    file << "    \"file_size_gb\": " << (results_.model_info.file_size_bytes / 1e9) << ",\n";
    file << "    \"vocab_size\": " << results_.model_info.vocab_size << ",\n";
    file << "    \"hidden_size\": " << results_.model_info.hidden_size << ",\n";
    file << "    \"num_layers\": " << results_.model_info.num_layers << ",\n";
    file << "    \"num_heads\": " << results_.model_info.num_heads << "\n";
    file << "  },\n";
    
    // Overall metrics
    file << "  \"overall\": {\n";
    file << "    \"tokens_per_second\": " << std::fixed << std::setprecision(2) 
         << results_.overall.tokens_per_second << ",\n";
    file << "    \"time_to_first_token_ms\": " << results_.overall.time_to_first_token_ms << ",\n";
    file << "    \"avg_latency_per_token_ms\": " << results_.overall.avg_latency_per_token_ms << ",\n";
    file << "    \"total_time_ms\": " << results_.overall.total_time_ms << ",\n";
    file << "    \"tokens_generated\": " << results_.overall.tokens_generated << ",\n";
    file << "    \"tps_min\": " << results_.overall.tps_min << ",\n";
    file << "    \"tps_max\": " << results_.overall.tps_max << ",\n";
    file << "    \"tps_stddev\": " << results_.overall.tps_stddev << "\n";
    file << "  },\n";
    
    // Component timings
    file << "  \"component_timings\": [\n";
    bool first = true;
    for (const auto& [name, timing] : results_.component_timings) {
        if (!first) file << ",\n";
        first = false;
        file << "    {\n";
        file << "      \"name\": \"" << name << "\",\n";
        file << "      \"total_ms\": " << timing.total_ms << ",\n";
        file << "      \"mean_ms\": " << timing.mean_ms << ",\n";
        file << "      \"percentage\": " << timing.percentage << "\n";
        file << "    }";
    }
    file << "\n  ]\n";
    
    file << "}\n";
    return true;
}

std::string StandardizedBenchmark::GenerateReport() const {
    std::ostringstream oss;
    
    oss << "========================================\n";
    oss << "RawrXD Standardized Benchmark Report\n";
    oss << "========================================\n\n";
    
    oss << "Timestamp: " << results_.timestamp << "\n";
    oss << "Status: " << (results_.passed ? "PASSED" : "FAILED") << "\n\n";
    
    if (!results_.failure_reason.empty()) {
        oss << "Failure Reason: " << results_.failure_reason << "\n\n";
    }
    
    oss << "System Information:\n";
    oss << "  CPU Cores: " << results_.system_info.cpu_cores << "\n";
    oss << "  CPU Threads: " << results_.system_info.cpu_threads << "\n";
    oss << "  AVX2: " << (results_.system_info.has_avx2 ? "Yes" : "No") << "\n";
    oss << "  AVX-512: " << (results_.system_info.has_avx512 ? "Yes" : "No") << "\n";
    oss << "  Total Memory: " << (results_.system_info.total_memory_bytes / (1024*1024*1024)) << " GB\n\n";
    
    oss << "Model Information:\n";
    oss << "  Path: " << results_.model_info.path << "\n";
    oss << "  File Size: " << (results_.model_info.file_size_bytes / (1024*1024*1024)) << " GB\n";
    oss << "  Vocab Size: " << results_.model_info.vocab_size << "\n";
    oss << "  Hidden Size: " << results_.model_info.hidden_size << "\n";
    oss << "  Layers: " << results_.model_info.num_layers << "\n";
    oss << "  Heads: " << results_.model_info.num_heads << "\n\n";
    
    oss << "Performance Metrics:\n";
    oss << "  Tokens/sec: " << std::fixed << std::setprecision(2) 
        << results_.overall.tokens_per_second << "\n";
    oss << "  Time to first token: " << results_.overall.time_to_first_token_ms << " ms\n";
    oss << "  Avg latency/token: " << results_.overall.avg_latency_per_token_ms << " ms\n";
    oss << "  Total time: " << results_.overall.total_time_ms << " ms\n";
    oss << "  Tokens generated: " << results_.overall.tokens_generated << "\n\n";
    
    oss << "Statistical Analysis:\n";
    oss << "  TPS min: " << results_.overall.tps_min << "\n";
    oss << "  TPS max: " << results_.overall.tps_max << "\n";
    oss << "  TPS stddev: " << results_.overall.tps_stddev << "\n\n";
    
    if (!results_.component_timings.empty()) {
        oss << "Component Breakdown:\n";
        for (const auto& [name, timing] : results_.component_timings) {
            oss << "  " << std::left << std::setw(20) << name
                << std::right << std::setw(10) << std::fixed << std::setprecision(2) 
                << timing.total_ms << " ms (" << std::setprecision(1) 
                << timing.percentage << "%)\n";
        }
        oss << "\n";
    }
    
    oss << "========================================\n";
    
    return oss.str();
}

// ============================================================================
// Convenience Functions
// ============================================================================

BenchmarkResults QuickBenchmark(const std::string& model_path) {
    BenchmarkConfig config;
    config.model_path = model_path;
    config.benchmark_iterations = 5;
    config.max_tokens = 50;
    
    StandardizedBenchmark benchmark(config);
    return benchmark.Run();
}

ComparisonResult CompareBenchmarks(const BenchmarkResults& baseline,
                                     const BenchmarkResults& current) {
    ComparisonResult result;
    
    double tps_delta = current.overall.tokens_per_second - baseline.overall.tokens_per_second;
    result.tps_delta_percent = (tps_delta / baseline.overall.tokens_per_second) * 100.0;
    
    double latency_delta = current.overall.avg_latency_per_token_ms - 
                          baseline.overall.avg_latency_per_token_ms;
    result.latency_delta_percent = (latency_delta / baseline.overall.avg_latency_per_token_ms) * 100.0;
    
    if (current.overall.tokens_per_second > baseline.overall.tokens_per_second) {
        result.winner = "current";
    } else {
        result.winner = "baseline";
    }
    
    std::ostringstream oss;
    oss << "TPS change: " << std::showpos << std::fixed << std::setprecision(1) 
        << result.tps_delta_percent << "%\n";
    oss << "Latency change: " << result.latency_delta_percent << "%\n";
    result.analysis = oss.str();
    
    return result;
}

std::string EstimateDuration(const BenchmarkConfig& config) {
    // Rough estimate: ~100ms per token on CPU
    double estimated_seconds = (config.warmup_iterations + config.benchmark_iterations) * 
                               config.max_tokens * 0.1;
    
    int minutes = static_cast<int>(estimated_seconds / 60);
    int seconds = static_cast<int>(estimated_seconds) % 60;
    
    std::ostringstream oss;
    if (minutes > 0) {
        oss << minutes << "m " << seconds << "s";
    } else {
        oss << seconds << "s";
    }
    return oss.str();
}

} // namespace benchmark
} // namespace rawrxd
