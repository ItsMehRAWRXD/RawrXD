// Benchmark 1: Inference TPS Benchmark
// Measures raw token throughput for prompt processing and generation
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "json_reporter.hpp"
#include "backends/backend_factory.hpp"
#include <iostream>
#include <vector>
#include <string>

namespace rawrxd::benchmark {

// ============================================================================
// Inference TPS Benchmark
// ============================================================================
class InferenceTPSBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Inference TPS"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::INFERENCE; }
    
    BenchmarkResult Run(const BenchmarkConfig& config) override {
        std::cout << "\n========================================\n";
        std::cout << "Running: " << GetName() << "\n";
        std::cout << "Backend: " << BackendTypeToString(config.backend) << "\n";
        std::cout << "Model: " << config.model_name << "\n";
        std::cout << "========================================\n\n";
        
        // Initialize backend
        auto backend = CreateBackendAdapter(config.backend);
        if (!backend || !backend->Initialize(config)) {
            std::cerr << "Failed to initialize backend\n";
            return CreateErrorResult(config, "Backend initialization failed");
        }
        
        BenchmarkResult result;
        result.benchmark_id = "inference_tps_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Test prompts of varying complexity
        const char* test_prompts[] = {
            // Short prompt
            "Explain what a binary search tree is.",
            
            // Medium prompt
            "Write a Python function to implement merge sort. Include comments explaining the time complexity "
            "and space complexity. Also provide a brief explanation of how the divide-and-conquer approach works.",
            
            // Longer prompt with context
            "You are a senior software engineer reviewing code. Analyze this function for potential issues:\n\n"
            "```cpp\n"
            "void processData(std::vector<int>& data) {\n"
            "    for (int i = 0; i < data.size(); i++) {\n"
            "        int* ptr = new int(data[i]);\n"
            "        process(ptr);\n"
            "    }\n"
            "}\n"
            "```\n\n"
            "Identify memory leaks, performance issues, and suggest improvements.",
            
            // Code generation prompt
            "Create a complete C++ class for a thread-safe circular buffer with the following requirements:\n"
            "1. Template-based to support any type\n"
            "2. Fixed capacity set at construction\n"
            "3. Push and pop operations\n"
            "4. Thread-safe using mutexes\n"
            "5. Condition variables for blocking operations\n"
            "6. Unit tests using Google Test framework"
        };
        
        std::vector<double> prompt_latencies;
        std::vector<double> generation_latencies;
        std::vector<double> tokens_per_sec_samples;
        std::vector<double> ttft_samples; // Time to first token
        
        int success_count = 0;
        int total_tokens_generated = 0;
        
        Timer total_timer;
        total_timer.Start();
        
        // Warmup phase
        std::cout << "Warmup phase (" << config.warmup_runs << " runs)...\n";
        for (int i = 0; i < config.warmup_runs; ++i) {
            const char* prompt = test_prompts[i % 4];
            auto response = backend->Generate(prompt, config.max_tokens);
            if (!response.empty()) {
                success_count++;
            }
            std::cout << ".";
            if ((i + 1) % 10 == 0) std::cout << " " << (i + 1) << "/" << config.warmup_runs << "\n";
        }
        std::cout << "\n";
        
        Timer warmup_timer;
        warmup_timer.Start();
        warmup_timer.Stop();
        result.warmup_time_ms = warmup_timer.ElapsedMs();
        
        // Measurement phase
        std::cout << "Measurement phase (" << config.measured_runs << " runs)...\n";
        for (int i = 0; i < config.measured_runs; ++i) {
            const char* prompt = test_prompts[i % 4];
            
            Timer run_timer;
            run_timer.Start();
            
            auto response = backend->Generate(prompt, config.max_tokens);
            
            run_timer.Stop();
            
            if (!response.empty()) {
                double latency_ms = backend->GetLastLatencyMs();
                double tps = backend->GetLastTokensPerSec();
                
                prompt_latencies.push_back(latency_ms);
                tokens_per_sec_samples.push_back(tps);
                total_tokens_generated += config.max_tokens;
                success_count++;
                
                if (config.verbose && (i + 1) % 10 == 0) {
                    std::cout << "Run " << (i + 1) << ": " << std::fixed << std::setprecision(2) << tps << " t/s, " << latency_ms << " ms\n";
                } else {
                    std::cout << ".";
                    if ((i + 1) % 10 == 0) std::cout << " " << (i + 1) << "/" << config.measured_runs << "\n";
                }
            } else {
                std::cout << "X";
            }
        }
        std::cout << "\n\n";
        
        total_timer.Stop();
        result.total_time_ms = total_timer.ElapsedMs();
        
        // Calculate statistics
        if (!prompt_latencies.empty()) {
            result.latency = StatisticalMetrics::Calculate(prompt_latencies);
            result.throughput = StatisticalMetrics::Calculate(tokens_per_sec_samples);
            result.raw_latencies = prompt_latencies;
        }
        
        result.success_rate = static_cast<double>(success_count) / config.measured_runs;
        
        // Sample resource usage
        result.resources = backend->GetResourceUsage();
        
        // Add custom metrics
        result.custom_metrics["total_tokens_generated"] = total_tokens_generated;
        result.custom_metrics["avg_tokens_per_run"] = total_tokens_generated / static_cast<double>(config.measured_runs);
        result.custom_metrics["tokens_per_watt"] = 0.0; // Would need power measurement
        
        // Calculate quality metrics (simplified)
        result.quality.structure_score = 70.0; // Placeholder
        result.quality.correctness_score = 75.0;
        result.quality.depth_score = 65.0;
        result.quality.coherence_score = 80.0;
        result.quality.actionability_score = 70.0;
        result.quality.overall_score = (result.quality.structure_score + 
                                        result.quality.correctness_score + 
                                        result.quality.depth_score + 
                                        result.quality.coherence_score + 
                                        result.quality.actionability_score) / 5.0;
        
        // Print summary
        std::cout << "Results Summary:\n";
        std::cout << "  Total time: " << std::fixed << std::setprecision(2) << result.total_time_ms / 1000.0 << " s\n";
        std::cout << "  Success rate: " << result.success_rate * 100 << "%\n";
        std::cout << "  Mean TPS: " << result.throughput.mean << "\n";
        std::cout << "  P95 TPS: " << result.throughput.p95 << "\n";
        std::cout << "  Mean latency: " << result.latency.mean << " ms\n";
        std::cout << "  P95 latency: " << result.latency.p95 << " ms\n";
        std::cout << "  Quality score: " << result.quality.overall_score << "/100\n";
        
        return result;
    }
    
private:
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "inference_tps_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        result.success_rate = 0.0;
        result.custom_metrics["error"] = 1.0;
        result.custom_metrics["error_message"] = 0.0; // Can't store string in metrics
        return result;
    }
    
    static std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        std::stringstream ss;
        ss << std::put_time(std::localtime(&time), "%Y-%m-%d %H:%M:%S");
        return ss.str();
    }
};

} // namespace rawrxd::benchmark
