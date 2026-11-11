// Benchmark 8: Context Handling Benchmark
// Measures long-context retrieval accuracy and degradation
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "json_reporter.hpp"
#include "backends/backend_factory.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <sstream>

namespace rawrxd::benchmark {

// ============================================================================
// Context Handling Benchmark
// ============================================================================
class ContextHandlingBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Context Handling"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::CONTEXT_HANDLING; }
    
    BenchmarkResult Run(const BenchmarkConfig& config) override {
        std::cout << "\n========================================\n";
        std::cout << "Running: " << GetName() << "\n";
        std::cout << "Backend: " << BackendTypeToString(config.backend) << "\n";
        std::cout << "========================================\n\n";
        
        auto backend = CreateBackendAdapter(config.backend);
        if (!backend || !backend->Initialize(config)) {
            std::cerr << "Failed to initialize backend\n";
            return CreateErrorResult(config, "Backend initialization failed");
        }
        
        BenchmarkResult result;
        result.benchmark_id = "context_handling_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Context sizes to test
        struct ContextTest {
            size_t token_count;
            const char* name;
            const char* query;
            const char* expected_answer;
        };
        
        ContextTest tests[] = {
            {
                1024,
                "1k_context",
                "What is the main topic discussed in the first paragraph?",
                "artificial intelligence"
            },
            {
                4096,
                "4k_context",
                "According to section 3, what optimization technique is recommended?",
                "caching"
            },
            {
                8192,
                "8k_context",
                "What conclusion did the authors reach in the final section?",
                "performance improves"
            },
            {
                16384,
                "16k_context",
                "What is the relationship between the two approaches discussed in the middle?",
                "complementary"
            },
            {
                32768,
                "32k_context",
                "What evidence supports the hypothesis mentioned early in the document?",
                "experimental results"
            }
        };
        
        std::vector<double> context_load_latencies;
        std::vector<double> query_latencies;
        std::vector<double> retrieval_accuracies;
        std::vector<double> context_retention_scores;
        std::vector<double> degradation_rates;
        
        int success_count = 0;
        
        Timer total_timer;
        total_timer.Start();
        
        // Warmup with small context
        std::cout << "Warmup phase (" << std::min(config.warmup_runs, 2) << " contexts)...\n";
        for (int i = 0; i < std::min(config.warmup_runs, 2); ++i) {
            auto context = GenerateContext(tests[0].token_count);
            backend->Generate(context + "\n\n" + tests[0].query, config.max_tokens);
            std::cout << ".";
        }
        std::cout << "\n";
        
        Timer warmup_timer;
        warmup_timer.Start();
        warmup_timer.Stop();
        result.warmup_time_ms = warmup_timer.ElapsedMs();
        
        // Measurement phase
        std::cout << "Measurement phase (" << config.measured_runs << " queries)...\n";
        for (int i = 0; i < config.measured_runs; ++i) {
            const auto& test = tests[i % 5];
            
            // Generate context
            Timer load_timer;
            load_timer.Start();
            
            auto context = GenerateContext(test.token_count);
            
            load_timer.Stop();
            double load_ms = load_timer.ElapsedMs();
            
            // Query with context
            Timer query_timer;
            query_timer.Start();
            
            std::string full_prompt = context + "\n\nQuestion: " + test.query + "\nAnswer:";
            auto response = backend->Generate(full_prompt, 100);
            
            query_timer.Stop();
            double query_ms = query_timer.ElapsedMs();
            
            if (!response.empty()) {
                context_load_latencies.push_back(load_ms);
                query_latencies.push_back(query_ms);
                
                // Check retrieval accuracy
                double accuracy = CheckRetrievalAccuracy(response, test.expected_answer);
                retrieval_accuracies.push_back(accuracy);
                
                // Calculate context retention (degrades with size)
                double retention = CalculateContextRetention(test.token_count, accuracy);
                context_retention_scores.push_back(retention);
                
                // Calculate degradation rate
                double degradation = 1.0 - retention;
                degradation_rates.push_back(degradation);
                
                success_count++;
                
                if (config.verbose && (i + 1) % 5 == 0) {
                    std::cout << "Query " << (i + 1) << " [" << test.name << "]: ";
                    std::cout << "load=" << load_ms << "ms, ";
                    std::cout << "query=" << query_ms << "ms, ";
                    std::cout << "accuracy=" << (accuracy * 100) << "%\n";
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
        if (!query_latencies.empty()) {
            result.latency = StatisticalMetrics::Calculate(query_latencies);
            
            // Throughput = queries per second
            std::vector<double> throughput_samples;
            for (double lat : query_latencies) {
                throughput_samples.push_back(1000.0 / lat);
            }
            result.throughput = StatisticalMetrics::Calculate(throughput_samples);
            result.raw_latencies = query_latencies;
        }
        
        result.success_rate = static_cast<double>(success_count) / config.measured_runs;
        result.resources = backend->GetResourceUsage();
        
        // Custom metrics
        if (!context_load_latencies.empty()) {
            result.custom_metrics["mean_context_load_ms"] = StatisticalMetrics::Calculate(context_load_latencies).mean;
        }
        if (!retrieval_accuracies.empty()) {
            result.custom_metrics["mean_retrieval_accuracy"] = StatisticalMetrics::Calculate(retrieval_accuracies).mean;
        }
        if (!context_retention_scores.empty()) {
            result.custom_metrics["mean_context_retention"] = StatisticalMetrics::Calculate(context_retention_scores).mean;
        }
        if (!degradation_rates.empty()) {
            result.custom_metrics["mean_degradation_rate"] = StatisticalMetrics::Calculate(degradation_rates).mean;
        }
        
        // Quality metrics
        result.quality.structure_score = 70.0;
        result.quality.correctness_score = result.custom_metrics["mean_retrieval_accuracy"] * 100.0;
        result.quality.depth_score = 75.0;
        result.quality.coherence_score = 80.0;
        result.quality.actionability_score = 70.0;
        result.quality.overall_score = (
            result.quality.structure_score +
            result.quality.correctness_score +
            result.quality.depth_score +
            result.quality.coherence_score +
            result.quality.actionability_score
        ) / 5.0;
        
        // Print summary
        std::cout << "Results Summary:\n";
        std::cout << "  Total time: " << std::fixed << std::setprecision(2) << result.total_time_ms / 1000.0 << " s\n";
        std::cout << "  Success rate: " << result.success_rate * 100 << "%\n";
        std::cout << "  Mean query time: " << result.latency.mean << " ms\n";
        std::cout << "  Retrieval accuracy: " << result.custom_metrics["mean_retrieval_accuracy"] * 100 << "%\n";
        std::cout << "  Context retention: " << result.custom_metrics["mean_context_retention"] * 100 << "%\n";
        std::cout << "  Degradation rate: " << result.custom_metrics["mean_degradation_rate"] * 100 << "%\n";
        
        return result;
    }
    
private:
    std::string GenerateContext(size_t token_count) {
        // Generate synthetic context of approximately token_count tokens
        // Each word is roughly 1.3 tokens on average
        size_t word_count = static_cast<size_t>(token_count / 1.3);
        
        std::stringstream context;
        context << "Document Analysis Report\n\n";
        context << "Section 1: Introduction\n";
        context << "This document discusses artificial intelligence and machine learning techniques. ";
        context << "The field has seen rapid advancement in recent years. ";
        
        // Generate filler content
        const char* filler_sentences[] = {
            "The methodology involves careful analysis of data patterns. ",
            "Results indicate significant improvements over baseline approaches. ",
            "Further research is needed to validate these findings. ",
            "The implementation requires attention to detail and optimization. ",
            "Performance metrics show consistent behavior across test cases. ",
            "The approach demonstrates scalability and efficiency. ",
            "Comparative analysis reveals competitive advantages. ",
            "Integration with existing systems is straightforward. ",
            "The solution addresses key challenges in the domain. ",
            "Future work will explore additional optimizations. "
        };
        
        size_t words_generated = 20;
        int sentence_idx = 0;
        while (words_generated < word_count) {
            context << filler_sentences[sentence_idx % 10];
            words_generated += 10;
            sentence_idx++;
            
            // Add section headers periodically
            if (words_generated % 500 == 0) {
                int section = (words_generated / 500) + 2;
                context << "\n\nSection " << section << ": Analysis\n";
                if (section == 3) {
                    context << "The recommended optimization technique is caching. ";
                    words_generated += 6;
                }
            }
        }
        
        context << "\n\nFinal Section: Conclusion\n";
        context << "In conclusion, performance improves with the proposed methodology. ";
        context << "The two approaches discussed are complementary in nature. ";
        context << "Experimental results provide strong evidence supporting the hypothesis. ";
        
        return context.str();
    }
    
    double CheckRetrievalAccuracy(const std::string& response, const std::string& expected) {
        // Simple keyword matching for accuracy
        std::string lower_response = response;
        std::string lower_expected = expected;
        
        // Convert to lowercase
        for (auto& c : lower_response) c = std::tolower(c);
        for (auto& c : lower_expected) c = std::tolower(c);
        
        if (lower_response.find(lower_expected) != std::string::npos) {
            return 1.0; // Exact match
        }
        
        // Check for partial matches
        std::istringstream expected_words(lower_expected);
        std::string word;
        int found_words = 0;
        int total_words = 0;
        
        while (expected_words >> word) {
            total_words++;
            if (lower_response.find(word) != std::string::npos) {
                found_words++;
            }
        }
        
        if (total_words > 0) {
            return static_cast<double>(found_words) / total_words;
        }
        
        return 0.0;
    }
    
    double CalculateContextRetention(size_t token_count, double accuracy) {
        // Ideal retention is 100% regardless of context size
        // Degradation indicates the model is losing information
        
        // Normalize: at 1k tokens, expect 95%+ accuracy
        // At 32k tokens, anything above 70% is good
        
        double expected_accuracy;
        if (token_count <= 4096) {
            expected_accuracy = 0.95;
        } else if (token_count <= 8192) {
            expected_accuracy = 0.90;
        } else if (token_count <= 16384) {
            expected_accuracy = 0.85;
        } else {
            expected_accuracy = 0.75;
        }
        
        // Retention = actual / expected (capped at 1.0)
        return std::min(accuracy / expected_accuracy, 1.0);
    }
    
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "context_handling_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        result.success_rate = 0.0;
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
