// Benchmark 7: Response Quality Benchmark
// Measures response structure, correctness, depth, coherence, actionability
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "json_reporter.hpp"
#include "backends/backend_factory.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <regex>

namespace rawrxd::benchmark {

// ============================================================================
// Response Quality Benchmark
// ============================================================================
class ResponseQualityBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Response Quality"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::RESPONSE_QUALITY; }
    
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
        result.benchmark_id = "response_quality_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Quality test prompts
        struct QualityTest {
            const char* prompt;
            const char* category;
            int expected_min_sections;
            bool expect_code;
            bool expect_steps;
        };
        
        QualityTest tests[] = {
            {
                "Explain how to implement a thread-safe queue in C++. Include code examples.",
                "coding",
                3,
                true,
                true
            },
            {
                "Analyze the time and space complexity of merge sort. Provide a detailed explanation.",
                "analysis",
                4,
                true,
                true
            },
            {
                "What are the tradeoffs between REST and GraphQL APIs? Compare them systematically.",
                "architecture",
                5,
                false,
                true
            },
            {
                "Debug this code: for (int i = 0; i <= array.size(); i++) { cout << array[i]; }",
                "debugging",
                3,
                true,
                true
            },
            {
                "Design a rate limiter for a high-traffic API. Consider scalability and fairness.",
                "design",
                4,
                true,
                true
            },
            {
                "Explain the CAP theorem and its implications for distributed systems.",
                "theory",
                4,
                false,
                true
            },
            {
                "How would you optimize a slow SQL query? Provide a systematic approach.",
                "optimization",
                4,
                true,
                true
            },
            {
                "Describe the differences between processes and threads. When to use each?",
                "systems",
                4,
                false,
                true
            }
        };
        
        std::vector<double> generation_latencies;
        std::vector<double> structure_scores;
        std::vector<double> correctness_scores;
        std::vector<double> depth_scores;
        std::vector<double> coherence_scores;
        std::vector<double> actionability_scores;
        std::vector<double> overall_scores;
        
        int success_count = 0;
        
        Timer total_timer;
        total_timer.Start();
        
        // Warmup
        std::cout << "Warmup phase (" << std::min(config.warmup_runs, 3) << " prompts)...\n";
        for (int i = 0; i < std::min(config.warmup_runs, 3); ++i) {
            backend->Generate(tests[i % 8].prompt, config.max_tokens);
            std::cout << ".";
        }
        std::cout << "\n";
        
        Timer warmup_timer;
        warmup_timer.Start();
        warmup_timer.Stop();
        result.warmup_time_ms = warmup_timer.ElapsedMs();
        
        // Measurement phase
        std::cout << "Measurement phase (" << config.measured_runs << " prompts)...\n";
        for (int i = 0; i < config.measured_runs; ++i) {
            const auto& test = tests[i % 8];
            
            Timer gen_timer;
            gen_timer.Start();
            
            auto response = backend->Generate(test.prompt, config.max_tokens);
            
            gen_timer.Stop();
            double gen_ms = gen_timer.ElapsedMs();
            
            if (!response.empty()) {
                generation_latencies.push_back(gen_ms);
                
                // Analyze response quality
                auto quality = AnalyzeResponseQuality(response, test);
                
                structure_scores.push_back(quality.structure_score);
                correctness_scores.push_back(quality.correctness_score);
                depth_scores.push_back(quality.depth_score);
                coherence_scores.push_back(quality.coherence_score);
                actionability_scores.push_back(quality.actionability_score);
                overall_scores.push_back(quality.overall_score);
                
                success_count++;
                
                if (config.verbose && (i + 1) % 5 == 0) {
                    std::cout << "Prompt " << (i + 1) << ": " << gen_ms << "ms, ";
                    std::cout << "quality=" << quality.overall_score << "/100\n";
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
        if (!generation_latencies.empty()) {
            result.latency = StatisticalMetrics::Calculate(generation_latencies);
            
            // Throughput = responses per second
            std::vector<double> throughput_samples;
            for (double lat : generation_latencies) {
                throughput_samples.push_back(1000.0 / lat);
            }
            result.throughput = StatisticalMetrics::Calculate(throughput_samples);
            result.raw_latencies = generation_latencies;
        }
        
        result.success_rate = static_cast<double>(success_count) / config.measured_runs;
        result.resources = backend->GetResourceUsage();
        
        // Quality metrics
        if (!structure_scores.empty()) {
            result.quality.structure_score = StatisticalMetrics::Calculate(structure_scores).mean;
            result.quality.correctness_score = StatisticalMetrics::Calculate(correctness_scores).mean;
            result.quality.depth_score = StatisticalMetrics::Calculate(depth_scores).mean;
            result.quality.coherence_score = StatisticalMetrics::Calculate(coherence_scores).mean;
            result.quality.actionability_score = StatisticalMetrics::Calculate(actionability_scores).mean;
            result.quality.overall_score = StatisticalMetrics::Calculate(overall_scores).mean;
        }
        
        // Custom metrics
        result.custom_metrics["mean_structure"] = result.quality.structure_score;
        result.custom_metrics["mean_correctness"] = result.quality.correctness_score;
        result.custom_metrics["mean_depth"] = result.quality.depth_score;
        result.custom_metrics["mean_coherence"] = result.quality.coherence_score;
        result.custom_metrics["mean_actionability"] = result.quality.actionability_score;
        
        // Print summary
        std::cout << "Results Summary:\n";
        std::cout << "  Total time: " << std::fixed << std::setprecision(2) << result.total_time_ms / 1000.0 << " s\n";
        std::cout << "  Success rate: " << result.success_rate * 100 << "%\n";
        std::cout << "  Mean generation time: " << result.latency.mean << " ms\n";
        std::cout << "  Structure score: " << result.quality.structure_score << "/100\n";
        std::cout << "  Correctness score: " << result.quality.correctness_score << "/100\n";
        std::cout << "  Depth score: " << result.quality.depth_score << "/100\n";
        std::cout << "  Coherence score: " << result.quality.coherence_score << "/100\n";
        std::cout << "  Actionability score: " << result.quality.actionability_score << "/100\n";
        std::cout << "  OVERALL QUALITY: " << result.quality.overall_score << "/100\n";
        
        return result;
    }
    
private:
    QualityMetrics AnalyzeResponseQuality(const std::string& response, const struct QualityTest& test) {
        QualityMetrics quality;
        
        // Structure score: check for headings, lists, code blocks
        int structure_points = 0;
        
        // Check for headings (markdown style)
        if (response.find("#") != std::string::npos) structure_points += 10;
        if (response.find("##") != std::string::npos) structure_points += 10;
        
        // Check for lists
        if (response.find("- ") != std::string::npos || response.find("* ") != std::string::npos) {
            structure_points += 15;
        }
        if (response.find("1.") != std::string::npos) structure_points += 10;
        
        // Check for code blocks
        if (response.find("```") != std::string::npos) structure_points += 20;
        if (response.find("`") != std::string::npos) structure_points += 10;
        
        // Check for sections
        int section_count = 0;
        std::regex section_regex("(?:^|\n)(?:#+\\s|\\d+\\.\\s|[A-Z][A-Za-z\\s]{2,50}:)");
        auto sections_begin = std::sregex_iterator(response.begin(), response.end(), section_regex);
        auto sections_end = std::sregex_iterator();
        section_count = std::distance(sections_begin, sections_end);
        structure_points += std::min(section_count * 5, 25);
        
        quality.structure_score = std::min(structure_points, 100);
        
        // Correctness score: check for relevant keywords
        int correctness_points = 50; // Base score
        std::vector<std::string> positive_indicators = {
            "correct", "properly", "should", "must", "important", "note", "remember"
        };
        for (const auto& indicator : positive_indicators) {
            if (response.find(indicator) != std::string::npos) {
                correctness_points += 5;
            }
        }
        quality.correctness_score = std::min(correctness_points, 100);
        
        // Depth score: check response length and detail
        int word_count = 0;
        std::istringstream iss(response);
        std::string word;
        while (iss >> word) word_count++;
        
        if (word_count > 200) depth_points += 30;
        else if (word_count > 100) depth_points += 20;
        else if (word_count > 50) depth_points += 10;
        
        // Check for detailed explanations
        std::vector<std::string> depth_indicators = {
            "because", "therefore", "however", "although", "furthermore", "moreover",
            "example", "specifically", "detail", "implementation"
        };
        int depth_points = word_count > 50 ? 20 : 10;
        for (const auto& indicator : depth_indicators) {
            if (response.find(indicator) != std::string::npos) {
                depth_points += 5;
            }
        }
        quality.depth_score = std::min(depth_points, 100);
        
        // Coherence score: check for transition words and flow
        int coherence_points = 40; // Base
        std::vector<std::string> coherence_indicators = {
            "first", "second", "third", "next", "then", "finally",
            "however", "therefore", "thus", "consequently", "in addition"
        };
        for (const auto& indicator : coherence_indicators) {
            if (response.find(indicator) != std::string::npos) {
                coherence_points += 5;
            }
        }
        quality.coherence_score = std::min(coherence_points, 100);
        
        // Actionability score: check for actionable content
        int actionability_points = 30; // Base
        std::vector<std::string> action_indicators = {
            "step", "implement", "create", "add", "modify", "change",
            "use", "call", "define", "declare", "include"
        };
        for (const auto& indicator : action_indicators) {
            if (response.find(indicator) != std::string::npos) {
                actionability_points += 5;
            }
        }
        if (test.expect_code && response.find("```") != std::string::npos) {
            actionability_points += 20;
        }
        quality.actionability_score = std::min(actionability_points, 100);
        
        // Overall score
        quality.overall_score = (
            quality.structure_score +
            quality.correctness_score +
            quality.depth_score +
            quality.coherence_score +
            quality.actionability_score
        ) / 5.0;
        
        return quality;
    }
    
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "response_quality_" + std::string(BackendTypeToString(config.backend));
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
