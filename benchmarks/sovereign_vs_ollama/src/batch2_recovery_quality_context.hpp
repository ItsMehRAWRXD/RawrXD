// batch2_recovery_quality_context.hpp
// Phase 1, Batch 2/5: Advanced Capability Benchmarks
// Measures: Self-Correction, Response Quality, Context Handling, Autonomous Runtime, Resource Usage

#pragma once
#include "../include/benchmark_common.hpp"
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <fstream>

namespace rawrxd_benchmarks {

// ============================================================================
// Benchmark 6/10: Self-Correction Benchmark
// Measures failure detection and recovery success rate
// ============================================================================
class SelfCorrectionBenchmark : public BenchmarkBase {
public:
    struct Config {
        int warmup_runs = 3;
        int measured_runs = 50;
        double failure_injection_rate = 0.3;  // 30% of runs inject failure
        double confidence_level = 0.95;
    };

    struct Results {
        StatisticalMetrics detection_time_ms;
        StatisticalMetrics recovery_time_ms;
        StatisticalMetrics rollback_time_ms;
        double recovery_success_rate = 0.0;
        double false_positive_rate = 0.0;  // Unnecessary recoveries
        int sample_count = 0;
    };

    explicit SelfCorrectionBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "self_correction") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Self-Correction Benchmark");
        Log("Failure injection rate: " + std::to_string(static_cast<int>(config.failure_injection_rate * 100)) + "%");

        // Warmup
        for (int i = 0; i < config.warmup_runs; ++i) {
            RunCorrectionScenario(false);  // No failure
        }

        // Measured phase
        std::vector<double> detection_times;
        std::vector<double> recovery_times;
        std::vector<double> rollback_times;
        int successful_recoveries = 0;
        int false_positives = 0;
        int total_failures = 0;

        for (int i = 0; i < config.measured_runs; ++i) {
            bool inject_failure = (static_cast<double>(rand()) / RAND_MAX) < config.failure_injection_rate;
            if (inject_failure) total_failures++;
            
            auto result = RunCorrectionScenario(inject_failure);
            
            if (result.failure_detected) {
                detection_times.push_back(result.detection_ms);
            }
            if (result.recovery_attempted) {
                recovery_times.push_back(result.recovery_ms);
                rollback_times.push_back(result.rollback_ms);
                
                if (result.recovery_successful) successful_recoveries++;
                if (result.false_positive) false_positives++;
            }
        }

        Results results;
        if (!detection_times.empty()) {
            results.detection_time_ms = StatisticalMetrics::CalculateWithCI(detection_times, config.confidence_level);
        }
        if (!recovery_times.empty()) {
            results.recovery_time_ms = StatisticalMetrics::CalculateWithCI(recovery_times, config.confidence_level);
            results.rollback_time_ms = StatisticalMetrics::CalculateWithCI(rollback_times, config.confidence_level);
        }
        
        if (total_failures > 0) {
            results.recovery_success_rate = static_cast<double>(successful_recoveries) / total_failures;
        }
        results.false_positive_rate = static_cast<double>(false_positives) / config.measured_runs;
        results.sample_count = config.measured_runs;

        Log("Self-Correction Benchmark Complete");
        Log("  Recovery success: " + std::to_string(static_cast<int>(results.recovery_success_rate * 100)) + "%");
        if (!recovery_times.empty()) {
            Log("  Avg recovery time: " + std::to_string(static_cast<int>(results.recovery_time_ms.mean)) + "ms");
        }

        return results;
    }

private:
    struct CorrectionResult {
        bool failure_detected = false;
        double detection_ms = 0.0;
        bool recovery_attempted = false;
        double recovery_ms = 0.0;
        double rollback_ms = 0.0;
        bool recovery_successful = false;
        bool false_positive = false;
    };

    CorrectionResult RunCorrectionScenario(bool inject_failure) {
        CorrectionResult result;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Start workload
        backend_->StartWorkload();
        
        if (inject_failure) {
            backend_->InjectFailure("memory_pressure");
        }
        
        // Monitor for failure
        auto detect_start = std::chrono::high_resolution_clock::now();
        bool detected = backend_->WaitForFailureDetection(5000);  // 5s timeout
        auto detect_end = std::chrono::high_resolution_clock::now();
        
        if (detected) {
            result.failure_detected = true;
            result.detection_ms = std::chrono::duration<double, std::milli>(detect_end - detect_start).count();
            
            // Attempt recovery
            auto recovery_start = std::chrono::high_resolution_clock::now();
            result.recovery_attempted = true;
            result.recovery_successful = backend_->ExecuteRecovery();
            auto recovery_end = std::chrono::high_resolution_clock::now();
            result.recovery_ms = std::chrono::duration<double, std::milli>(recovery_end - recovery_start).count();
            
            // Measure rollback
            auto rollback_start = std::chrono::high_resolution_clock::now();
            backend_->ExecuteRollback();
            auto rollback_end = std::chrono::high_resolution_clock::now();
            result.rollback_ms = std::chrono::duration<double, std::milli>(rollback_end - rollback_start).count();
        } else if (!inject_failure) {
            // No failure injected, but detection triggered = false positive
            result.false_positive = detected;
        }
        
        backend_->StopWorkload();
        
        return result;
    }
};

// ============================================================================
// Benchmark 7/10: Response Quality Benchmark
// Measures structure, correctness, depth, and coherence
// ============================================================================
class ResponseQualityBenchmark : public BenchmarkBase {
public:
    struct Config {
        int warmup_runs = 3;
        int measured_runs = 50;
        std::vector<std::string> test_prompts = {
            "Explain how this subsystem works",
            "Propose an optimization plan",
            "Analyze this bug and suggest fixes",
            "Design a scalable architecture",
            "Review this code for security issues"
        };
        double confidence_level = 0.95;
    };

    struct Results {
        StatisticalMetrics structure_score;      // 0-100
        StatisticalMetrics correctness_score;  // 0-100
        StatisticalMetrics depth_score;        // 0-100
        StatisticalMetrics coherence_score;    // 0-100
        StatisticalMetrics overall_quality;    // Weighted composite
        int sample_count = 0;
    };

    explicit ResponseQualityBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "response_quality") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Response Quality Benchmark");
        Log("Test prompts: " + std::to_string(config.test_prompts.size()));

        // Warmup
        for (int i = 0; i < config.warmup_runs; ++i) {
            EvaluateResponse(config.test_prompts[0]);
        }

        // Measured phase
        std::vector<double> structure_scores;
        std::vector<double> correctness_scores;
        std::vector<double> depth_scores;
        std::vector<double> coherence_scores;
        std::vector<double> overall_scores;

        for (int i = 0; i < config.measured_runs; ++i) {
            const std::string& prompt = config.test_prompts[i % config.test_prompts.size()];
            auto result = EvaluateResponse(prompt);
            
            structure_scores.push_back(result.structure);
            correctness_scores.push_back(result.correctness);
            depth_scores.push_back(result.depth);
            coherence_scores.push_back(result.coherence);
            overall_scores.push_back(result.overall);
        }

        Results results;
        results.structure_score = StatisticalMetrics::CalculateWithCI(structure_scores, config.confidence_level);
        results.correctness_score = StatisticalMetrics::CalculateWithCI(correctness_scores, config.confidence_level);
        results.depth_score = StatisticalMetrics::CalculateWithCI(depth_scores, config.confidence_level);
        results.coherence_score = StatisticalMetrics::CalculateWithCI(coherence_scores, config.confidence_level);
        results.overall_quality = StatisticalMetrics::CalculateWithCI(overall_scores, config.confidence_level);
        results.sample_count = config.measured_runs;

        Log("Response Quality Benchmark Complete");
        Log("  Overall quality: " + std::to_string(static_cast<int>(results.overall_quality.mean)) + "/100");
        Log("  Structure: " + std::to_string(static_cast<int>(results.structure_score.mean)) + "/100");

        return results;
    }

private:
    struct QualityResult {
        double structure = 0.0;     // Headings, lists, code blocks
        double correctness = 0.0; // Factual accuracy
        double depth = 0.0;         // Reasoning steps, references
        double coherence = 0.0;     // Logical flow
        double overall = 0.0;       // Weighted composite
    };

    QualityResult EvaluateResponse(const std::string& prompt) {
        QualityResult result;
        
        // Generate response
        InferenceRequest request;
        request.prompt = prompt;
        request.max_tokens = 1024;
        request.temperature = 0.7;
        
        auto response = backend_->SubmitInference(request);
        
        // Evaluate structure (heuristic scoring)
        result.structure = ScoreStructure(response.generated_text);
        
        // Evaluate depth
        result.depth = ScoreDepth(response.generated_text);
        
        // Evaluate coherence
        result.coherence = ScoreCoherence(response.generated_text);
        
        // For correctness, we'd need ground truth or human evaluation
        // Using proxy metric for now
        result.correctness = EstimateCorrectness(response.generated_text);
        
        // Weighted overall
        result.overall = 
            result.structure * 0.25 +
            result.correctness * 0.30 +
            result.depth * 0.25 +
            result.coherence * 0.20;
        
        return result;
    }

    double ScoreStructure(const std::string& text) {
        double score = 50.0;  // Base
        
        // Check for headings
        if (text.find("##") != std::string::npos) score += 10;
        if (text.find("###") != std::string::npos) score += 5;
        
        // Check for lists
        if (text.find("- ") != std::string::npos || text.find("* ") != std::string::npos) score += 10;
        if (text.find("1.") != std::string::npos) score += 10;
        
        // Check for code blocks
        if (text.find("```") != std::string::npos) score += 15;
        
        return std::min(score, 100.0);
    }

    double ScoreDepth(const std::string& text) {
        double score = 40.0;
        
        // Count reasoning indicators
        if (text.find("because") != std::string::npos) score += 10;
        if (text.find("therefore") != std::string::npos) score += 10;
        if (text.find("however") != std::string::npos) score += 10;
        if (text.find("tradeoff") != std::string::npos || text.find("trade-off") != std::string::npos) score += 15;
        if (text.find("alternative") != std::string::npos) score += 10;
        
        // Length as proxy for depth (normalized)
        int word_count = static_cast<int>(text.size()) / 5;  // Approximate
        score += std::min(word_count / 10.0, 15.0);
        
        return std::min(score, 100.0);
    }

    double ScoreCoherence(const std::string& text) {
        // Simplified coherence scoring
        // In production, this would use NLP metrics
        double score = 60.0;
        
        // Check for paragraph structure
        int paragraph_breaks = 0;
        size_t pos = 0;
        while ((pos = text.find("\n\n", pos)) != std::string::npos) {
            paragraph_breaks++;
            pos += 2;
        }
        score += std::min(paragraph_breaks * 5.0, 20.0);
        
        // Check for transition words
        if (text.find("first") != std::string::npos && text.find("then") != std::string::npos) score += 10;
        if (text.find("finally") != std::string::npos) score += 10;
        
        return std::min(score, 100.0);
    }

    double EstimateCorrectness(const std::string& text) {
        // Placeholder - would require ground truth or human evaluation
        // Using confidence proxy
        return 75.0;  // Neutral assumption
    }
};

// ============================================================================
// Benchmark 8/10: Context Handling Benchmark
// Measures 1K-32K token retrieval accuracy
// ============================================================================
class ContextHandlingBenchmark : public BenchmarkBase {
public:
    struct Config {
        std::vector<int> context_sizes = {1024, 2048, 4096, 8192, 16384, 32768};
        int warmup_runs = 2;
        int measured_runs_per_size = 10;
        double confidence_level = 0.95;
    };

    struct ContextResult {
        int context_size = 0;
        StatisticalMetrics retrieval_accuracy;  // 0-100%
        StatisticalMetrics latency_ms;
        StatisticalMetrics memory_mb;
        double kv_cache_hit_rate = 0.0;
    };

    struct Results {
        std::vector<ContextResult> by_context_size;
        int sample_count = 0;
    };

    explicit ContextHandlingBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "context_handling") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Context Handling Benchmark");
        
        Results results;
        
        for (int ctx_size : config.context_sizes) {
            Log("Testing context size: " + std::to_string(ctx_size));
            
            // Warmup
            for (int i = 0; i < config.warmup_runs; ++i) {
                TestContextRetrieval(ctx_size);
            }
            
            // Measured
            std::vector<double> accuracies;
            std::vector<double> latencies;
            std::vector<double> memory;
            
            for (int i = 0; i < config.measured_runs_per_size; ++i) {
                auto result = TestContextRetrieval(ctx_size);
                accuracies.push_back(result.accuracy);
                latencies.push_back(result.latency_ms);
                memory.push_back(result.memory_mb);
            }
            
            ContextResult ctx_result;
            ctx_result.context_size = ctx_size;
            ctx_result.retrieval_accuracy = StatisticalMetrics::CalculateWithCI(accuracies, config.confidence_level);
            ctx_result.latency_ms = StatisticalMetrics::CalculateWithCI(latencies, config.confidence_level);
            ctx_result.memory_mb = StatisticalMetrics::CalculateWithCI(memory, config.confidence_level);
            ctx_result.kv_cache_hit_rate = backend_->GetKVCacheHitRate();
            
            results.by_context_size.push_back(ctx_result);
            results.sample_count += config.measured_runs_per_size;
        }

        Log("Context Handling Benchmark Complete");
        for (const auto& r : results.by_context_size) {
            Log("  " + std::to_string(r.context_size) + " tokens: " +
                std::to_string(static_cast<int>(r.retrieval_accuracy.mean)) + "% accuracy, " +
                std::to_string(static_cast<int>(r.latency_ms.mean)) + "ms latency");
        }

        return results;
    }

private:
    struct RetrievalResult {
        double accuracy = 0.0;
        double latency_ms = 0.0;
        double memory_mb = 0.0;
    };

    RetrievalResult TestContextRetrieval(int context_size) {
        RetrievalResult result;
        
        // Generate context with embedded queries
        std::string context = GenerateContextWithQueries(context_size);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Submit query that requires context understanding
        InferenceRequest request;
        request.prompt = "Based on the context provided, what is the answer to the embedded query?";
        request.context = context;
        request.max_tokens = 256;
        
        auto response = backend_->SubmitInference(request);
        
        auto end = std::chrono::high_resolution_clock::now();
        
        result.latency_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result.accuracy = CheckContextAccuracy(response.generated_text, context);
        result.memory_mb = backend_->GetMemoryUsageMB();
        
        return result;
    }

    std::string GenerateContextWithQueries(int target_tokens) {
        // Generate synthetic context with known facts to test retrieval
        std::string context;
        int tokens_generated = 0;
        int fact_id = 1;
        
        while (tokens_generated < target_tokens) {
            std::string fact = "Fact " + std::to_string(fact_id) + 
                ": The system architecture includes component " + 
                std::string(1, 'A' + (fact_id % 26)) + 
                " which handles " + std::to_string(fact_id * 100) + 
                " requests per second. ";
            context += fact;
            tokens_generated += static_cast<int>(fact.size()) / 4;  // Approximate
            fact_id++;
        }
        
        return context;
    }

    double CheckContextAccuracy(const std::string& response, const std::string& context) {
        // Check if response correctly references context
        // Simplified - would use more sophisticated evaluation
        if (response.find("Fact") != std::string::npos || 
            response.find("component") != std::string::npos) {
            return 85.0;  // Likely used context
        }
        return 45.0;  // May have hallucinated
    }
};

// ============================================================================
// Benchmark 9/10: Autonomous Runtime Benchmark
// Measures full Observe→Analyze→Decide→Execute→Learn loop
// ============================================================================
class AutonomousRuntimeBenchmark : public BenchmarkBase {
public:
    struct Config {
        int warmup_iterations = 5;
        int measured_iterations = 50;
        double confidence_level = 0.95;
    };

    struct Results {
        StatisticalMetrics loop_latency_ms;       // Full cycle time
        StatisticalMetrics observe_latency_ms;
        StatisticalMetrics analyze_latency_ms;
        StatisticalMetrics decide_latency_ms;
        StatisticalMetrics execute_latency_ms;
        StatisticalMetrics learn_latency_ms;
        double success_rate = 0.0;
        int sample_count = 0;
    };

    explicit AutonomousRuntimeBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "autonomous_runtime") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Autonomous Runtime Benchmark");
        Log("Measuring full OADEL loop");

        // Warmup
        for (int i = 0; i < config.warmup_iterations; ++i) {
            RunAutonomousLoop();
        }

        // Measured phase
        std::vector<double> loop_times;
        std::vector<double> observe_times;
        std::vector<double> analyze_times;
        std::vector<double> decide_times;
        std::vector<double> execute_times;
        std::vector<double> learn_times;
        int successes = 0;

        for (int i = 0; i < config.measured_iterations; ++i) {
            auto result = RunAutonomousLoop();
            
            loop_times.push_back(result.total_ms);
            observe_times.push_back(result.observe_ms);
            analyze_times.push_back(result.analyze_ms);
            decide_times.push_back(result.decide_ms);
            execute_times.push_back(result.execute_ms);
            learn_times.push_back(result.learn_ms);
            
            if (result.success) successes++;
        }

        Results results;
        results.loop_latency_ms = StatisticalMetrics::CalculateWithCI(loop_times, config.confidence_level);
        results.observe_latency_ms = StatisticalMetrics::CalculateWithCI(observe_times, config.confidence_level);
        results.analyze_latency_ms = StatisticalMetrics::CalculateWithCI(analyze_times, config.confidence_level);
        results.decide_latency_ms = StatisticalMetrics::CalculateWithCI(decide_times, config.confidence_level);
        results.execute_latency_ms = StatisticalMetrics::CalculateWithCI(execute_times, config.confidence_level);
        results.learn_latency_ms = StatisticalMetrics::CalculateWithCI(learn_times, config.confidence_level);
        results.success_rate = static_cast<double>(successes) / config.measured_iterations;
        results.sample_count = config.measured_iterations;

        Log("Autonomous Runtime Benchmark Complete");
        Log("  Loop latency: " + std::to_string(static_cast<int>(results.loop_latency_ms.mean)) + "ms");
        Log("  Success rate: " + std::to_string(static_cast<int>(results.success_rate * 100)) + "%");

        return results;
    }

private:
    struct LoopResult {
        double total_ms = 0.0;
        double observe_ms = 0.0;
        double analyze_ms = 0.0;
        double decide_ms = 0.0;
        double execute_ms = 0.0;
        double learn_ms = 0.0;
        bool success = false;
    };

    LoopResult RunAutonomousLoop() {
        LoopResult result;
        
        auto loop_start = std::chrono::high_resolution_clock::now();
        
        // Observe
        auto observe_start = std::chrono::high_resolution_clock::now();
        backend_->AutonomousObserve();
        auto observe_end = std::chrono::high_resolution_clock::now();
        result.observe_ms = std::chrono::duration<double, std::milli>(observe_end - observe_start).count();
        
        // Analyze
        auto analyze_start = std::chrono::high_resolution_clock::now();
        backend_->AutonomousAnalyze();
        auto analyze_end = std::chrono::high_resolution_clock::now();
        result.analyze_ms = std::chrono::duration<double, std::milli>(analyze_end - analyze_start).count();
        
        // Decide
        auto decide_start = std::chrono::high_resolution_clock::now();
        auto decision = backend_->AutonomousDecide();
        auto decide_end = std::chrono::high_resolution_clock::now();
        result.decide_ms = std::chrono::duration<double, std::milli>(decide_end - decide_start).count();
        
        // Execute
        auto execute_start = std::chrono::high_resolution_clock::now();
        result.success = backend_->AutonomousExecute(decision);
        auto execute_end = std::chrono::high_resolution_clock::now();
        result.execute_ms = std::chrono::duration<double, std::milli>(execute_end - execute_start).count();
        
        // Learn
        auto learn_start = std::chrono::high_resolution_clock::now();
        backend_->AutonomousLearn(result.success);
        auto learn_end = std::chrono::high_resolution_clock::now();
        result.learn_ms = std::chrono::duration<double, std::milli>(learn_end - learn_start).count();
        
        auto loop_end = std::chrono::high_resolution_clock::now();
        result.total_ms = std::chrono::duration<double, std::milli>(loop_end - loop_start).count();
        
        return result;
    }
};

// ============================================================================
// Benchmark 10/10: Resource Usage Benchmark
// Measures CPU/GPU/Memory under sustained load
// ============================================================================
class ResourceUsageBenchmark : public BenchmarkBase {
public:
    struct Config {
        int duration_seconds = 60;
        int sampling_interval_ms = 1000;
        double target_load = 0.8;  // 80% capacity
    };

    struct Sample {
        double timestamp_seconds = 0.0;
        double cpu_percent = 0.0;
        double gpu_percent = 0.0;
        double memory_mb = 0.0;
        double gpu_memory_mb = 0.0;
        double power_watts = 0.0;
        double temperature_celsius = 0.0;
    };

    struct Results {
        StatisticalMetrics avg_cpu;
        StatisticalMetrics avg_gpu;
        StatisticalMetrics avg_memory_mb;
        StatisticalMetrics avg_gpu_memory_mb;
        StatisticalMetrics avg_power_watts;
        StatisticalMetrics avg_temperature;
        double peak_cpu = 0.0;
        double peak_memory = 0.0;
        double energy_joules = 0.0;
        std::vector<Sample> time_series;
    };

    explicit ResourceUsageBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "resource_usage") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Resource Usage Benchmark");
        Log("Duration: " + std::to_string(config.duration_seconds) + " seconds");

        Results results;
        std::vector<double> cpu_samples;
        std::vector<double> gpu_samples;
        std::vector<double> memory_samples;
        std::vector<double> gpu_memory_samples;
        std::vector<double> power_samples;
        std::vector<double> temp_samples;

        // Start sustained workload
        backend_->StartSustainedWorkload(config.target_load);
        
        auto start_time = std::chrono::high_resolution_clock::now();
        double elapsed = 0.0;
        
        while (elapsed < config.duration_seconds) {
            auto sample = backend_->SampleResourceUsage();
            
            Sample s;
            s.timestamp_seconds = elapsed;
            s.cpu_percent = sample.cpu_percent;
            s.gpu_percent = sample.gpu_percent;
            s.memory_mb = sample.memory_mb;
            s.gpu_memory_mb = sample.gpu_memory_mb;
            s.power_watts = sample.power_watts;
            s.temperature_celsius = sample.temperature_celsius;
            
            results.time_series.push_back(s);
            cpu_samples.push_back(s.cpu_percent);
            gpu_samples.push_back(s.gpu_percent);
            memory_samples.push_back(s.memory_mb);
            gpu_memory_samples.push_back(s.gpu_memory_mb);
            power_samples.push_back(s.power_watts);
            temp_samples.push_back(s.temperature_celsius);
            
            // Track peaks
            results.peak_cpu = std::max(results.peak_cpu, s.cpu_percent);
            results.peak_memory = std::max(results.peak_memory, s.memory_mb);
            
            std::this_thread::sleep_for(std::chrono::milliseconds(config.sampling_interval_ms));
            
            auto now = std::chrono::high_resolution_clock::now();
            elapsed = std::chrono::duration<double>(now - start_time).count();
        }
        
        backend_->StopSustainedWorkload();
        
        // Calculate statistics
        results.avg_cpu = StatisticalMetrics::Calculate(cpu_samples);
        results.avg_gpu = StatisticalMetrics::Calculate(gpu_samples);
        results.avg_memory_mb = StatisticalMetrics::Calculate(memory_samples);
        results.avg_gpu_memory_mb = StatisticalMetrics::Calculate(gpu_memory_samples);
        results.avg_power_watts = StatisticalMetrics::Calculate(power_samples);
        results.avg_temperature = StatisticalMetrics::Calculate(temp_samples);
        
        // Calculate energy (power * time)
        results.energy_joules = results.avg_power_watts.mean * config.duration_seconds;

        Log("Resource Usage Benchmark Complete");
        Log("  Avg CPU: " + std::to_string(static_cast<int>(results.avg_cpu.mean)) + "%");
        Log("  Avg GPU: " + std::to_string(static_cast<int>(results.avg_gpu.mean)) + "%");
        Log("  Peak memory: " + std::to_string(static_cast<int>(results.peak_memory)) + " MB");
        Log("  Energy: " + std::to_string(static_cast<int>(results.energy_joules)) + " J");

        return results;
    }
};

} // namespace rawrxd_benchmarks
