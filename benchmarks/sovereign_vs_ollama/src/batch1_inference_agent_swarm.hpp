// batch1_inference_agent_swarm.hpp
// Phase 1, Batch 1/5: Core Performance Benchmarks
// Measures: Inference TPS, Agent Spawn, Swarm16, SEG Execution, Decision Making

#pragma once
#include "../include/benchmark_common.hpp"
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>

namespace rawrxd_benchmarks {

// ============================================================================
// Benchmark 1/10: Inference TPS Benchmark
// Measures raw token throughput for prompt processing and generation
// ============================================================================
class InferenceTPSBenchmark : public BenchmarkBase {
public:
    struct Config {
        std::string model_name = "phi-3-mini-Q4";
        int prompt_tokens = 512;
        int max_generation_tokens = 256;
        int warmup_runs = 5;
        int measured_runs = 50;
        double confidence_level = 0.95;
    };

    struct Results {
        StatisticalMetrics prompt_tps;      // Tokens per second (prompt processing)
        StatisticalMetrics generation_tps;  // Tokens per second (generation)
        StatisticalMetrics ttft;            // Time to first token
        StatisticalMetrics total_latency;   // Total request latency
        double kv_cache_efficiency = 0.0;
        int sample_count = 0;
    };

    explicit InferenceTPSBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "inference_tps") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Inference TPS Benchmark");
        Log("Model: " + config.model_name);
        Log("Prompt tokens: " + std::to_string(config.prompt_tokens));
        Log("Max generation: " + std::to_string(config.max_generation_tokens));

        // Warmup phase
        Log("Warming up with " + std::to_string(config.warmup_runs) + " runs...");
        for (int i = 0; i < config.warmup_runs; ++i) {
            RunSingleInference(config.prompt_tokens, config.max_generation_tokens);
        }

        // Measured phase
        Log("Measuring " + std::to_string(config.measured_runs) + " runs...");
        std::vector<double> prompt_tps_samples;
        std::vector<double> generation_tps_samples;
        std::vector<double> ttft_samples;
        std::vector<double> latency_samples;

        for (int i = 0; i < config.measured_runs; ++i) {
            auto result = RunSingleInference(config.prompt_tokens, config.max_generation_tokens);
            prompt_tps_samples.push_back(result.prompt_tps);
            generation_tps_samples.push_back(result.generation_tps);
            ttft_samples.push_back(result.ttft_ms);
            latency_samples.push_back(result.total_latency_ms);
            
            if (i % 10 == 0) {
                Log("  Progress: " + std::to_string(i) + "/" + std::to_string(config.measured_runs));
            }
        }

        Results results;
        results.prompt_tps = StatisticalMetrics::CalculateWithCI(prompt_tps_samples, config.confidence_level);
        results.generation_tps = StatisticalMetrics::CalculateWithCI(generation_tps_samples, config.confidence_level);
        results.ttft = StatisticalMetrics::CalculateWithCI(ttft_samples, config.confidence_level);
        results.total_latency = StatisticalMetrics::CalculateWithCI(latency_samples, config.confidence_level);
        results.sample_count = config.measured_runs;

        Log("Inference TPS Benchmark Complete");
        Log("  Prompt TPS: " + std::to_string(static_cast<int>(results.prompt_tps.mean)) + " ± " + 
            std::to_string(static_cast<int>(results.prompt_tps.stddev)));
        Log("  Generation TPS: " + std::to_string(static_cast<int>(results.generation_tps.mean)) + " ± " +
            std::to_string(static_cast<int>(results.generation_tps.stddev)));

        return results;
    }

private:
    struct SingleResult {
        double prompt_tps = 0.0;
        double generation_tps = 0.0;
        double ttft_ms = 0.0;
        double total_latency_ms = 0.0;
    };

    SingleResult RunSingleInference(int prompt_tokens, int max_gen_tokens) {
        SingleResult result;
        
        // Generate test prompt of specified token length
        std::string prompt = GenerateTestPrompt(prompt_tokens);
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Submit inference request
        InferenceRequest request;
        request.prompt = prompt;
        request.max_tokens = max_gen_tokens;
        request.temperature = 0.0;  // Deterministic
        
        auto response = backend_->SubmitInference(request);
        
        auto end = std::chrono::high_resolution_clock::now();
        
        // Calculate metrics
        double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
        double prompt_time_ms = response.prompt_eval_time_ms;
        double generation_time_ms = response.generation_time_ms;
        
        result.prompt_tps = response.prompt_tokens_evaluated / (prompt_time_ms / 1000.0);
        result.generation_tps = response.tokens_generated / (generation_time_ms / 1000.0);
        result.ttft_ms = response.time_to_first_token_ms;
        result.total_latency_ms = total_ms;
        
        return result;
    }

    std::string GenerateTestPrompt(int target_tokens) {
        // Generate a prompt that will tokenize to approximately target_tokens
        // Using a repetitive pattern for consistency
        std::string base = "The quick brown fox jumps over the lazy dog. ";
        int tokens_per_sentence = 10;  // Approximate
        int repetitions = target_tokens / tokens_per_sentence;
        
        std::string prompt;
        for (int i = 0; i < repetitions; ++i) {
            prompt += base;
        }
        return prompt;
    }
};

// ============================================================================
// Benchmark 2/10: Agent Spawn Benchmark
// Measures agent lifecycle performance (creation, initialization, teardown)
// ============================================================================
class AgentSpawnBenchmark : public BenchmarkBase {
public:
    struct Config {
        int warmup_spawns = 10;
        int measured_spawns = 100;
        int concurrent_agents = 16;
        double confidence_level = 0.95;
    };

    struct Results {
        StatisticalMetrics spawn_latency_ms;      // Time to create and initialize
        StatisticalMetrics teardown_latency_ms;   // Time to destroy
        StatisticalMetrics total_lifecycle_ms;  // Full lifecycle
        double spawn_rate_per_second = 0.0;       // Agents spawned per second
        int sample_count = 0;
    };

    explicit AgentSpawnBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "agent_spawn") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Agent Spawn Benchmark");
        Log("Concurrent agents: " + std::to_string(config.concurrent_agents));

        // Warmup
        Log("Warming up with " + std::to_string(config.warmup_spawns) + " spawns...");
        for (int i = 0; i < config.warmup_spawns; ++i) {
            SpawnAndTeardownAgent();
        }

        // Measured phase
        Log("Measuring " + std::to_string(config.measured_spawns) + " spawns...");
        std::vector<double> spawn_times;
        std::vector<double> teardown_times;
        std::vector<double> lifecycle_times;

        auto batch_start = std::chrono::high_resolution_clock::now();

        for (int i = 0; i < config.measured_spawns; ++i) {
            auto result = SpawnAndTeardownAgent();
            spawn_times.push_back(result.spawn_ms);
            teardown_times.push_back(result.teardown_ms);
            lifecycle_times.push_back(result.total_ms);
        }

        auto batch_end = std::chrono::high_resolution_clock::now();
        double batch_seconds = std::chrono::duration<double>(batch_end - batch_start).count();

        Results results;
        results.spawn_latency_ms = StatisticalMetrics::CalculateWithCI(spawn_times, config.confidence_level);
        results.teardown_latency_ms = StatisticalMetrics::CalculateWithCI(teardown_times, config.confidence_level);
        results.total_lifecycle_ms = StatisticalMetrics::CalculateWithCI(lifecycle_times, config.confidence_level);
        results.spawn_rate_per_second = config.measured_spawns / batch_seconds;
        results.sample_count = config.measured_spawns;

        Log("Agent Spawn Benchmark Complete");
        Log("  Spawn latency: " + std::to_string(static_cast<int>(results.spawn_latency_ms.mean)) + "ms");
        Log("  Spawn rate: " + std::to_string(static_cast<int>(results.spawn_rate_per_second)) + " agents/sec");

        return results;
    }

private:
    struct SingleResult {
        double spawn_ms = 0.0;
        double teardown_ms = 0.0;
        double total_ms = 0.0;
    };

    SingleResult SpawnAndTeardownAgent() {
        SingleResult result;
        
        // Spawn
        auto spawn_start = std::chrono::high_resolution_clock::now();
        std::string agent_id = backend_->SpawnAgent("benchmark_agent");
        auto spawn_end = std::chrono::high_resolution_clock::now();
        result.spawn_ms = std::chrono::duration<double, std::milli>(spawn_end - spawn_start).count();
        
        // Brief operation simulation
        std::this_thread::sleep_for(std::chrono::milliseconds(1));
        
        // Teardown
        auto teardown_start = std::chrono::high_resolution_clock::now();
        backend_->TeardownAgent(agent_id);
        auto teardown_end = std::chrono::high_resolution_clock::now();
        result.teardown_ms = std::chrono::duration<double, std::milli>(teardown_end - teardown_start).count();
        
        result.total_ms = result.spawn_ms + result.teardown_ms;
        
        return result;
    }
};

// ============================================================================
// Benchmark 3/10: Swarm16 Benchmark
// Measures 16-agent parallel execution throughput and efficiency
// ============================================================================
class Swarm16Benchmark : public BenchmarkBase {
public:
    struct Config {
        int num_agents = 16;
        int tasks_per_agent = 10;
        int warmup_rounds = 2;
        int measured_rounds = 10;
        double confidence_level = 0.95;
    };

    struct Results {
        StatisticalMetrics tasks_per_second;
        StatisticalMetrics latency_per_task_ms;
        StatisticalMetrics parallel_efficiency;  // 0.0-1.0
        double ideal_tps = 0.0;  // Theoretical max
        double actual_tps = 0.0; // Achieved
        int sample_count = 0;
    };

    explicit Swarm16Benchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "swarm16") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Swarm16 Benchmark");
        Log("Agents: " + std::to_string(config.num_agents));
        Log("Tasks per agent: " + std::to_string(config.tasks_per_agent));

        // Warmup
        Log("Warming up with " + std::to_string(config.warmup_rounds) + " rounds...");
        for (int i = 0; i < config.warmup_rounds; ++i) {
            RunSwarmRound(config.num_agents, config.tasks_per_agent);
        }

        // Measured phase
        Log("Measuring " + std::to_string(config.measured_rounds) + " rounds...");
        std::vector<double> tps_samples;
        std::vector<double> latency_samples;
        std::vector<double> efficiency_samples;

        for (int i = 0; i < config.measured_rounds; ++i) {
            auto result = RunSwarmRound(config.num_agents, config.tasks_per_agent);
            tps_samples.push_back(result.tps);
            latency_samples.push(result.avg_latency_ms);
            efficiency_samples.push_back(result.efficiency);
        }

        // Calculate single-agent baseline for efficiency
        double single_agent_tps = MeasureSingleAgentTPS();
        double theoretical_max_tps = single_agent_tps * config.num_agents;

        Results results;
        results.tasks_per_second = StatisticalMetrics::CalculateWithCI(tps_samples, config.confidence_level);
        results.latency_per_task_ms = StatisticalMetrics::CalculateWithCI(latency_samples, config.confidence_level);
        results.parallel_efficiency = StatisticalMetrics::CalculateWithCI(efficiency_samples, config.confidence_level);
        results.ideal_tps = theoretical_max_tps;
        results.actual_tps = results.tasks_per_second.mean;
        results.sample_count = config.measured_rounds;

        Log("Swarm16 Benchmark Complete");
        Log("  TPS: " + std::to_string(static_cast<int>(results.actual_tps)) + 
            " (ideal: " + std::to_string(static_cast<int>(results.ideal_tps)) + ")");
        Log("  Efficiency: " + std::to_string(static_cast<int>(results.parallel_efficiency.mean * 100)) + "%");

        return results;
    }

private:
    struct RoundResult {
        double tps = 0.0;
        double avg_latency_ms = 0.0;
        double efficiency = 0.0;
    };

    RoundResult RunSwarmRound(int num_agents, int tasks_per_agent) {
        RoundResult result;
        
        int total_tasks = num_agents * tasks_per_agent;
        std::atomic<int> completed_tasks{0};
        std::vector<std::thread> threads;
        
        auto start = std::chrono::high_resolution_clock::now();
        
        // Launch all agents
        for (int i = 0; i < num_agents; ++i) {
            threads.emplace_back([this, tasks_per_agent, &completed_tasks]() {
                for (int t = 0; t < tasks_per_agent; ++t) {
                    backend_->ExecuteAgentTask("inference_task");
                    completed_tasks++;
                }
            });
        }
        
        // Wait for completion
        for (auto& t : threads) {
            t.join();
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double duration_seconds = std::chrono::duration<double>(end - start).count();
        
        result.tps = total_tasks / duration_seconds;
        result.avg_latency_ms = (duration_seconds * 1000.0) / total_tasks;
        
        return result;
    }

    double MeasureSingleAgentTPS() {
        // Measure single agent TPS for efficiency calculation
        int tasks = 20;
        auto start = std::chrono::high_resolution_clock::now();
        
        for (int i = 0; i < tasks; ++i) {
            backend_->ExecuteAgentTask("inference_task");
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double duration_seconds = std::chrono::duration<double>(end - start).count();
        
        return tasks / duration_seconds;
    }
};

// ============================================================================
// Benchmark 4/10: SEG Execution Benchmark
// Measures Sovereign Execution Graph creation and parallel efficiency
// ============================================================================
class SEGExecutionBenchmark : public BenchmarkBase {
public:
    struct Config {
        int num_nodes = 100;
        int num_edges = 300;
        int warmup_runs = 3;
        int measured_runs = 20;
        double confidence_level = 0.95;
    };

    struct Results {
        StatisticalMetrics graph_build_time_ms;
        StatisticalMetrics plan_generation_time_ms;
        StatisticalMetrics execution_time_ms;
        StatisticalMetrics parallel_efficiency;
        int critical_path_length = 0;
        int sample_count = 0;
    };

    explicit SEGExecutionBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "seg_execution") {}

    Results Run(const Config& config = Config{}) {
        Log("Running SEG Execution Benchmark");
        Log("Nodes: " + std::to_string(config.num_nodes));
        Log("Edges: " + std::to_string(config.num_edges));

        // Warmup
        for (int i = 0; i < config.warmup_runs; ++i) {
            RunSEGExecution(config.num_nodes, config.num_edges);
        }

        // Measured phase
        std::vector<double> build_times;
        std::vector<double> plan_times;
        std::vector<double> exec_times;
        std::vector<double> efficiencies;

        for (int i = 0; i < config.measured_runs; ++i) {
            auto result = RunSEGExecution(config.num_nodes, config.num_edges);
            build_times.push_back(result.build_ms);
            plan_times.push_back(result.plan_ms);
            exec_times.push_back(result.execution_ms);
            efficiencies.push_back(result.efficiency);
        }

        Results results;
        results.graph_build_time_ms = StatisticalMetrics::CalculateWithCI(build_times, config.confidence_level);
        results.plan_generation_time_ms = StatisticalMetrics::CalculateWithCI(plan_times, config.confidence_level);
        results.execution_time_ms = StatisticalMetrics::CalculateWithCI(exec_times, config.confidence_level);
        results.parallel_efficiency = StatisticalMetrics::CalculateWithCI(efficiencies, config.confidence_level);
        results.sample_count = config.measured_runs;

        Log("SEG Execution Benchmark Complete");
        Log("  Build time: " + std::to_string(static_cast<int>(results.graph_build_time_ms.mean)) + "ms");
        Log("  Execution time: " + std::to_string(static_cast<int>(results.execution_time_ms.mean)) + "ms");

        return results;
    }

private:
    struct SEGResult {
        double build_ms = 0.0;
        double plan_ms = 0.0;
        double execution_ms = 0.0;
        double efficiency = 0.0;
    };

    SEGResult RunSEGExecution(int num_nodes, int num_edges) {
        SEGResult result;
        
        // Build graph
        auto build_start = std::chrono::high_resolution_clock::now();
        std::string graph_id = backend_->BuildExecutionGraph(num_nodes, num_edges);
        auto build_end = std::chrono::high_resolution_clock::now();
        result.build_ms = std::chrono::duration<double, std::milli>(build_end - build_start).count();
        
        // Generate plan
        auto plan_start = std::chrono::high_resolution_clock::now();
        std::string plan_id = backend_->GenerateExecutionPlan(graph_id);
        auto plan_end = std::chrono::high_resolution_clock::now();
        result.plan_ms = std::chrono::duration<double, std::milli>(plan_end - plan_start).count();
        
        // Execute
        auto exec_start = std::chrono::high_resolution_clock::now();
        backend_->ExecutePlan(plan_id);
        auto exec_end = std::chrono::high_resolution_clock::now();
        result.execution_ms = std::chrono::duration<double, std::milli>(exec_end - exec_start).count();
        
        // Calculate efficiency (actual vs theoretical)
        result.efficiency = backend_->GetExecutionEfficiency(plan_id);
        
        return result;
    }
};

// ============================================================================
// Benchmark 5/10: Decision Making Benchmark
// Measures decision quality under resource pressure
// ============================================================================
class DecisionMakingBenchmark : public BenchmarkBase {
public:
    struct Config {
        int warmup_decisions = 10;
        int measured_decisions = 100;
        double cpu_pressure = 0.8;  // Simulate 80% CPU load
        double memory_pressure = 0.7;
        double confidence_level = 0.95;
    };

    struct Results {
        StatisticalMetrics decision_latency_ms;
        StatisticalMetrics confidence_score;
        double accuracy = 0.0;  // Ground truth comparison
        double false_positive_rate = 0.0;
        double false_negative_rate = 0.0;
        int sample_count = 0;
    };

    explicit DecisionMakingBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "decision_making") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Decision Making Benchmark");
        Log("Simulating CPU pressure: " + std::to_string(static_cast<int>(config.cpu_pressure * 100)) + "%");

        // Setup resource pressure
        backend_->SetResourcePressure(config.cpu_pressure, config.memory_pressure);

        // Warmup
        for (int i = 0; i < config.warmup_decisions; ++i) {
            MakeDecision();
        }

        // Measured phase
        std::vector<double> latencies;
        std::vector<double> confidences;
        int correct_decisions = 0;
        int false_positives = 0;
        int false_negatives = 0;

        for (int i = 0; i < config.measured_decisions; ++i) {
            auto result = MakeDecision();
            latencies.push_back(result.latency_ms);
            confidences.push_back(result.confidence);
            
            if (result.correct) correct_decisions++;
            if (result.false_positive) false_positives++;
            if (result.false_negative) false_negatives++;
        }

        // Clear pressure
        backend_->ClearResourcePressure();

        Results results;
        results.decision_latency_ms = StatisticalMetrics::CalculateWithCI(latencies, config.confidence_level);
        results.confidence_score = StatisticalMetrics::CalculateWithCI(confidences, config.confidence_level);
        results.accuracy = static_cast<double>(correct_decisions) / config.measured_decisions;
        results.false_positive_rate = static_cast<double>(false_positives) / config.measured_decisions;
        results.false_negative_rate = static_cast<double>(false_negatives) / config.measured_decisions;
        results.sample_count = config.measured_decisions;

        Log("Decision Making Benchmark Complete");
        Log("  Latency: " + std::to_string(static_cast<int>(results.decision_latency_ms.mean)) + "ms");
        Log("  Accuracy: " + std::to_string(static_cast<int>(results.accuracy * 100)) + "%");

        return results;
    }

private:
    struct DecisionResult {
        double latency_ms = 0.0;
        double confidence = 0.0;
        bool correct = false;
        bool false_positive = false;
        bool false_negative = false;
    };

    DecisionResult MakeDecision() {
        DecisionResult result;
        
        auto start = std::chrono::high_resolution_clock::now();
        auto decision = backend_->MakeAutonomousDecision();
        auto end = std::chrono::high_resolution_clock::now();
        
        result.latency_ms = std::chrono::duration<double, std::milli>(end - start).count();
        result.confidence = decision.confidence;
        result.correct = decision.is_correct;
        result.false_positive = decision.false_positive;
        result.false_negative = decision.false_negative;
        
        return result;
    }
};

} // namespace rawrxd_benchmarks
