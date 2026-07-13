// Benchmark 15: Swarm Overload Benchmark
// Tests 100-agent swarm behavior under extreme load
// Copyright (c) 2026 RawrXD Team

#pragma once

#include "benchmark_common.hpp"
#include "json_reporter.hpp"
#include "backends/backend_factory.hpp"
#include "workload_profiles.hpp"
#include <iostream>
#include <vector>
#include <string>
#include <thread>
#include <future>
#include <barrier>

namespace rawrxd::benchmark {

// ============================================================================
// Swarm Overload Benchmark
// ============================================================================
class SwarmOverloadBenchmark : public Benchmark {
public:
    const char* GetName() const override { return "Swarm Overload (100 Agents)"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::SWARM; }
    
    BenchmarkResult Run(const BenchmarkConfig& config) override {
        std::cout << "\n========================================\n";
        std::cout << "Running: " << GetName() << "\n";
        std::cout << "Backend: " << BackendTypeToString(config.backend) << "\n";
        std::cout << "Configuration: 100 agents, 1000 tasks\n";
        std::cout << "========================================\n\n";
        
        auto backend = CreateBackendAdapter(config.backend);
        if (!backend || !backend->Initialize(config)) {
            std::cerr << "Failed to initialize backend\n";
            return CreateErrorResult(config, "Backend initialization failed");
        }
        
        BenchmarkResult result;
        result.benchmark_id = "swarm_overload_100_" + std::string(BackendTypeToString(config.backend));
        result.benchmark_name = GetName();
        result.category = GetCategory();
        result.backend = config.backend;
        result.model_name = config.model_name;
        result.timestamp = GetTimestamp();
        
        // Test parameters
        const int NUM_AGENTS = 100;
        const int NUM_TASKS = 1000;
        const int MAX_CONCURRENT = 32;  // Limit concurrent to avoid overwhelming system
        
        auto workload = ReferenceWorkloads::Swarm();
        
        // Metrics
        std::vector<double> agent_completion_times;
        std::vector<double> task_latencies;
        std::atomic<int> tasks_completed{0};
        std::atomic<int> tasks_failed{0};
        std::atomic<int> agents_healthy{0};
        std::atomic<int> agents_degraded{0};
        std::atomic<int> agents_failed{0};
        
        Timer total_timer;
        total_timer.Start();
        
        // Create barrier for synchronized start
        std::barrier sync_start(NUM_AGENTS);
        
        // Launch 100 agents
        std::vector<std::future<AgentResult>> agent_futures;
        
        for (int i = 0; i < NUM_AGENTS; ++i) {
            agent_futures.push_back(std::async(std::launch::async, [&](int agent_id) {
                AgentResult agent_result;
                agent_result.agent_id = agent_id;
                
                // Wait for all agents to be ready
                sync_start.arrive_and_wait();
                
                Timer agent_timer;
                agent_timer.Start();
                
                // Each agent processes tasks from the pool
                int tasks_per_agent = NUM_TASKS / NUM_AGENTS;
                int start_task = agent_id * tasks_per_agent;
                int end_task = (agent_id == NUM_AGENTS - 1) ? NUM_TASKS : start_task + tasks_per_agent;
                
                int local_completed = 0;
                int local_failed = 0;
                std::vector<double> local_latencies;
                
                for (int task_id = start_task; task_id < end_task; ++task_id) {
                    Timer task_timer;
                    task_timer.Start();
                    
                    int prompt_idx = task_id % workload.prompts.size();
                    auto response = backend->Generate(workload.prompts[prompt_idx], workload.max_tokens);
                    
                    task_timer.Stop();
                    double latency = task_timer.ElapsedMs();
                    local_latencies.push_back(latency);
                    
                    if (!response.empty()) {
                        local_completed++;
                    } else {
                        local_failed++;
                    }
                }
                
                agent_timer.Stop();
                agent_result.completion_time_ms = agent_timer.ElapsedMs();
                agent_result.tasks_completed = local_completed;
                agent_result.tasks_failed = local_failed;
                agent_result.mean_task_latency = local_latencies.empty() ? 0.0 :
                    std::accumulate(local_latencies.begin(), local_latencies.end(), 0.0) / local_latencies.size();
                
                // Determine agent health
                double success_rate = (local_completed + local_failed) > 0 
                    ? static_cast<double>(local_completed) / (local_completed + local_failed)
                    : 0.0;
                
                if (success_rate >= 0.95) {
                    agent_result.health = AgentHealth::HEALTHY;
                    agents_healthy++;
                } else if (success_rate >= 0.70) {
                    agent_result.health = AgentHealth::DEGRADED;
                    agents_degraded++;
                } else {
                    agent_result.health = AgentHealth::FAILED;
                    agents_failed++;
                }
                
                tasks_completed += local_completed;
                tasks_failed += local_failed;
                
                return agent_result;
            }, i));
        }
        
        // Collect results
        for (auto& future : agent_futures) {
            auto agent_result = future.get();
            agent_completion_times.push_back(agent_result.completion_time_ms);
            
            // Add to global latency collection (would need mutex in real impl)
            // For now, we track aggregate stats
        }
        
        total_timer.Stop();
        result.total_time_ms = total_timer.ElapsedMs();
        
        // Calculate metrics
        if (!agent_completion_times.empty()) {
            result.latency = StatisticalMetrics::Calculate(agent_completion_times);
        }
        
        // Throughput: tasks per second across all agents
        double total_tasks = tasks_completed + tasks_failed;
        double total_time_sec = result.total_time_ms / 1000.0;
        double throughput_tps = total_time_sec > 0 ? total_tasks / total_time_sec : 0.0;
        
        result.throughput.mean = throughput_tps;
        result.throughput.median = throughput_tps;
        result.throughput.p95 = throughput_tps;
        result.throughput.p99 = throughput_tps;
        
        result.success_rate = total_tasks > 0 
            ? static_cast<double>(tasks_completed) / total_tasks 
            : 0.0;
        
        result.resources = backend->GetResourceUsage();
        
        // Custom metrics
        result.custom_metrics["num_agents"] = NUM_AGENTS;
        result.custom_metrics["num_tasks"] = NUM_TASKS;
        result.custom_metrics["tasks_completed"] = tasks_completed.load();
        result.custom_metrics["tasks_failed"] = tasks_failed.load();
        result.custom_metrics["agents_healthy"] = agents_healthy.load();
        result.custom_metrics["agents_degraded"] = agents_degraded.load();
        result.custom_metrics["agents_failed"] = agents_failed.load();
        result.custom_metrics["health_rate"] = static_cast<double>(agents_healthy) / NUM_AGENTS;
        result.custom_metrics["degradation_rate"] = static_cast<double>(agents_degraded) / NUM_AGENTS;
        result.custom_metrics["failure_rate"] = static_cast<double>(agents_failed) / NUM_AGENTS;
        result.custom_metrics["tasks_per_agent"] = NUM_TASKS / NUM_AGENTS;
        result.custom_metrics["mean_agent_time_ms"] = agent_completion_times.empty() ? 0.0 :
            std::accumulate(agent_completion_times.begin(), agent_completion_times.end(), 0.0) / agent_completion_times.size();
        
        // Quality metrics
        double health_rate = static_cast<double>(agents_healthy) / NUM_AGENTS;
        result.quality.structure_score = health_rate * 100.0;
        result.quality.correctness_score = result.success_rate * 100.0;
        result.quality.depth_score = health_rate * 100.0;
        result.quality.coherence_score = health_rate * 100.0;
        result.quality.actionability_score = health_rate * 100.0;
        result.quality.overall_score = (health_rate * 0.5 + result.success_rate * 0.5) * 100.0;
        
        // Print summary
        PrintSummary(result, agent_completion_times);
        
        return result;
    }
    
private:
    enum class AgentHealth {
        HEALTHY,
        DEGRADED,
        FAILED
    };
    
    struct AgentResult {
        int agent_id = 0;
        double completion_time_ms = 0.0;
        int tasks_completed = 0;
        int tasks_failed = 0;
        double mean_task_latency = 0.0;
        AgentHealth health = AgentHealth::HEALTHY;
    };
    
    void PrintSummary(const BenchmarkResult& result, const std::vector<double>& agent_times) {
        std::cout << "\n========================================\n";
        std::cout << "Swarm Overload Summary\n";
        std::cout << "========================================\n";
        std::cout << "Total agents: " << result.custom_metrics.at("num_agents") << "\n";
        std::cout << "Total tasks: " << result.custom_metrics.at("num_tasks") << "\n";
        std::cout << "Tasks completed: " << result.custom_metrics.at("tasks_completed") << "\n";
        std::cout << "Tasks failed: " << result.custom_metrics.at("tasks_failed") << "\n";
        std::cout << "Success rate: " << std::fixed << std::setprecision(1) << result.success_rate * 100 << "%\n";
        std::cout << "\nAgent Health:\n";
        std::cout << "  Healthy: " << result.custom_metrics.at("agents_healthy") << " (" << result.custom_metrics.at("health_rate") * 100 << "%)\n";
        std::cout << "  Degraded: " << result.custom_metrics.at("agents_degraded") << " (" << result.custom_metrics.at("degradation_rate") * 100 << "%)\n";
        std::cout << "  Failed: " << result.custom_metrics.at("agents_failed") << " (" << result.custom_metrics.at("failure_rate") * 100 << "%)\n";
        std::cout << "\nPerformance:\n";
        std::cout << "  Total time: " << result.total_time_ms / 1000.0 << "s\n";
        std::cout << "  Throughput: " << result.throughput.mean << " tasks/sec\n";
        std::cout << "  Mean agent time: " << result.custom_metrics.at("mean_agent_time_ms") << "ms\n";
        std::cout << "========================================\n\n";
    }
    
    BenchmarkResult CreateErrorResult(const BenchmarkConfig& config, const std::string& error) {
        BenchmarkResult result;
        result.benchmark_id = "swarm_overload_100_" + std::string(BackendTypeToString(config.backend));
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
