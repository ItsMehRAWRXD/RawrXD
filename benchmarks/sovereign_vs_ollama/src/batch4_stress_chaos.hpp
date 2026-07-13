// batch4_stress_chaos.hpp
// Phase 1, Batch 4/5: Stress & Chaos Benchmarks
// Measures: System resilience under failure storms, mutation storms, resource starvation

#pragma once
#include "../include/benchmark_common.hpp"
#include <vector>
#include <thread>
#include <chrono>
#include <atomic>
#include <random>

namespace rawrxd_benchmarks {

// ============================================================================
// Benchmark 11/15: Failure Storm Benchmark
// Measures system behavior under cascading failures
// ============================================================================
class FailureStormBenchmark : public BenchmarkBase {
public:
    struct Config {
        int base_agents = 16;
        int storm_duration_seconds = 60;
        double failure_rate = 0.3;  // 30% of agents fail during storm
        double recovery_rate = 0.8;  // 80% recovery success
        int sampling_interval_ms = 1000;
    };

    struct StormSnapshot {
        double timestamp_seconds = 0.0;
        int active_agents = 0;
        int failed_agents = 0;
        int recovering_agents = 0;
        double throughput_tps = 0.0;
        double latency_ms = 0.0;
        double error_rate = 0.0;
    };

    struct Results {
        std::vector<StormSnapshot> timeline;
        double min_throughput = 0.0;
        double max_throughput = 0.0;
        double avg_throughput_during_storm = 0.0;
        double recovery_time_ms = 0.0;  // Time to restore 95% throughput
        double error_rate_during_storm = 0.0;
        int total_failures_injected = 0;
        int total_recoveries = 0;
    };

    explicit FailureStormBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "failure_storm") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Failure Storm Benchmark");
        Log("Duration: " + std::to_string(config.storm_duration_seconds) + "s");
        Log("Failure rate: " + std::to_string(static_cast<int>(config.failure_rate * 100)) + "%");

        Results results;
        std::vector<std::string> agent_ids;
        std::atomic<int> active_count{config.base_agents};
        std::atomic<int> failed_count{0};
        std::atomic<int> recovering_count{0};
        std::atomic<int> completed_tasks{0};
        std::atomic<int> error_count{0};
        
        // Spawn base agents
        for (int i = 0; i < config.base_agents; ++i) {
            agent_ids.push_back(backend_->SpawnAgent("storm_agent_" + std::to_string(i)));
        }
        
        // Start workload
        std::atomic<bool> running{true};
        std::thread workload_thread([&]() {
            while (running) {
                for (const auto& agent_id : agent_ids) {
                    if (backend_->IsAgentActive(agent_id)) {
                        auto result = backend_->ExecuteAgentTask(agent_id, "inference_task");
                        if (result.success) {
                            completed_tasks++;
                        } else {
                            error_count++;
                        }
                    }
                }
            }
        });
        
        // Run storm with periodic snapshots
        auto start_time = std::chrono::high_resolution_clock::now();
        double baseline_throughput = 0.0;
        
        while (true) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            
            if (elapsed >= config.storm_duration_seconds) break;
            
            // Inject failures randomly
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_real_distribution<> dis(0.0, 1.0);
            
            for (auto& agent_id : agent_ids) {
                if (backend_->IsAgentActive(agent_id) && dis(gen) < config.failure_rate / 10.0) {
                    backend_->InjectAgentFailure(agent_id, "random_failure");
                    failed_count++;
                    active_count--;
                    results.total_failures_injected++;
                }
            }
            
            // Attempt recoveries
            for (auto& agent_id : agent_ids) {
                if (!backend_->IsAgentActive(agent_id) && dis(gen) < config.recovery_rate / 10.0) {
                    if (backend_->RecoverAgent(agent_id)) {
                        recovering_count++;
                        failed_count--;
                        active_count++;
                        results.total_recoveries++;
                    }
                }
            }
            
            // Take snapshot
            StormSnapshot snapshot;
            snapshot.timestamp_seconds = elapsed;
            snapshot.active_agents = active_count.load();
            snapshot.failed_agents = failed_count.load();
            snapshot.recovering_agents = recovering_count.load();
            snapshot.throughput_tps = completed_tasks.exchange(0) / (config.sampling_interval_ms / 1000.0);
            snapshot.error_rate = error_count.exchange(0) / std::max(snapshot.active_agents, 1);
            
            if (elapsed < 5.0) {
                baseline_throughput = snapshot.throughput_tps;
            }
            
            results.timeline.push_back(snapshot);
            
            // Check for recovery (95% of baseline)
            if (results.recovery_time_ms == 0.0 && 
                snapshot.throughput_tps >= baseline_throughput * 0.95 &&
                elapsed > 10.0) {
                results.recovery_time_ms = elapsed * 1000.0;
            }
            
            std::this_thread::sleep_for(std::chrono::milliseconds(config.sampling_interval_ms));
        }
        
        running = false;
        workload_thread.join();
        
        // Calculate results
        if (!results.timeline.empty()) {
            results.min_throughput = results.timeline[0].throughput_tps;
            results.max_throughput = results.timeline[0].throughput_tps;
            double total_throughput = 0.0;
            double total_error_rate = 0.0;
            
            for (const auto& snap : results.timeline) {
                results.min_throughput = std::min(results.min_throughput, snap.throughput_tps);
                results.max_throughput = std::max(results.max_throughput, snap.throughput_tps);
                total_throughput += snap.throughput_tps;
                total_error_rate += snap.error_rate;
            }
            
            results.avg_throughput_during_storm = total_throughput / results.timeline.size();
            results.error_rate_during_storm = total_error_rate / results.timeline.size();
        }
        
        // Cleanup
        for (const auto& agent_id : agent_ids) {
            backend_->TeardownAgent(agent_id);
        }
        
        Log("Failure Storm Benchmark Complete");
        Log("  Min throughput: " + std::to_string(static_cast<int>(results.min_throughput)) + " TPS");
        Log("  Recovery time: " + std::to_string(static_cast<int>(results.recovery_time_ms / 1000.0)) + "s");
        Log("  Failures injected: " + std::to_string(results.total_failures_injected));
        Log("  Recoveries: " + std::to_string(results.total_recoveries));
        
        return results;
    }
};

// ============================================================================
// Benchmark 12/15: Mutation Storm Benchmark
// Measures SEG stability under rapid graph mutations
// ============================================================================
class MutationStormBenchmark : public BenchmarkBase {
public:
    struct Config {
        int base_nodes = 50;
        int storm_duration_seconds = 60;
        int mutations_per_second = 5;
        int max_concurrent_mutations = 10;
    };

    struct MutationResult {
        double timestamp_seconds = 0.0;
        int mutations_applied = 0;
        int mutations_rolled_back = 0;
        double graph_stability = 1.0;  // 0-1
        double execution_success_rate = 1.0;
        double avg_mutation_latency_ms = 0.0;
    };

    struct Results {
        std::vector<MutationResult> timeline;
        int total_mutations = 0;
        int total_rollbacks = 0;
        double avg_stability = 1.0;
        double min_stability = 1.0;
        int oscillation_events = 0;
    };

    explicit MutationStormBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "mutation_storm") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Mutation Storm Benchmark");
        Log("Duration: " + std::to_string(config.storm_duration_seconds) + "s");
        Log("Mutations/sec: " + std::to_string(config.mutations_per_second));

        Results results;
        
        // Create base graph
        std::string graph_id = backend_->BuildExecutionGraph(config.base_nodes, config.base_nodes * 3);
        std::string plan_id = backend_->GenerateExecutionPlan(graph_id);
        
        std::atomic<int> mutations_applied{0};
        std::atomic<int> mutations_rolled_back{0};
        std::atomic<int> execution_successes{0};
        std::atomic<int> execution_attempts{0};
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Mutation thread
        std::atomic<bool> running{true};
        std::thread mutation_thread([&]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_int_distribution<> mutation_type(0, 4);
            
            while (running) {
                for (int i = 0; i < config.mutations_per_second; ++i) {
                    auto mut_start = std::chrono::high_resolution_clock::now();
                    
                    bool success = false;
                    switch (mutation_type(gen)) {
                        case 0: success = backend_->MutateAddNode(graph_id); break;
                        case 1: success = backend_->MutateRemoveNode(graph_id); break;
                        case 2: success = backend_->MutateReorderEdges(graph_id); break;
                        case 3: success = backend_->MutateChangePriority(graph_id); break;
                        case 4: success = backend_->MutateAdjustWeights(graph_id); break;
                    }
                    
                    if (success) {
                        mutations_applied++;
                    } else {
                        mutations_rolled_back++;
                    }
                    
                    auto mut_end = std::chrono::high_resolution_clock::now();
                    double latency = std::chrono::duration<double, std::milli>(mut_end - mut_start).count();
                    
                    // Small delay between mutations
                    std::this_thread::sleep_for(std::chrono::milliseconds(200));
                }
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
        
        // Execution thread
        std::thread execution_thread([&]() {
            while (running) {
                execution_attempts++;
                if (backend_->ExecutePlan(plan_id)) {
                    execution_successes++;
                }
                std::this_thread::sleep_for(std::chrono::milliseconds(100));
            }
        });
        
        // Monitoring loop
        double prev_stability = 1.0;
        while (true) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            
            if (elapsed >= config.storm_duration_seconds) break;
            
            MutationResult snapshot;
            snapshot.timestamp_seconds = elapsed;
            snapshot.mutations_applied = mutations_applied.exchange(0);
            snapshot.mutations_rolled_back = mutations_rolled_back.exchange(0);
            snapshot.graph_stability = backend_->GetGraphStability(graph_id);
            snapshot.execution_success_rate = execution_attempts > 0 ? 
                static_cast<double>(execution_successes.exchange(0)) / execution_attempts.exchange(0) : 1.0;
            
            results.timeline.push_back(snapshot);
            
            // Detect oscillation
            if (std::abs(snapshot.graph_stability - prev_stability) > 0.2) {
                results.oscillation_events++;
            }
            prev_stability = snapshot.graph_stability;
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        running = false;
        mutation_thread.join();
        execution_thread.join();
        
        // Calculate results
        if (!results.timeline.empty()) {
            double total_stability = 0.0;
            results.min_stability = results.timeline[0].graph_stability;
            
            for (const auto& snap : results.timeline) {
                total_stability += snap.graph_stability;
                results.min_stability = std::min(results.min_stability, snap.graph_stability);
                results.total_mutations += snap.mutations_applied;
                results.total_rollbacks += snap.mutations_rolled_back;
            }
            
            results.avg_stability = total_stability / results.timeline.size();
        }
        
        Log("Mutation Storm Benchmark Complete");
        Log("  Total mutations: " + std::to_string(results.total_mutations));
        Log("  Total rollbacks: " + std::to_string(results.total_rollbacks));
        Log("  Min stability: " + std::to_string(static_cast<int>(results.min_stability * 100)) + "%");
        Log("  Oscillation events: " + std::to_string(results.oscillation_events));
        
        return results;
    }
};

// ============================================================================
// Benchmark 13/15: Resource Starvation Benchmark
// Measures behavior under memory/CPU pressure
// ============================================================================
class ResourceStarvationBenchmark : public BenchmarkBase {
public:
    struct Config {
        int duration_seconds = 60;
        double memory_pressure_start = 0.5;  // 50%
        double memory_pressure_end = 0.95;   // 95%
        double cpu_pressure_start = 0.5;
        double cpu_pressure_end = 0.95;
    };

    struct StarvationSnapshot {
        double timestamp_seconds = 0.0;
        double memory_pressure = 0.0;
        double cpu_pressure = 0.0;
        double throughput_tps = 0.0;
        double latency_ms = 0.0;
        double error_rate = 0.0;
        int oom_events = 0;
        int throttling_events = 0;
    };

    struct Results {
        std::vector<StarvationSnapshot> timeline;
        double throughput_at_50_percent = 0.0;
        double throughput_at_95_percent = 0.0;
        double degradation_rate = 0.0;  // TPS loss per % pressure
        int total_oom_events = 0;
        int total_throttling_events = 0;
        bool graceful_degradation = true;
    };

    explicit ResourceStarvationBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "resource_starvation") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Resource Starvation Benchmark");
        Log("Duration: " + std::to_string(config.duration_seconds) + "s");

        Results results;
        std::atomic<int> completed_tasks{0};
        std::atomic<int> error_count{0};
        std::atomic<int> oom_events{0};
        std::atomic<int> throttle_events{0};
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Gradually increase pressure
        std::thread pressure_thread([&]() {
            for (int i = 0; i < config.duration_seconds; ++i) {
                double progress = static_cast<double>(i) / config.duration_seconds;
                
                double mem_pressure = config.memory_pressure_start + 
                    (config.memory_pressure_end - config.memory_pressure_start) * progress;
                double cpu_pressure = config.cpu_pressure_start + 
                    (config.cpu_pressure_end - config.cpu_pressure_start) * progress;
                
                backend_->SetResourcePressure(cpu_pressure, mem_pressure);
                std::this_thread::sleep_for(std::chrono::seconds(1));
            }
        });
        
        // Workload thread
        std::atomic<bool> running{true};
        std::thread workload_thread([&]() {
            while (running) {
                auto result = backend_->SubmitInference({"test", 64, 0.0});
                if (result.success) {
                    completed_tasks++;
                } else {
                    error_count++;
                    if (result.error_type == "OOM") oom_events++;
                    if (result.error_type == "THROTTLED") throttle_events++;
                }
            }
        });
        
        // Monitoring
        while (true) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            
            if (elapsed >= config.duration_seconds) break;
            
            StarvationSnapshot snapshot;
            snapshot.timestamp_seconds = elapsed;
            snapshot.memory_pressure = backend_->GetMemoryPressure();
            snapshot.cpu_pressure = backend_->GetCPUPressure();
            snapshot.throughput_tps = completed_tasks.exchange(0);
            snapshot.error_rate = error_count.exchange(0) / std::max(snapshot.throughput_tps, 1.0);
            snapshot.oom_events = oom_events.exchange(0);
            snapshot.throttling_events = throttle_events.exchange(0);
            
            results.timeline.push_back(snapshot);
            
            // Record throughput at specific pressure points
            if (std::abs(snapshot.memory_pressure - 0.5) < 0.05) {
                results.throughput_at_50_percent = snapshot.throughput_tps;
            }
            if (std::abs(snapshot.memory_pressure - 0.95) < 0.05) {
                results.throughput_at_95_percent = snapshot.throughput_tps;
            }
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        running = false;
        pressure_thread.join();
        workload_thread.join();
        
        // Calculate degradation
        if (results.throughput_at_50_percent > 0 && results.throughput_at_95_percent > 0) {
            double tps_drop = results.throughput_at_50_percent - results.throughput_at_95_percent;
            double pressure_increase = 0.95 - 0.50;
            results.degradation_rate = tps_drop / pressure_increase;
        }
        
        // Check for graceful degradation
        for (const auto& snap : results.timeline) {
            results.total_oom_events += snap.oom_events;
            results.total_throttling_events += snap.throttling_events;
            if (snap.error_rate > 0.5) {
                results.graceful_degradation = false;
            }
        }
        
        // Clear pressure
        backend_->ClearResourcePressure();
        
        Log("Resource Starvation Benchmark Complete");
        Log("  Throughput at 50%: " + std::to_string(static_cast<int>(results.throughput_at_50_percent)) + " TPS");
        Log("  Throughput at 95%: " + std::to_string(static_cast<int>(results.throughput_at_95_percent)) + " TPS");
        Log("  Degradation rate: " + std::to_string(static_cast<int>(results.degradation_rate)) + " TPS/%");
        Log("  Graceful degradation: " + std::string(results.graceful_degradation ? "YES" : "NO"));
        
        return results;
    }
};

// ============================================================================
// Benchmark 14/15: Oscillation Storm Benchmark
// Measures stability under rapid decision oscillations
// ============================================================================
class OscillationStormBenchmark : public BenchmarkBase {
public:
    struct Config {
        int duration_seconds = 60;
        int decision_changes_per_second = 10;
        double oscillation_amplitude = 0.5;
    };

    struct OscillationResult {
        double timestamp_seconds = 0.0;
        int decisions_made = 0;
        int decisions_changed = 0;
        double oscillation_frequency = 0.0;
        double stability_score = 1.0;
        double dampening_effectiveness = 0.0;
    };

    struct Results {
        std::vector<OscillationResult> timeline;
        int total_decisions = 0;
        int total_changes = 0;
        double avg_oscillation_frequency = 0.0;
        double stability_recovery_time_ms = 0.0;
        bool dampening_activated = false;
    };

    explicit OscillationStormBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "oscillation_storm") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Oscillation Storm Benchmark");
        Log("Duration: " + std::to_string(config.duration_seconds) + "s");

        Results results;
        std::atomic<int> decisions_made{0};
        std::atomic<int> decisions_changed{0};
        std::string last_decision = "";
        
        auto start_time = std::chrono::high_resolution_clock::now();
        
        // Rapid decision thread
        std::atomic<bool> running{true};
        std::thread decision_thread([&]() {
            std::random_device rd;
            std::mt19937 gen(rd());
            std::uniform_real_distribution<> dis(0.0, 1.0);
            
            while (running) {
                for (int i = 0; i < config.decision_changes_per_second; ++i) {
                    // Force oscillation by rapidly changing inputs
                    double pressure = 0.3 + dis(gen) * config.oscillation_amplitude;
                    backend_->SetResourcePressure(pressure, pressure);
                    
                    auto decision = backend_->MakeAutonomousDecision();
                    decisions_made++;
                    
                    if (decision.id != last_decision) {
                        decisions_changed++;
                        last_decision = decision.id;
                    }
                    
                    std::this_thread::sleep_for(std::chrono::milliseconds(100));
                }
            }
        });
        
        // Monitoring
        while (true) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            
            if (elapsed >= config.duration_seconds) break;
            
            OscillationResult snapshot;
            snapshot.timestamp_seconds = elapsed;
            snapshot.decisions_made = decisions_made.exchange(0);
            snapshot.decisions_changed = decisions_changed.exchange(0);
            snapshot.oscillation_frequency = snapshot.decisions_changed > 0 ?
                static_cast<double>(snapshot.decisions_changed) / snapshot.decisions_made : 0.0;
            snapshot.stability_score = backend_->GetSystemStability();
            snapshot.dampening_effectiveness = backend_->GetDampeningEffectiveness();
            
            if (snapshot.dampening_effectiveness > 0.5) {
                results.dampening_activated = true;
            }
            
            results.timeline.push_back(snapshot);
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        running = false;
        decision_thread.join();
        
        // Calculate results
        if (!results.timeline.empty()) {
            double total_freq = 0.0;
            for (const auto& snap : results.timeline) {
                total_freq += snap.oscillation_frequency;
                results.total_decisions += snap.decisions_made;
                results.total_changes += snap.decisions_changed;
            }
            results.avg_oscillation_frequency = total_freq / results.timeline.size();
        }
        
        // Clear pressure
        backend_->ClearResourcePressure();
        
        Log("Oscillation Storm Benchmark Complete");
        Log("  Total decisions: " + std::to_string(results.total_decisions));
        Log("  Total changes: " + std::to_string(results.total_changes));
        Log("  Avg oscillation freq: " + std::to_string(results.avg_oscillation_frequency));
        Log("  Dampening activated: " + std::string(results.dampening_activated ? "YES" : "NO"));
        
        return results;
    }
};

// ============================================================================
// Benchmark 15/15: Degraded Hardware Benchmark
// Measures performance under hardware constraints
// ============================================================================
class DegradedHardwareBenchmark : public BenchmarkBase {
public:
    struct Config {
        int duration_seconds = 60;
        double max_memory_gb = 8.0;  // Limit to 8GB
        int max_cpu_cores = 4;
        double gpu_clock_reduction = 0.5;  // 50% GPU clock
    };

    struct DegradationResult {
        double timestamp_seconds = 0.0;
        double available_memory_gb = 0.0;
        int available_cores = 0;
        double gpu_clock_mhz = 0.0;
        double throughput_tps = 0.0;
        double efficiency = 1.0;  // vs unconstrained
    };

    struct Results {
        std::vector<DegradationResult> timeline;
        double baseline_throughput = 0.0;
        double degraded_throughput = 0.0;
        double efficiency_under_constraints = 1.0;
        bool maintained_functionality = true;
    };

    explicit DegradedHardwareBenchmark(IBackendAdapter* backend)
        : BenchmarkBase(backend, "degraded_hardware") {}

    Results Run(const Config& config = Config{}) {
        Log("Running Degraded Hardware Benchmark");
        Log("Memory limit: " + std::to_string(config.max_memory_gb) + " GB");
        Log("CPU cores: " + std::to_string(config.max_cpu_cores));

        Results results;
        
        // Measure baseline first
        Log("Measuring baseline (unconstrained)...");
        auto baseline_start = std::chrono::high_resolution_clock::now();
        int baseline_tasks = 0;
        auto baseline_end = baseline_start + std::chrono::seconds(10);
        
        while (std::chrono::high_resolution_clock::now() < baseline_end) {
            backend_->SubmitInference({"test", 64, 0.0});
            baseline_tasks++;
        }
        results.baseline_throughput = baseline_tasks / 10.0;
        
        // Apply constraints
        backend_->SetMemoryConstraint(config.max_memory_gb);
        backend_->SetCPUConstraint(config.max_cpu_cores);
        backend_->SetGPUClock(config.gpu_clock_reduction);
        
        // Measure under constraints
        Log("Measuring under constraints...");
        auto start_time = std::chrono::high_resolution_clock::now();
        std::atomic<int> constrained_tasks{0};
        std::atomic<bool> running{true};
        
        std::thread workload_thread([&]() {
            while (running) {
                auto result = backend_->SubmitInference({"test", 64, 0.0});
                if (result.success) {
                    constrained_tasks++;
                } else {
                    results.maintained_functionality = false;
                }
            }
        });
        
        // Monitor
        while (true) {
            auto now = std::chrono::high_resolution_clock::now();
            double elapsed = std::chrono::duration<double>(now - start_time).count();
            
            if (elapsed >= config.duration_seconds) break;
            
            DegradationResult snapshot;
            snapshot.timestamp_seconds = elapsed;
            snapshot.available_memory_gb = backend_->GetAvailableMemoryGB();
            snapshot.available_cores = backend_->GetAvailableCores();
            snapshot.gpu_clock_mhz = backend_->GetGPUClockMHz();
            snapshot.throughput_tps = constrained_tasks.exchange(0);
            snapshot.efficiency = results.baseline_throughput > 0 ? 
                snapshot.throughput_tps / results.baseline_throughput : 0.0;
            
            results.timeline.push_back(snapshot);
            
            std::this_thread::sleep_for(std::chrono::seconds(1));
        }
        
        running = false;
        workload_thread.join();
        
        // Calculate results
        if (!results.timeline.empty()) {
            double total_throughput = 0.0;
            double total_efficiency = 0.0;
            
            for (const auto& snap : results.timeline) {
                total_throughput += snap.throughput_tps;
                total_efficiency += snap.efficiency;
            }
            
            results.degraded_throughput = total_throughput / results.timeline.size();
            results.efficiency_under_constraints = total_efficiency / results.timeline.size();
        }
        
        // Clear constraints
        backend_->ClearConstraints();
        
        Log("Degraded Hardware Benchmark Complete");
        Log("  Baseline: " + std::to_string(static_cast<int>(results.baseline_throughput)) + " TPS");
        Log("  Degraded: " + std::to_string(static_cast<int>(results.degraded_throughput)) + " TPS");
        Log("  Efficiency: " + std::to_string(static_cast<int>(results.efficiency_under_constraints * 100)) + "%");
        Log("  Functionality maintained: " + std::string(results.maintained_functionality ? "YES" : "NO"));
        
        return results;
    }
};

} // namespace rawrxd_benchmarks
