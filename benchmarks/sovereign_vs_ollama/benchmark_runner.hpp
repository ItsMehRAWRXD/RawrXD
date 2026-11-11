// benchmark_runner.hpp
// Phase D.4 Batch 2/5 — Sovereign vs Ollama Benchmark Framework
// Comparative benchmarking suite for sovereign runtime validation

#ifndef BENCHMARK_RUNNER_HPP
#define BENCHMARK_RUNNER_HPP

#include <vector>
#include <string>
#include <map>
#include <chrono>
#include <functional>
#include <future>
#include <iostream>
#include <fstream>

namespace Benchmark {

// ============================================================================
// Benchmark Types
// ============================================================================

enum class BenchmarkCategory {
    INFERENCE,      // Raw inference performance
    AGENTIC,        // Agent creation and execution
    SWARM,          // Multi-agent swarm coordination
    PLANNING,       // SEG planning and execution
    AUTONOMY,       // Autonomous decision loop
    RECOVERY,       // Failure recovery
    QUALITY,        // Output quality
    INTEGRATION     // End-to-end integration
};

enum class BenchmarkTarget {
    SOVEREIGN,      // RawrXD sovereign runtime
    OLLAMA          // Ollama baseline
};

// ============================================================================
// Metrics
// ============================================================================

struct InferenceMetrics {
    double prompt_tps;           // Prompt tokens per second
    double generation_tps;     // Generation tokens per second
    double ttft_ms;              // Time to first token (ms)
    double total_latency_ms;     // Total request latency
    size_t memory_mb;            // Peak memory usage
    double gpu_utilization;      // GPU utilization %
    
    InferenceMetrics()
        : prompt_tps(0.0), generation_tps(0.0)
        , ttft_ms(0.0), total_latency_ms(0.0)
        , memory_mb(0), gpu_utilization(0.0)
    {}
};

struct AgenticMetrics {
    double agent_creation_ms;    // Time to create agent
    double context_load_ms;      // Time to load context
    double tool_execution_ms;    // Tool execution time
    double response_merge_ms;      // Response merge time
    uint32_t successful_agents;  // Successfully created agents
    uint32_t failed_agents;      // Failed agent creations
    
    AgenticMetrics()
        : agent_creation_ms(0.0), context_load_ms(0.0)
        , tool_execution_ms(0.0), response_merge_ms(0.0)
        , successful_agents(0), failed_agents(0)
    {}
};

struct SwarmMetrics {
    double parallel_efficiency;  // Parallel execution efficiency
    double consensus_time_ms;      // Time to reach consensus
    double conflict_resolution_ms; // Conflict resolution time
    double completion_time_ms;     // Total completion time
    uint32_t agents_completed;     // Agents that completed
    uint32_t agents_failed;          // Agents that failed
    
    SwarmMetrics()
        : parallel_efficiency(0.0), consensus_time_ms(0.0)
        , conflict_resolution_ms(0.0), completion_time_ms(0.0)
        , agents_completed(0), agents_failed(0)
    {}
};

struct AutonomyMetrics {
    double decisions_per_minute;   // Autonomous decisions/min
    double recovery_rate;            // Successful recovery rate
    double convergence_time_ms;      // Time to converge
    uint32_t total_decisions;        // Total decisions made
    uint32_t successful_mutations;   // Successful mutations
    uint32_t failed_mutations;         // Failed mutations
    
    AutonomyMetrics()
        : decisions_per_minute(0.0), recovery_rate(0.0)
        , convergence_time_ms(0.0), total_decisions(0)
        , successful_mutations(0), failed_mutations(0)
    {}
};

struct RecoveryMetrics {
    double detection_time_ms;      // Time to detect failure
    double recovery_time_ms;         // Time to recover
    double checkpoint_restore_ms;    // Checkpoint restore time
    bool recovery_successful;        // Whether recovery succeeded
    uint32_t checkpoints_created;    // Checkpoints during test
    
    RecoveryMetrics()
        : detection_time_ms(0.0), recovery_time_ms(0.0)
        , checkpoint_restore_ms(0.0), recovery_successful(false)
        , checkpoints_created(0)
    {}
};

struct QualityMetrics {
    double correctness_score;        // Output correctness (0-1)
    double relevance_score;            // Response relevance (0-1)
    double coherence_score;            // Response coherence (0-1)
    double completeness_score;         // Task completeness (0-1)
    uint32_t human_ratings;            // Number of human ratings
    double average_human_score;        // Average human score
    
    QualityMetrics()
        : correctness_score(0.0), relevance_score(0.0)
        , coherence_score(0.0), completeness_score(0.0)
        , human_ratings(0), average_human_score(0.0)
    {}
};

// ============================================================================
// Benchmark Result
// ============================================================================

struct BenchmarkResult {
    std::string benchmark_name;
    BenchmarkCategory category;
    BenchmarkTarget target;
    
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    
    bool success;
    std::string error_message;
    
    // Category-specific metrics
    InferenceMetrics inference;
    AgenticMetrics agentic;
    SwarmMetrics swarm;
    AutonomyMetrics autonomy;
    RecoveryMetrics recovery;
    QualityMetrics quality;
    
    // Raw measurements
    std::map<std::string, double> raw_measurements;
    
    BenchmarkResult()
        : success(false)
    {}
    
    double GetDurationMs() const {
        return std::chrono::duration_cast<std::chrono::milliseconds>(
            end_time - start_time).count();
    }
};

// ============================================================================
// Benchmark Configuration
// ============================================================================

struct BenchmarkConfig {
    // General settings
    uint32_t warmup_iterations;
    uint32_t measurement_iterations;
    std::chrono::seconds max_benchmark_duration;
    bool collect_telemetry;
    bool save_checkpoints;
    
    // Inference settings
    std::string model_name;
    uint32_t prompt_tokens;
    uint32_t generation_tokens;
    uint32_t batch_size;
    
    // Swarm settings
    uint32_t swarm_size;
    std::string swarm_task;
    
    // Autonomy settings
    std::chrono::seconds autonomy_test_duration;
    uint32_t max_decisions;
    
    // Recovery settings
    std::string failure_injection_type;
    std::chrono::seconds recovery_timeout;
    
    // Quality settings
    std::vector<std::string> quality_test_cases;
    
    BenchmarkConfig()
        : warmup_iterations(3)
        , measurement_iterations(10)
        , max_benchmark_duration(std::chrono::seconds(300))
        , collect_telemetry(true)
        , save_checkpoints(true)
        , model_name("phi-4")
        , prompt_tokens(512)
        , generation_tokens(256)
        , batch_size(1)
        , swarm_size(16)
        , swarm_task("code_review")
        , autonomy_test_duration(std::chrono::seconds(60))
        , max_decisions(100)
        , failure_injection_type("memory_pressure")
        , recovery_timeout(std::chrono::seconds(30))
    {}
};

// ============================================================================
// Benchmark Base Class
// ============================================================================

class BenchmarkBase {
public:
    virtual ~BenchmarkBase() = default;
    
    virtual std::string GetName() const = 0;
    virtual BenchmarkCategory GetCategory() const = 0;
    virtual std::string GetDescription() const = 0;
    
    virtual bool Setup(const BenchmarkConfig& config) = 0;
    virtual BenchmarkResult Run(BenchmarkTarget target) = 0;
    virtual void Teardown() = 0;
    
    virtual bool IsSupported(BenchmarkTarget target) const {
        return true;
    }
};

// ============================================================================
// Specific Benchmarks
// ============================================================================

// Inference Benchmark
class InferenceBenchmark : public BenchmarkBase {
public:
    std::string GetName() const override { return "inference_throughput"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::INFERENCE; }
    std::string GetDescription() const override {
        return "Measures raw inference throughput (prompt TPS, generation TPS, TTFT)";
    }
    
    bool Setup(const BenchmarkConfig& config) override;
    BenchmarkResult Run(BenchmarkTarget target) override;
    void Teardown() override;
    
private:
    BenchmarkConfig config_;
};

// Agentic Benchmark
class AgenticBenchmark : public BenchmarkBase {
public:
    std::string GetName() const override { return "agentic_execution"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::AGENTIC; }
    std::string GetDescription() const override {
        return "Measures agent creation, context loading, and tool execution performance";
    }
    
    bool Setup(const BenchmarkConfig& config) override;
    BenchmarkResult Run(BenchmarkTarget target) override;
    void Teardown() override;
    
private:
    BenchmarkConfig config_;
};

// Swarm Benchmark (16× Phi)
class SwarmBenchmark : public BenchmarkBase {
public:
    std::string GetName() const override { return "swarm_coordination"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::SWARM; }
    std::string GetDescription() const override {
        return "Measures 16-agent swarm parallel efficiency and consensus";
    }
    
    bool Setup(const BenchmarkConfig& config) override;
    BenchmarkResult Run(BenchmarkTarget target) override;
    void Teardown() override;
    
private:
    BenchmarkConfig config_;
};

// Autonomy Benchmark
class AutonomyBenchmark : public BenchmarkBase {
public:
    std::string GetName() const override { return "autonomous_loop"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::AUTONOMY; }
    std::string GetDescription() const override {
        return "Measures autonomous decision rate, recovery, and convergence";
    }
    
    bool Setup(const BenchmarkConfig& config) override;
    BenchmarkResult Run(BenchmarkTarget target) override;
    void Teardown() override;
    
private:
    BenchmarkConfig config_;
};

// Recovery Benchmark
class RecoveryBenchmark : public BenchmarkBase {
public:
    std::string GetName() const override { return "failure_recovery"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::RECOVERY; }
    std::string GetDescription() const override {
        return "Measures failure detection and recovery performance";
    }
    
    bool Setup(const BenchmarkConfig& config) override;
    BenchmarkResult Run(BenchmarkTarget target) override;
    void Teardown() override;
    
private:
    BenchmarkConfig config_;
};

// Quality Benchmark
class QualityBenchmark : public BenchmarkBase {
public:
    std::string GetName() const override { return "output_quality"; }
    BenchmarkCategory GetCategory() const override { return BenchmarkCategory::QUALITY; }
    std::string GetDescription() const override {
        return "Measures output correctness, relevance, and coherence";
    }
    
    bool Setup(const BenchmarkConfig& config) override;
    BenchmarkResult Run(BenchmarkTarget target) override;
    void Teardown() override;
    
private:
    BenchmarkConfig config_;
};

// ============================================================================
// Benchmark Runner
// ============================================================================

class BenchmarkRunner {
public:
    BenchmarkRunner();
    ~BenchmarkRunner();
    
    // Registration
    void RegisterBenchmark(std::unique_ptr<BenchmarkBase> benchmark);
    void RegisterDefaultBenchmarks();
    
    // Execution
    std::vector<BenchmarkResult> RunAll(const BenchmarkConfig& config);
    std::vector<BenchmarkResult> RunCategory(BenchmarkCategory category, 
                                                const BenchmarkConfig& config);
    BenchmarkResult RunSingle(const std::string& benchmark_name,
                              const BenchmarkConfig& config);
    
    // Comparison
    struct ComparisonResult {
        std::string metric_name;
        double sovereign_value;
        double ollama_value;
        double improvement_pct;  // Positive = sovereign better
        bool statistically_significant;
    };
    
    std::vector<ComparisonResult> CompareResults(
        const std::vector<BenchmarkResult>& sovereign_results,
        const std::vector<BenchmarkResult>& ollama_results);
    
    // Reporting
    struct BenchmarkReport {
        std::string report_id;
        std::chrono::steady_clock::time_point generated_at;
        
        std::vector<BenchmarkResult> sovereign_results;
        std::vector<BenchmarkResult> ollama_results;
        std::vector<ComparisonResult> comparisons;
        
        double overall_sovereign_score;
        double overall_ollama_score;
        double overall_improvement_pct;
        
        bool passed_threshold;  // e.g., 20% improvement
        std::string summary;
    };
    
    BenchmarkReport GenerateReport(
        const std::vector<BenchmarkResult>& sovereign_results,
        const std::vector<BenchmarkResult>& ollama_results);
    
    void ExportReport(const BenchmarkReport& report, const std::string& path);
    void PrintReport(const BenchmarkReport& report);
    
    // Utilities
    std::vector<std::string> GetAvailableBenchmarks() const;
    bool HasBenchmark(const std::string& name) const;
    
private:
    std::vector<std::unique_ptr<BenchmarkBase>> benchmarks_;
    mutable std::mutex benchmarks_mutex_;
    
    BenchmarkResult RunBenchmark(BenchmarkBase& benchmark, BenchmarkTarget target);
    ComparisonResult CompareMetric(const std::string& name,
                                   double sovereign, double ollama);
};

// ============================================================================
// CLI Interface
// ============================================================================

class BenchmarkCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintUsage();
    static void PrintHelp();
    static BenchmarkConfig ParseArgs(int argc, char* argv[]);
};

// ============================================================================
// Utility Functions
// ============================================================================

namespace BenchmarkUtils {
    // Statistical analysis
    double CalculateMean(const std::vector<double>& values);
    double CalculateStdDev(const std::vector<double>& values);
    double CalculateConfidenceInterval(const std::vector<double>& values, 
                                        double confidence);
    bool IsSignificantDifference(double mean1, double mean2, 
                                  double stddev1, double stddev2,
                                  uint32_t n1, uint32_t n2);
    
    // Formatting
    std::string FormatDuration(double milliseconds);
    std::string FormatThroughput(double tps);
    std::string FormatPercentage(double pct);
    std::string FormatBytes(size_t bytes);
    
    // Category names
    std::string CategoryToString(BenchmarkCategory cat);
    std::string TargetToString(BenchmarkTarget target);
} // namespace BenchmarkUtils

} // namespace Benchmark

#endif // BENCHMARK_RUNNER_HPP
