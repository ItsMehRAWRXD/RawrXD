#pragma once

/**
 * CanonicalBenchmark.hpp
 *
 * Phase C.1 Batch 3/5: Canonical Benchmark Capture
 *
 * Records the first canonical performance baseline for the Sovereign Runtime.
 * This becomes the reference for future optimization work.
 */

#include "PerformanceBaseline.hpp"
#include <chrono>
#include <map>
#include <string>

namespace Sovereign {

/**
 * Benchmark configuration
 */
struct BenchmarkConfig {
    int warmupIterations = 3;
    int measurementIterations = 10;
    double targetConvergence = 0.85;
    int maxConvergenceIterations = 100;
    bool enableCheckpointTest = true;
    bool enableMemoryProfiling = true;
    std::string outputPath = "canonical_benchmark.json";
};

/**
 * Single benchmark measurement
 */
struct BenchmarkMeasurement {
    std::string name;
    double value;
    std::string unit;
    double min;
    double max;
    double mean;
    double median;
    double stddev;
    int sampleCount;

    std::string ToJson() const;
};

/**
 * Memory profile snapshot
 */
struct MemoryProfile {
    size_t baselineBytes = 0;
    size_t peakBytes = 0;
    size_t currentBytes = 0;
    std::map<std::string, size_t> componentUsage;

    size_t GetUsedBytes() const { return currentBytes - baselineBytes; }
    size_t GetPeakUsedBytes() const { return peakBytes - baselineBytes; }

    std::string ToJson() const;
};

/**
 * Complete canonical benchmark results
 */
struct CanonicalBenchmarkResults {
    std::string version = "1.0.0";
    std::string timestamp;
    std::string gitCommit;
    std::string platform;

    // Latency measurements (ms)
    BenchmarkMeasurement startupLatency;
    BenchmarkMeasurement graphConstructionLatency;
    BenchmarkMeasurement planningLatency;
    BenchmarkMeasurement workflowExecutionLatency;
    BenchmarkMeasurement unitySequenceLatency;
    BenchmarkMeasurement checkpointSaveLatency;
    BenchmarkMeasurement checkpointRestoreLatency;

    // Throughput measurements
    BenchmarkMeasurement cyclesPerSecond;
    BenchmarkMeasurement convergenceRate;

    // Memory measurements (MB)
    MemoryProfile memoryProfile;

    // Convergence metrics
    int iterationsToConverge = 0;
    double finalConvergenceScore = 0.0;
    bool achievedConvergence = false;

    // Component counts
    int segNodes = 0;
    int engineCycles = 0;
    int swarmTasks = 0;
    int telemetryEvents = 0;

    std::string ToJson() const;
    void PrintSummary() const;
    bool SaveToFile(const std::string& path) const;
};

/**
 * Canonical benchmark capture
 */
class CanonicalBenchmark {
public:
    CanonicalBenchmark();
    ~CanonicalBenchmark();

    // Run full canonical benchmark
    CanonicalBenchmarkResults Run(const BenchmarkConfig& config = BenchmarkConfig{});

    // Individual benchmarks
    BenchmarkMeasurement BenchmarkStartup(int iterations);
    BenchmarkMeasurement BenchmarkGraphConstruction(int iterations);
    BenchmarkMeasurement BenchmarkPlanning(int iterations);
    BenchmarkMeasurement BenchmarkWorkflowExecution(int iterations);
    BenchmarkMeasurement BenchmarkUnitySequence(int iterations);
    BenchmarkMeasurement BenchmarkCheckpointSave(int iterations);
    BenchmarkMeasurement BenchmarkCheckpointRestore(int iterations);

    // Memory profiling
    MemoryProfile CaptureMemoryProfile();

    // Convergence benchmark
    struct ConvergenceResult {
        int iterations;
        double finalScore;
        int64_t totalDurationMs;
        bool success;
    };
    ConvergenceResult BenchmarkConvergence(double target, int maxIterations);

private:
    std::unique_ptr<IntegratedSovereignRuntime> runtime_;

    bool InitializeRuntime();
    void ShutdownRuntime();

    // Helper methods
    std::string GetTimestamp() const;
    std::string GetGitCommit() const;
    std::string GetPlatform() const;
    size_t GetCurrentMemoryUsage() const;
};

/**
 * CLI for canonical benchmark
 */
class CanonicalBenchmarkCLI {
public:
    static int Run(int argc, char* argv[]);

private:
    static void PrintBanner();
    static void PrintUsage();
    static BenchmarkConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Sovereign
