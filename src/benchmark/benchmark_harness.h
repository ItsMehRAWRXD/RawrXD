/**
 * @file benchmark_harness.h
 * @brief RawrXD Performance Benchmark Harness Interface
 * @version 1.0.0
 * 
 * Defines the C++ interface for benchmarking MASM-accelerated inference operations.
 * Links directly to the MASM loader without IDE overhead.
 * 
 * @copyright (c) 2025 RawrXD Project
 */

#pragma once

#include <cstdint>
#include <cstddef>
#include <string>
#include <vector>
#include <chrono>

// ============================================================================
// BENCHMARK CONFIGURATION
// ============================================================================

namespace RawrXD::Benchmark {

/// Benchmark test modes
enum class TestMode {
    COLD_START,           ///< Measure GGUF file mapping + header parsing
    KERNEL_DEQUANT,      ///< Measure Q4_0 dequantization throughput
    KERNEL_ATTENTION,    ///< Measure attention matrix multiplication
    KV_CACHE_ACCESS,     ///< Measure KV-cache random access latency
    END_TO_END_TOKEN,    ///< Measure full token generation pipeline
    ALL                  ///< Run all benchmarks
};

/// Quantization types supported for benchmarking
enum class QuantType {
    Q4_0,
    Q4_1,
    Q5_0,
    Q5_1,
    Q8_0,
    F16,
    F32
};

// ============================================================================
// BENCHMARK RESULTS
// ============================================================================

/**
 * @brief Single benchmark iteration result
 */
struct IterationResult {
    uint64_t    iteration;          ///< Iteration number
    double      durationUs;         ///< Duration in microseconds
    double      throughputGbps;     ///< Throughput in GB/s (if applicable)
    uint64_t    bytesProcessed;     ///< Bytes processed in this iteration
    uint64_t    operations;         ///< Number of operations performed
};

/**
 * @brief Complete benchmark test results
 */
struct BenchmarkResult {
    std::string         testName;           ///< Name of the test
    TestMode            mode;               ///< Test mode
    uint64_t            totalIterations;    ///< Total iterations run
    double              totalTimeMs;        ///< Total time in milliseconds
    double              meanLatencyUs;      ///< Mean latency in microseconds
    double              minLatencyUs;       ///< Minimum latency
    double              maxLatencyUs;       ///< Maximum latency
    double              p50LatencyUs;       ///< 50th percentile (median)
    double              p95LatencyUs;       ///< 95th percentile
    double              p99LatencyUs;       ///< 99th percentile
    double              throughputGbps;     ///< Average throughput GB/s
    double              stdDeviation;       ///< Standard deviation
    std::vector<IterationResult> rawData;  ///< Raw iteration data
    
    /**
     * @brief Export results to CSV format
     * @param filepath Output file path
     * @return true on success
     */
    bool ExportToCSV(const std::string& filepath) const;
    
    /**
     * @brief Export results to JSON format
     * @param filepath Output file path
     * @return true on success
     */
    bool ExportToJSON(const std::string& filepath) const;
    
    /**
     * @brief Print formatted results to console
     */
    void PrintResults() const;
};

// ============================================================================
// BENCHMARK CONFIGURATION
// ============================================================================

/**
 * @brief Configuration for benchmark runs
 */
struct BenchmarkConfig {
    uint64_t    warmupIterations = 10;      ///< Iterations before measurement
    uint64_t    benchmarkIterations = 1000; ///< Main benchmark iterations
    uint64_t    minDurationMs = 1000;       ///< Minimum benchmark duration
    bool        enableProfiling = false;    ///< Enable detailed profiling
    bool        verifyResults = true;       ///< Verify computation correctness
    std::string outputDir = "./benchmark_results"; ///< Output directory
    
    /// Model paths for loading benchmarks
    std::vector<std::string> modelPaths;
};

// ============================================================================
// BENCHMARK HARNESS INTERFACE
// ============================================================================

/**
 * @brief Main benchmark harness class
 * 
 * Usage:
 * @code
 *   BenchmarkHarness harness;
 *   harness.Initialize(config);
 *   
 *   auto result = harness.RunColdStart("model.gguf");
 *   result.PrintResults();
 *   
 *   auto dequant = harness.RunDequantBenchmark(QuantType::Q4_0, 1024);
 *   dequant.ExportToCSV("dequant_results.csv");
 * @endcode
 */
class BenchmarkHarness {
public:
    BenchmarkHarness();
    ~BenchmarkHarness();
    
    // Non-copyable
    BenchmarkHarness(const BenchmarkHarness&) = delete;
    BenchmarkHarness& operator=(const BenchmarkHarness&) = delete;
    
    /**
     * @brief Initialize the benchmark harness
     * @param config Benchmark configuration
     * @return true on success
     */
    bool Initialize(const BenchmarkConfig& config);
    
    /**
     * @brief Shutdown and cleanup
     */
    void Shutdown();
    
    // ========================================================================
    // BENCHMARK TESTS
    // ========================================================================
    
    /**
     * @brief Measure cold start latency (file map + header parse)
     * @param modelPath Path to GGUF model file
     * @return Benchmark results
     */
    BenchmarkResult RunColdStart(const std::string& modelPath);
    
    /**
     * @brief Measure dequantization kernel throughput
     * @param type Quantization type
     * @param tensorCount Number of tensors to process
     * @return Benchmark results
     */
    BenchmarkResult RunDequantBenchmark(QuantType type, uint64_t tensorCount);
    
    /**
     * @brief Measure attention matrix multiplication
     * @param seqLen Sequence length (e.g., 512, 1024, 2048)
     * @param headDim Head dimension (e.g., 64, 128)
     * @return Benchmark results
     */
    BenchmarkResult RunAttentionBenchmark(uint32_t seqLen, uint32_t headDim);
    
    /**
     * @brief Measure KV-cache random access latency
     * @param cacheSizeMB Cache size in MB
     * @param accessCount Number of random accesses
     * @return Benchmark results
     */
    BenchmarkResult RunKVCacheBenchmark(uint64_t cacheSizeMB, uint64_t accessCount);
    
    /**
     * @brief Measure end-to-end token generation
     * @param modelPath Path to model
     * @param tokenCount Number of tokens to generate
     * @return Benchmark results
     */
    BenchmarkResult RunTokenGeneration(const std::string& modelPath, uint32_t tokenCount);
    
    /**
     * @brief Run all configured benchmarks
     * @return Vector of all results
     */
    std::vector<BenchmarkResult> RunAllBenchmarks();
    
    /**
     * @brief Compare results against baseline
     * @param current Current benchmark results
     * @param baselinePath Path to baseline results file
     * @return Comparison report string
     */
    std::string CompareToBaseline(const BenchmarkResult& current, 
                                   const std::string& baselinePath);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl;
};

// ============================================================================
// C INTERFACE (FOR MASM INTEROP)
// ============================================================================

extern "C" {

/**
 * @brief C interface for MASM bridge benchmarking
 * 
 * These functions are called directly from MASM to measure
 * kernel-level performance.
 */

/// Initialize benchmark timer
void __cdecl Benchmark_InitTimer(void);

/// Start timing a section
void __cdecl Benchmark_StartTimer(const char* sectionName);

/// Stop timing and record result
void __cdecl Benchmark_StopTimer(const char* sectionName);

/// Get elapsed microseconds for a section
uint64_t __cdecl Benchmark_GetElapsedUs(const char* sectionName);

/// Reset all timers
void __cdecl Benchmark_ResetTimers(void);

/// Export results to file (C interface)
int __cdecl Benchmark_ExportResults(const char* filepath);

} // extern "C"

// ============================================================================
// UTILITY FUNCTIONS
// ============================================================================

/**
 * @brief High-resolution timer utility
 */
class HighResTimer {
public:
    using Clock = std::chrono::high_resolution_clock;
    using TimePoint = Clock::time_point;
    
    void Start();
    void Stop();
    double GetElapsedUs() const;
    double GetElapsedMs() const;
    
private:
    TimePoint startTime_;
    TimePoint endTime_;
    bool running_ = false;
};

/**
 * @brief Statistical analysis utilities
 */
class Statistics {
public:
    static double CalculateMean(const std::vector<double>& values);
    static double CalculateStdDev(const std::vector<double>& values);
    static double CalculatePercentile(const std::vector<double>& values, double percentile);
    static double CalculateMin(const std::vector<double>& values);
    static double CalculateMax(const std::vector<double>& values);
};

} // namespace RawrXD::Benchmark

// ============================================================================
// VERSION INFO
// ============================================================================

#define RAWRXD_BENCHMARK_VERSION_MAJOR 1
#define RAWRXD_BENCHMARK_VERSION_MINOR 0
#define RAWRXD_BENCHMARK_VERSION_PATCH 0

#define RAWRXD_BENCHMARK_VERSION_STRING "1.0.0"
