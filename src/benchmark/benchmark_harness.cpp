/**
 * @file benchmark_harness.cpp
 * @brief RawrXD Performance Benchmark Harness Implementation
 * @version 1.0.0
 *
 * Implements the benchmark harness for measuring MASM-accelerated
 * inference operations with T-P-O (Time-Per-Operation) metrics.
 *
 * @copyright (c) 2025 RawrXD Project
 */

#include "benchmark_harness.h"
#include "ollama_client.h"
#include <iostream>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <cmath>
#include <string>

#ifdef _WIN32
#include <windows.h>
#include <psapi.h>
#endif

namespace RawrXD::Benchmark {

// ============================================================================
// FORWARD DECLARATIONS (MASM BRIDGE FUNCTIONS)
// ============================================================================

// These are implemented in MASM and linked at build time
extern "C" {
    // Dequantization kernel
    void __cdecl Aperture_Q4_0_Dequant(void* dst, const void* src, size_t count);
    void __cdecl Aperture_Q8_0_Dequant(void* dst, const void* src, size_t count);
    
    // Attention kernels
    void __cdecl Pyre_GEMM_F32_AVX512(float* C, const float* A, const float* B, 
                                       size_t M, size_t N, size_t K);
    
    // KV-cache operations
    void __cdecl KVCache_Read(void* dst, size_t slot_idx, size_t head, size_t dim);
    void __cdecl KVCache_Write(const void* src, size_t slot_idx, size_t head, size_t dim);
    
    // Model loading
    int __cdecl ModelBridge_Load(const char* path);
    int __cdecl ModelBridge_ValidateLoad(const char* path);
}

// ============================================================================
// HIGH RESOLUTION TIMER IMPLEMENTATION
// ============================================================================

void HighResTimer::Start() {
    startTime_ = Clock::now();
    running_ = true;
}

void HighResTimer::Stop() {
    endTime_ = Clock::now();
    running_ = false;
}

double HighResTimer::GetElapsedUs() const {
    if (running_) {
        auto now = Clock::now();
        return std::chrono::duration_cast<std::chrono::nanoseconds>(now - startTime_).count() / 1000.0;
    }
    return std::chrono::duration_cast<std::chrono::nanoseconds>(endTime_ - startTime_).count() / 1000.0;
}

double HighResTimer::GetElapsedMs() const {
    return GetElapsedUs() / 1000.0;
}

// ============================================================================
// STATISTICS IMPLEMENTATION
// ============================================================================

double Statistics::CalculateMean(const std::vector<double>& values) {
    if (values.empty()) return 0.0;
    double sum = std::accumulate(values.begin(), values.end(), 0.0);
    return sum / values.size();
}

double Statistics::CalculateStdDev(const std::vector<double>& values) {
    if (values.size() < 2) return 0.0;
    double mean = CalculateMean(values);
    double sq_sum = std::accumulate(values.begin(), values.end(), 0.0,
        [mean](double acc, double val) { return acc + (val - mean) * (val - mean); });
    return std::sqrt(sq_sum / values.size());
}

double Statistics::CalculatePercentile(const std::vector<double>& values, double percentile) {
    if (values.empty()) return 0.0;
    std::vector<double> sorted = values;
    std::sort(sorted.begin(), sorted.end());
    
    size_t index = static_cast<size_t>(std::ceil((percentile / 100.0) * sorted.size())) - 1;
    index = std::min(index, sorted.size() - 1);
    return sorted[index];
}

double Statistics::CalculateMin(const std::vector<double>& values) {
    if (values.empty()) return 0.0;
    return *std::min_element(values.begin(), values.end());
}

double Statistics::CalculateMax(const std::vector<double>& values) {
    if (values.empty()) return 0.0;
    return *std::max_element(values.begin(), values.end());
}

// ============================================================================
// BENCHMARK RESULT IMPLEMENTATION
// ============================================================================

bool BenchmarkResult::ExportToCSV(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;
    
    // Write header
    file << "iteration,duration_us,throughput_gbps,bytes_processed,operations\n";
    
    // Write raw data
    for (const auto& iter : rawData) {
        file << iter.iteration << ","
           << iter.durationUs << ","
           << iter.throughputGbps << ","
           << iter.bytesProcessed << ","
           << iter.operations << "\n";
    }
    
    // Write summary
    file << "\n# Summary\n";
    file << "test_name," << testName << "\n";
    file << "total_iterations," << totalIterations << "\n";
    file << "total_time_ms," << totalTimeMs << "\n";
    file << "mean_latency_us," << meanLatencyUs << "\n";
    file << "min_latency_us," << minLatencyUs << "\n";
    file << "max_latency_us," << maxLatencyUs << "\n";
    file << "p50_latency_us," << p50LatencyUs << "\n";
    file << "p95_latency_us," << p95LatencyUs << "\n";
    file << "p99_latency_us," << p99LatencyUs << "\n";
    file << "throughput_gbps," << throughputGbps << "\n";
    file << "std_deviation," << stdDeviation << "\n";
    
    file.close();
    return true;
}

bool BenchmarkResult::ExportToJSON(const std::string& filepath) const {
    std::ofstream file(filepath);
    if (!file.is_open()) return false;
    
    file << "{\n";
    file << "  \"test_name\": \"" << testName << "\",\n";
    file << "  \"total_iterations\": " << totalIterations << ",\n";
    file << "  \"total_time_ms\": " << totalTimeMs << ",\n";
    file << "  \"mean_latency_us\": " << meanLatencyUs << ",\n";
    file << "  \"min_latency_us\": " << minLatencyUs << ",\n";
    file << "  \"max_latency_us\": " << maxLatencyUs << ",\n";
    file << "  \"p50_latency_us\": " << p50LatencyUs << ",\n";
    file << "  \"p95_latency_us\": " << p95LatencyUs << ",\n";
    file << "  \"p99_latency_us\": " << p99LatencyUs << ",\n";
    file << "  \"throughput_gbps\": " << throughputGbps << ",\n";
    file << "  \"std_deviation\": " << stdDeviation << ",\n";
    file << "  \"raw_data\": [\n";
    
    for (size_t i = 0; i < rawData.size(); ++i) {
        file << "    {\n";
        file << "      \"iteration\": " << rawData[i].iteration << ",\n";
        file << "      \"duration_us\": " << rawData[i].durationUs << ",\n";
        file << "      \"throughput_gbps\": " << rawData[i].throughputGbps << ",\n";
        file << "      \"bytes_processed\": " << rawData[i].bytesProcessed << ",\n";
        file << "      \"operations\": " << rawData[i].operations << "\n";
        file << "    }";
        if (i < rawData.size() - 1) file << ",";
        file << "\n";
    }
    
    file << "  ]\n";
    file << "}\n";
    
    file.close();
    return true;
}

void BenchmarkResult::PrintResults() const {
    std::cout << "\n  Test: " << testName << "\n";
    std::cout << "  ─────────────────────────────────────────────────────────────\n";
    std::cout << "  Total Iterations: " << totalIterations << "\n";
    std::cout << "  Total Time: " << std::fixed << std::setprecision(2) << totalTimeMs << " ms\n";
    std::cout << "\n  Latency Statistics (microseconds):\n";
    std::cout << "    Mean:  " << std::setw(10) << std::setprecision(3) << meanLatencyUs << " μs\n";
    std::cout << "    Min:   " << std::setw(10) << minLatencyUs << " μs\n";
    std::cout << "    Max:   " << std::setw(10) << maxLatencyUs << " μs\n";
    std::cout << "    P50:   " << std::setw(10) << p50LatencyUs << " μs\n";
    std::cout << "    P95:   " << std::setw(10) << p95LatencyUs << " μs\n";
    std::cout << "    P99:   " << std::setw(10) << p99LatencyUs << " μs\n";
    std::cout << "    StdDev:" << std::setw(10) << stdDeviation << " μs\n";
    std::cout << "\n  Throughput: " << std::setprecision(2) << throughputGbps << " GB/s\n";
}

// ============================================================================
// BENCHMARK HARNESS PIMPL
// ============================================================================

class BenchmarkHarness::Impl {
public:
    BenchmarkConfig config;
    bool initialized = false;
    
    // Timer storage for C interface
    struct TimerEntry {
        std::string name;
        HighResTimer timer;
        double elapsedUs = 0;
    };
    std::vector<TimerEntry> timers;
    
    bool Initialize(const BenchmarkConfig& cfg) {
        config = cfg;
        
        // Create output directory
        #ifdef _WIN32
        CreateDirectoryA(config.outputDir.c_str(), nullptr);
        #else
        mkdir(config.outputDir.c_str(), 0755);
        #endif
        
        initialized = true;
        return true;
    }
    
    void Shutdown() {
        initialized = false;
    }
    
    BenchmarkResult RunColdStart(const std::string& modelPath) {
        BenchmarkResult result;
        result.testName = "Cold Start - " + modelPath;
        result.mode = TestMode::COLD_START;
        
        std::vector<double> latencies;
        HighResTimer timer;
        
        // Warmup
        for (uint64_t i = 0; i < config.warmupIterations; ++i) {
            timer.Start();
            ModelBridge_ValidateLoad(modelPath.c_str());
            timer.Stop();
        }
        
        // Benchmark
        timer.Start();
        auto startTotal = timer;
        
        for (uint64_t i = 0; i < config.benchmarkIterations; ++i) {
            timer.Start();
            ModelBridge_ValidateLoad(modelPath.c_str());
            timer.Stop();
            
            double elapsed = timer.GetElapsedUs();
            latencies.push_back(elapsed);
            
            IterationResult iterResult;
            iterResult.iteration = i;
            iterResult.durationUs = elapsed;
            iterResult.bytesProcessed = 0;
            iterResult.operations = 1;
            result.rawData.push_back(iterResult);
        }
        
        // Calculate statistics
        result.totalIterations = config.benchmarkIterations;
        result.totalTimeMs = Statistics::CalculateMean(latencies) * config.benchmarkIterations / 1000.0;
        result.meanLatencyUs = Statistics::CalculateMean(latencies);
        result.minLatencyUs = Statistics::CalculateMin(latencies);
        result.maxLatencyUs = Statistics::CalculateMax(latencies);
        result.p50LatencyUs = Statistics::CalculatePercentile(latencies, 50);
        result.p95LatencyUs = Statistics::CalculatePercentile(latencies, 95);
        result.p99LatencyUs = Statistics::CalculatePercentile(latencies, 99);
        result.stdDeviation = Statistics::CalculateStdDev(latencies);
        result.throughputGbps = 0; // Not applicable for cold start
        
        return result;
    }
    
    BenchmarkResult RunDequantBenchmark(QuantType type, uint64_t tensorCount) {
        BenchmarkResult result;
        result.testName = "Dequantization - " + std::to_string(static_cast<int>(type));
        result.mode = TestMode::KERNEL_DEQUANT;
        
        // Allocate test data
        const size_t blockSize = 32; // Q4_0 block size
        std::vector<uint8_t> srcData(tensorCount * blockSize);
        std::vector<float> dstData(tensorCount * 32); // 32 floats per block
        
        // Fill with test pattern
        for (auto& b : srcData) b = static_cast<uint8_t>(rand() % 256);
        
        std::vector<double> latencies;
        HighResTimer timer;
        
        // Warmup
        for (uint64_t i = 0; i < config.warmupIterations; ++i) {
            if (type == QuantType::Q4_0) {
                Aperture_Q4_0_Dequant(dstData.data(), srcData.data(), tensorCount);
            } else if (type == QuantType::Q8_0) {
                Aperture_Q8_0_Dequant(dstData.data(), srcData.data(), tensorCount);
            }
        }
        
        // Benchmark
        for (uint64_t i = 0; i < config.benchmarkIterations; ++i) {
            timer.Start();
            if (type == QuantType::Q4_0) {
                Aperture_Q4_0_Dequant(dstData.data(), srcData.data(), tensorCount);
            } else if (type == QuantType::Q8_0) {
                Aperture_Q8_0_Dequant(dstData.data(), srcData.data(), tensorCount);
            }
            timer.Stop();
            
            double elapsed = timer.GetElapsedUs();
            latencies.push_back(elapsed);
            
            IterationResult iterResult;
            iterResult.iteration = i;
            iterResult.durationUs = elapsed;
            iterResult.bytesProcessed = tensorCount * blockSize;
            iterResult.operations = tensorCount;
            iterResult.throughputGbps = (tensorCount * blockSize) / (elapsed * 1000.0); // GB/s
            result.rawData.push_back(iterResult);
        }
        
        // Calculate statistics
        result.totalIterations = config.benchmarkIterations;
        result.totalTimeMs = Statistics::CalculateMean(latencies) * config.benchmarkIterations / 1000.0;
        result.meanLatencyUs = Statistics::CalculateMean(latencies);
        result.minLatencyUs = Statistics::CalculateMin(latencies);
        result.maxLatencyUs = Statistics::CalculateMax(latencies);
        result.p50LatencyUs = Statistics::CalculatePercentile(latencies, 50);
        result.p95LatencyUs = Statistics::CalculatePercentile(latencies, 95);
        result.p99LatencyUs = Statistics::CalculatePercentile(latencies, 99);
        result.stdDeviation = Statistics::CalculateStdDev(latencies);
        
        // Calculate throughput
        double totalBytes = config.benchmarkIterations * tensorCount * blockSize;
        double totalTimeS = result.totalTimeMs / 1000.0;
        result.throughputGbps = totalBytes / (totalTimeS * 1e9);
        
        return result;
    }
    
    BenchmarkResult RunAttentionBenchmark(uint32_t seqLen, uint32_t headDim) {
        BenchmarkResult result;
        result.testName = "Attention - seq=" + std::to_string(seqLen) + ",head=" + std::to_string(headDim);
        result.mode = TestMode::KERNEL_ATTENTION;
        
        // Allocate matrices
        std::vector<float> A(seqLen * headDim);
        std::vector<float> B(headDim * headDim);
        std::vector<float> C(seqLen * headDim);
        
        // Fill with test data
        for (auto& v : A) v = static_cast<float>(rand()) / RAND_MAX;
        for (auto& v : B) v = static_cast<float>(rand()) / RAND_MAX;
        
        std::vector<double> latencies;
        HighResTimer timer;
        
        // Warmup
        for (uint64_t i = 0; i < config.warmupIterations; ++i) {
            Pyre_GEMM_F32_AVX512(C.data(), A.data(), B.data(), seqLen, headDim, headDim);
        }
        
        // Benchmark
        for (uint64_t i = 0; i < config.benchmarkIterations; ++i) {
            timer.Start();
            Pyre_GEMM_F32_AVX512(C.data(), A.data(), B.data(), seqLen, headDim, headDim);
            timer.Stop();
            
            double elapsed = timer.GetElapsedUs();
            latencies.push_back(elapsed);
            
            IterationResult iterResult;
            iterResult.iteration = i;
            iterResult.durationUs = elapsed;
            iterResult.bytesProcessed = (A.size() + B.size() + C.size()) * sizeof(float);
            iterResult.operations = seqLen * headDim * headDim; // Matrix multiply ops
            result.rawData.push_back(iterResult);
        }
        
        // Calculate statistics
        result.totalIterations = config.benchmarkIterations;
        result.totalTimeMs = Statistics::CalculateMean(latencies) * config.benchmarkIterations / 1000.0;
        result.meanLatencyUs = Statistics::CalculateMean(latencies);
        result.minLatencyUs = Statistics::CalculateMin(latencies);
        result.maxLatencyUs = Statistics::CalculateMax(latencies);
        result.p50LatencyUs = Statistics::CalculatePercentile(latencies, 50);
        result.p95LatencyUs = Statistics::CalculatePercentile(latencies, 95);
        result.p99LatencyUs = Statistics::CalculatePercentile(latencies, 99);
        result.stdDeviation = Statistics::CalculateStdDev(latencies);
        result.throughputGbps = 0; // Calculate based on FLOPs
        
        return result;
    }
    
    BenchmarkResult RunKVCacheBenchmark(uint64_t cacheSizeMB, uint64_t accessCount) {
        BenchmarkResult result;
        result.testName = "KV-Cache - " + std::to_string(cacheSizeMB) + "MB";
        result.mode = TestMode::KV_CACHE_ACCESS;
        
        // Simulate KV-cache with random access pattern
        const size_t slotSize = 4096; // 4KB per slot
        const size_t numSlots = (cacheSizeMB * 1024 * 1024) / slotSize;
        std::vector<std::vector<float>> cache(numSlots, std::vector<float>(slotSize / sizeof(float)));
        
        // Fill cache
        for (auto& slot : cache) {
            for (auto& v : slot) v = static_cast<float>(rand()) / RAND_MAX;
        }
        
        std::vector<double> latencies;
        HighResTimer timer;
        
        // Warmup
        for (uint64_t i = 0; i < config.warmupIterations; ++i) {
            size_t slotIdx = rand() % numSlots;
            volatile float dummy = cache[slotIdx][0]; // Force read
        }
        
        // Benchmark random access
        for (uint64_t i = 0; i < config.benchmarkIterations; ++i) {
            size_t slotIdx = rand() % numSlots;
            
            timer.Start();
            volatile float dummy = cache[slotIdx][0]; // Random read
            timer.Stop();
            
            double elapsed = timer.GetElapsedUs();
            latencies.push_back(elapsed);
            
            IterationResult iterResult;
            iterResult.iteration = i;
            iterResult.durationUs = elapsed;
            iterResult.bytesProcessed = sizeof(float);
            iterResult.operations = 1;
            result.rawData.push_back(iterResult);
        }
        
        // Calculate statistics
        result.totalIterations = config.benchmarkIterations;
        result.totalTimeMs = Statistics::CalculateMean(latencies) * config.benchmarkIterations / 1000.0;
        result.meanLatencyUs = Statistics::CalculateMean(latencies);
        result.minLatencyUs = Statistics::CalculateMin(latencies);
        result.maxLatencyUs = Statistics::CalculateMax(latencies);
        result.p50LatencyUs = Statistics::CalculatePercentile(latencies, 50);
        result.p95LatencyUs = Statistics::CalculatePercentile(latencies, 95);
        result.p99LatencyUs = Statistics::CalculatePercentile(latencies, 99);
        result.stdDeviation = Statistics::CalculateStdDev(latencies);
        result.throughputGbps = 0; // Latency-focused benchmark
        
        return result;
    }
    
    BenchmarkResult RunTokenGeneration(const std::string& modelPath, uint32_t tokenCount) {
        BenchmarkResult result;
        result.testName = "Token Generation - " + std::to_string(tokenCount) + " tokens";
        result.mode = TestMode::END_TO_END_TOKEN;
        
        // This is a placeholder - actual implementation would:
        // 1. Load model
        // 2. Run inference for N tokens
        // 3. Measure tokens/sec
        
        std::vector<double> latencies;
        HighResTimer timer;
        
        // Run actual token generation via Ollama
        RawrXD::Backend::NativeClient ollamaClient("http://localhost:11434");
        if (!ollamaClient.testConnection()) {
            result.error = "Cannot connect to Ollama";
            return result;
        }

        for (uint64_t i = 0; i < config.benchmarkIterations; ++i) {
            timer.Start();

            // Actual inference via Ollama
            RawrXD::Backend::OllamaGenerateRequest req;
            req.model = "phi3:mini";
            req.prompt = "Generate a creative story about AI:";
            req.stream = false;
            req.options["num_predict"] = tokenCount;

            auto response = ollamaClient.generateSync(req);

            timer.Stop();
            
            double elapsed = timer.GetElapsedUs();
            latencies.push_back(elapsed);
            
            IterationResult iterResult;
            iterResult.iteration = i;
            iterResult.durationUs = elapsed;
            iterResult.bytesProcessed = 0;
            iterResult.operations = tokenCount;
            iterResult.throughputGbps = tokenCount / (elapsed / 1e6); // tokens/sec
            result.rawData.push_back(iterResult);
        }
        
        // Calculate statistics
        result.totalIterations = config.benchmarkIterations;
        result.totalTimeMs = Statistics::CalculateMean(latencies) * config.benchmarkIterations / 1000.0;
        result.meanLatencyUs = Statistics::CalculateMean(latencies);
        result.minLatencyUs = Statistics::CalculateMin(latencies);
        result.maxLatencyUs = Statistics::CalculateMax(latencies);
        result.p50LatencyUs = Statistics::CalculatePercentile(latencies, 50);
        result.p95LatencyUs = Statistics::CalculatePercentile(latencies, 95);
        result.p99LatencyUs = Statistics::CalculatePercentile(latencies, 99);
        result.stdDeviation = Statistics::CalculateStdDev(latencies);
        result.throughputGbps = tokenCount / (result.meanLatencyUs / 1e6); // tokens/sec
        
        return result;
    }
};

// ============================================================================
// BENCHMARK HARNESS PUBLIC INTERFACE
// ============================================================================

BenchmarkHarness::BenchmarkHarness() : pImpl(std::make_unique<Impl>()) {}
BenchmarkHarness::~BenchmarkHarness() = default;

bool BenchmarkHarness::Initialize(const BenchmarkConfig& config) {
    return pImpl->Initialize(config);
}

void BenchmarkHarness::Shutdown() {
    pImpl->Shutdown();
}

BenchmarkResult BenchmarkHarness::RunColdStart(const std::string& modelPath) {
    return pImpl->RunColdStart(modelPath);
}

BenchmarkResult BenchmarkHarness::RunDequantBenchmark(QuantType type, uint64_t tensorCount) {
    return pImpl->RunDequantBenchmark(type, tensorCount);
}

BenchmarkResult BenchmarkHarness::RunAttentionBenchmark(uint32_t seqLen, uint32_t headDim) {
    return pImpl->RunAttentionBenchmark(seqLen, headDim);
}

BenchmarkResult BenchmarkHarness::RunKVCacheBenchmark(uint64_t cacheSizeMB, uint64_t accessCount) {
    return pImpl->RunKVCacheBenchmark(cacheSizeMB, accessCount);
}

BenchmarkResult BenchmarkHarness::RunTokenGeneration(const std::string& modelPath, uint32_t tokenCount) {
    return pImpl->RunTokenGeneration(modelPath, tokenCount);
}

std::vector<BenchmarkResult> BenchmarkHarness::RunAllBenchmarks() {
    std::vector<BenchmarkResult> results;
    
    // Run all benchmark types
    if (!pImpl->config.modelPaths.empty()) {
        for (const auto& model : pImpl->config.modelPaths) {
            results.push_back(RunColdStart(model));
        }
    }
    
    results.push_back(RunDequantBenchmark(QuantType::Q4_0, 1024));
    results.push_back(RunDequantBenchmark(QuantType::Q8_0, 1024));
    results.push_back(RunAttentionBenchmark(512, 64));
    results.push_back(RunAttentionBenchmark(1024, 128));
    results.push_back(RunKVCacheBenchmark(512, 10000));
    
    if (!pImpl->config.modelPaths.empty()) {
        for (const auto& model : pImpl->config.modelPaths) {
            results.push_back(RunTokenGeneration(model, 100));
        }
    }
    
    return results;
}

std::string BenchmarkHarness::CompareToBaseline(const BenchmarkResult& current, 
                                                   const std::string& baselinePath) {
    std::stringstream report;
    report << "\n  Comparison to Baseline:\n";
    report << "  ─────────────────────────────────────────────────────────────\n";
    
    // TODO: Load baseline and compare
    // For now, just report current values
    report << "    Current Mean Latency: " << current.meanLatencyUs << " μs\n";
    report << "    Current Throughput: " << current.throughputGbps << " GB/s\n";
    report << "    (Baseline comparison not yet implemented)\n";
    
    return report.str();
}

// ============================================================================
// C INTERFACE IMPLEMENTATION
// ============================================================================

extern "C" {

static std::vector<std::pair<std::string, double>> g_timerResults;

void __cdecl Benchmark_InitTimer(void) {
    g_timerResults.clear();
}

void __cdecl Benchmark_StartTimer(const char* sectionName) {
    // Implementation would track timer start
    (void)sectionName;
}

void __cdecl Benchmark_StopTimer(const char* sectionName) {
    // Implementation would track timer stop and store result
    (void)sectionName;
}

uint64_t __cdecl Benchmark_GetElapsedUs(const char* sectionName) {
    for (const auto& result : g_timerResults) {
        if (result.first == sectionName) {
            return static_cast<uint64_t>(result.second);
        }
    }
    return 0;
}

void __cdecl Benchmark_ResetTimers(void) {
    g_timerResults.clear();
}

int __cdecl Benchmark_ExportResults(const char* filepath) {
    std::ofstream file(filepath);
    if (!file.is_open()) return -1;
    
    file << "section,elapsed_us\n";
    for (const auto& result : g_timerResults) {
        file << result.first << "," << result.second << "\n";
    }
    
    file.close();
    return 0;
}

} // extern "C"

} // namespace RawrXD::Benchmark
