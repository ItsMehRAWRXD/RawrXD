/**
 * @file benchmark_inference.cpp
 * @brief Performance benchmarks for inference engine
 * 
 * Phase 2: Performance Validation
 * 
 * Measures:
 * - Token generation speed (tokens/sec)
 * - Memory usage
 * - Latency (time to first token)
 * - Throughput under load
 * 
 * @copyright RawrXD 2026
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>
#include <math>
#include <fstream>
#include <map>

// Unified architecture
#include "../../src/agentic/Core.h"
#include "../../src/inference/InferenceEngine.h"

using namespace RawrXD;

// ============================================================================
// Benchmark Configuration
// ============================================================================

struct BenchmarkConfig {
    std::string modelPath;
    std::string modelName;
    std::string quantization;
    
    int warmupRuns = 3;
    int benchmarkRuns = 10;
    int maxTokens = 100;
    
    std::vector<std::string> prompts = {
        "Hello, how are you?",
        "Explain quantum computing in simple terms.",
        "Write a function to calculate fibonacci numbers in Python.",
        "The quick brown fox jumps over the lazy dog. This is a test of longer context handling and generation capabilities.",
        "In the year 2050, artificial intelligence has become ubiquitous. Describe a day in the life of a software engineer."
    };
};

struct BenchmarkResult {
    std::string modelName;
    std::string quantization;
    std::string prompt;
    
    double timeToFirstTokenMs = 0;
    double tokensPerSecond = 0;
    double totalTimeMs = 0;
    int tokensGenerated = 0;
    size_t peakMemoryMB = 0;
    
    double avgTokensPerSecond = 0;
    double minTokensPerSecond = 0;
    double maxTokensPerSecond = 0;
    double stdDevTokensPerSecond = 0;
};

// ============================================================================
// Memory Tracking (Platform-specific)
// ============================================================================

#ifdef _WIN32
    #include <windows.h>
    #include <psapi.h>
    
    size_t GetPeakMemoryUsageMB() {
        PROCESS_MEMORY_COUNTERS pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), &pmc, sizeof(pmc))) {
            return pmc.PeakWorkingSetSize / (1024 * 1024);
        }
        return 0;
    }
#else
    #include <unistd.h>
    #include <sys/resource.h>
    
    size_t GetPeakMemoryUsageMB() {
        struct rusage rusage;
        if (getrusage(RUSAGE_SELF, &rusage) == 0) {
            return rusage.ru_maxrss / 1024;  // Convert KB to MB
        }
        return 0;
    }
#endif

// ============================================================================
// Benchmark Functions
// ============================================================================

class InferenceBenchmark {
public:
    InferenceBenchmark(const BenchmarkConfig& config) : m_config(config) {}
    
    BenchmarkResult Run() {
        BenchmarkResult result;
        result.modelName = m_config.modelName;
        result.quantization = m_config.quantization;
        
        std::cout << "Initializing inference engine..." << std::endl;
        
        // Create engine
        Inference::EngineConfig engineConfig;
        engineConfig.backendType = Inference::BackendType::GGML;
        engineConfig.modelPath = m_config.modelPath;
        engineConfig.maxContextLength = 4096;
        
        auto engine = Inference::InferenceEngine::Create(engineConfig);
        if (!engine->Initialize()) {
            std::cerr << "Failed to initialize engine" << std::endl;
            return result;
        }
        
        // Load model
        auto loadResult = engine->LoadModel(m_config.modelPath);
        if (!loadResult.success) {
            std::cerr << "Failed to load model: " << loadResult.errorMessage << std::endl;
            return result;
        }
        
        std::cout << "Model loaded. Running benchmarks..." << std::endl;
        
        // Warmup runs
        std::cout << "Warmup (" << m_config.warmupRuns << " runs)..." << std::endl;
        for (int i = 0; i < m_config.warmupRuns; ++i) {
            RunSingleBenchmark(engine, m_config.prompts[0], false);
        }
        
        // Benchmark runs
        std::cout << "Benchmarking (" << m_config.benchmarkRuns << " runs)..." << std::endl;
        std::vector<double> tokensPerSecondValues;
        
        for (int run = 0; run < m_config.benchmarkRuns; ++run) {
            for (const auto& prompt : m_config.prompts) {
                auto singleResult = RunSingleBenchmark(engine, prompt, true);
                if (singleResult.tokensPerSecond > 0) {
                    tokensPerSecondValues.push_back(singleResult.tokensPerSecond);
                }
            }
            std::cout << "." << std::flush;
        }
        std::cout << std::endl;
        
        // Calculate statistics
        if (!tokensPerSecondValues.empty()) {
            result.avgTokensPerSecond = CalculateAverage(tokensPerSecondValues);
            result.minTokensPerSecond = *std::min_element(tokensPerSecondValues.begin(), 
                                                            tokensPerSecondValues.end());
            result.maxTokensPerSecond = *std::max_element(tokensPerSecondValues.begin(), 
                                                            tokensPerSecondValues.end());
            result.stdDevTokensPerSecond = CalculateStdDev(tokensPerSecondValues, result.avgTokensPerSecond);
        }
        
        // Final detailed run for memory measurement
        auto finalResult = RunSingleBenchmark(engine, m_config.prompts[0], true);
        result.timeToFirstTokenMs = finalResult.timeToFirstTokenMs;
        result.tokensPerSecond = finalResult.tokensPerSecond;
        result.totalTimeMs = finalResult.totalTimeMs;
        result.tokensGenerated = finalResult.tokensGenerated;
        result.peakMemoryMB = GetPeakMemoryUsageMB();
        
        engine->Shutdown();
        
        return result;
    }
    
private:
    BenchmarkResult RunSingleBenchmark(std::shared_ptr<Inference::InferenceEngine> engine,
                                        const std::string& prompt,
                                        bool measureMemory) {
        BenchmarkResult result;
        result.prompt = prompt;
        
        Inference::GenerationParams params;
        params.prompt = prompt;
        params.maxTokens = m_config.maxTokens;
        params.temperature = 0.7f;
        params.topP = 0.95f;
        
        // Measure time to first token
        auto startTime = std::chrono::high_resolution_clock::now();
        auto firstTokenTime = startTime;
        bool firstTokenReceived = false;
        
        int tokensGenerated = 0;
        
        auto genResult = engine->Generate(params, 
            [&firstTokenTime, &firstTokenReceived, &tokensGenerated](const std::string& token) {
                if (!firstTokenReceived) {
                    firstTokenTime = std::chrono::high_resolution_clock::now();
                    firstTokenReceived = true;
                }
                tokensGenerated++;
            });
        
        auto endTime = std::chrono::high_resolution_clock::now();
        
        if (genResult.success) {
            auto totalDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                endTime - startTime).count();
            auto ttftDuration = std::chrono::duration_cast<std::chrono::milliseconds>(
                firstTokenTime - startTime).count();
            
            result.timeToFirstTokenMs = ttftDuration;
            result.totalTimeMs = totalDuration;
            result.tokensGenerated = tokensGenerated;
            
            if (totalDuration > 0 && tokensGenerated > 0) {
                result.tokensPerSecond = (tokensGenerated * 1000.0) / totalDuration;
            }
        }
        
        return result;
    }
    
    double CalculateAverage(const std::vector<double>& values) {
        if (values.empty()) return 0.0;
        double sum = std::accumulate(values.begin(), values.end(), 0.0);
        return sum / values.size();
    }
    
    double CalculateStdDev(const std::vector<double>& values, double mean) {
        if (values.size() < 2) return 0.0;
        double sum = 0.0;
        for (double val : values) {
            sum += (val - mean) * (val - mean);
        }
        return std::sqrt(sum / (values.size() - 1));
    }
    
    BenchmarkConfig m_config;
};

// ============================================================================
// Results Output
// ============================================================================

void PrintResults(const std::vector<BenchmarkResult>& results) {
    std::cout << "\n" << std::string(80, '=') << std::endl;
    std::cout << "BENCHMARK RESULTS" << std::endl;
    std::cout << std::string(80, '=') << std::endl;
    std::cout << std::endl;
    
    std::cout << std::left << std::setw(20) << "Model"
              << std::setw(10) << "Quant"
              << std::setw(12) << "TTFT (ms)"
              << std::setw(12) << "Avg TPS"
              << std::setw(12) << "Min TPS"
              << std::setw(12) << "Max TPS"
              << std::setw(12) << "StdDev"
              << std::setw(12) << "Peak MB"
              << std::endl;
    std::cout << std::string(80, '-') << std::endl;
    
    for (const auto& result : results) {
        std::cout << std::left << std::setw(20) << result.modelName
                  << std::setw(10) << result.quantization
                  << std::fixed << std::setprecision(2)
                  << std::setw(12) << result.timeToFirstTokenMs
                  << std::setw(12) << result.avgTokensPerSecond
                  << std::setw(12) << result.minTokensPerSecond
                  << std::setw(12) << result.maxTokensPerSecond
                  << std::setw(12) << result.stdDevTokensPerSecond
                  << std::setw(12) << result.peakMemoryMB
                  << std::endl;
    }
    
    std::cout << std::string(80, '=') << std::endl;
}

void ExportCSV(const std::vector<BenchmarkResult>& results, const std::string& filename) {
    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Failed to open " << filename << std::endl;
        return;
    }
    
    file << "Model,Quantization,TTFT_ms,Avg_TPS,Min_TPS,Max_TPS,StdDev_TPS,Peak_MB\n";
    
    for (const auto& result : results) {
        file << result.modelName << ","
             << result.quantization << ","
             << result.timeToFirstTokenMs << ","
             << result.avgTokensPerSecond << ","
             << result.minTokensPerSecond << ","
             << result.maxTokensPerSecond << ","
             << result.stdDevTokensPerSecond << ","
             << result.peakMemoryMB << "\n";
    }
    
    std::cout << "Results exported to " << filename << std::endl;
}

// ============================================================================
// Main
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD Inference Benchmark" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Parse arguments
    std::string modelPath = "models/llama-7b-q4.gguf";
    std::string modelName = "llama-7b";
    std::string quantization = "Q4_0";
    
    if (argc > 1) modelPath = argv[1];
    if (argc > 2) modelName = argv[2];
    if (argc > 3) quantization = argv[3];
    
    std::cout << "Model: " << modelName << std::endl;
    std::cout << "Path: " << modelPath << std::endl;
    std::cout << "Quantization: " << quantization << std::endl;
    std::cout << std::endl;
    
    // Configure benchmark
    BenchmarkConfig config;
    config.modelPath = modelPath;
    config.modelName = modelName;
    config.quantization = quantization;
    config.warmupRuns = 3;
    config.benchmarkRuns = 10;
    config.maxTokens = 100;
    
    // Run benchmark
    InferenceBenchmark benchmark(config);
    auto result = benchmark.Run();
    
    // Output results
    std::vector<BenchmarkResult> results = {result};
    PrintResults(results);
    
    // Export to CSV
    ExportCSV(results, "benchmark_results.csv");
    
    std::cout << "\nBenchmark complete!" << std::endl;
    
    return 0;
}
