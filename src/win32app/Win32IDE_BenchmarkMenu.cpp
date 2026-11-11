// Win32IDE_BenchmarkMenu.cpp — Model Benchmarking (Batch 5 M05)
// Tokens/second, memory usage per model
#include "Win32IDE.h"
#include <windows.h>
#include <string>
#include <chrono>

struct BenchmarkResult {
    std::string modelName;
    double tokensPerSecond;
    double memoryMB;
};

static std::vector<BenchmarkResult> g_benchmarkResults;

void Win32IDE::runModelBenchmark(const std::string& modelName) {
    auto start = std::chrono::high_resolution_clock::now();
    // Stub: simulate benchmark
    std::this_thread::sleep_for(std::chrono::milliseconds(100));
    auto end = std::chrono::high_resolution_clock::now();

    double elapsed = std::chrono::duration<double>(end - start).count();
    double tps = elapsed > 0 ? 100.0 / elapsed : 0.0;

    BenchmarkResult result;
    result.modelName = modelName;
    result.tokensPerSecond = tps;
    result.memoryMB = 0.0;
    g_benchmarkResults.push_back(result);

    appendToOutput("[BenchmarkMenu] " + modelName + ": " + std::to_string(tps) + " tokens/sec\n",
                   "Output", OutputSeverity::Info);
}

std::vector<BenchmarkResult> Win32IDE::getBenchmarkResults() const {
    return g_benchmarkResults;
}
