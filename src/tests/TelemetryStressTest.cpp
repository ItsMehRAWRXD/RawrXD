#include "../metrics/BackendTelemetry.hpp"
#include <iostream>
#include <thread>
#include <vector>
#include <chrono>
#include <atomic>
#include <cmath>

std::atomic<bool> g_stressThreadsRunning(true);

void ArtificialComputeLoadWorker() {
    volatile unsigned long long accumulator = 0;
    while (g_stressThreadsRunning.load(std::memory_order_relaxed)) {
        accumulator += 7;
        accumulator *= 3;
    }
}

int main() {
    std::cout << "=== RAWRXD TELEMETRY STRESS TEST ===\n";
    
    BackendTelemetry telemetry;
    std::vector<std::thread> threadPool;

    unsigned int threadCount = std::thread::hardware_concurrency();
    if (threadCount == 0) threadCount = 4;

    std::cout << "[STRESS] Spawning " << threadCount << " compute-bound worker threads...\n";
    for (unsigned int i = 0; i < threadCount; ++i) {
        threadPool.emplace_back(ArtificialComputeLoadWorker);
    }

    std::this_thread::sleep_for(std::chrono::seconds(2));

    std::cout << "[STRESS] Capturing telemetry checkpoint under load...\n";
    std::string payload = telemetry.CompileAggregatedTelemetryPayload("BareMetal");
    std::cout << payload << "\n";

    bool hasCpuData = (payload.find("cpuUtilization") != std::string::npos);
    bool hasGpuData = (payload.find("gpuAdapters") != std::string::npos);

    if (!hasCpuData) {
        std::cerr << "[FAIL] Telemetry payload missing CPU metrics\n";
        g_stressThreadsRunning = false;
        for (auto& t : threadPool) t.join();
        return 1;
    }

    std::cout << "[PASS] Telemetry stress test completed successfully\n";
    g_stressThreadsRunning = false;
    for (auto& t : threadPool) t.join();
    return 0;
}
