#pragma once

#include <windows.h>
#include <cstdint>
#include <iostream>
#include <iomanip>
#include <vector>
#include <numeric>
#include <algorithm>
#include <string>

class Deep2Profiler {
private:
    LARGE_INTEGER frequency;
    LARGE_INTEGER startIngestion, endIngestion;
    LARGE_INTEGER startGeneration, endGeneration;
    
    // Per-token metrics
    std::vector<double> tokenLatenciesMs;
    
    // Hardware and I/O metrics
    uint64_t totalIoWaitCycles = 0;
    uint64_t totalComputeCycles = 0;
    uint64_t totalOverlapCycles = 0;
    uint32_t starvationCount = 0;
    uint32_t slotAWaitCount = 0;
    uint32_t slotBWaitCount = 0;

    uint64_t totalPromptTokens = 0;
    uint64_t totalGeneratedTokens = 0;

    inline uint64_t ReadCycles() {
        return __rdtsc();
    }

public:
    Deep2Profiler() {
        QueryPerformanceFrequency(&frequency);
    }

    void StartPromptIngestion(uint64_t promptTokenCount) {
        totalPromptTokens = promptTokenCount;
        QueryPerformanceCounter(&startIngestion);
    }

    void EndPromptIngestion() {
        QueryPerformanceCounter(&endIngestion);
    }

    void StartTokenGeneration() {
        QueryPerformanceCounter(&startGeneration);
        tokenLatenciesMs.clear();
    }

    void StartTokenStep() {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        // Step start
    }

    void EndTokenStep() {
        LARGE_INTEGER now;
        QueryPerformanceCounter(&now);
        // Step end - logic moved to LogGeneratedToken for simplicity
    }

    void LogGeneratedToken(double latencyMs) {
        totalGeneratedTokens++;
        tokenLatenciesMs.push_back(latencyMs);
    }

    void EndTokenGeneration() {
        QueryPerformanceCounter(&endGeneration);
    }

    void RecordIoWait(uint64_t cycles) { totalIoWaitCycles += cycles; }
    void RecordCompute(uint64_t cycles) { totalComputeCycles += cycles; }
    void RecordOverlap(uint64_t cycles) { totalOverlapCycles += cycles; }
    void IncrementStarvation() { starvationCount++; }
    void IncrementSlotAWait() { slotAWaitCount++; }
    void IncrementSlotBWait() { slotBWaitCount++; }

    void PrintReport(const std::string& runLabel, uint64_t matrixRows, uint64_t matrixColumns) {
        double ingestionTimeMs = (static_cast<double>(endIngestion.QuadPart - startIngestion.QuadPart) * 1000.0) / frequency.QuadPart;
        double generationTimeMs = (static_cast<double>(endGeneration.QuadPart - startGeneration.QuadPart) * 1000.0) / frequency.QuadPart;

        double ingestionTPS = (totalPromptTokens / (ingestionTimeMs / 1000.0));
        double generationTPS = (totalGeneratedTokens / (generationTimeMs / 1000.0));

        // Sorting for percentiles
        std::vector<double> sortedLatencies = tokenLatenciesMs;
        std::sort(sortedLatencies.begin(), sortedLatencies.end());

        double p50 = sortedLatencies.empty() ? 0 : sortedLatencies[sortedLatencies.size() * 50 / 100];
        double p95 = sortedLatencies.empty() ? 0 : sortedLatencies[sortedLatencies.size() * 95 / 100];
        double p99 = sortedLatencies.empty() ? 0 : sortedLatencies[sortedLatencies.size() * 99 / 100];
        double maxLatency = sortedLatencies.empty() ? 0 : sortedLatencies.back();

        double cpuFreqGhz = 4.8; // Assumed for 7800X3D
        double ioWaitMs = (totalIoWaitCycles / (cpuFreqGhz * 1000000.0));
        double computeMs = (totalComputeCycles / (cpuFreqGhz * 1000000.0));
        double overlapMs = (totalOverlapCycles / (cpuFreqGhz * 1000000.0));

        double overlapRatio = (overlapMs / (ioWaitMs + overlapMs + 1e-9));
        double computeDuty = (computeMs / (generationTimeMs + 1e-9));

        std::cout << "\n============================================================\n";
        std::cout << " RUN: " << runLabel << "\n";
        std::cout << "============================================================\n";
        std::cout << " [Metrics] Ingestion Speed         : " << std::fixed << std::setprecision(2) << ingestionTPS << " Prompt TPS\n";
        std::cout << " [Metrics] Token Generation Speed  : " << std::fixed << std::setprecision(2) << generationTPS << " Eval TPS\n";
        std::cout << " [Latency] P50 / P95 / P99 / MAX   : " << p50 << " / " << p95 << " / " << p99 << " / " << maxLatency << " ms/token\n";
        std::cout << "------------------------------------------------------------\n";
        std::cout << " [I/O] IO Wait / Compute / Overlap : " << ioWaitMs << " / " << computeMs << " / " << overlapMs << " ms\n";
        std::cout << " [I/O] Starvations / A_Wait / B_Wait: " << starvationCount << " / " << slotAWaitCount << " / " << slotBWaitCount << "\n";
        std::cout << " [Derived] ASYNC_OVERLAP_RATIO      : " << std::fixed << std::setprecision(4) << overlapRatio << "\n";
        std::cout << " [Derived] COMPUTE_DUTY             : " << std::fixed << std::setprecision(4) << computeDuty << "\n";
        std::cout << "============================================================\n\n";
    }
};
