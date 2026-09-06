#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <cstdint>

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

class Deep2Profiler {
private:
    LARGE_INTEGER frequency;
    LARGE_INTEGER startIngestion, endIngestion;
    LARGE_INTEGER startGeneration, endGeneration;
    
    uint64_t totalIoWaitCycles = 0;
    uint64_t totalComputeCycles = 0;
    uint64_t totalOverlapCycles = 0;
    uint32_t starvationCount = 0;

    uint64_t totalPromptTokens = 0;
    uint64_t totalGeneratedTokens = 0;

    // Added members for label and CPU clock speed
    const char* m_TestLabel = "";
    double m_CpuClockSpeedGhz = 0.0;

public:
    Deep2Profiler() {
        QueryPerformanceFrequency(&frequency);
    }

    // Constructor with label and CPU clock speed
    Deep2Profiler(const char* label, double cpuClockSpeedGhz) 
        : m_TestLabel(label), m_CpuClockSpeedGhz(cpuClockSpeedGhz) {
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
    }

    void LogGeneratedToken(double latencyMs) {
        (void)latencyMs;
        totalGeneratedTokens++;
    }

    void EndTokenGeneration() {
        QueryPerformanceCounter(&endGeneration);
    }

    void RecordIoWait(uint64_t cycles) { totalIoWaitCycles += cycles; }
    void RecordCompute(uint64_t cycles) { totalComputeCycles += cycles; }
    void RecordOverlap(uint64_t cycles) { totalOverlapCycles += cycles; }
    void IncrementStarvation() { starvationCount++; }

    double GetTPS() const {
        double generationTimeMs = (static_cast<double>(endGeneration.QuadPart - startGeneration.QuadPart) * 1000.0) / frequency.QuadPart;
        return (totalGeneratedTokens / (generationTimeMs / 1000.0 + 1e-9));
    }
};
