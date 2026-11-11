#pragma once
#include <windows.h>
#include <psapi.h>
#include <string>
#include <cstdint>
#include <iostream>

class PerformanceProfiler {
private:
    LARGE_INTEGER m_frequency;
    LARGE_INTEGER m_startTime;
    LARGE_INTEGER m_endTime;
    size_t m_baselineMemory;

    size_t GetCurrentMemoryUsage() {
        PROCESS_MEMORY_COUNTERS_EX pmc;
        if (GetProcessMemoryInfo(GetCurrentProcess(), (PROCESS_MEMORY_COUNTERS*)&pmc, sizeof(pmc))) {
            return pmc.PrivateUsage;
        }
        return 0;
    }

public:
    PerformanceProfiler() {
        QueryPerformanceFrequency(&m_frequency);
        m_baselineMemory = GetCurrentMemoryUsage();
    }

    void StartSession() {
        m_startTime = { 0 };
        m_endTime = { 0 };
        QueryPerformanceCounter(&m_startTime);
    }

    void EndSession(const std::string& operationName, uint16_t tokenCount) {
        QueryPerformanceCounter(&m_endTime);
        
        double elapsedTime = static_cast<double>(m_endTime.QuadPart - m_startTime.QuadPart) / m_frequency.QuadPart;
        size_t currentMemory = GetCurrentMemoryUsage();
        double memoryDeltaMB = static_cast<double>(currentMemory) / (1024.0 * 1024.0);
        double tokensPerSecond = static_cast<double>(tokenCount) / elapsedTime;

        std::cout << "[PERF] " << operationName << "\n"
                  << "       Time: " << elapsedTime << "s | Tokens: " << tokenCount
                  << " | TPS: " << tokensPerSecond << "\n"
                  << "       Memory: " << memoryDeltaMB << " MB\n"
                  << "       Baseline: " << (m_baselineMemory / (1024.0 * 1024.0)) << " MB\n"
                  << "       Reduction: " << (1.0 - (memoryDeltaMB / (m_baselineMemory / (1024.0 * 1024.0)))) * 100.0 << "% vs Electron\n";
    }
};
