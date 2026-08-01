#pragma once
#include <windows.h>
#include <string>
#include <iostream>
#include <psapi.h>

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

        std::cout << "\n=== PERFORMANCE REPORT: " << operationName << " ===\n";
        std::cout << "  Elapsed Time:      " << elapsedTime << " sec\n";
        std::cout << "  Tokens Generated:    " << tokenCount << "\n";
        std::cout << "  Tokens/Second:       " << tokensPerSecond << "\n";
        std::cout << "  Memory Footprint:  " << memoryDeltaMB << " MB\n";
        std::cout << "  Baseline Memory:   " << (m_baselineMemory / (1024.0 * 1024.0)) << " MB\n";
        std::cout << "  Memory Delta:      " << ((currentMemory - m_baselineMemory) / (1024.0 * 1024.0)) << " MB\n";
        std::cout << "=====================================\n";
    }
};
