#pragma once

#ifndef NOMINMAX
#define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <iostream>
#include <cstdint>
#include <string>
#include <iomanip>
#include <vector>
#include <algorithm>
#include <numeric>
#include <mutex>
#include <windows.h>
#include <intrin.h>

#ifdef max
#undef max
#endif
#ifdef min
#undef min
#endif

extern "C" uint64_t ReadCycleCounter();

class Deep2MicroProfiler {
public:
    struct Event {
        uint64_t timestamp;
        uint32_t cpuId;
        std::string message;

        // Comparison operator for sorting by timestamp
        bool operator<(const Event& other) const {
            return timestamp < other.timestamp;
        }
    };

private:
    std::vector<Event> m_events;
    mutable std::mutex m_lock;
    double m_nanosecondsPerCycle;
    double m_baseClockGhz;

public:
    Deep2MicroProfiler(double cpuClockSpeedGhz = 4.2) // Default to a more common 7800X3D base clock
        : m_baseClockGhz(cpuClockSpeedGhz) 
    {
        m_nanosecondsPerCycle = 1.0 / m_baseClockGhz;
        // Optionally, dynamically measure TSC frequency here for more accuracy
    }

    inline void LogEvent(const std::string& message) {
        uint32_t cpuId;
        uint64_t timestamp = __rdtscp(&cpuId);
        std::lock_guard<std::mutex> guard(m_lock);
        m_events.push_back({timestamp, cpuId, message});
    }

    void GenerateReport(const std::string& reportLabel) const {
        std::vector<Event> sortedEvents;
        {
            std::lock_guard<std::mutex> guard(m_lock);
            if (m_events.empty()) {
                std::cerr << "[-] MicroProfiler: No events logged for report: " << reportLabel << std::endl;
                return;
            }
            sortedEvents = m_events;
        }
        std::sort(sortedEvents.begin(), sortedEvents.end());

        std::cout << "\n=================================================================\n";
        std::cout << "🛰️ MICRO-PROFILER REPORT: " << reportLabel << "\n";
        std::cout << "=================================================================\n";
        std::cout << "TSC Clock Frequency: " << std::fixed << std::setprecision(2) << m_baseClockGhz << " GHz\n";
        std::cout << "\n--- Event Timeline ---\n";

        uint64_t firstTimestamp = sortedEvents[0].timestamp;
        for (const auto& event : sortedEvents) {
            double relativeNs = static_cast<double>(event.timestamp - firstTimestamp) * m_nanosecondsPerCycle;
            std::cout << std::fixed << std::setprecision(3)
                      << "[+" << std::setw(9) << relativeNs << " ns] CPU " << event.cpuId << ": " << event.message << "\n";
        }
        std::cout << "=================================================================\n";
    }
};
