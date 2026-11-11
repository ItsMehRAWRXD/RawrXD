#pragma once
#include <stdint.h>
#include <unordered_map>
#include <string>
#include <iostream>
#include <iomanip>

namespace Deep2Rom::Diagnostics {

    struct HardwareMetric {
        uint64_t total_cycles{ 0 };
        uint64_t call_count{ 0 };
        uint64_t worst_cycles{ 0 };
    };

    class HardwareProfiler {
    public:
        inline uint64_t start() const { return __rdtsc(); }
        inline void stop(const std::string& metric_name, uint64_t start_ticks) {
            uint64_t elapsed = __rdtsc() - start_ticks;
            auto& m = m_metrics[metric_name];
            m.total_cycles += elapsed;
            m.call_count++;
            if (elapsed > m.worst_cycles) m.worst_cycles = elapsed;
        }

        void print_report() const {
            std::cout << "\n============================================================\n";
            std::cout << "               WaaF EXTREME RUNTIME METRICS REPORT         \n";
            std::cout << "============================================================\n";
            for (const auto& [name, m] : m_metrics) {
                uint64_t avg = m.call_count ? (m.total_cycles / m.call_count) : 0;
                std::cout << " -> " << std::left << std::setw(28) << name 
                          << " | Avg: " << std::setw(12) << avg 
                          << " | Worst: " << m.worst_cycles << "\n";
            }
            std::cout << "============================================================\n";
        }
    private:
        std::unordered_map<std::string, HardwareMetric> m_metrics;
    };
}