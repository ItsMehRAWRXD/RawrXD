#pragma once
#include <stdint.h>
#include <string>
#include <unordered_map>
#include <iostream>
#include <iomanip>

namespace Deep2Engine::Emulator {

    struct ProfileMetrics {
        uint64_t total_cycles{ 0 };
        uint64_t call_count{ 0 };
        uint64_t max_cycles{ 0 };
        uint64_t min_cycles{ UINT64_MAX };
    };

    class HardwareProfiler {
    public:
        HardwareProfiler() = default;

        inline uint64_t start_timer() const {
            return __rdtsc();
        }

        inline void stop_timer(const std::string& key, uint64_t start_time) {
            uint64_t delta = __rdtsc() - start_time;
            auto& metric = m_metrics[key];
            metric.total_cycles += delta;
            metric.call_count++;
            if (delta > metric.max_cycles) metric.max_cycles = delta;
            if (delta < metric.min_cycles) metric.min_cycles = delta;
        }

        void print_telemetry_report() const {
            std::cout << "\n======================================================================\n";
            std::cout << "         DEEP2ENGINE CORE HARDWARE PROFILER RUNTIME METRICS           \n";
            std::cout << "======================================================================\n";
            std::cout << std::left << std::setw(25) << "Pipeline Operation"
                      << std::setw(15) << "Invocations"
                      << std::setw(20) << "Avg Clock Cycles"
                      << "Worst-Case Burst\n";
            std::cout << "----------------------------------------------------------------------\n";

            for (const auto& [key, m] : m_metrics) {
                uint64_t avg = m.call_count ? (m.total_cycles / m.call_count) : 0;
                std::cout << std::left << std::setw(25) << key
                          << std::setw(15) << m.call_count
                          << std::setw(20) << avg
                          << m.max_cycles << "\n";
            }
            std::cout << "======================================================================\n";
        }

    private:
        std::unordered_map<std::string, ProfileMetrics> m_metrics;
    };
}
