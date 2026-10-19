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
        void stop(const std::string& metric_name, uint64_t start_ticks);
        void print_report() const;
    private:
        std::unordered_map<std::string, HardwareMetric> m_metrics;
    };
}