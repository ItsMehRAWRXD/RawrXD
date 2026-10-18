#include "PerformanceProfiler.hpp"
#include <iostream>
#include <iomanip>

namespace Deep2Rom::Diagnostics {

    void HardwareProfiler::print_report() const {
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
}