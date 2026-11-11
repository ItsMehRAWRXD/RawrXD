#pragma once

#include <cstdint>
#include <intrin.h>

namespace RawrXD::E2E {

/**
 * @brief RDTSC-based latency monitor
 * 
 * Phase 19: Tracks CPU cycles for P95 latency validation
 */
class TSCMonitor {
public:
    /**
     * @brief Latency measurement report
     */
    struct LatencyReport {
        uint64_t cycles;      // CPU cycles
        double ms;            // Milliseconds (assuming 3GHz)
    };
    
    /**
     * @brief Scoped monitor for automatic timing
     */
    class Scope {
    public:
        Scope();
        ~Scope();
    private:
        uint64_t m_start;
    };
    
    /**
     * @brief Get current latency report (P95)
     */
    static LatencyReport GetReport();
    
    /**
     * @brief Get budget utilization (0.0-1.0)
     */
    static double GetBudgetUtilization();
    
    /**
     * @brief Reset all samples
     */
    static void Reset();
    
    /**
     * @brief Print statistics to stdout
     */
    static void PrintStats();
    
    /**
     * @brief Check if P95 is within budget
     */
    static bool IsWithinBudget();

private:
    static constexpr uint64_t CYCLE_BUDGET = 30000000ULL; // 30M cycles (~10ms @ 3GHz)
};

} // namespace RawrXD::E2E
