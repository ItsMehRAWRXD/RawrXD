#pragma once
#include <mutex>
#include <algorithm>
#include "memory_policy_types.h"
#include "memory_oracle_metrics.h"

namespace RawrXD::Memory {

class MemoryOracle {
public:
    void reportHardwareUsage(uint64_t vram, uint64_t ram, uint64_t vramTotal, uint64_t ramTotal) {
        std::lock_guard<std::mutex> lock(m_mutex);
        m_metrics.vram_used = vram;
        m_metrics.ram_used = ram;
        
        // Dynamic Pressure Calculation using actual hardware capacity
        double vram_p = (vramTotal > 0) ? (double)vram / vramTotal : 0.0;
        double ram_p = (ramTotal > 0) ? (double)ram / ramTotal : 0.0;
        
        // Oracle scales pressure non-linearly to provide early warning
        m_metrics.pressure = (float)std::max(vram_p, ram_p);
        
        updateWeights();
    }

    OracleAggregateMetrics getMetricSnapshot() {
        std::lock_guard<std::mutex> lock(m_mutex);
        return m_metrics;
    }

private:
    void updateWeights() {
        float p = m_metrics.pressure;
        
        // Hysteresis-aware weight adjustment to prevent rapid switching
        // weights[0]: RETAIN, weights[1]: COMPRESS, weights[2]: TIERDOWN/OFFLOAD
        
        if (p < 0.25f) {
            // Cool mode: Prioritize speed
            m_metrics.weights[0] = 0.90f; m_metrics.weights[1] = 0.05f; m_metrics.weights[2] = 0.05f;
        } else if (p < 0.50f) {
            // Warm mode: Balanced compression
            m_metrics.weights[0] = 0.60f; m_metrics.weights[1] = 0.30f; m_metrics.weights[2] = 0.10f;
        } else if (p < 0.80f) {
            // Hot mode: Aggressive tiered storage
            m_metrics.weights[0] = 0.20f; m_metrics.weights[1] = 0.40f; m_metrics.weights[2] = 0.40f;
        } else {
            // Thermal mode: Emergency offloading
            m_metrics.weights[0] = 0.05f; m_metrics.weights[1] = 0.15f; m_metrics.weights[2] = 0.80f;
        }
    }

    OracleAggregateMetrics m_metrics;
    std::mutex m_mutex;
};

class MemoryOrchestrator {
public:
    MemoryOrchestrator(MemoryOracle& oracle) : m_oracle(oracle) {}
private:
    MemoryOracle& m_oracle;
};

}