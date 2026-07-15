#include "TSCMonitor.h"
#include <iostream>
#include <vector>
#include <algorithm>
#include <numeric>
#include <mutex>
#include <iomanip>

namespace RawrXD::E2E {

// Budget: 30M cycles (~10ms on 3GHz CPU)
static constexpr uint64_t CYCLE_BUDGET = 30000000ULL;

// Thread-local storage for latency samples
thread_local std::vector<uint64_t> t_latency_samples;
static std::vector<uint64_t> g_all_samples;
static std::mutex g_samples_mutex;

TSCMonitor::Scope::Scope() {
    m_start = __rdtsc();
}

TSCMonitor::Scope::~Scope() {
    uint64_t end = __rdtsc();
    uint64_t cycles = end - m_start;
    
    // Store sample
    t_latency_samples.push_back(cycles);
    
    // Flush to global periodically
    if (t_latency_samples.size() >= 100) {
        std::lock_guard<std::mutex> lock(g_samples_mutex);
        g_all_samples.insert(g_all_samples.end(), 
                            t_latency_samples.begin(), 
                            t_latency_samples.end());
        t_latency_samples.clear();
    }
}

TSCMonitor::LatencyReport TSCMonitor::GetReport() {
    LatencyReport report;
    
    // Flush remaining samples
    {
        std::lock_guard<std::mutex> lock(g_samples_mutex);
        g_all_samples.insert(g_all_samples.end(), 
                            t_latency_samples.begin(), 
                            t_latency_samples.end());
        t_latency_samples.clear();
        
        if (g_all_samples.empty()) {
            report.cycles = 0;
            report.ms = 0.0;
            return report;
        }
        
        // Calculate statistics
        std::sort(g_all_samples.begin(), g_all_samples.end());
        
        // P95 latency
        size_t p95_idx = static_cast<size_t>(g_all_samples.size() * 0.95);
        report.cycles = g_all_samples[p95_idx];
        
        // Convert to ms (assuming 3GHz)
        report.ms = static_cast<double>(report.cycles) / 3000000.0;
    }
    
    return report;
}

double TSCMonitor::GetBudgetUtilization() {
    auto report = GetReport();
    if (CYCLE_BUDGET == 0) return 0.0;
    
    return static_cast<double>(report.cycles) / static_cast<double>(CYCLE_BUDGET);
}

void TSCMonitor::Reset() {
    std::lock_guard<std::mutex> lock(g_samples_mutex);
    g_all_samples.clear();
    t_latency_samples.clear();
}

void TSCMonitor::PrintStats() {
    std::lock_guard<std::mutex> lock(g_samples_mutex);
    
    if (g_all_samples.empty()) {
        std::cout << "[TSCMonitor] No samples collected.\n";
        return;
    }
    
    std::vector<uint64_t> sorted = g_all_samples;
    std::sort(sorted.begin(), sorted.end());
    
    uint64_t min_cycles = sorted.front();
    uint64_t max_cycles = sorted.back();
    uint64_t p50_cycles = sorted[sorted.size() / 2];
    uint64_t p95_cycles = sorted[static_cast<size_t>(sorted.size() * 0.95)];
    uint64_t p99_cycles = sorted[static_cast<size_t>(sorted.size() * 0.99)];
    
    double avg_cycles = std::accumulate(sorted.begin(), sorted.end(), 0.0) / sorted.size();
    
    std::cout << "╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    TSC LATENCY STATISTICS                    ║\n";
    std::cout << "╠══════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Samples:      " << std::setw(10) << sorted.size() << "                                    ║\n";
    std::cout << "║  Min:          " << std::setw(10) << min_cycles << " cycles (" 
              << std::fixed << std::setprecision(3) << (min_cycles / 3000000.0) << "ms)              ║\n";
    std::cout << "║  Max:          " << std::setw(10) << max_cycles << " cycles (" 
              << (max_cycles / 3000000.0) << "ms)              ║\n";
    std::cout << "║  Avg:          " << std::setw(10) << static_cast<uint64_t>(avg_cycles) << " cycles (" 
              << (avg_cycles / 3000000.0) << "ms)              ║\n";
    std::cout << "║  P50:          " << std::setw(10) << p50_cycles << " cycles (" 
              << (p50_cycles / 3000000.0) << "ms)              ║\n";
    std::cout << "║  P95:          " << std::setw(10) << p95_cycles << " cycles (" 
              << (p95_cycles / 3000000.0) << "ms)              ║\n";
    std::cout << "║  P99:          " << std::setw(10) << p99_cycles << " cycles (" 
              << (p99_cycles / 3000000.0) << "ms)              ║\n";
    std::cout << "║  Budget:       " << std::setw(10) << CYCLE_BUDGET << " cycles (10ms)              ║\n";
    std::cout << "║  Utilization:  " << std::setw(10) << std::fixed << std::setprecision(1) 
              << (GetBudgetUtilization() * 100.0) << "%" << std::string(26, ' ') << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
}

} // namespace RawrXD::E2E
