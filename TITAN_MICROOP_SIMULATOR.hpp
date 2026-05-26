#pragma once
#include <string>
#include <vector>
#include <algorithm>
#include <iostream>
#include <iomanip>

// =============================================================================
// TITAN MICRO-OP EXECUTION SIMULATOR
// =============================================================================
// Transitions the architecture from "SIMD Optimization" to "Predictive Modeling".
// Simulates the x86 Superscalar Out-of-Order Engine to identify the exact 
// microarchitectural bottleneck (queue-bound vs execution-bound vs issue-bound)
// BEFORE code is emitted or executed.
// =============================================================================

namespace Titan {
namespace Simulator {

    enum class Bottleneck {
        FMA_PORT_SATURATED,
        AGU_PORT_SATURATED,
        FRONTEND_ISSUE_LIMITED,
        DEPENDENCY_LATENCY_STALL,
        ROB_CAPACITY_LIMITED
    };

    struct CpuMicroArch {
        int issue_width;    // decoded/issued micro-ops per cycle
        int fma_ports;      // physical execution ports for FMA
        int agu_ports;      // physical execution ports for Load/Store
        int alu_ports;      // physical execution ports for integer math
        int fma_latency;    // cycles to retire an FMA
        int rob_size;       // Reorder Buffer capacity (in-flight tracking limit)
    };

    struct ExecutionStats {
        float estimated_ipc;
        float fma_utilization;
        float agu_utilization;
        float issue_utilization;
        Bottleneck primary_limiter;
        float estimated_flops_per_cycle;
        int bottleneck_cycles;
    };

    class MicroOpExecutionModel {
    public:
        // Analyzes a deterministic steady-state loop iteration
        static ExecutionStats SimulateKernel(int accumulators, int total_fmas, int total_loads, int total_alus, const CpuMicroArch& arch) {
            int total_uops = total_fmas + total_loads + total_alus;

            // 1. Calculate ideal floor limits based on hardware topology
            float issue_cycles = (float)total_uops / arch.issue_width;
            float fma_cycles = (float)total_fmas / arch.fma_ports;
            float agu_cycles = (float)total_loads / arch.agu_ports;

            // 2. Assess Dependency Stalls (Little's Law limit)
            // If WIP (accumulators) is less than Pipeline Depth (latency * ports), we stall.
            float min_required_wip = arch.fma_latency * arch.fma_ports;
            float latency_stall_cycles = (accumulators < min_required_wip) ? 
                                         ((min_required_wip - accumulators) / arch.fma_ports) : 0.0f;

            // 3. Assess Reorder Buffer (ROB) tracking limits
            // If our unrolled block + prefetch creates an instruction window larger than the ROB
            float rob_stall_cycles = (total_uops > arch.rob_size) ? 
                                     ((total_uops - arch.rob_size) * 0.5f) : 0.0f; // Penalize overflow

            // Overall critical path is the maximum of all physical bounds + stalls
            float actual_cycles = std::max({issue_cycles, fma_cycles, agu_cycles});
            actual_cycles += latency_stall_cycles + rob_stall_cycles;

            // 4. Derive Stats
            ExecutionStats stats;
            stats.estimated_ipc = total_uops / actual_cycles;
            stats.fma_utilization = (fma_cycles / actual_cycles) * 100.0f;
            stats.agu_utilization = (agu_cycles / actual_cycles) * 100.0f;
            stats.issue_utilization = (issue_cycles / actual_cycles) * 100.0f;
            stats.estimated_flops_per_cycle = (total_fmas * 2.0f) / actual_cycles; // 2 FLOPs per FMA

            // Identify the precise hardware boundary limiting the kernel
            if (rob_stall_cycles > 0) {
                stats.primary_limiter = Bottleneck::ROB_CAPACITY_LIMITED;
            } else if (latency_stall_cycles > 0) {
                stats.primary_limiter = Bottleneck::DEPENDENCY_LATENCY_STALL;
            } else if (actual_cycles == fma_cycles) {
                stats.primary_limiter = Bottleneck::FMA_PORT_SATURATED;
            } else if (actual_cycles == issue_cycles) {
                stats.primary_limiter = Bottleneck::FRONTEND_ISSUE_LIMITED;
            } else {
                stats.primary_limiter = Bottleneck::AGU_PORT_SATURATED;
            }

            return stats;
        }

        static void PrintReport(const ExecutionStats& s) {
            std::cout << "=== MICROARCHITECTURAL EXECUTION PREDICTION ===\n";
            std::cout << std::fixed << std::setprecision(2);
            std::cout << " Estimated IPC     : " << s.estimated_ipc << "\n";
            std::cout << " FLOPs/Cycle       : " << s.estimated_flops_per_cycle << "\n";
            std::cout << " FMA Port Util     : " << s.fma_utilization << " %\n";
            std::cout << " AGU Port Util     : " << s.agu_utilization << " %\n";
            std::cout << " Decode/Issue Util : " << s.issue_utilization << " %\n";
            
            std::cout << " PRIMARY LIMITER   : ";
            switch(s.primary_limiter) {
                case Bottleneck::FMA_PORT_SATURATED: std::cout << "FMA Port Throughput (COMPUTE BOUND)\n"; break;
                case Bottleneck::AGU_PORT_SATURATED: std::cout << "Address Generation (LOAD BOUND)\n"; break;
                case Bottleneck::FRONTEND_ISSUE_LIMITED: std::cout << "Decode/Rename/Issue Bandwidth (FRONTEND BOUND)\n"; break;
                case Bottleneck::DEPENDENCY_LATENCY_STALL: std::cout << "Little's Law Dependency Gap (LATENCY STALL)\n"; break;
                case Bottleneck::ROB_CAPACITY_LIMITED: std::cout << "Reorder Buffer Size (INSTRUCTION WINDOW EXHAUSTED)\n"; break;
            }
            std::cout << "===============================================\n";
        }
    };

} // namespace Simulator
} // namespace Titan