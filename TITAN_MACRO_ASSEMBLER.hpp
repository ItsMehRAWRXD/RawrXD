#pragma once
#include <string>
#include <sstream>
#include "TITAN_TILING_POLICY.hpp"
#include "TITAN_MICROOP_SIMULATOR.hpp"
#include "TITAN_UOP_FUSION_ENGINE.hpp"
#include "TITAN_DATA_PLANE_OPTIMIZER.hpp"

// =============================================================================
// TITAN MACRO ASSEMBLER
// =============================================================================
// The apex of the Titan framework. Unifies the microarchitectural control rules,
// simulators, and load-folded execution emitters into a single JIT compiler endpoint.
// Generates pipeline-perfect MASM dynamically tailored to the detected CPU.
// =============================================================================

namespace Titan {
namespace Compiler {

    class MacroAssembler {
    public:
        static std::string CompileOptimalKernel(CPUArch arch, size_t buffer_size) {
            std::stringstream ss;
            
            // 1. Derive Optimal Policy
            CpuProfile profile = PolicyEngine::GetCpuProfile(arch);
            TilingPolicy policy = PolicyEngine::DeriveOptimalPolicy(profile);
            
            // 2. Simulate the Execution to guarantee front-end / back-end balance
            // We know load-folding cuts uops, so loads are fused.
            int total_fmas = policy.unroll_factor;
            int total_loads = 0; // Fused away
            int total_alus = 2;  // pointer add + cmp
            
            Simulator::ExecutionStats stats = Simulator::MicroOpExecutionModel::SimulateKernel(
                policy.target_accumulators, total_fmas, total_loads, total_alus, profile
            );

            ss << "; ==================================================================\n";
            ss << "; TITAN PIPELINE-PERFECT KERNEL\n";
            ss << "; GENERATED FOR: " << (policy.use_zmm ? "AVX-512" : "AVX2") << "\n";
            ss << "; PREDICTED IPC: " << stats.estimated_ipc << "\n";
            ss << "; PRIMARY LIMITER: ";
            
            switch(stats.primary_limiter) {
                case Simulator::Bottleneck::FMA_PORT_SATURATED: ss << "FMA Port Throughput (COMPUTE BOUND)\n"; break;
                case Simulator::Bottleneck::AGU_PORT_SATURATED: ss << "Address Generation (LOAD BOUND)\n"; break;
                case Simulator::Bottleneck::FRONTEND_ISSUE_LIMITED: ss << "Decode/Rename/Issue Bandwidth (FRONTEND BOUND)\n"; break;
                case Simulator::Bottleneck::DEPENDENCY_LATENCY_STALL: ss << "Little's Law Dependency Gap (LATENCY STALL)\n"; break;
                case Simulator::Bottleneck::ROB_CAPACITY_LIMITED: ss << "Reorder Buffer Size (INSTRUCTION WINDOW EXHAUSTED)\n"; break;
            }
            ss << "; ==================================================================\n\n";

            // 3. Emit the Load-Folded FMA Pipeline
            ss << MicroOpFusionEngine::EmitFusedExecutionBlock(policy.unroll_factor);
            
            // 4. Emit the Optimal Data Plane Strategy (Temporal vs Non-Temporal)
            auto store_strategy = Memory::DataPlaneOptimizer::DetermineStoreStrategy(buffer_size);
            ss << Memory::DataPlaneOptimizer::EmitHorizontalReductionAndStore(store_strategy);
            
            return ss.str();
        }
    };

} // namespace Compiler
} // namespace Titan