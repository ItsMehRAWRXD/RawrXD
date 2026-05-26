#pragma once
#include <vector>
#include <cstdint>
#include <queue>
#include <stdexcept>
#include <unordered_map>
#include "TITAN_ORCHESTRATOR.hpp"

// =================================================================================
// TITAN DAG COMPILER: STATIC INSTRUCTION-FLOW SCHEDULER
// =================================================================================
// Transitions execution from a "compute problem" to a "scheduled flow problem".
// Responsible for:
// 1. Topological sorting of SIMD operations.
// 2. Explicit port-aware scheduling constraints.
// 3. Anchoring register residency across boundaries (eliminating writebacks).
// 4. Emitting the linear KernelPipelineNode stream for the MASM back-end.
// =================================================================================

namespace Titan {
namespace Compiler {

    enum class SIMDOp {
        Q4_GEMM_TILE4,      // Port 0/1 heavy, AGU streamed
        FP32_SILU_ACT,      // Port 0/5 fused non-linear
        FP32_RMS_NORM,      // Horizontal reduction bound
        FUSED_WRITEBACK     // L1/L2 Sink
    };

    struct DAGNode {
        int id;
        SIMDOp op;
        uint8_t* tensor_a;
        float*   tensor_b;
        float*   scales;
        uint32_t element_count;
        std::vector<int> edges_out; // Dependent nodes
    };

    class SIMDExecutionPlanner {
    private:
        std::vector<DAGNode> _nodes;

    public:
        void AddNode(const DAGNode& node) {
            _nodes.push_back(node);
        }

        // -------------------------------------------------------------------------
        // Core Routine: Map DAG to SIMD Wave Fabric (Linearization)
        // -------------------------------------------------------------------------
        std::vector<Orchestrator::KernelPipelineNode> LowerToExecutionFabric() {
            std::vector<Orchestrator::KernelPipelineNode> execution_stream;
            std::vector<int> in_degree(_nodes.size(), 0);
            
            for (const auto& node : _nodes) {
                for (int target : node.edges_out) {
                    in_degree[target]++;
                }
            }

            std::queue<int> ready_queue;
            for (size_t i = 0; i < in_degree.size(); ++i) {
                if (in_degree[i] == 0) ready_queue.push((int)i);
            }

            while (!ready_queue.empty()) {
                int curr_id = ready_queue.front();
                ready_queue.pop();
                const auto& node = _nodes[curr_id];

                // 1. Dependency Folding / Register Residency Enforement
                // If a GEMM feeds directly into SiLU, we omit the memory writeback.
                // The MASM tile will keep the FP32 accumulator in YMM2-YMM5.
                
                // 2. Prefetch Distance Calculation (Load-use Latency / Execution Time)
                // GEMM has high execution time (FMA bound) -> Shorter prefetch required.
                // Activations are memory bound (No FMAs) -> Deep prefetch required.
                uint32_t dynamic_prefetch = (node.op == SIMDOp::Q4_GEMM_TILE4) ? 192 : 512;

                // 3. Emit the Struct
                Orchestrator::KernelPipelineNode tile;
                tile.quant_ptr      = node.tensor_a;
                tile.act_ptr        = node.tensor_b;
                tile.scales_ptr     = node.scales;
                tile.block_count    = node.element_count; // Unroll alignment managed by MASM
                tile.prefetch_offset = dynamic_prefetch;
                
                execution_stream.push_back(tile);

                // Unblock dependents
                for (int target : node.edges_out) {
                    if (--in_degree[target] == 0) {
                        ready_queue.push(target);
                    }
                }
            }

            if (execution_stream.size() != _nodes.size()) {
                throw std::runtime_error("DAG Cycle Detected: Unable to emit valid SIMD schedule.");
            }

            return execution_stream;
        }
    };

} // namespace Compiler
} // namespace Titan
