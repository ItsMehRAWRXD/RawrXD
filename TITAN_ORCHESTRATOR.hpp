#pragma once
#include <cstdint>
#include <vector>
#include <thread>
#include <atomic>

// =================================================================================
// TITAN C++ DAG ORCHESTRATOR 
// MAPS TO: KERNEL_FUSED_Q4_GEMM_TILE4 (TITAN_X64_CORE.ASM)
// =================================================================================

namespace Titan {
namespace Orchestrator {

    // -----------------------------------------------------------------------------
    // MACRO-OP EXECUTION STRUCT (32 bytes - Cache Line Aligned)
    // Sent directly to the MASM ring buffer. The Graph Walker iterates over these.
    // -----------------------------------------------------------------------------
    struct alignas(32) KernelPipelineNode {
        uint8_t*  quant_ptr;       // RCX : Tensor A (Quantized Streams)
        float*    act_ptr;         // RDX : Tensor B (Activation Tiles) / Accumulator Output
        float*    scales_ptr;      // R8  : Tensor Scales Data
        uint32_t  block_count;     // R11 : Execution loops (must be div by tile unroll factor)
        uint32_t  prefetch_offset; // Dynamic distance: L / E (e.g., 256 or 512 bytes)
    };

    // -----------------------------------------------------------------------------
    // DOUBLE-BUFFERED TASK QUEUE (Streaming ping-pong fabric)
    // -----------------------------------------------------------------------------
    class WaveGenerator {
        static constexpr size_t QUEUE_DEPTH = 1024;
    private:
        KernelPipelineNode _ring_buffer_A[QUEUE_DEPTH];
        KernelPipelineNode _ring_buffer_B[QUEUE_DEPTH];
        
        std::atomic<bool> _flip_state{false};
        std::atomic<uint32_t> _write_head{0};
        
        // MASM external symbol hook
        extern "C" void KERNEL_GRAPH_WALKER(KernelPipelineNode* head, uint64_t count);

    public:
        WaveGenerator() = default;

        // Compile a sub-graph of network layers into a continuous tiled stream
        void CompileLayerToTiles(const uint8_t* quant_weights, float* activations, float* scales, uint64_t total_blocks) {
            uint32_t current_buffer = _flip_state.load(std::memory_order_relaxed);
            KernelPipelineNode* target_ring = current_buffer ? _ring_buffer_B : _ring_buffer_A;
            uint32_t head = _write_head.fetch_add(1, std::memory_order_relaxed);

            if (head >= QUEUE_DEPTH) {
                Flush(); // Force execution of filled ring buffer
                head = 0;
            }

            // Populate the struct obeying the Register-Tiling ABI constraints
            target_ring[head].quant_ptr = const_cast<uint8_t*>(quant_weights);
            target_ring[head].act_ptr = activations;
            target_ring[head].scales_ptr = scales;
            
            // Dynamic prefetch tuning: Deep tiles need longer lookahead 
            target_ring[head].prefetch_offset = 256; 
            target_ring[head].block_count = total_blocks; // ABI handles SHR 2 for 4-way internally
        }

        // Commits the ring buffer to the MASM fabric without yielding CPU cores
        void Flush() {
            uint32_t count = _write_head.exchange(0, std::memory_order_acquire);
            if (count == 0) return;

            bool current_buffer = _flip_state.load();
            KernelPipelineNode* target_ring = current_buffer ? _ring_buffer_B : _ring_buffer_A;

            // Swap buffers for next C++ compile phase (Host builds C+1 while MASM executes C)
            _flip_state.store(!current_buffer, std::memory_order_release);

            // CPU blocking call -- Execution thread drops into MASM L0-saturated regime 
            KERNEL_GRAPH_WALKER(target_ring, count);
        }
    };

} // namespace Orchestrator
} // namespace Titan