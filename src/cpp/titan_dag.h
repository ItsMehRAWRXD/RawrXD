#pragma once
#include <cstdint>
#include <vector>

// ---------------------------------------------------------
// COMPUTE HAL BINDING
// Maps directly to KERNEL_DISPATCH in titan_core.asm
// RCX = src, RDX = dst, R8 = count, R9 = opcode
// ---------------------------------------------------------
extern "C" void KERNEL_DISPATCH(void* src, void* dst, uint64_t count, uint64_t opcode);

// ---------------------------------------------------------
// DAG DEFINITIONS
// ---------------------------------------------------------
enum class TitanOpCode : uint64_t {
    HYDRATE_WEIGHTS = 0, // rep stosq memory map streaming
    COMPUTE_SIMD    = 1, // SIMD vector processing
    DEQUANT_Q4      = 2, // Q4_K block decompression
    FUSED_Q4_ACCUM  = 3, // Fused Q4 Load -> Unpack -> Scale -> Accumulate -> Store
    STRIDE_MAT      = 4  // Matrix stride calculation
};

struct TitanToken {
    TitanOpCode opcode;
    void* src_buffer;
    void* dst_buffer;
    uint64_t count;
};

// ---------------------------------------------------------
// ORCHESTRATOR
// ---------------------------------------------------------
class TitanGraph {
private:
    std::vector<TitanToken> execution_queue;

public:
    // Pushes a new execution token onto the DAG sequence
    void PushToken(TitanOpCode op, void* src, void* dst, uint64_t count) {
        execution_queue.push_back({op, src, dst, count});
    }

    // Synchronously executes the entire mapped token space.
    void Execute() {
        for (const auto& token : execution_queue) {
            KERNEL_DISPATCH(
                token.src_buffer, 
                token.dst_buffer, 
                token.count, 
                static_cast<uint64_t>(token.opcode)
            );
        }
    }
};
