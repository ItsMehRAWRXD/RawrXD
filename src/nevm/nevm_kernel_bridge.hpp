//============================================================================
// nevm_kernel_bridge.hpp
// Bridge between NEVM Precision Controller and Kernel Registry
// Maps precision decisions to actual kernel execution
//============================================================================

#pragma once

#include "nevm_precision_controller.hpp"
#include "../kernels/KernelRegistry.hpp"
#include <functional>

namespace RawrXD {
namespace NEVM {

//============================================================================
// Kernel Bridge
// Connects NEVM precision decisions to Kernel Registry execution
//============================================================================

class KernelBridge {
public:
    // Execution context for a tensor operation
    struct ExecutionContext {
        VirtualTensorAddress vta_a;
        VirtualTensorAddress vta_b;
        VirtualTensorAddress vta_out;
        ISA::PrecisionMode precision;
        size_t m, n, k;  // Matrix dimensions
        float latency_budget_ms;
    };
    
    // Result of kernel dispatch
    struct DispatchResult {
        bool success;
        Kernels::QuantType quant_used;
        float actual_latency_ms;
        float numerical_error;
        const char* kernel_name;
    };
    
    // Initialize bridge
    static void Initialize();
    
    // Main dispatch entry: NEVM_MATMUL instruction
    static DispatchResult DispatchMatMul(
        const ExecutionContext& ctx,
        const void* tensor_a,
        const void* tensor_b,
        void* tensor_out
    );
    
    // Convert NEVM precision mode to Kernel Registry quant type
    static Kernels::QuantType PrecisionToQuant(ISA::PrecisionMode mode);
    
    // Check if kernel is available for precision mode
    static bool IsKernelAvailable(ISA::PrecisionMode mode);
    
    // Get kernel descriptor for telemetry
    static Kernels::KernelDesc GetKernelDescriptor(ISA::PrecisionMode mode);

private:
    static bool s_initialized;
    
    // Fallback to reference implementation
    static DispatchResult FallbackMatMul(const ExecutionContext& ctx,
                                          const void* a, const void* b, void* out);
};

//============================================================================
// NEVM Instruction Dispatcher
// Top-level dispatch for neural instructions
//============================================================================

class InstructionDispatcher {
public:
    // NEVM instruction types
    enum class OpCode {
        MATMUL = 0x01,      // Matrix multiplication
        MATVEC = 0x02,      // Matrix-vector multiplication
        SOFTMAX = 0x03,     // Softmax activation
        ROPE = 0x04,        // Rotary positional embedding
        RMSNORM = 0x05,     // RMS normalization
        SILU = 0x06,        // SiLU activation
    };
    
    // Instruction format
    struct Instruction {
        OpCode opcode;
        uint32_t flags;     // AUTO precision, etc.
        VirtualTensorAddress src_a;
        VirtualTensorAddress src_b;
        VirtualTensorAddress dst;
        union {
            float float_param;
            uint32_t int_param;
        } param;
    };
    
    // Initialize dispatcher
    static void Initialize();
    
    // Execute single instruction
    static bool Execute(const Instruction& inst);
    
    // Execute batch of instructions
    static bool ExecuteBatch(const std::vector<Instruction>& batch);
    
    // Set precision override (for testing)
    static void SetPrecisionOverride(ISA::PrecisionMode mode);

private:
    static ISA::PrecisionMode s_precision_override;
    static bool s_initialized;
};

} // namespace NEVM
} // namespace RawrXD
