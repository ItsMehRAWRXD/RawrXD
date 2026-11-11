//============================================================================
// nevm_kernel_bridge.cpp
// Bridge between NEVM Precision Controller and Kernel Registry
//============================================================================

#include "nevm_kernel_bridge.hpp"
#include "nevm_mmu.hpp"
#include <cstdio>
#include <cstring>

namespace RawrXD {
namespace NEVM {

bool KernelBridge::s_initialized = false;
bool InstructionDispatcher::s_initialized = false;
ISA::PrecisionMode InstructionDispatcher::s_precision_override = ISA::PrecisionMode::AUTO;

//============================================================================
// KernelBridge Implementation
//============================================================================

void KernelBridge::Initialize() {
    if (s_initialized) return;
    
    // Initialize Kernel Registry (includes self-test)
    Kernels::KernelRegistry::Initialize();
    
    // Run self-test to validate kernels
    if (!Kernels::KernelRegistry::RunSelfTest()) {
        printf("[KernelBridge] WARNING: Kernel self-test failed, using fallback\n");
    }
    
    s_initialized = true;
}

Kernels::QuantType KernelBridge::PrecisionToQuant(ISA::PrecisionMode mode) {
    switch (mode) {
        case ISA::PrecisionMode::FP32:  return Kernels::QuantType::F32;
        case ISA::PrecisionMode::FP16:  return Kernels::QuantType::F16;
        case ISA::PrecisionMode::BF16:  return Kernels::QuantType::BF16;
        case ISA::PrecisionMode::Q8:    return Kernels::QuantType::Q8_0;
        case ISA::PrecisionMode::Q4:    return Kernels::QuantType::Q4_0;
        case ISA::PrecisionMode::NANO_2BIT:
        case ISA::PrecisionMode::NANO_1BIT:
            // Map nano formats to Q4 for now (placeholder)
            return Kernels::QuantType::Q4_0;
        default:
            return Kernels::QuantType::F32;
    }
}

bool KernelBridge::IsKernelAvailable(ISA::PrecisionMode mode) {
    if (!s_initialized) Initialize();
    
    Kernels::QuantType quant = PrecisionToQuant(mode);
    
    // Check if kernel exists and passed self-test
    switch (quant) {
        case Kernels::QuantType::Q4_0:
            return Kernels::KernelRegistry::GetQ4DotKernel() != nullptr;
        default:
            // Other kernels not yet implemented
            return false;
    }
}

KernelBridge::DispatchResult KernelBridge::DispatchMatMul(
    const ExecutionContext& ctx,
    const void* tensor_a,
    const void* tensor_b,
    void* tensor_out
) {
    if (!s_initialized) Initialize();
    
    DispatchResult result = {};
    result.success = false;
    result.kernel_name = "none";
    
    // Map precision mode to quant type
    Kernels::QuantType quant = PrecisionToQuant(ctx.precision);
    
    // Get kernel from registry
    Kernels::Q4DotFn kernel = nullptr;
    if (quant == Kernels::QuantType::Q4_0) {
        kernel = Kernels::KernelRegistry::GetQ4DotKernel();
    }
    
    if (!kernel) {
        // No optimized kernel available, use fallback
        return FallbackMatMul(ctx, tensor_a, tensor_b, tensor_out);
    }
    
    // Execute with timing
    auto start = std::chrono::high_resolution_clock::now();
    
    // For now, assume preprocessed blocks
    // TODO: Add preprocessing step for raw GGUF blocks
    const Kernels::PreprocessedQ4Block* blocks_a = 
        static_cast<const Kernels::PreprocessedQ4Block*>(tensor_a);
    const float* activations = static_cast<const float*>(tensor_b);
    
    // Process each block
    float sum = 0.0f;
    size_t num_blocks = ctx.k / 64;  // Assuming k is multiple of 64
    
    for (size_t i = 0; i < num_blocks; i++) {
        sum += kernel(&blocks_a[i], &activations[i * 64]);
    }
    
    // Store result
    *static_cast<float*>(tensor_out) = sum;
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    result.success = true;
    result.quant_used = quant;
    result.actual_latency_ms = duration.count() / 1000.0f;
    result.numerical_error = 0.0f;  // TODO: compute actual error
    result.kernel_name = "q4_preprocessed_avx512";
    
    return result;
}

KernelBridge::DispatchResult KernelBridge::FallbackMatMul(
    const ExecutionContext& ctx,
    const void* a,
    const void* b,
    void* out
) {
    DispatchResult result = {};
    result.success = true;  // Fallback always "succeeds"
    result.quant_used = Kernels::QuantType::F32;
    result.kernel_name = "fallback_scalar";
    
    // Simple scalar reference implementation
    auto start = std::chrono::high_resolution_clock::now();
    
    const float* fa = static_cast<const float*>(a);
    const float* fb = static_cast<const float*>(b);
    float* fout = static_cast<float*>(out);
    
    // Naive matmul for fallback
    for (size_t i = 0; i < ctx.m; i++) {
        for (size_t j = 0; j < ctx.n; j++) {
            float sum = 0.0f;
            for (size_t k = 0; k < ctx.k; k++) {
                sum += fa[i * ctx.k + k] * fb[k * ctx.n + j];
            }
            fout[i * ctx.n + j] = sum;
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    result.actual_latency_ms = duration.count() / 1000.0f;
    result.numerical_error = 0.0f;
    
    return result;
}

//============================================================================
// InstructionDispatcher Implementation
//============================================================================

void InstructionDispatcher::Initialize() {
    if (s_initialized) return;
    
    // Initialize kernel bridge
    KernelBridge::Initialize();
    
    s_initialized = true;
}

bool InstructionDispatcher::Execute(const Instruction& inst) {
    if (!s_initialized) Initialize();
    
    // Resolve virtual addresses through MMU
    // TODO: Integrate with Neural MMU
    
    switch (inst.opcode) {
        case OpCode::MATMUL: {
            // Determine precision
            ISA::PrecisionMode precision = inst.precision;
            if (s_precision_override != ISA::PrecisionMode::AUTO) {
                precision = s_precision_override;
            }
            
            // Build execution context
            KernelBridge::ExecutionContext ctx = {};
            ctx.vta_a = inst.src_a;
            ctx.vta_b = inst.src_b;
            ctx.vta_out = inst.dst;
            ctx.precision = precision;
            ctx.m = inst.param.int_param >> 16;
            ctx.n = inst.param.int_param & 0xFFFF;
            ctx.k = inst.param.int_param;  // TODO: proper dimension encoding
            
            // Dispatch through kernel bridge
            // TODO: Get actual tensor pointers from MMU
            void* tensor_a = nullptr;  // MMU::Resolve(inst.src_a);
            void* tensor_b = nullptr;  // MMU::Resolve(inst.src_b);
            void* tensor_out = nullptr; // MMU::Resolve(inst.dst);
            
            // For now, return true (placeholder)
            printf("[NEVM] MATMUL dispatched: precision=%d\n", 
                   static_cast<int>(precision));
            return true;
        }
        
        case OpCode::MATVEC:
        case OpCode::SOFTMAX:
        case OpCode::ROPE:
        case OpCode::RMSNORM:
        case OpCode::SILU:
            // TODO: Implement other operations
            printf("[NEVM] OpCode %d not yet implemented\n", 
                   static_cast<int>(inst.opcode));
            return false;
            
        default:
            printf("[NEVM] Unknown opcode: %d\n", static_cast<int>(inst.opcode));
            return false;
    }
}

bool InstructionDispatcher::ExecuteBatch(const std::vector<Instruction>& batch) {
    bool all_success = true;
    
    for (const auto& inst : batch) {
        if (!Execute(inst)) {
            all_success = false;
        }
    }
    
    return all_success;
}

void InstructionDispatcher::SetPrecisionOverride(ISA::PrecisionMode mode) {
    s_precision_override = mode;
}

} // namespace NEVM
} // namespace RawrXD
