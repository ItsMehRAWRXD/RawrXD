//=============================================================================
// NEVM Precision Controller - Implementation
//=============================================================================

#include "PrecisionController.hpp"
#include <algorithm>

namespace RawrXD {
namespace NEVM {

PrecisionLevel PrecisionController::s_forcedPrecision = PrecisionLevel::MAXIMUM;
bool PrecisionController::s_initialized = false;

void PrecisionController::Initialize() {
    if (s_initialized) return;
    
    // Initialize kernel registry
    Kernels::KernelRegistry::Initialize();
    
    // Run self-test
    Kernels::KernelRegistry::RunSelfTest();
    
    s_initialized = true;
}

ExecutionPlan PrecisionController::SelectPlan(
    Kernels::KernelOp op,
    PrecisionLevel precision,
    LatencyTarget latency
) {
    if (!s_initialized) Initialize();
    
    // Use forced precision if set
    if (s_forcedPrecision != PrecisionLevel::MAXIMUM) {
        precision = s_forcedPrecision;
    }
    
    ExecutionPlan plan = {};
    plan.available = false;
    
    // Get available plans
    auto plans = GetAvailablePlans(op);
    if (plans.empty()) {
        return plan;
    }
    
    // Filter by precision requirement
    std::vector<ExecutionPlan> candidates;
    for (const auto& p : plans) {
        // Check if precision is acceptable
        bool precision_ok = false;
        switch (precision) {
            case PrecisionLevel::MAXIMUM:
                precision_ok = (p.quant == Kernels::QuantType::F32);
                break;
            case PrecisionLevel::HIGH:
                precision_ok = (p.quant == Kernels::QuantType::F32 ||
                               p.quant == Kernels::QuantType::F16 ||
                               p.quant == Kernels::QuantType::BF16);
                break;
            case PrecisionLevel::MEDIUM:
                precision_ok = (p.quant != Kernels::QuantType::Q4_0 &&
                               p.quant != Kernels::QuantType::Q4_1);
                break;
            case PrecisionLevel::LOW:
            case PrecisionLevel::MINIMUM:
                precision_ok = true;  // Accept anything
                break;
        }
        
        if (precision_ok && p.available) {
            candidates.push_back(p);
        }
    }
    
    if (candidates.empty()) {
        return plan;
    }
    
    // Sort by latency target
    switch (latency) {
        case LatencyTarget::REALTIME:
        case LatencyTarget::LOW:
            // Pick fastest
            std::sort(candidates.begin(), candidates.end(),
                [](const ExecutionPlan& a, const ExecutionPlan& b) {
                    return a.estimated_latency_ms < b.estimated_latency_ms;
                });
            break;
            
        case LatencyTarget::MEDIUM:
        case LatencyTarget::HIGH:
            // Pick best precision within latency budget
            std::sort(candidates.begin(), candidates.end(),
                [](const ExecutionPlan& a, const ExecutionPlan& b) {
                    // Prefer lower error, but weight latency
                    float score_a = a.estimated_error * 10 + a.estimated_latency_ms;
                    float score_b = b.estimated_error * 10 + b.estimated_latency_ms;
                    return score_a < score_b;
                });
            break;
    }
    
    return candidates[0];
}

std::vector<ExecutionPlan> PrecisionController::GetAvailablePlans(
    Kernels::KernelOp op
) {
    std::vector<ExecutionPlan> plans;
    
    if (op != Kernels::KernelOp::MatVec && op != Kernels::KernelOp::MatMul) {
        return plans;
    }
    
    // Check what kernels are available
    Kernels::KernelCaps caps = Kernels::KernelRegistry::GetCpuCaps();
    bool has_avx512 = Kernels::has_cap(caps, Kernels::KernelCaps::AVX512F) &&
                      Kernels::has_cap(caps, Kernels::KernelCaps::AVX512VL);
    bool has_fma = Kernels::has_cap(caps, Kernels::KernelCaps::FMA);
    
    // Q4 AVX-512
    if (has_avx512 && has_fma) {
        ExecutionPlan q4_plan = {};
        q4_plan.quant = Kernels::QuantType::Q4_0;
        q4_plan.isa = Kernels::KernelCaps::AVX512F | Kernels::KernelCaps::AVX512VL | Kernels::KernelCaps::FMA;
        q4_plan.estimated_error = 0.004f;  // ~0.4% typical Q4 error
        q4_plan.estimated_latency_ms = 0.001f;  // ~1us per block
        q4_plan.kernel_entry = Kernels::KernelRegistry::GetQ4DotKernel();
        q4_plan.available = (q4_plan.kernel_entry != nullptr);
        plans.push_back(q4_plan);
    }
    
    // Q8 (placeholder - would need implementation)
    if (has_avx512) {
        ExecutionPlan q8_plan = {};
        q8_plan.quant = Kernels::QuantType::Q8_0;
        q8_plan.isa = Kernels::KernelCaps::AVX512F;
        q8_plan.estimated_error = 0.001f;  // ~0.1% typical Q8 error
        q8_plan.estimated_latency_ms = 0.002f;  // ~2us per block
        q8_plan.kernel_entry = nullptr;  // TODO: implement
        q8_plan.available = false;
        plans.push_back(q8_plan);
    }
    
    // FP16 (placeholder)
    ExecutionPlan fp16_plan = {};
    fp16_plan.quant = Kernels::QuantType::FP16;
    fp16_plan.isa = Kernels::KernelCaps::NONE;
    fp16_plan.estimated_error = 0.0001f;  // ~0.01% FP16 error
    fp16_plan.estimated_latency_ms = 0.004f;  // ~4us per block
    fp16_plan.kernel_entry = nullptr;  // TODO: implement
    fp16_plan.available = false;
    plans.push_back(fp16_plan);
    
    // FP32 reference (always available)
    ExecutionPlan fp32_plan = {};
    fp32_plan.quant = Kernels::QuantType::F32;
    fp32_plan.isa = Kernels::KernelCaps::NONE;
    fp32_plan.estimated_error = 0.0f;  // Reference
    fp32_plan.estimated_latency_ms = 0.08f;  // ~80us per block (scalar)
    fp32_plan.kernel_entry = nullptr;  // Reference path
    fp32_plan.available = true;
    plans.push_back(fp32_plan);
    
    return plans;
}

void PrecisionController::ForcePrecision(PrecisionLevel level) {
    s_forcedPrecision = level;
}

PrecisionLevel PrecisionController::GetCurrentPrecision() {
    return s_forcedPrecision;
}

} // namespace NEVM
} // namespace RawrXD
