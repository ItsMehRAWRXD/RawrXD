//=============================================================================
// NEVM Precision Controller Test
// Validates dynamic kernel selection
//=============================================================================

#include <cstdio>
#include <vector>
#include "../src/nevm/PrecisionController.hpp"

using namespace RawrXD::NEVM;
using namespace RawrXD::Kernels;

void print_plan(const ExecutionPlan& plan) {
    const char* quant_name = "Unknown";
    switch (plan.quant) {
        case QuantType::F32: quant_name = "FP32"; break;
        case QuantType::F16: quant_name = "FP16"; break;
        case QuantType::Q8_0: quant_name = "Q8_0"; break;
        case QuantType::Q4_0: quant_name = "Q4_0"; break;
        default: quant_name = "Other"; break;
    }
    
    printf("  Quant: %s\n", quant_name);
    printf("  Error: %.4f%%\n", plan.estimated_error * 100);
    printf("  Latency: %.3f ms\n", plan.estimated_latency_ms);
    printf("  Available: %s\n", plan.available ? "YES" : "NO");
}

int main() {
    printf("NEVM Precision Controller Test\n");
    printf("===============================\n\n");
    
    // Initialize
    PrecisionController::Initialize();
    
    // Test 1: Get available plans
    printf("Test 1: Available Plans for MatMul\n");
    auto plans = PrecisionController::GetAvailablePlans(KernelOp::MatMul);
    printf("Found %zu plans:\n\n", plans.size());
    
    for (size_t i = 0; i < plans.size(); i++) {
        printf("Plan %zu:\n", i + 1);
        print_plan(plans[i]);
        printf("\n");
    }
    
    // Test 2: Select plan with different requirements
    printf("Test 2: Plan Selection\n\n");
    
    struct TestCase {
        const char* name;
        PrecisionLevel precision;
        LatencyTarget latency;
    };
    
    TestCase tests[] = {
        {"Maximum precision, any latency", PrecisionLevel::MAXIMUM, LatencyTarget::HIGH},
        {"Low precision, realtime", PrecisionLevel::LOW, LatencyTarget::REALTIME},
        {"Medium precision, low latency", PrecisionLevel::MEDIUM, LatencyTarget::LOW},
    };
    
    for (const auto& test : tests) {
        printf("Request: %s\n", test.name);
        
        ExecutionPlan plan = PrecisionController::SelectPlan(
            KernelOp::MatMul, test.precision, test.latency);
        
        if (plan.available) {
            printf("Selected:\n");
            print_plan(plan);
        } else {
            printf("No suitable plan found\n");
        }
        printf("\n");
    }
    
    // Test 3: Force precision
    printf("Test 3: Force Precision\n");
    PrecisionController::ForcePrecision(PrecisionLevel::LOW);
    printf("Forced to LOW precision\n");
    
    ExecutionPlan forced = PrecisionController::SelectPlan(
        KernelOp::MatMul, PrecisionLevel::MAXIMUM, LatencyTarget::HIGH);
    
    printf("Selected (should be Q4):\n");
    print_plan(forced);
    
    printf("\n✓ NEVM Precision Controller test complete\n");
    return 0;
}
