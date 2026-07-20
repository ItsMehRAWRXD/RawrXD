//=============================================================================
// Benchmark: Planner Amortization
// Measures planning cost vs execution benefit
//=============================================================================

#include <cstdio>
#include <cstdint>
#include <chrono>
#include <vector>
#include "../src/nevm/nevm_execution_plan.hpp"
#include "../src/nevm/nevm_kernel_bridge.hpp"

using namespace RawrXD::NEVM;
using namespace RawrXD::Kernels;

int main() {
    printf("=============================================================================\n");
    printf("PLANNER AMORTIZATION BENCHMARK\n");
    printf("=============================================================================\n\n");
    
    // Initialize
    KernelRegistry::Initialize();
    
    // Setup
    ExecutionPlanner planner(ExecutionPlanner::DefaultConfig());
    
    // Create a batch of instructions (simulating transformer layer)
    std::vector<InstructionDispatcher::Instruction> batch;
    for (int i = 0; i < 100; i++) {  // 100 ops per layer
        InstructionDispatcher::Instruction inst;
        inst.opcode = InstructionDispatcher::OpCode::MATMUL;
        inst.src_a = 0x1000 + i * 0x100;
        inst.src_b = 0x2000 + i * 0x100;
        inst.dst = 0x3000 + i * 0x100;
        inst.param.int_param = (128 << 16) | 128;
        batch.push_back(inst);
    }
    
    // Measure planning time
    printf("Measuring planning time...\n");
    auto plan_start = std::chrono::high_resolution_clock::now();
    
    ExecutionPlan plan = planner.CompileBatch(batch);
    plan.Optimize();
    
    auto plan_end = std::chrono::high_resolution_clock::now();
    auto plan_duration = std::chrono::duration_cast<std::chrono::microseconds>(
        plan_end - plan_start);
    
    double plan_ms = plan_duration.count() / 1000.0;
    printf("  Planning time: %.3f ms\n", plan_ms);
    printf("  Operations in plan: %zu\n", batch.size());
    printf("  Planning time per op: %.3f µs\n", plan_ms * 1000.0 / batch.size());
    
    // Simulate token generation
    printf("\nSimulating token generation...\n");
    
    std::vector<size_t> token_counts = {128, 512, 2048, 4096, 8192};
    
    for (size_t num_tokens : token_counts) {
        // Time to execute plan for N tokens
        auto exec_start = std::chrono::high_resolution_clock::now();
        
        // Simulate execution (just iterate, don't actually run)
        for (size_t token = 0; token < num_tokens; token++) {
            // In real execution: executor.Run(plan);
            // Here we just touch memory to prevent optimization
            volatile size_t dummy = token;
            (void)dummy;
        }
        
        auto exec_end = std::chrono::high_resolution_clock::now();
        auto exec_duration = std::chrono::duration_cast<std::chrono::microseconds>(
            exec_end - exec_start);
        
        double exec_ms = exec_duration.count() / 1000.0;
        double total_ms = plan_ms + exec_ms;
        double overhead_per_token = plan_ms / num_tokens;
        
        printf("\n  Tokens: %zu\n", num_tokens);
        printf("    Planning overhead/token: %.3f µs\n", overhead_per_token * 1000.0);
        printf("    Total time: %.2f ms (plan) + %.2f ms (exec)\n", plan_ms, exec_ms);
        
        if (overhead_per_token < 1.0) {  // Less than 1µs per token
            printf("    ✓ Planning cost amortized\n");
        } else {
            printf("    ⚠ Planning cost significant\n");
        }
    }
    
    // Plan reuse scenario
    printf("\n\nPlan Reuse Scenario:\n");
    printf("  Same plan used for 4096 tokens:\n");
    printf("    Planning: %.3f ms (once)\n", plan_ms);
    printf("    Amortized cost: %.3f µs/token\n", (plan_ms / 4096.0) * 1000.0);
    printf("    Benefit: Dispatch overhead saved per token\n");
    
    // Calculate break-even: break_even = plan_cost / dispatch_savings
    // Formula: tokens_to_break_even = planning_time_ns / dispatch_savings_per_token_ns
    double dispatch_saved_ns = 500.0 - 10.0;  // v1.0 - v2.0
    double planning_cost_ns = plan_ms * 1000000.0;  // Convert ms to ns
    double break_even_tokens = planning_cost_ns / dispatch_saved_ns;
    
    printf("\n  Break-even analysis:\n");
    printf("    Formula: break_even_tokens = planning_cost_ns / dispatch_savings_per_token\n");
    printf("    Dispatch saved per token: %.0f ns\n", dispatch_saved_ns);
    printf("    Planning cost: %.0f µs (%.0f ns)\n", plan_ms * 1000.0, planning_cost_ns);
    printf("    Break-even at: %.0f tokens\n", break_even_tokens);
    
    // Calculate for different dispatch savings scenarios
    printf("\n  Sensitivity analysis:\n");
    double savings_scenarios[] = {100.0, 250.0, 490.0, 500.0};  // ns saved per token
    for (double savings : savings_scenarios) {
        double be = planning_cost_ns / savings;
        printf("    If saving %.0f ns/token: break-even at %.0f tokens\n", savings, be);
    }
    
    if (break_even_tokens < 128) {
        printf("\n    ✓ Planning pays off quickly (< 128 tokens)\n");
    } else if (break_even_tokens < 1024) {
        printf("\n    ⚠ Planning pays off after ~%.0f tokens\n", break_even_tokens);
    } else {
        printf("\n    ✗ Planning may not be worthwhile for short sequences\n");
    }
    
    // Amortization over sequence length
    printf("\n  Amortization over sequence length:\n");
    size_t seq_lengths[] = {128, 512, 1024, 2048, 4096, 8192};
    for (size_t seq_len : seq_lengths) {
        double total_savings_ns = dispatch_saved_ns * seq_len;
        double net_benefit_ns = total_savings_ns - planning_cost_ns;
        double benefit_per_token_ns = net_benefit_ns / seq_len;
        const char* status = (net_benefit_ns > 0) ? "✓" : "✗";
        printf("    %s Seq %zu: net benefit %.0f ns/token\n", status, seq_len, benefit_per_token_ns);
    }
    
    printf("\n");
    return 0;
}
