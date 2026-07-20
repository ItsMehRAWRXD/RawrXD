// ═══════════════════════════════════════════════════════════════════════════════
// VAL-038: Validation Benchmark (B → C → A)
// ═══════════════════════════════════════════════════════════════════════════════
// Step B: Validate control flow with debug counters
// Step C: Validate numerical correctness against scalar reference
// Step A: (Future) Optimize with AVX-512
// ═══════════════════════════════════════════════════════════════════════════════

#include <cstdio>
#include <cstdint>
#include <vector>
#include <chrono>
#include <random>
#include <cstring>
#include "../validation/kernels/TreeAttention_Fused_VAL038_Debug.hpp"
#include "../validation/kernels/TreeAttention_Fused_VAL038_Reference.cpp"

using namespace RawrXD;

// External assembly functions (C linkage)
extern "C" {
    void TreeAttention_Fused_VAL038_Debug(
        float* output,
        const float* Q,
        const float* K,
        const float* V,
        uint32_t num_q,
        uint32_t num_k,
        const uint8_t* tree_mask
    );
}

// Use C++ namespace version from header for ResetDebugCounters and GetDebugStats
using RawrXD::ResetDebugCounters;
using RawrXD::GetDebugStats;

// ═══════════════════════════════════════════════════════════════════════════════
// Test Configuration
// ═══════════════════════════════════════════════════════════════════════════════
constexpr uint32_t HEAD_DIM = 64;
constexpr uint32_t NUM_Q = 16;
constexpr uint32_t NUM_K = 16;
constexpr uint32_t ITERATIONS = 100;

// ═══════════════════════════════════════════════════════════════════════════════
// Utility Functions
// ═══════════════════════════════════════════════════════════════════════════════
void InitializeMatrix(float* data, uint32_t rows, uint32_t cols, uint32_t seed) {
    std::mt19937 rng(seed);
    std::uniform_real_distribution<float> dist(-0.5f, 0.5f);
    for (uint32_t i = 0; i < rows * cols; i++) {
        data[i] = dist(rng);
    }
}

void InitializeTreeMask(uint8_t* mask, uint32_t num_q, uint32_t num_k) {
    // Causal tree mask: query i can attend to key j if j <= i
    for (uint32_t i = 0; i < num_q; i++) {
        for (uint32_t j = 0; j < num_k; j++) {
            mask[i * num_k + j] = (j <= i) ? 1 : 0;
        }
    }
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test B: Control Flow Validation (Debug Counters)
// ═══════════════════════════════════════════════════════════════════════════════
bool TestControlFlowValidation() {
    printf("\n=== Test B: Control Flow Validation ===\n");
    
    // Allocate matrices
    std::vector<float> Q(NUM_Q * HEAD_DIM);
    std::vector<float> K(NUM_K * HEAD_DIM);
    std::vector<float> V(NUM_K * HEAD_DIM);
    std::vector<float> output(NUM_Q * HEAD_DIM);
    std::vector<uint8_t> treeMask(NUM_Q * NUM_K);
    
    InitializeMatrix(Q.data(), NUM_Q, HEAD_DIM, 42);
    InitializeMatrix(K.data(), NUM_K, HEAD_DIM, 43);
    InitializeMatrix(V.data(), NUM_K, HEAD_DIM, 44);
    InitializeTreeMask(treeMask.data(), NUM_Q, NUM_K);
    
    // Reset debug counters
    ResetDebugCounters();
    
    // Run debug kernel
    auto start = std::chrono::high_resolution_clock::now();
    TreeAttention_Fused_VAL038_Debug(
        output.data(),
        Q.data(),
        K.data(),
        V.data(),
        NUM_Q,
        NUM_K,
        treeMask.data()
    );
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
    
    // Get debug stats
    DebugStats stats = GetDebugStats();
    
    printf("  Configuration: %u queries, %u keys, head_dim=%u\n", NUM_Q, NUM_K, HEAD_DIM);
    printf("  Execution time: %.2f µs\n", duration / 1000.0f);
    printf("\n  Debug Counters:\n");
    printf("    Q iterations:     %llu (expected: %u)\n", stats.qIterations, NUM_Q);
    printf("    K iterations:     %llu (expected: ~%u)\n", stats.kIterations, NUM_Q * NUM_K / 2);
    printf("    Max K per Q:      %llu (expected: <= %u)\n", stats.kMaxPerQ, NUM_K);
    printf("    Watchdog aborts:  %llu (expected: 0)\n", stats.abortCount);
    printf("    Avg K per Q:      %.1f\n", stats.avgKeysPerQuery);
    
    // Validate
    bool q_ok = (stats.qIterations == NUM_Q);
    bool k_ok = (stats.kIterations > 0 && stats.kIterations <= NUM_Q * NUM_K);
    bool max_k_ok = (stats.kMaxPerQ <= NUM_K);
    bool abort_ok = (stats.abortCount == 0);
    
    bool pass = q_ok && k_ok && max_k_ok && abort_ok;
    printf("\n  [%s] Control flow validation\n", pass ? "PASS" : "FAIL");
    
    if (!pass) {
        if (!q_ok) printf("    ERROR: Q iteration count mismatch\n");
        if (!k_ok) printf("    ERROR: K iteration count out of range\n");
        if (!max_k_ok) printf("    ERROR: Max K per Q exceeded bounds\n");
        if (!abort_ok) printf("    ERROR: Watchdog abort triggered\n");
    }
    
    return pass;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test C: Numerical Correctness (vs Scalar Reference)
// ═══════════════════════════════════════════════════════════════════════════════
bool TestNumericalCorrectness() {
    printf("\n=== Test C: Numerical Correctness ===\n");
    
    // Allocate matrices
    std::vector<float> Q(NUM_Q * HEAD_DIM);
    std::vector<float> K(NUM_K * HEAD_DIM);
    std::vector<float> V(NUM_K * HEAD_DIM);
    std::vector<float> output_asm(NUM_Q * HEAD_DIM);
    std::vector<float> output_ref(NUM_Q * HEAD_DIM);
    std::vector<uint8_t> treeMask(NUM_Q * NUM_K);
    
    InitializeMatrix(Q.data(), NUM_Q, HEAD_DIM, 42);
    InitializeMatrix(K.data(), NUM_K, HEAD_DIM, 43);
    InitializeMatrix(V.data(), NUM_K, HEAD_DIM, 44);
    InitializeTreeMask(treeMask.data(), NUM_Q, NUM_K);
    
    // Run scalar reference
    auto start_ref = std::chrono::high_resolution_clock::now();
    TreeAttention_Fused_VAL038_Reference(
        output_ref.data(),
        Q.data(),
        K.data(),
        V.data(),
        NUM_Q,
        NUM_K,
        treeMask.data(),
        HEAD_DIM
    );
    auto end_ref = std::chrono::high_resolution_clock::now();
    auto duration_ref = std::chrono::duration_cast<std::chrono::microseconds>(end_ref - start_ref).count();
    
    // Run ASM debug kernel
    ResetDebugCounters();
    auto start_asm = std::chrono::high_resolution_clock::now();
    TreeAttention_Fused_VAL038_Debug(
        output_asm.data(),
        Q.data(),
        K.data(),
        V.data(),
        NUM_Q,
        NUM_K,
        treeMask.data()
    );
    auto end_asm = std::chrono::high_resolution_clock::now();
    auto duration_asm = std::chrono::duration_cast<std::chrono::microseconds>(end_asm - start_asm).count();
    
    // Validate
    ValidationResult result = ValidateAttentionOutput(
        output_asm.data(),
        output_ref.data(),
        NUM_Q,
        HEAD_DIM,
        0.01f  // Tolerance: 1%
    );
    
    printf("  Configuration: %u queries, %u keys, head_dim=%u\n", NUM_Q, NUM_K, HEAD_DIM);
    printf("\n  Performance:\n");
    printf("    Reference: %.2f µs\n", duration_ref / 1000.0f);
    printf("    ASM Debug: %.2f µs\n", duration_asm / 1000.0f);
    printf("    Speedup:   %.2fx\n", duration_ref / (float)duration_asm);
    
    printf("\n  Numerical Validation:\n");
    printf("    Max error:  %.6f @ index %u\n", result.maxError, result.maxErrorIndex);
    printf("    Avg error:  %.6f\n", result.avgError);
    printf("    Tolerance:  0.01 (1%%)\n");
    
    printf("\n  [%s] Numerical correctness\n", result.passed ? "PASS" : "FAIL");
    
    if (!result.passed) {
        // Print first few mismatches
        printf("\n  First 5 mismatches:\n");
        uint32_t mismatches = 0;
        for (uint32_t i = 0; i < NUM_Q * HEAD_DIM && mismatches < 5; i++) {
            float error = std::abs(output_asm[i] - output_ref[i]);
            if (error > 0.01f) {
                printf("    [%u] ASM=%.6f REF=%.6f ERR=%.6f\n",
                       i, output_asm[i], output_ref[i], error);
                mismatches++;
            }
        }
    }
    
    return result.passed;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main Entry Point
// ═══════════════════════════════════════════════════════════════════════════════
int main() {
    printf("=============================================================================\n");
    printf("VAL-038: Validation Benchmark (B → C → A)\n");
    printf("=============================================================================\n");
    printf("\nPriority order:\n");
    printf("  B: Control flow validation (debug counters)\n");
    printf("  C: Numerical correctness (vs scalar reference)\n");
    printf("  A: AVX-512 optimization (after B and C pass)\n");
    printf("\nTarget: Correctness + deterministic execution\n");
    printf("=============================================================================\n");
    
    bool allPass = true;
    
    // Step B: Control flow validation
    allPass &= TestControlFlowValidation();
    
    // Step C: Numerical correctness
    allPass &= TestNumericalCorrectness();
    
    printf("\n=============================================================================\n");
    printf("VALIDATION SUMMARY\n");
    printf("=============================================================================\n");
    printf("Test B (Control Flow):    %s\n", allPass ? "PASS" : "FAIL");
    printf("Test C (Numerical):       %s\n", allPass ? "PASS" : "FAIL");
    printf("\n");
    printf("VAL-038: %s\n", allPass ? "READY FOR AVX-512 OPTIMIZATION" : "BLOCKED - FIX ISSUES");
    printf("=============================================================================\n");
    
    return allPass ? 0 : 1;
}
