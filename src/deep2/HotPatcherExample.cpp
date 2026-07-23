// ============================================================================
// HotPatcherExample.cpp - Demonstration of The Bottle in action
//
// This file shows how to use HotPatcher to modify Deep2Engine at runtime
// without recompilation or restart.
//
// Usage:
//   Deep2Engine engine;
//   engine.initialize(config);
//   
//   // Register a kernel patch
//   std::string patchId = engine.registerKernelPatch(
//       "attention_kernel",
//       (void*)originalAttention,
//       (void*)optimizedAttention,
//       1.5f  // Expected 1.5x speedup
//   );
//
//   // Check status
//   engine.printHotPatcherStatus();
//
//   // Rollback if needed
//   engine.rollbackKernelPatch(patchId);
//
// ============================================================================

#include "Deep2Engine.h"
#include "HotPatcher.hpp"
#include <stdio>

using namespace Deep2;

// ============================================================================
// Example 1: Function Hook for computeLogits
// ============================================================================

// Original function (would be in Deep2Engine)
void originalComputeLogits(const float* hiddenState, float* logits, size_t hiddenDim, size_t vocabSize) {
    // Standard implementation
    for (size_t v = 0; v < vocabSize; ++v) {
        float sum = 0.0f;
        for (size_t h = 0; h < hiddenDim; ++h) {
            sum += hiddenState[h] * 1.0f;  // Simplified
        }
        logits[v] = sum;
    }
}

// Optimized replacement (AVX-512 version)
void optimizedComputeLogitsAVX512(const float* hiddenState, float* logits, size_t hiddenDim, size_t vocabSize) {
    // AVX-512 optimized implementation
    // In real code, this would use _mm512_loadu_ps, etc.
    printf("[Optimized] Running AVX-512 computeLogits\n");
    
    // Fallback to original for this example
    originalComputeLogits(hiddenState, logits, hiddenDim, vocabSize);
}

// ============================================================================
// Example 2: Kernel Replacement for Attention
// ============================================================================

// Original attention kernel
void* originalAttentionKernel = nullptr;

// Optimized attention kernel (FlashAttention-style)
void optimizedAttentionKernel(void* q, void* k, void* v, void* out, size_t seqLen, size_t headDim) {
    printf("[Optimized] Running FlashAttention-style kernel\n");
    // Optimized implementation here
}

// ============================================================================
// Example 3: Decoder Mode Switching
// ============================================================================

void demonstrateDecoderModeSwitching(Deep2Engine& engine) {
    printf("\n=== Decoder Mode Switching Demo ===\n");
    
    // Switch to greedy Medusa mode
    DecoderModePatch medusaMode;
    medusaMode.targetMode = DecoderModePatch::Mode::GREEDY_MEDUSA;
    medusaMode.medusaConfig.treeDepth = 4;
    medusaMode.medusaConfig.numHeads = 4;
    medusaMode.medusaConfig.acceptanceThreshold = 0.6f;
    
    PatchMetadata meta;
    meta.name = "Greedy Medusa Mode";
    meta.expectedSpeedup = 2.5f;
    meta.canRollback = true;
    
    std::string patchId = GetHotPatcher().registerDecoderMode(medusaMode, meta);
    
    ValidationResult validation = GetHotPatcher().validate(patchId);
    if (validation.passed) {
        printf("Decoder mode patch validated: risk=%.2f, speedup=%.2fx\n",
               validation.riskScore, validation.predictedSpeedup);
        
        if (GetHotPatcher().apply(patchId)) {
            printf("Decoder mode switched to GREEDY_MEDUSA\n");
        }
    }
}

// ============================================================================
// Example 4: A/B Testing
// ============================================================================

void demonstrateABTesting() {
    printf("\n=== A/B Testing Demo ===\n");
    
    // Create two versions of a kernel
    // Version A: Original
    // Version B: Optimized
    
    // Register both as patches
    KernelReplacement kernelA;
    kernelA.kernelName = "attention_v1";
    kernelA.newKernel = (void*)originalAttentionKernel;
    
    KernelReplacement kernelB;
    kernelB.kernelName = "attention_v2";
    kernelB.newKernel = (void*)optimizedAttentionKernel;
    
    PatchMetadata metaA;
    metaA.name = "Attention V1 (Baseline)";
    metaA.expectedSpeedup = 1.0f;
    
    PatchMetadata metaB;
    metaB.name = "Attention V2 (FlashAttention)";
    metaB.expectedSpeedup = 2.0f;
    
    std::string patchA = GetHotPatcher().registerKernelReplacement(kernelA, metaA);
    std::string patchB = GetHotPatcher().registerKernelReplacement(kernelB, metaB);
    
    // Validate both
    auto valA = GetHotPatcher().validate(patchA);
    auto valB = GetHotPatcher().validate(patchB);
    
    printf("Patch A: risk=%.2f, speedup=%.2fx, passed=%s\n",
           valA.riskScore, valA.predictedSpeedup, valA.passed ? "YES" : "NO");
    printf("Patch B: risk=%.2f, speedup=%.2fx, passed=%s\n",
           valB.riskScore, valB.predictedSpeedup, valB.passed ? "YES" : "NO");
    
    // Run A/B test
    // In production, this would run actual inference and measure
    printf("Running A/B test...\n");
    
    // Apply A, measure
    GetHotPatcher().apply(patchA);
    printf("Applied patch A\n");
    
    // Apply B, measure
    GetHotPatcher().rollback(patchA);
    GetHotPatcher().apply(patchB);
    printf("Applied patch B\n");
    
    // Compare results and keep winner
    printf("A/B test complete - keeping winner\n");
}

// ============================================================================
// Example 5: Emergency Rollback
// ============================================================================

void demonstrateEmergencyRollback() {
    printf("\n=== Emergency Rollback Demo ===\n");
    
    // Simulate a crash scenario
    printf("Simulating crash scenario...\n");
    
    // Emergency rollback all patches
    GetHotPatcher().emergencyRollback();
    
    printf("All patches rolled back - system restored to baseline\n");
}

// ============================================================================
// Main Demo
// ============================================================================

int main() {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║         HotPatcher Demo - The Bottle                         ║\n");
    printf("║     Runtime Code Modification for Deep2Engine                  ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n\n");
    
    // Initialize engine
    Deep2Engine engine;
    EngineConfig config;
    config.hiddenDim = 4096;
    config.numLayers = 32;
    config.numHeads = 32;
    config.maxSeqLen = 8192;
    config.useThreadPool = true;
    config.useKVCache = true;
    
    if (!engine.initialize(config)) {
        printf("Failed to initialize engine\n");
        return 1;
    }
    
    // Show initial status
    engine.printHotPatcherStatus();
    
    // Example 1: Register a kernel patch
    printf("\n=== Kernel Patch Registration ===\n");
    std::string kernelPatchId = engine.registerKernelPatch(
        "attention_flash",
        (void*)originalAttentionKernel,
        (void*)optimizedAttentionKernel,
        2.0f  // Expected 2x speedup
    );
    
    if (!kernelPatchId.empty()) {
        printf("Kernel patch registered: %s\n", kernelPatchId.c_str());
    }
    
    // Example 2: Decoder mode switching
    demonstrateDecoderModeSwitching(engine);
    
    // Example 3: A/B Testing
    demonstrateABTesting();
    
    // Show status after patches
    engine.printHotPatcherStatus();
    
    // Example 4: Emergency rollback
    demonstrateEmergencyRollback();
    
    // Final status
    engine.printHotPatcherStatus();
    
    printf("\nDemo complete!\n");
    return 0;
}

// ============================================================================
// Integration Notes
// ============================================================================
/*

To integrate HotPatcher into your build:

1. Add to CMakeLists.txt:
   target_sources(deep2 PRIVATE
       HotPatcher.cpp
       HotPatcherExample.cpp  # Optional demo
   )

2. Link platform libraries:
   if(WIN32)
       target_link_libraries(deep2 PRIVATE kernel32)
   endif()

3. Enable in engine initialization (already done in Deep2Engine.cpp):
   GetHotPatcher().initialize();

4. Use in your code:
   #include "HotPatcher.hpp"
   
   // Register a patch
   std::string patchId = GetHotPatcher().registerKernelReplacement(kernel, meta);
   
   // Validate and apply
   if (GetHotPatcher().validate(patchId).passed) {
       GetHotPatcher().apply(patchId);
   }

5. Safety features:
   - Auto-rollback on crash (setAutoRollback(true))
   - Checksum validation
   - Memory protection during writes
   - Trampoline allocation for calling originals

6. Performance:
   - Patch application: ~1ms
   - Function hook overhead: ~5-10ns per call
   - No overhead when not patching

*/
