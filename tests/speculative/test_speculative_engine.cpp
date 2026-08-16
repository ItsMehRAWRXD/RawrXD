// ============================================================================
// test_speculative_engine.cpp — Minimal harness to run the Sovereign Speculative Decoder
// ============================================================================
// Build: cl.exe /O2 /arch:AVX512 /EHsc /I.. test_speculative_engine.cpp ..\speculative_inference_engine.cpp /Fe:test_speculative.exe /link /STACK:8388608
// ============================================================================

#include "speculative_inference_engine.hpp"
#include <cstdio>
#include <vector>
#include <string>

using namespace RawrXD::Inference;

int main(int argc, char** argv) {
    (void)argc; (void)argv;
    
    printf("=== Sovereign Speculative Decoder Test ===\n");
    printf("Hardware target: Ryzen 7 7800X3D + RX 7800 XT 16GB\n\n");
    
    // Create engine with 2GB arena
    printf("[1/5] Creating engine (arena=2GB)...\n");
    SpeculativeEngineHandle engine = SpeculativeEngine_Create(2);
    if (!engine) {
        fprintf(stderr, "FATAL: Failed to create speculative engine\n");
        return 1;
    }
    printf("      Engine created successfully\n");
    
    // Enable self-improvement
    printf("[2/5] Enabling self-improvement...\n");
    SpeculativeEngine_EnableSelfImprovement(engine, 1);
    printf("      Self-improvement active\n");
    
    // Simple prompt (token IDs: 1=BOS, 100=hello, 200=world)
    printf("[3/5] Preparing prompt...\n");
    int prompt[] = {1, 100, 200};
    int prompt_len = 3;
    printf("      Prompt tokens: %d\n", prompt_len);
    
    // Generate tokens
    printf("[4/5] Generating 32 tokens...\n");
    int output[64] = {0};
    int generated = SpeculativeEngine_Generate(engine, output, 64,
                                                prompt, prompt_len,
                                                32, 0.8f);
    printf("      Generated: %d tokens\n", generated);
    
    // Report stats
    printf("[5/5] Statistics:\n");
    double tps = SpeculativeEngine_GetTPS(engine);
    double acceptance = SpeculativeEngine_GetAcceptanceRate(engine);
    printf("      Tokens/sec: %.2f\n", tps);
    printf("      Acceptance rate: %.1f%%\n", acceptance * 100.0);
    
    // Show first few output tokens
    printf("\nOutput tokens (first 10): ");
    for (int i = 0; i < std::min(generated, 10); i++) {
        printf("%d ", output[i]);
    }
    printf("\n");
    
    // Trigger training cycle
    printf("\n[Bonus] Triggering self-improvement cycle...\n");
    SpeculativeEngine_TriggerTrainingCycle(engine);
    printf("      Cycle complete\n");
    
    // Cleanup
    SpeculativeEngine_Destroy(engine);
    printf("\n=== Test Complete ===\n");
    
    return 0;
}
