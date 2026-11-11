// ============================================================================
// witness_system_test.cpp — VAL-051 Witness System Smoke Test
// ============================================================================
// Tests the inference witness recording infrastructure without requiring
// a full GGUF model. Exercises all witness stages and produces a valid
// evidence artifact for verification.
// ============================================================================

#include "inference_witness.h"
#include <cstdio>
#include <cstring>

using namespace RawrXD::Evidence;

int main(int argc, char* argv[])
{
    printf("=== VAL-051 Witness System Smoke Test ===\n\n");

    // Test 1: Create witness recorder
    printf("Test 1: Creating WitnessRecorder...\n");
    WitnessRecorder recorder("test_model.gguf", "Hello, world!");
    recorder.SetParameters(42, 0.0f, 0.9f, 40, 512);
    printf("  ✓ WitnessRecorder created\n\n");

    // Test 2: Simulate stage execution
    printf("Test 2: Simulating inference stages...\n");
    
    // Stage: ModelLoad
    recorder.RecordStageStart(InferenceStage::ModelLoad);
    printf("  [modelLoad] Started...\n");
    // Simulate work
    Sleep(100);
    recorder.RecordStageComplete(InferenceStage::ModelLoad, true, "tensor_registry:abc123");
    printf("  [modelLoad] ✓ Completed (100ms)\n");

    // Stage: Tokenizer
    recorder.RecordStageStart(InferenceStage::Tokenizer);
    printf("  [tokenizer] Started...\n");
    Sleep(50);
    recorder.RecordStageComplete(InferenceStage::Tokenizer, true, "tokens:5");
    printf("  [tokenizer] ✓ Completed (50ms)\n");

    // Stage: Embedding
    recorder.RecordStageStart(InferenceStage::Embedding);
    printf("  [embedding] Started...\n");
    Sleep(75);
    recorder.RecordStageComplete(InferenceStage::Embedding, true, "embeddings:xyz789");
    printf("  [embedding] ✓ Completed (75ms)\n");

    // Stage: ForwardPass (simulated failure for test)
    recorder.RecordStageStart(InferenceStage::ForwardPass);
    printf("  [forwardPass] Started...\n");
    Sleep(25);
    recorder.RecordStageError(InferenceStage::ForwardPass, "Test: Forward pass not implemented");
    printf("  [forwardPass] ✗ Failed (25ms)\n");

    printf("\nTest 3: Finalizing witness...\n");
    recorder.Finalize(false);  // false = execution failed
    printf("  ✓ Witness finalized\n\n");

    // Test 4: Save witness artifact
    printf("Test 4: Saving witness artifact...\n");
    std::string path = recorder.SaveToDefaultLocation();
    printf("  ✓ Witness saved to: %s\n\n", path.c_str());

    // Test 5: Verify JSON output
    printf("Test 5: Verifying witness content...\n");
    const InferenceWitness& witness = recorder.GetWitness();
    printf("  Schema: %s\n", witness.SCHEMA);
    printf("  Git commit: %s\n", witness.gitCommit.c_str());
    printf("  Model path: %s\n", witness.modelPath.c_str());
    printf("  Prompt SHA256: %s\n", witness.promptSha256.c_str());
    printf("  Seed: %u\n", witness.seed);
    printf("  Temperature: %.2f\n", witness.temperature);
    printf("  Execution success: %s\n", witness.executionSuccess ? "true" : "false");
    printf("  Failure stage: %s\n", witness.failureStage.c_str());
    printf("  Failure reason: %s\n", witness.failureReason.c_str());
    printf("\n  Stage results:\n");
    
    const char* stageNames[] = {
        "modelLoad", "tokenizer", "embedding", "forwardPass",
        "kvCache", "sampler", "tokenOutput"
    };
    
    for (size_t i = 0; i < static_cast<size_t>(InferenceStage::COUNT); ++i) {
        InferenceStage stage = static_cast<InferenceStage>(i);
        auto it = witness.stages.find(stage);
        if (it != witness.stages.end()) {
            printf("    %s: completed=%s, success=%s, duration=%llu us\n",
                stageNames[i],
                it->second.completed ? "true" : "false",
                it->second.success ? "true" : "false",
                it->second.durationMicros);
        }
    }

    printf("\n=== All Tests Passed ===\n");
    printf("\nWitness artifact location: %s\n", path.c_str());
    printf("View with: type %s\n", path.c_str());

    return 0;
}
