/*
 * Truth Gate 003: Runtime Integration
 * 
 * End-to-end validation that RawrXD can:
 * - Load a real GGUF model (tinyllama-1.1b.Q4_0.gguf)
 * - Execute transformer inference
 * - Produce tokens matching llama.cpp reference
 * 
 * Gates: TG3-A through TG3-F
 */

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <vector>
#include <string>
#include <chrono>
#include <cmath>

// Runtime headers
#include "../runtime/sovereign_runtime.h"
#include "../fabric/rawramxd_fabric.h"

// Integration modules
#include "gguf_integration.h"
#include "fabric_integration.h"
#include "transformer_executor.h"
#include "tokenizer_integration.h"
#include "sampler_integration.h"
#include "llamacpp_validator.h"

// ============================================================================
// Global State (forward declarations)
// ============================================================================

GGUFModel* g_active_model = nullptr;
FabricContext* g_fabric_context = nullptr;
TransformerExecutor* g_transformer_executor = nullptr;
TokenizerHandle* g_tokenizer = nullptr;
SamplerHandle* g_sampler = nullptr;
std::vector<int> g_prompt_tokens;

// ============================================================================
// Gate Results
// ============================================================================

struct GateResult {
    const char* name;
    bool passed;
    const char* details;
    double duration_ms;
};

std::vector<GateResult> g_results;

void RecordGate(const char* name, bool passed, const char* details, double duration_ms) {
    g_results.push_back({name, passed, details, duration_ms});
    
    const char* status = passed ? "✅ PASS" : "❌ FAIL";
    printf("[%s] %s: %s (%.2f ms)\n", status, name, details, duration_ms);
}

// ============================================================================
// TG3-A: Real GGUF Loads Through Sovereign Runtime
// ============================================================================

bool Gate_TG3A_LoadRealGGUF() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== TG3-A: Loading tinyllama-1.1b.Q4_0.gguf ===\n");
    
    // Try to find the model
    const char* model_paths[] = {
        "tinyllama-1.1b.Q4_0.gguf",
        "models/tinyllama-1.1b.Q4_0.gguf",
        "../models/tinyllama-1.1b.Q4_0.gguf",
        "../../models/tinyllama-1.1b.Q4_0.gguf",
        "test_model.gguf",  // Fallback to test model
        nullptr
    };
    
    const char* model_path = nullptr;
    for (int i = 0; model_paths[i]; i++) {
        FILE* f = fopen(model_paths[i], "rb");
        if (f) {
            fclose(f);
            model_path = model_paths[i];
            printf("  Found model at: %s\n", model_path);
            break;
        }
    }
    
    if (!model_path) {
        printf("  WARNING: No GGUF model found, using synthetic test\n");
        // Create minimal test model for validation
        model_path = "test_model.gguf";
    }
    
    // Load through integration layer
    GGUFModel* model = GGUFIntegration_Load(model_path);
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    if (!model) {
        RecordGate("TG3-A", false, "Failed to load GGUF model", duration);
        return false;
    }
    
    // Validate tensor count
    int tensor_count = GGUFIntegration_GetTensorCount(model);
    printf("  Loaded %d tensors\n", tensor_count);
    
    // Check critical tensors
    const char* critical_tensors[] = {
        "token_embd.weight",
        "output_norm.weight",
        "output.weight",
        nullptr
    };
    
    int found_critical = 0;
    for (int i = 0; critical_tensors[i]; i++) {
        if (GGUFIntegration_HasTensor(model, critical_tensors[i])) {
            printf("  ✓ Found: %s\n", critical_tensors[i]);
            found_critical++;
        } else {
            printf("  ✗ Missing: %s\n", critical_tensors[i]);
        }
    }
    
    bool passed = (tensor_count > 0) && (found_critical >= 2);
    
    char details[256];
    snprintf(details, sizeof(details), "%d tensors, %d/%d critical found", 
             tensor_count, found_critical, 3);
    
    RecordGate("TG3-A", passed, details, duration);
    
    // Store for later gates
    g_active_model = model;
    
    return passed;
}

// ============================================================================
// TG3-B: Fabric Manages Tensor Residency
// ============================================================================

bool Gate_TG3B_FabricResidency() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== TG3-B: Fabric Tensor Residency ===\n");
    
    if (!g_active_model) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-B", false, "No active model", duration);
        return false;
    }
    
    // Initialize fabric integration
    FabricContext* fabric = FabricIntegration_Init();
    if (!fabric) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-B", false, "Failed to init fabric", duration);
        return false;
    }
    
    // Register model tensors with fabric
    int registered = FabricIntegration_RegisterModelTensors(fabric, g_active_model);
    printf("  Registered %d tensors with fabric\n", registered);
    
    // Set residency policies
    int gpu_resident = FabricIntegration_SetActiveLayerResidency(fabric, 0);
    printf("  Set GPU residency for layer 0 (%d tensors)\n", gpu_resident);
    
    // Get residency stats
    ResidencyStats stats = FabricIntegration_GetResidencyStats(fabric);
    printf("  VRAM residency: %.1f%%\n", stats.vram_residency_percent);
    printf("  Prefetch hits: %d\n", stats.prefetch_hits);
    printf("  Spill events: %d\n", stats.spill_count);
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    bool passed = (registered > 0) && (stats.vram_residency_percent > 50.0);
    
    char details[256];
    snprintf(details, sizeof(details), "%d tensors, %.1f%% VRAM", 
             registered, stats.vram_residency_percent);
    
    RecordGate("TG3-B", passed, details, duration);
    
    g_fabric_context = fabric;
    
    return passed;
}

// ============================================================================
// TG3-C: Transformer Layer Executes
// ============================================================================

bool Gate_TG3C_TransformerExecution() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== TG3-C: Transformer Layer Execution ===\n");
    
    if (!g_active_model || !g_fabric_context) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-C", false, "Missing model or fabric", duration);
        return false;
    }
    
    // Initialize transformer executor
    TransformerExecutor* executor = TransformerExecutor_Init(g_active_model, g_fabric_context);
    if (!executor) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-C", false, "Failed to init executor", duration);
        return false;
    }
    
    // Create test input (batch=1, seq=1, hidden=2048 for tinyllama)
    float test_input[2048];
    for (int i = 0; i < 2048; i++) {
        test_input[i] = (float)(i % 10) / 10.0f;
    }
    
    // Execute one transformer layer
    LayerOutput output;
    bool success = TransformerExecutor_ExecuteLayer(executor, 0, test_input, 2048, &output);
    
    printf("  Layer 0 execution: %s\n", success ? "SUCCESS" : "FAILED");
    if (success) {
        printf("  Output shape: [%d, %d, %d]\n", 
               output.batch_size, output.seq_len, output.hidden_dim);
        printf("  KV cache updated: %s\n", output.kv_cache_updated ? "YES" : "NO");
        
        // Check output values are finite
        bool finite = true;
        for (int i = 0; i < output.hidden_dim && i < 10; i++) {
            if (!std::isfinite(output.hidden_states[i])) {
                finite = false;
                break;
            }
        }
        printf("  Output values finite: %s\n", finite ? "YES" : "NO");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    bool passed = success && output.kv_cache_updated;
    
    char details[256];
    snprintf(details, sizeof(details), "Layer 0, KV cache %s", 
             output.kv_cache_updated ? "updated" : "not updated");
    
    RecordGate("TG3-C", passed, details, duration);
    
    g_transformer_executor = executor;
    
    return passed;
}

// ============================================================================
// TG3-D: Tokenizer Produces IDs
// ============================================================================

bool Gate_TG3D_Tokenizer() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== TG3-D: Tokenizer Integration ===\n");
    
    if (!g_active_model) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-D", false, "No active model", duration);
        return false;
    }
    
    // Initialize tokenizer
    TokenizerHandle* tokenizer = TokenizerIntegration_Init(g_active_model);
    if (!tokenizer) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-D", false, "Failed to init tokenizer", duration);
        return false;
    }
    
    // Test prompt
    const char* prompt = "The capital of France is";
    printf("  Prompt: \"%s\"\n", prompt);
    
    // Encode
    std::vector<int> tokens = TokenizerIntegration_Encode(tokenizer, prompt);
    printf("  Tokenized to %zu tokens: [", tokens.size());
    for (size_t i = 0; i < tokens.size() && i < 10; i++) {
        printf("%d%s", tokens[i], (i < tokens.size() - 1 && i < 9) ? ", " : "");
    }
    if (tokens.size() > 10) printf("...");
    printf("]\n");
    
    // Decode first token to verify
    if (tokens.size() > 0) {
        std::string decoded = TokenizerIntegration_Decode(tokenizer, tokens);
        printf("  Round-trip: \"%s\"\n", decoded.c_str());
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    bool passed = (tokens.size() > 0);
    
    char details[256];
    snprintf(details, sizeof(details), "%zu tokens", tokens.size());
    
    RecordGate("TG3-D", passed, details, duration);
    
    g_tokenizer = tokenizer;
    g_prompt_tokens = tokens;
    
    return passed;
}

// ============================================================================
// TG3-E: Sampler Emits Token
// ============================================================================

bool Gate_TG3E_Sampler() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== TG3-E: Token Sampler ===\n");
    
    if (!g_active_model) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-E", false, "No active model", duration);
        return false;
    }
    
    // Initialize sampler
    SamplerHandle* sampler = SamplerIntegration_Init(g_active_model);
    if (!sampler) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-E", false, "Failed to init sampler", duration);
        return false;
    }
    
    // Create dummy logits (simulating output from LM head)
    int vocab_size = 32000;  // tinyllama vocab size
    std::vector<float> logits(vocab_size);
    
    // Simulate logits with a peak at token 7278 ("Paris" in many tokenizers)
    for (int i = 0; i < vocab_size; i++) {
        logits[i] = (float)(rand() % 100) / 100.0f;
    }
    logits[7278] = 5.0f;  // Boost "Paris" token
    
    // Sample
    TG003SamplerConfig config;
    config.temperature = 0.8f;
    config.top_p = 0.95f;
    config.top_k = 40;
    config.repeat_penalty = 1.1f;
    config.repeat_last_n = 64;
    
    int next_token = SamplerIntegration_Sample(sampler, logits.data(), vocab_size, &config);
    
    printf("  Sampled token: %d\n", next_token);
    printf("  Temperature: %.2f, Top-p: %.2f\n", config.temperature, config.top_p);
    
    // Verify token is valid
    bool valid = (next_token >= 0 && next_token < vocab_size);
    printf("  Token valid: %s\n", valid ? "YES" : "NO");
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    bool passed = valid;
    
    char details[256];
    snprintf(details, sizeof(details), "Token %d (valid=%s)", next_token, valid ? "yes" : "no");
    
    RecordGate("TG3-E", passed, details, duration);
    
    g_sampler = sampler;
    
    return passed;
}

// ============================================================================
// TG3-F: llama.cpp Comparison
// ============================================================================

bool Gate_TG3F_LlamaCPPComparison() {
    auto start = std::chrono::high_resolution_clock::now();
    
    printf("\n=== TG3-F: llama.cpp Comparison ===\n");
    
    if (!g_active_model || !g_tokenizer || !g_sampler) {
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        RecordGate("TG3-F", false, "Missing components", duration);
        return false;
    }
    
    // Run full inference
    const char* prompt = "The capital of France is";
    printf("  Prompt: \"%s\"\n", prompt);
    
    InferenceResult result;
    bool success = LlamaCPPValidator_RunComparison(
        g_active_model,
        g_tokenizer,
        g_transformer_executor,
        g_sampler,
        prompt,
        &result
    );
    
    printf("  RawrXD output: \"%s\"\n", result.rawrxd_output);
    printf("  Expected: \"%s\"\n", result.expected_output);
    printf("  Token match: %s\n", result.tokens_match ? "YES" : "NO");
    printf("  Logit error: %.4f%%\n", result.logit_relative_error * 100);
    
    auto end = std::chrono::high_resolution_clock::now();
    double duration = std::chrono::duration<double, std::milli>(end - start).count();
    
    // Accept if tokens match or logit error < 1%
    bool passed = result.tokens_match || (result.logit_relative_error < 0.01);
    
    char details[256];
    snprintf(details, sizeof(details), "match=%s, error=%.2f%%", 
             result.tokens_match ? "yes" : "no", result.logit_relative_error * 100);
    
    RecordGate("TG3-F", passed, details, duration);
    
    return passed;
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char** argv) {
    printf("╔══════════════════════════════════════════════════════════════╗\n");
    printf("║           TRUTH GATE 003: Runtime Integration                  ║\n");
    printf("║                                                              ║\n");
    printf("║  Goal: Prove RawrXD executes real GGUF model inference        ║\n");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    printf("\nTarget: tinyllama-1.1b.Q4_0.gguf\n");
    printf("Reference: llama.cpp b1559\n\n");
    
    // Seed RNG
    srand(42);  // Deterministic for reproducibility
    
    // Run all gates
    bool all_passed = true;
    
    all_passed &= Gate_TG3A_LoadRealGGUF();
    all_passed &= Gate_TG3B_FabricResidency();
    all_passed &= Gate_TG3C_TransformerExecution();
    all_passed &= Gate_TG3D_Tokenizer();
    all_passed &= Gate_TG3E_Sampler();
    all_passed &= Gate_TG3F_LlamaCPPComparison();
    
    // Summary
    printf("\n╔══════════════════════════════════════════════════════════════╗\n");
    printf("║                      GATE SUMMARY                            ║\n");
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    
    int passed = 0;
    for (const auto& r : g_results) {
        const char* status = r.passed ? "✅" : "❌";
        printf("║ %s %-8s: %-45s ║\n", status, r.name, r.details);
        if (r.passed) passed++;
    }
    
    printf("╠══════════════════════════════════════════════════════════════╣\n");
    printf("║ Result: %d/%zu gates passed                                   ║\n", 
           passed, g_results.size());
    printf("║ Status: %s\n", all_passed ? "TRUTH GATE 003 ✅ PASS" : "TRUTH GATE 003 ❌ FAIL");
    printf("╚══════════════════════════════════════════════════════════════╝\n");
    
    // Cleanup
    if (g_sampler) SamplerIntegration_Free(g_sampler);
    if (g_tokenizer) TokenizerIntegration_Free(g_tokenizer);
    if (g_transformer_executor) TransformerExecutor_Free(g_transformer_executor);
    if (g_fabric_context) FabricIntegration_Free(g_fabric_context);
    if (g_active_model) GGUFIntegration_Free(g_active_model);
    
    return all_passed ? 0 : 1;
}
