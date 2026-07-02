// =============================================================================
// test_phase22_engine.cpp
// Phase 22: Inference Engine Integration - Test Suite
// Validates end-to-end inference pipeline
// =============================================================================

#include "../core/sovereign_engine_controller.h"
#include <stdio.h>
#include <stdlib.h>
#include <windows.h>
#include <string.h>

// =============================================================================
// Test Results
// =============================================================================

struct TestResult {
    const char* name;
    int passed;
    double duration_ms;
    char message[256];
};

static TestResult g_results[20];
static int g_num_results = 0;

void record_result(const char* name, int passed, double duration, const char* msg) {
    if (g_num_results < 20) {
        g_results[g_num_results].name = name;
        g_results[g_num_results].passed = passed;
        g_results[g_num_results].duration_ms = duration;
        strncpy(g_results[g_num_results].message, msg, 255);
        g_results[g_num_results].message[255] = '\0';
        g_num_results++;
    }
}

// =============================================================================
// Timing Utilities
// =============================================================================

double get_time_ms() {
    LARGE_INTEGER freq, now;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&now);
    return (double)now.QuadPart * 1000.0 / freq.QuadPart;
}

// =============================================================================
// Test 1: Engine Creation
// =============================================================================

void test_engine_creation() {
    printf("\n[Test 1] Engine Creation\n");
    
    double start = get_time_ms();
    
    SovereignLoaderConfig loader_config = {};
    loader_config.use_memory_mapping = 1;
    loader_config.use_zero_copy = 1;
    loader_config.use_prefetch = 1;
    loader_config.enable_amx_tiling = 1;
    loader_config.num_threads = 4;
    
    SovereignInferenceConfig inference_config = {};
    inference_config.max_tokens = 100;
    inference_config.temperature = 0.8f;
    inference_config.top_p = 0.9f;
    inference_config.top_k = 40;
    inference_config.num_threads = 4;
    inference_config.use_amx = 1;
    inference_config.use_int8 = 1;
    inference_config.enable_kv_cache = 1;
    
    SovereignEngineHandle engine = Sovereign_Engine_Create(
        &loader_config, &inference_config);
    
    double duration = get_time_ms() - start;
    
    int passed = (engine != nullptr) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Engine created: %s, Threads: %d, AMX: %d",
        engine ? "Yes" : "No", inference_config.num_threads,
        inference_config.use_amx);
    
    record_result("Engine_Creation", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
    
    if (engine) {
        Sovereign_Engine_Destroy(engine);
    }
}

// =============================================================================
// Test 2: Session Management
// =============================================================================

void test_session_management() {
    printf("\n[Test 2] Session Management\n");
    
    double start = get_time_ms();
    
    SovereignLoaderConfig loader_config = {};
    SovereignInferenceConfig inference_config = {};
    inference_config.num_threads = 4;
    
    SovereignEngineHandle engine = Sovereign_Engine_Create(
        &loader_config, &inference_config);
    
    int session_created = 0;
    int session_destroyed = 0;
    
    if (engine) {
        SovereignSessionHandle session = Sovereign_Session_Create(engine, 1);
        session_created = (session != nullptr) ? 1 : 0;
        
        if (session) {
            Sovereign_Session_Destroy(session);
            session_destroyed = 1;
        }
        
        Sovereign_Engine_Destroy(engine);
    }
    
    double duration = get_time_ms() - start;
    
    int passed = (session_created && session_destroyed) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Created: %s, Destroyed: %s",
        session_created ? "Yes" : "No",
        session_destroyed ? "Yes" : "No");
    
    record_result("Session_Management", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 3: Tokenization
// =============================================================================

void test_tokenization() {
    printf("\n[Test 3] Tokenization\n");
    
    double start = get_time_ms();
    
    SovereignLoaderConfig loader_config = {};
    SovereignInferenceConfig inference_config = {};
    
    SovereignEngineHandle engine = Sovereign_Engine_Create(
        &loader_config, &inference_config);
    
    int tokenize_ok = 0;
    int detokenize_ok = 0;
    
    if (engine) {
        const char* text = "Hello world";
        SovereignToken tokens[256];
        uint32_t num_tokens = 0;
        
        if (Sovereign_Tokenize(engine, text, tokens, &num_tokens, 256) == 0) {
            tokenize_ok = (num_tokens > 0) ? 1 : 0;
            
            char output[256];
            if (Sovereign_Detokenize(engine, tokens, num_tokens, output, 256) == 0) {
                detokenize_ok = (strlen(output) > 0) ? 1 : 0;
            }
        }
        
        Sovereign_Engine_Destroy(engine);
    }
    
    double duration = get_time_ms() - start;
    
    int passed = (tokenize_ok && detokenize_ok) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Tokenize: %s, Detokenize: %s",
        tokenize_ok ? "OK" : "FAIL",
        detokenize_ok ? "OK" : "FAIL");
    
    record_result("Tokenization", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 4: Sampling Methods
// =============================================================================

void test_sampling() {
    printf("\n[Test 4] Sampling Methods\n");
    
    double start = get_time_ms();
    
    // Create dummy logits
    float logits[100];
    for (int i = 0; i < 100; i++) {
        logits[i] = (float)(rand() % 100) / 10.0f;
    }
    
    SovereignToken greedy = Sovereign_Sample_Greedy(logits, 100);
    SovereignToken temp = Sovereign_Sample_Temperature(logits, 100, 0.8f);
    SovereignToken top_p = Sovereign_Sample_TopP(logits, 100, 0.9f, 0.8f);
    SovereignToken top_k = Sovereign_Sample_TopK(logits, 100, 40, 0.8f);
    
    double duration = get_time_ms() - start;
    
    int passed = (greedy < 100 && temp < 100 && top_p < 100 && top_k < 100) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Greedy: %u, Temp: %u, TopP: %u, TopK: %u",
        greedy, temp, top_p, top_k);
    
    record_result("Sampling", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 5: Kernel Dispatch
// =============================================================================

void test_kernel_dispatch() {
    printf("\n[Test 5] Kernel Dispatch\n");
    
    double start = get_time_ms();
    
    const SovereignKernelDispatch* dispatch = Sovereign_GetKernelDispatch();
    
    int has_attention_qk = (dispatch && dispatch->attention_qk) ? 1 : 0;
    int has_attention_softmax = (dispatch && dispatch->attention_softmax) ? 1 : 0;
    int has_ffn_silu = (dispatch && dispatch->ffn_silu) ? 1 : 0;
    int has_rms_norm = (dispatch && dispatch->rms_norm) ? 1 : 0;
    
    double duration = get_time_ms() - start;
    
    int passed = (has_attention_qk && has_attention_softmax && 
                  has_ffn_silu && has_rms_norm) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "QK: %s, Softmax: %s, SiLU: %s, RMS: %s",
        has_attention_qk ? "Yes" : "No",
        has_attention_softmax ? "Yes" : "No",
        has_ffn_silu ? "Yes" : "No",
        has_rms_norm ? "Yes" : "No");
    
    record_result("Kernel_Dispatch", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 6: Engine Validation
// =============================================================================

void test_engine_validation() {
    printf("\n[Test 6] Engine Validation\n");
    
    double start = get_time_ms();
    
    SovereignLoaderConfig loader_config = {};
    SovereignInferenceConfig inference_config = {};
    
    SovereignEngineHandle engine = Sovereign_Engine_Create(
        &loader_config, &inference_config);
    
    int validation_result = -1;
    if (engine) {
        validation_result = Sovereign_Engine_Validate(engine);
        Sovereign_Engine_Destroy(engine);
    }
    
    double duration = get_time_ms() - start;
    
    // Validation should fail because no model is loaded (expected)
    int passed = (validation_result == -1) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Validation result: %d (expected: -1 for uninitialized)",
        validation_result);
    
    record_result("Engine_Validation", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Test 7: End-to-End Inference (Mock)
// =============================================================================

void test_end_to_end() {
    printf("\n[Test 7] End-to-End Inference\n");
    
    double start = get_time_ms();
    
    SovereignLoaderConfig loader_config = {};
    SovereignInferenceConfig inference_config = {};
    inference_config.max_tokens = 10;
    inference_config.temperature = 0.8f;
    inference_config.num_threads = 4;
    
    SovereignEngineHandle engine = Sovereign_Engine_Create(
        &loader_config, &inference_config);
    
    int session_ok = 0;
    int prompt_ok = 0;
    int generation_ok = 0;
    
    if (engine) {
        SovereignSessionHandle session = Sovereign_Session_Create(engine, 1);
        if (session) {
            session_ok = 1;
            
            // Tokenize prompt
            const char* prompt = "Hello";
            SovereignToken tokens[256];
            uint32_t num_tokens = 0;
            if (Sovereign_Tokenize(engine, prompt, tokens, &num_tokens, 256) == 0) {
                
                // Process prompt
                if (Sovereign_Session_ProcessPrompt(session, tokens, num_tokens) == 0) {
                    prompt_ok = 1;
                    
                    // Generate a token
                    SovereignGenerationResult result;
                    if (Sovereign_Session_GenerateToken(session, &result) == 0) {
                        generation_ok = 1;
                    }
                }
            }
            
            Sovereign_Session_Destroy(session);
        }
        
        Sovereign_Engine_Destroy(engine);
    }
    
    double duration = get_time_ms() - start;
    
    int passed = (session_ok && prompt_ok && generation_ok) ? 1 : 0;
    
    char msg[256];
    snprintf(msg, sizeof(msg), 
        "Session: %s, Prompt: %s, Generation: %s",
        session_ok ? "OK" : "FAIL",
        prompt_ok ? "OK" : "FAIL",
        generation_ok ? "OK" : "FAIL");
    
    record_result("End_to_End", passed, duration, msg);
    
    printf("  %s\n", passed ? "PASS" : "FAIL");
    printf("  %s\n", msg);
}

// =============================================================================
// Main Test Runner
// =============================================================================

int main() {
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Phase 22: Inference Engine Integration Test Suite         ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // Run all tests
    test_engine_creation();
    test_session_management();
    test_tokenization();
    test_sampling();
    test_kernel_dispatch();
    test_engine_validation();
    test_end_to_end();
    
    // Print summary
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  Test Summary                                                    ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    int total_passed = 0;
    int total_failed = 0;
    double total_duration = 0;
    
    for (int i = 0; i < g_num_results; i++) {
        const char* status = g_results[i].passed ? "PASS" : "FAIL";
        printf("\n[%s] %-30s %.1fms\n", status, g_results[i].name, g_results[i].duration_ms);
        printf("      %s\n", g_results[i].message);
        
        if (g_results[i].passed) total_passed++;
        else total_failed++;
        total_duration += g_results[i].duration_ms;
    }
    
    printf("\n────────────────────────────────────────────────────────────────\n");
    printf("Total: %d tests, %d passed, %d failed\n", g_num_results, total_passed, total_failed);
    printf("Duration: %.1f ms\n", total_duration);
    printf("────────────────────────────────────────────────────────────────\n");
    
    if (total_failed == 0) {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  ALL TESTS PASSED - Phase 22 Ready for Production            ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        return 0;
    } else {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  SOME TESTS FAILED - Review output above                       ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        return 1;
    }
}
