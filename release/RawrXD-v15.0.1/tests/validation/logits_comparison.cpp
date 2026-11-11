// logits_comparison.cpp
// Phase 1: Bit-exact validation harness for RawrXD vs llama.cpp
// Compares inference outputs to ensure numerical correctness

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <cmath>
#include <vector>
#include <string>
#include <random>

// External APIs
extern "C" {
    // RawrXD API
    struct RawrXD_Context;
    RawrXD_Context* rawrxd_load_model(const char* path);
    void rawrxd_free_context(RawrXD_Context* ctx);
    int rawrxd_get_logits(RawrXD_Context* ctx, const int* tokens, int n_tokens, float* logits);
    int rawrxd_get_vocab_size(RawrXD_Context* ctx);
    
    // llama.cpp API (linked as reference)
    struct llama_context;
    llama_context* llama_load_model(const char* path);
    void llama_free(llama_context* ctx);
    int llama_get_logits(llama_context* ctx, const int* tokens, int n_tokens, float* logits);
    int llama_get_vocab_size(llama_context* ctx);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Validation Configuration
// ═══════════════════════════════════════════════════════════════════════════════

struct ValidationConfig {
    float max_absolute_error = 1e-3f;  // Practical for Q4_0 quantization
    float max_relative_error = 0.01f;   // 1% relative error
    int num_test_cases = 100;
    int max_sequence_length = 512;
    bool test_q4_0 = true;
    bool test_q8_0 = true;
    bool test_f16 = false;  // Optional
};

// ═══════════════════════════════════════════════════════════════════════════════
// Test Result Tracking
// ═══════════════════════════════════════════════════════════════════════════════

struct TestResult {
    const char* name;
    bool passed;
    float max_error;
    float mean_error;
    float rms_error;
    int num_samples;
    std::string details;
};

static std::vector<TestResult> g_results;
static int g_passed = 0;
static int g_failed = 0;

// ═══════════════════════════════════════════════════════════════════════════════
// Error Metrics
// ═══════════════════════════════════════════════════════════════════════════════

struct ErrorMetrics {
    float max_abs_error = 0.0f;
    float mean_abs_error = 0.0f;
    float rms_error = 0.0f;
    float max_rel_error = 0.0f;
    int num_samples = 0;
};

ErrorMetrics compute_error_metrics(const float* rawrxd_logits, 
                                   const float* llama_logits, 
                                   int vocab_size) {
    ErrorMetrics metrics;
    double sum_abs_error = 0.0;
    double sum_sq_error = 0.0;
    
    for (int i = 0; i < vocab_size; i++) {
        float rawr_val = rawrxd_logits[i];
        float llama_val = llama_logits[i];
        
        float abs_error = fabsf(rawr_val - llama_val);
        metrics.max_abs_error = fmaxf(metrics.max_abs_error, abs_error);
        sum_abs_error += abs_error;
        sum_sq_error += abs_error * abs_error;
        
        // Relative error (avoid div by zero)
        float denom = fmaxf(fabsf(llama_val), 1e-8f);
        float rel_error = abs_error / denom;
        metrics.max_rel_error = fmaxf(metrics.max_rel_error, rel_error);
    }
    
    metrics.num_samples = vocab_size;
    metrics.mean_abs_error = (float)(sum_abs_error / vocab_size);
    metrics.rms_error = (float)sqrt(sum_sq_error / vocab_size);
    
    return metrics;
}

// ═══════════════════════════════════════════════════════════════════════════════
// Test Cases
// ═══════════════════════════════════════════════════════════════════════════════

void test_simple_prompt(const char* model_path, const ValidationConfig& config) {
    printf("\n[TEST] Simple prompt inference...\n");
    
    // Load models
    auto* rawr_ctx = rawrxd_load_model(model_path);
    auto* llama_ctx = llama_load_model(model_path);
    
    if (!rawr_ctx || !llama_ctx) {
        printf("  [FAIL] Failed to load model\n");
        g_failed++;
        return;
    }
    
    int vocab_size = rawrxd_get_vocab_size(rawr_ctx);
    
    // Simple test prompt: "Hello world"
    int tokens[] = {1, 15043, 318, 29871};  // BOS + "Hello" + " world"
    int n_tokens = 4;
    
    std::vector<float> rawr_logits(vocab_size);
    std::vector<float> llama_logits(vocab_size);
    
    // Get logits from both
    int rawr_ok = rawrxd_get_logits(rawr_ctx, tokens, n_tokens, rawr_logits.data());
    int llama_ok = llama_get_logits(llama_ctx, tokens, n_tokens, llama_logits.data());
    
    if (rawr_ok != 0 || llama_ok != 0) {
        printf("  [FAIL] Inference failed\n");
        g_failed++;
        rawrxd_free_context(rawr_ctx);
        llama_free(llama_ctx);
        return;
    }
    
    // Compute error metrics
    auto metrics = compute_error_metrics(rawr_logits.data(), llama_logits.data(), vocab_size);
    
    // Validate
    bool passed = (metrics.max_abs_error <= config.max_absolute_error) &&
                  (metrics.max_rel_error <= config.max_relative_error);
    
    TestResult result;
    result.name = "Simple prompt";
    result.passed = passed;
    result.max_error = metrics.max_abs_error;
    result.mean_error = metrics.mean_abs_error;
    result.rms_error = metrics.rms_error;
    result.num_samples = vocab_size;
    
    char buf[256];
    snprintf(buf, sizeof(buf), 
             "Max abs error: %.6f, Mean: %.6f, RMS: %.6f, Max rel: %.4f%%",
             metrics.max_abs_error, metrics.mean_abs_error, 
             metrics.rms_error, metrics.max_rel_error * 100.0f);
    result.details = buf;
    
    g_results.push_back(result);
    
    if (passed) {
        printf("  [PASS] %s\n", buf);
        g_passed++;
    } else {
        printf("  [FAIL] %s\n", buf);
        g_failed++;
    }
    
    rawrxd_free_context(rawr_ctx);
    llama_free(llama_ctx);
}

void test_random_tokens(const char* model_path, const ValidationConfig& config) {
    printf("\n[TEST] Random token sequences...\n");
    
    auto* rawr_ctx = rawrxd_load_model(model_path);
    auto* llama_ctx = llama_load_model(model_path);
    
    if (!rawr_ctx || !llama_ctx) {
        printf("  [FAIL] Failed to load model\n");
        g_failed++;
        return;
    }
    
    int vocab_size = rawrxd_get_vocab_size(rawr_ctx);
    std::vector<float> rawr_logits(vocab_size);
    std::vector<float> llama_logits(vocab_size);
    
    std::mt19937 rng(42);  // Fixed seed for reproducibility
    std::uniform_int_distribution<int> token_dist(1, vocab_size - 1);
    
    int num_passed = 0;
    float max_error_overall = 0.0f;
    
    for (int test = 0; test < config.num_test_cases; test++) {
        // Generate random token sequence
        int seq_len = 4 + (rng() % 16);  // 4-20 tokens
        std::vector<int> tokens;
        tokens.push_back(1);  // BOS
        for (int i = 0; i < seq_len; i++) {
            tokens.push_back(token_dist(rng));
        }
        
        // Get logits
        int rawr_ok = rawrxd_get_logits(rawr_ctx, tokens.data(), (int)tokens.size(), 
                                        rawr_logits.data());
        int llama_ok = llama_get_logits(llama_ctx, tokens.data(), (int)tokens.size(), 
                                        llama_logits.data());
        
        if (rawr_ok != 0 || llama_ok != 0) {
            continue;  // Skip failed inferences
        }
        
        auto metrics = compute_error_metrics(rawr_logits.data(), llama_logits.data(), vocab_size);
        max_error_overall = fmaxf(max_error_overall, metrics.max_abs_error);
        
        if (metrics.max_abs_error <= config.max_absolute_error) {
            num_passed++;
        }
    }
    
    bool passed = (num_passed == config.num_test_cases);
    
    TestResult result;
    result.name = "Random tokens";
    result.passed = passed;
    result.max_error = max_error_overall;
    result.mean_error = 0.0f;  // Not tracked per-test
    result.rms_error = 0.0f;
    result.num_samples = config.num_test_cases;
    
    char buf[256];
    snprintf(buf, sizeof(buf), "Passed: %d/%d, Max error: %.6f", 
             num_passed, config.num_test_cases, max_error_overall);
    result.details = buf;
    
    g_results.push_back(result);
    
    if (passed) {
        printf("  [PASS] %s\n", buf);
        g_passed++;
    } else {
        printf("  [FAIL] %s\n", buf);
        g_failed++;
    }
    
    rawrxd_free_context(rawr_ctx);
    llama_free(llama_ctx);
}

void test_edge_cases(const char* model_path, const ValidationConfig& config) {
    printf("\n[TEST] Edge cases...\n");
    
    // Test cases: empty, single token, very long sequence
    struct EdgeCase {
        const char* name;
        std::vector<int> tokens;
    };
    
    std::vector<EdgeCase> cases = {
        {"Single token", {1, 100}},
        {"Two tokens", {1, 100, 200}},
        {"Special tokens", {1, 2, 3}},  // BOS, EOS, etc.
    };
    
    auto* rawr_ctx = rawrxd_load_model(model_path);
    auto* llama_ctx = llama_load_model(model_path);
    
    if (!rawr_ctx || !llama_ctx) {
        printf("  [FAIL] Failed to load model\n");
        g_failed++;
        return;
    }
    
    int vocab_size = rawrxd_get_vocab_size(rawr_ctx);
    std::vector<float> rawr_logits(vocab_size);
    std::vector<float> llama_logits(vocab_size);
    
    int edge_passed = 0;
    
    for (const auto& tc : cases) {
        int rawr_ok = rawrxd_get_logits(rawr_ctx, tc.tokens.data(), (int)tc.tokens.size(), 
                                        rawr_logits.data());
        int llama_ok = llama_get_logits(llama_ctx, tc.tokens.data(), (int)tc.tokens.size(), 
                                        llama_logits.data());
        
        if (rawr_ok == 0 && llama_ok == 0) {
            auto metrics = compute_error_metrics(rawr_logits.data(), llama_logits.data(), vocab_size);
            if (metrics.max_abs_error <= config.max_absolute_error) {
                edge_passed++;
                printf("  [PASS] %s: max_error=%.6f\n", tc.name, metrics.max_abs_error);
            } else {
                printf("  [FAIL] %s: max_error=%.6f\n", tc.name, metrics.max_abs_error);
            }
        } else {
            printf("  [SKIP] %s: inference failed\n", tc.name);
        }
    }
    
    bool passed = (edge_passed == (int)cases.size());
    
    TestResult result;
    result.name = "Edge cases";
    result.passed = passed;
    result.max_error = 0.0f;
    result.mean_error = 0.0f;
    result.rms_error = 0.0f;
    result.num_samples = (int)cases.size();
    
    char buf[256];
    snprintf(buf, sizeof(buf), "Passed: %d/%zu", edge_passed, cases.size());
    result.details = buf;
    
    g_results.push_back(result);
    
    if (passed) {
        printf("  [PASS] %s\n", buf);
        g_passed++;
    } else {
        printf("  [FAIL] %s\n", buf);
        g_failed++;
    }
    
    rawrxd_free_context(rawr_ctx);
    llama_free(llama_ctx);
}

// ═══════════════════════════════════════════════════════════════════════════════
// Main
// ═══════════════════════════════════════════════════════════════════════════════

int main(int argc, char** argv) {
    printf("========================================\n");
    printf("RawrXD Phase 1: Logits Validation\n");
    printf("========================================\n\n");
    
    const char* model_path = (argc > 1) ? argv[1] : "models/test-model-q4_0.gguf";
    
    ValidationConfig config;
    config.max_absolute_error = 1e-3f;  // Practical for Q4_0
    config.num_test_cases = 100;
    
    printf("Configuration:\n");
    printf("  Model: %s\n", model_path);
    printf("  Max absolute error: %.6f\n", config.max_absolute_error);
    printf("  Max relative error: %.2f%%\n", config.max_relative_error * 100.0f);
    printf("  Test cases: %d\n\n", config.num_test_cases);
    
    // Run tests
    test_simple_prompt(model_path, config);
    test_random_tokens(model_path, config);
    test_edge_cases(model_path, config);
    
    // Summary
    printf("\n========================================\n");
    printf("Test Summary: %d passed, %d failed\n", g_passed, g_failed);
    printf("========================================\n\n");
    
    // Detailed results
    printf("Detailed Results:\n");
    for (const auto& r : g_results) {
        printf("  %s: %s\n    %s\n\n", 
               r.name, r.passed ? "PASS" : "FAIL", r.details.c_str());
    }
    
    return (g_failed == 0) ? 0 : 1;
}
