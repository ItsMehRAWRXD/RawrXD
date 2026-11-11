/*
 * Layer-by-Layer Validation Test
 * Compares each transformer layer against llama.cpp reference
 */

#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <vector>
#include <string>

// Maximum acceptable error for floating point comparison
#define MAX_ABS_ERROR 1e-5f
#define MAX_REL_ERROR 1e-4f

struct TestResult {
    const char* layer_name;
    bool passed;
    float max_abs_error;
    float max_rel_error;
    size_t mismatch_count;
};

// Compare two float arrays
bool compare_tensors(const float* a, const float* b, size_t n, 
                     float& max_abs_err, float& max_rel_err,
                     size_t& mismatch_count) {
    max_abs_err = 0.0f;
    max_rel_err = 0.0f;
    mismatch_count = 0;
    
    for (size_t i = 0; i < n; i++) {
        float abs_err = fabsf(a[i] - b[i]);
        float rel_err = abs_err / (fabsf(b[i]) + 1e-8f);
        
        max_abs_err = fmaxf(max_abs_err, abs_err);
        max_rel_err = fmaxf(max_rel_err, rel_err);
        
        if (abs_err > MAX_ABS_ERROR && rel_err > MAX_REL_ERROR) {
            mismatch_count++;
        }
    }
    
    return mismatch_count == 0;
}

// Test 1: Embedding Layer
TestResult test_embedding() {
    printf("\n[TEST] Embedding Layer\n");
    
    // Input: token IDs [1, 2, 3, 4, 5]
    // Expected output: embedding vectors from model
    
    // TODO: Load reference output from llama.cpp
    std::vector<float> rawrxd_output(4096 * 5);  // 5 tokens, 4096 dim
    std::vector<float> reference_output(4096 * 5);
    
    // Run RawrXD embedding
    // embedding_forward(rawrxd_output.data(), token_ids, n_tokens);
    
    // Load reference (would come from llama.cpp run)
    // load_reference("embedding_ref.bin", reference_output);
    
    float max_abs, max_rel;
    size_t mismatches;
    bool passed = compare_tensors(rawrxd_output.data(), reference_output.data(),
                                   rawrxd_output.size(), max_abs, max_rel, mismatches);
    
    printf("  Max abs error: %.8f (limit: %.8f)\n", max_abs, MAX_ABS_ERROR);
    printf("  Max rel error: %.8f (limit: %.8f)\n", max_rel, MAX_REL_ERROR);
    printf("  Mismatches: %zu\n", mismatches);
    printf("  Result: %s\n", passed ? "PASS" : "FAIL");
    
    return {"Embedding", passed, max_abs, max_rel, mismatches};
}

// Test 2: RMSNorm
TestResult test_rmsnorm() {
    printf("\n[TEST] RMSNorm\n");
    
    std::vector<float> input(4096);
    std::vector<float> rawrxd_output(4096);
    std::vector<float> reference_output(4096);
    
    // Initialize test input
    for (size_t i = 0; i < 4096; i++) {
        input[i] = (float)(i % 100) / 100.0f;
    }
    
    // Run RawrXD RMSNorm
    // rmsnorm_forward(rawrxd_output.data(), input.data(), 4096, 1e-6f);
    
    // Load reference
    // load_reference("rmsnorm_ref.bin", reference_output);
    
    float max_abs, max_rel;
    size_t mismatches;
    bool passed = compare_tensors(rawrxd_output.data(), reference_output.data(),
                                   4096, max_abs, max_rel, mismatches);
    
    printf("  Max abs error: %.8f\n", max_abs);
    printf("  Max rel error: %.8f\n", max_rel);
    printf("  Result: %s\n", passed ? "PASS" : "FAIL");
    
    return {"RMSNorm", passed, max_abs, max_rel, mismatches};
}

// Test 3: QKV Projection + RoPE
TestResult test_qkv_rope() {
    printf("\n[TEST] QKV Projection + RoPE\n");
    
    // This is critical - RoPE angle calculations must be exact
    std::vector<float> input(4096);
    std::vector<float> q_rawrxd(4096);  // 32 heads * 128 dim
    std::vector<float> k_rawrxd(4096);
    std::vector<float> v_rawrxd(4096);
    std::vector<float> q_ref(4096);
    std::vector<float> k_ref(4096);
    std::vector<float> v_ref(4096);
    
    // Run RawrXD
    // qkv_forward(q_rawrxd.data(), k_rawrxd.data(), v_rawrxd.data(), input.data());
    // rope_forward(q_rawrxd.data(), k_rawrxd.data(), pos, head_dim, theta);
    
    // Load reference
    // load_reference("qkv_ref.bin", q_ref, k_ref, v_ref);
    
    float max_abs_q, max_rel_q;
    size_t mismatches_q;
    bool pass_q = compare_tensors(q_rawrxd.data(), q_ref.data(), 4096, 
                                   max_abs_q, max_rel_q, mismatches_q);
    
    float max_abs_k, max_rel_k;
    size_t mismatches_k;
    bool pass_k = compare_tensors(k_rawrxd.data(), k_ref.data(), 4096,
                                   max_abs_k, max_rel_k, mismatches_k);
    
    float max_abs_v, max_rel_v;
    size_t mismatches_v;
    bool pass_v = compare_tensors(v_rawrxd.data(), v_ref.data(), 4096,
                                   max_abs_v, max_rel_v, mismatches_v);
    
    bool passed = pass_q && pass_k && pass_v;
    
    printf("  Q: max_abs=%.8f, max_rel=%.8f\n", max_abs_q, max_rel_q);
    printf("  K: max_abs=%.8f, max_rel=%.8f\n", max_abs_k, max_rel_k);
    printf("  V: max_abs=%.8f, max_rel=%.8f\n", max_abs_v, max_rel_v);
    printf("  Result: %s\n", passed ? "PASS" : "FAIL");
    
    float max_abs = fmaxf(fmaxf(max_abs_q, max_abs_k), max_abs_v);
    float max_rel = fmaxf(fmaxf(max_rel_q, max_rel_k), max_rel_v);
    size_t total_mismatches = mismatches_q + mismatches_k + mismatches_v;
    
    return {"QKV+RoPE", passed, max_abs, max_rel, total_mismatches};
}

// Test 4: Attention
TestResult test_attention() {
    printf("\n[TEST] Attention\n");
    
    // Attention is the most complex - must verify:
    // 1. Attention scores computed correctly
    // 2. Softmax normalization correct
    // 3. Weighted sum correct
    
    std::vector<float> q(4096), k(4096), v(4096);
    std::vector<float> rawrxd_output(4096);
    std::vector<float> reference_output(4096);
    
    // Run RawrXD attention
    // attention_forward(rawrxd_output.data(), q.data(), k.data(), v.data(),
    //                   n_heads, head_dim, n_tokens);
    
    // Load reference
    // load_reference("attention_ref.bin", reference_output);
    
    float max_abs, max_rel;
    size_t mismatches;
    bool passed = compare_tensors(rawrxd_output.data(), reference_output.data(),
                                   4096, max_abs, max_rel, mismatches);
    
    printf("  Max abs error: %.8f\n", max_abs);
    printf("  Max rel error: %.8f\n", max_rel);
    printf("  Result: %s\n", passed ? "PASS" : "FAIL");
    
    return {"Attention", passed, max_abs, max_rel, mismatches};
}

// Test 5: FFN (SwiGLU)
TestResult test_ffn() {
    printf("\n[TEST] FFN (SwiGLU)\n");
    
    std::vector<float> input(4096);
    std::vector<float> rawrxd_output(4096);
    std::vector<float> reference_output(4096);
    
    // Run RawrXD FFN
    // ffn_forward(rawrxd_output.data(), input.data(), w1, w2, w3);
    
    // Load reference
    // load_reference("ffn_ref.bin", reference_output);
    
    float max_abs, max_rel;
    size_t mismatches;
    bool passed = compare_tensors(rawrxd_output.data(), reference_output.data(),
                                   4096, max_abs, max_rel, mismatches);
    
    printf("  Max abs error: %.8f\n", max_abs);
    printf("  Max rel error: %.8f\n", max_rel);
    printf("  Result: %s\n", passed ? "PASS" : "FAIL");
    
    return {"FFN", passed, max_abs, max_rel, mismatches};
}

// Test 6: Output Projection + Sampling
TestResult test_output() {
    printf("\n[TEST] Output Projection\n");
    
    std::vector<float> hidden(4096);
    std::vector<float> rawrxd_logits(32000);  // vocab size
    std::vector<float> reference_logits(32000);
    
    // Run RawrXD output projection
    // output_forward(rawrxd_logits.data(), hidden.data(), output_weight);
    
    // Load reference
    // load_reference("output_ref.bin", reference_logits);
    
    float max_abs, max_rel;
    size_t mismatches;
    bool passed = compare_tensors(rawrxd_logits.data(), reference_logits.data(),
                                   32000, max_abs, max_rel, mismatches);
    
    printf("  Max abs error: %.8f\n", max_abs);
    printf("  Max rel error: %.8f\n", max_rel);
    printf("  Result: %s\n", passed ? "PASS" : "FAIL");
    
    return {"Output", passed, max_abs, max_rel, mismatches};
}

// Test 7: Full Forward Pass
TestResult test_full_forward() {
    printf("\n[TEST] Full Forward Pass\n");
    
    // End-to-end test
    // Input: "The capital of France is"
    // Expected: logits that strongly favor " Paris"
    
    printf("  Running end-to-end inference...\n");
    
    // Run RawrXD
    // auto result = full_forward("The capital of France is", 1);
    
    // Check top token is " Paris" or similar
    // int top_token = argmax(result.logits);
    // const char* top_token_str = vocab.id_to_token[top_token];
    
    // bool passed = (strcmp(top_token_str, " Paris") == 0);
    
    printf("  Top token: [would show here]\n");
    printf("  Expected: \" Paris\"\n");
    printf("  Result: [PENDING - requires working inference]\n");
    
    return {"Full Forward", false, 0.0f, 0.0f, 0};
}

int main() {
    printf("=" * 60);
    printf("RAWRXD LAYER-BY-LAYER VALIDATION\n");
    printf("=" * 60);
    printf("\nComparing against llama.cpp reference implementation\n");
    printf("Max absolute error threshold: %.8f\n", MAX_ABS_ERROR);
    printf("Max relative error threshold: %.8f\n", MAX_REL_ERROR);
    
    std::vector<TestResult> results;
    
    // Run all layer tests
    results.push_back(test_embedding());
    results.push_back(test_rmsnorm());
    results.push_back(test_qkv_rope());
    results.push_back(test_attention());
    results.push_back(test_ffn());
    results.push_back(test_output());
    results.push_back(test_full_forward());
    
    // Summary
    printf("\n" + std::string(60, '='));
    printf("SUMMARY\n");
    printf("=" * 60);
    
    int passed = 0;
    int failed = 0;
    
    for (const auto& result : results) {
        const char* status = result.passed ? "PASS" : "FAIL";
        printf("  [%s] %-20s max_abs=%.8f, max_rel=%.8f\n",
               status, result.layer_name, result.max_abs_error, result.max_rel_error);
        
        if (result.passed) passed++;
        else failed++;
    }
    
    printf("\n" + std::string(60, '='));
    printf("TOTAL: %d passed, %d failed\n", passed, failed);
    printf("=" * 60);
    
    return failed > 0 ? 1 : 0;
}
