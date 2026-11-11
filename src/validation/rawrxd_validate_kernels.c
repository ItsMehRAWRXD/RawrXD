//=============================================================================
// rawrxd_validate_kernels.c
// Extended Kernel Validation Suite
//=============================================================================

#include "rawrxd_validate.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

//=============================================================================
// Extended Reference Implementations
//=============================================================================

void rawrxd_ref_gelu(f32* x, u32 n) {
    // GELU: x * 0.5 * (1 + tanh(sqrt(2/pi) * (x + 0.044715 * x^3)))
    const f32 sqrt_2_over_pi = 0.7978845608f;
    const f32 coeff = 0.044715f;
    
    for (u32 i = 0; i < n; i++) {
        f32 x_cubed = x[i] * x[i] * x[i];
        f32 inner = sqrt_2_over_pi * (x[i] + coeff * x_cubed);
        x[i] = x[i] * 0.5f * (1.0f + tanhf(inner));
    }
}

void rawrxd_ref_layer_norm(f32* output, const f32* input, u32 size, f32 eps) {
    // Calculate mean
    f32 mean = 0.0f;
    for (u32 i = 0; i < size; i++) {
        mean += input[i];
    }
    mean /= size;
    
    // Calculate variance
    f32 var = 0.0f;
    for (u32 i = 0; i < size; i++) {
        f32 diff = input[i] - mean;
        var += diff * diff;
    }
    var /= size;
    
    // Normalize
    f32 scale = 1.0f / sqrtf(var + eps);
    for (u32 i = 0; i < size; i++) {
        output[i] = (input[i] - mean) * scale;
    }
}

void rawrxd_ref_rope(f32* q, f32* k, u32 n_heads, u32 head_dim, u32 pos) {
    // RoPE: Rotary Position Embedding
    // Apply rotation to pairs of dimensions
    for (u32 h = 0; h < n_heads; h++) {
        for (u32 i = 0; i < head_dim; i += 2) {
            u32 idx = h * head_dim + i;
            
            // Calculate rotation angle
            f32 theta = pos / powf(10000.0f, (f32)i / head_dim);
            f32 cos_theta = cosf(theta);
            f32 sin_theta = sinf(theta);
            
            // Apply rotation to Q
            f32 q0 = q[idx];
            f32 q1 = q[idx + 1];
            q[idx] = q0 * cos_theta - q1 * sin_theta;
            q[idx + 1] = q0 * sin_theta + q1 * cos_theta;
            
            // Apply rotation to K
            f32 k0 = k[idx];
            f32 k1 = k[idx + 1];
            k[idx] = k0 * cos_theta - k1 * sin_theta;
            k[idx + 1] = k0 * sin_theta + k1 * cos_theta;
        }
    }
}

void rawrxd_ref_q4_k_mat_vec(const void* mat, const f32* vec, f32* out, u64 nrows, u64 ncols) {
    // Q4_K: 4-bit quantization with K-quant block structure
    // Simplified reference - actual Q4_K has complex block structure
    const block_q4_K* blocks = (const block_q4_K*)mat;
    u64 nb_per_row = ncols / 256;  // Q4_K uses 256-element blocks
    
    for (u64 row = 0; row < nrows; row++) {
        f32 sum = 0.0f;
        const block_q4_K* row_blocks = blocks + row * nb_per_row;
        
        for (u64 nb = 0; nb < nb_per_row; nb++) {
            // Q4_K has 2 scales (d, dmin) and 8-bit quants
            f32 d = row_blocks[nb].d;
            f32 dmin = row_blocks[nb].dmin;
            
            // Process 256 elements in groups of 32
            for (int g = 0; g < 8; g++) {
                // Simplified - actual implementation would unpack scales and quants
                for (int j = 0; j < 32; j++) {
                    u32 idx = nb * 256 + g * 32 + j;
                    if (idx < ncols) {
                        // Approximate dequantization
                        f32 val = d * 8.0f - dmin;  // Simplified
                        sum += val * vec[idx];
                    }
                }
            }
        }
        out[row] = sum;
    }
}

void rawrxd_ref_q6_k_mat_vec(const void* mat, const f32* vec, f32* out, u64 nrows, u64 ncols) {
    // Q6_K: 6-bit quantization with K-quant block structure
    const block_q6_K* blocks = (const block_q6_K*)mat;
    u64 nb_per_row = ncols / 256;
    
    for (u64 row = 0; row < nrows; row++) {
        f32 sum = 0.0f;
        const block_q6_K* row_blocks = blocks + row * nb_per_row;
        
        for (u64 nb = 0; nb < nb_per_row; nb++) {
            f32 d = row_blocks[nb].d;
            
            // Process 256 elements
            for (int j = 0; j < 256; j++) {
                u32 idx = nb * 256 + j;
                if (idx < ncols) {
                    // Simplified 6-bit dequantization
                    f32 val = d * 32.0f;  // Simplified
                    sum += val * vec[idx];
                }
            }
        }
        out[row] = sum;
    }
}

//=============================================================================
// Extended Kernel Validation Functions
//=============================================================================

rawrxd_kernel_validation* rawrxd_validate_kernel_softmax(u32 size) {
    rawrxd_kernel_validation* val = rawrxd_alloc(sizeof(rawrxd_kernel_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->kernel_name = "Softmax";
    val->num_elements = size;
    
    f32* input = rawrxd_alloc(size * sizeof(f32));
    f32* ref_output = rawrxd_alloc(size * sizeof(f32));
    f32* opt_output = rawrxd_alloc(size * sizeof(f32));
    
    if (!input || !ref_output || !opt_output) {
        strncpy(val->error_msg, "Memory allocation failed", sizeof(val->error_msg));
        val->passed = false;
        goto cleanup;
    }
    
    // Initialize with random data
    rawrxd_rng rng;
    rawrxd_rng_init(&rng, 42);
    for (u32 i = 0; i < size; i++) {
        input[i] = rawrxd_rng_f32(&rng) * 10.0f - 5.0f;  // Range [-5, 5]
        ref_output[i] = input[i];
        opt_output[i] = input[i];
    }
    
    // Run reference
    rawrxd_timer t1 = rawrxd_timer_start();
    rawrxd_ref_softmax(ref_output, size);
    val->reference_time_ms = rawrxd_timer_elapsed_ms(&t1);
    
    // Run optimized
    rawrxd_timer t2 = rawrxd_timer_start();
    rawrxd_softmax(opt_output, size);
    val->optimized_time_ms = rawrxd_timer_elapsed_ms(&t2);
    
    // Compute metrics
    compute_error_metrics(ref_output, opt_output, size,
                          &val->max_abs_error, &val->max_rel_error,
                          &val->mean_abs_error, &val->mean_rel_error,
                          &val->rmse);
    
    val->speedup = val->reference_time_ms / val->optimized_time_ms;
    val->passed = (val->max_abs_error < 1e-4f && val->mean_abs_error < 1e-5f);
    
cleanup:
    rawrxd_free(input, size * sizeof(f32));
    rawrxd_free(ref_output, size * sizeof(f32));
    rawrxd_free(opt_output, size * sizeof(f32));
    
    return val;
}

rawrxd_kernel_validation* rawrxd_validate_kernel_silu(u32 n) {
    rawrxd_kernel_validation* val = rawrxd_alloc(sizeof(rawrxd_kernel_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->kernel_name = "SiLU";
    val->num_elements = n;
    
    f32* input = rawrxd_alloc(n * sizeof(f32));
    f32* ref_output = rawrxd_alloc(n * sizeof(f32));
    f32* opt_output = rawrxd_alloc(n * sizeof(f32));
    
    if (!input || !ref_output || !opt_output) {
        strncpy(val->error_msg, "Memory allocation failed", sizeof(val->error_msg));
        val->passed = false;
        goto cleanup;
    }
    
    // Initialize
    rawrxd_rng rng;
    rawrxd_rng_init(&rng, 42);
    for (u32 i = 0; i < n; i++) {
        input[i] = rawrxd_rng_f32(&rng) * 6.0f - 3.0f;  // Range [-3, 3]
        ref_output[i] = input[i];
        opt_output[i] = input[i];
    }
    
    // Run reference
    rawrxd_timer t1 = rawrxd_timer_start();
    rawrxd_ref_silu(ref_output, n);
    val->reference_time_ms = rawrxd_timer_elapsed_ms(&t1);
    
    // Run optimized
    rawrxd_timer t2 = rawrxd_timer_start();
    rawrxd_silu(opt_output, n);
    val->optimized_time_ms = rawrxd_timer_elapsed_ms(&t2);
    
    // Compute metrics
    compute_error_metrics(ref_output, opt_output, n,
                          &val->max_abs_error, &val->max_rel_error,
                          &val->mean_abs_error, &val->mean_rel_error,
                          &val->rmse);
    
    val->speedup = val->reference_time_ms / val->optimized_time_ms;
    val->passed = (val->max_abs_error < 1e-4f && val->mean_abs_error < 1e-5f);
    
cleanup:
    rawrxd_free(input, n * sizeof(f32));
    rawrxd_free(ref_output, n * sizeof(f32));
    rawrxd_free(opt_output, n * sizeof(f32));
    
    return val;
}

rawrxd_kernel_validation* rawrxd_validate_kernel_gelu(u32 n) {
    rawrxd_kernel_validation* val = rawrxd_alloc(sizeof(rawrxd_kernel_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->kernel_name = "GELU";
    val->num_elements = n;
    
    f32* input = rawrxd_alloc(n * sizeof(f32));
    f32* ref_output = rawrxd_alloc(n * sizeof(f32));
    f32* opt_output = rawrxd_alloc(n * sizeof(f32));
    
    if (!input || !ref_output || !opt_output) {
        strncpy(val->error_msg, "Memory allocation failed", sizeof(val->error_msg));
        val->passed = false;
        goto cleanup;
    }
    
    // Initialize
    rawrxd_rng rng;
    rawrxd_rng_init(&rng, 42);
    for (u32 i = 0; i < n; i++) {
        input[i] = rawrxd_rng_f32(&rng) * 6.0f - 3.0f;
        ref_output[i] = input[i];
        opt_output[i] = input[i];
    }
    
    // Run reference
    rawrxd_timer t1 = rawrxd_timer_start();
    rawrxd_ref_gelu(ref_output, n);
    val->reference_time_ms = rawrxd_timer_elapsed_ms(&t1);
    
    // Run optimized
    rawrxd_timer t2 = rawrxd_timer_start();
    rawrxd_gelu(opt_output, n);
    val->optimized_time_ms = rawrxd_timer_elapsed_ms(&t2);
    
    // Compute metrics
    compute_error_metrics(ref_output, opt_output, n,
                          &val->max_abs_error, &val->max_rel_error,
                          &val->mean_abs_error, &val->mean_rel_error,
                          &val->rmse);
    
    val->speedup = val->reference_time_ms / val->optimized_time_ms;
    val->passed = (val->max_abs_error < 1e-4f && val->mean_abs_error < 1e-5f);
    
cleanup:
    rawrxd_free(input, n * sizeof(f32));
    rawrxd_free(ref_output, n * sizeof(f32));
    rawrxd_free(opt_output, n * sizeof(f32));
    
    return val;
}

rawrxd_kernel_validation* rawrxd_validate_kernel_q8_0_mat_vec(u64 nrows, u64 ncols) {
    rawrxd_kernel_validation* val = rawrxd_alloc(sizeof(rawrxd_kernel_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->kernel_name = "Q8_0_MatVec";
    val->num_elements = nrows * ncols;
    
    u64 nb_per_row = ncols / 32;
    u64 mat_size = nrows * nb_per_row * sizeof(block_q8_0);
    u64 vec_size = ncols * sizeof(f32);
    u64 out_size = nrows * sizeof(f32);
    
    block_q8_0* mat = rawrxd_alloc(mat_size);
    f32* vec = rawrxd_alloc(vec_size);
    f32* ref_out = rawrxd_alloc(out_size);
    f32* opt_out = rawrxd_alloc(out_size);
    
    if (!mat || !vec || !ref_out || !opt_out) {
        strncpy(val->error_msg, "Memory allocation failed", sizeof(val->error_msg));
        val->passed = false;
        goto cleanup;
    }
    
    // Initialize quantized matrix
    rawrxd_rng rng;
    rawrxd_rng_init(&rng, 42);
    for (u64 i = 0; i < nrows * nb_per_row; i++) {
        mat[i].d = 0.01f + rawrxd_rng_f32(&rng) * 0.1f;
        for (int j = 0; j < 32; j++) {
            mat[i].qs[j] = (i8)(rawrxd_rng_u32(&rng) % 256 - 128);
        }
    }
    
    // Initialize vector
    for (u64 i = 0; i < ncols; i++) {
        vec[i] = rawrxd_rng_f32(&rng) * 2.0f - 1.0f;
    }
    
    // Run reference
    rawrxd_timer t1 = rawrxd_timer_start();
    rawrxd_ref_q8_0_mat_vec(mat, vec, ref_out, nrows, ncols);
    val->reference_time_ms = rawrxd_timer_elapsed_ms(&t1);
    
    // Run optimized
    rawrxd_timer t2 = rawrxd_timer_start();
    rawrxd_q8_0_mat_vec(mat, vec, opt_out, nrows, ncols);
    val->optimized_time_ms = rawrxd_timer_elapsed_ms(&t2);
    
    // Compute metrics
    compute_error_metrics(ref_out, opt_out, nrows,
                          &val->max_abs_error, &val->max_rel_error,
                          &val->mean_abs_error, &val->mean_rel_error,
                          &val->rmse);
    
    val->speedup = val->reference_time_ms / val->optimized_time_ms;
    val->passed = (val->max_abs_error < 0.05f && val->mean_abs_error < 0.005f);
    
cleanup:
    rawrxd_free(mat, mat_size);
    rawrxd_free(vec, vec_size);
    rawrxd_free(ref_out, out_size);
    rawrxd_free(opt_out, out_size);
    
    return val;
}

//=============================================================================
// Comprehensive Kernel Test Suite
//=============================================================================

static rawrxd_test_result test_kernel_softmax(void) {
    printf("  [TEST] Softmax kernel... ");
    
    rawrxd_kernel_validation* val = rawrxd_validate_kernel_softmax(32000);
    if (!val) {
        printf("FAIL (allocation error)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    bool passed = val->passed;
    if (passed) {
        printf("PASS (max_err=%.6f, speedup=%.2fx)\n", 
               val->max_abs_error, val->speedup);
    } else {
        printf("FAIL (max_err=%.6f)\n", val->max_abs_error);
    }
    
    rawrxd_free(val, sizeof(*val));
    return passed ? RAWRXD_TEST_PASS : RAWRXD_TEST_FAIL;
}

static rawrxd_test_result test_kernel_silu(void) {
    printf("  [TEST] SiLU kernel... ");
    
    rawrxd_kernel_validation* val = rawrxd_validate_kernel_silu(4096);
    if (!val) {
        printf("FAIL (allocation error)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    bool passed = val->passed;
    if (passed) {
        printf("PASS (max_err=%.6f, speedup=%.2fx)\n", 
               val->max_abs_error, val->speedup);
    } else {
        printf("FAIL (max_err=%.6f)\n", val->max_abs_error);
    }
    
    rawrxd_free(val, sizeof(*val));
    return passed ? RAWRXD_TEST_PASS : RAWRXD_TEST_FAIL;
}

static rawrxd_test_result test_kernel_gelu(void) {
    printf("  [TEST] GELU kernel... ");
    
    rawrxd_kernel_validation* val = rawrxd_validate_kernel_gelu(4096);
    if (!val) {
        printf("FAIL (allocation error)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    bool passed = val->passed;
    if (passed) {
        printf("PASS (max_err=%.6f, speedup=%.2fx)\n", 
               val->max_abs_error, val->speedup);
    } else {
        printf("FAIL (max_err=%.6f)\n", val->max_abs_error);
    }
    
    rawrxd_free(val, sizeof(*val));
    return passed ? RAWRXD_TEST_PASS : RAWRXD_TEST_FAIL;
}

static rawrxd_test_result test_kernel_q8_0(void) {
    printf("  [TEST] Q8_0 MatVec kernel... ");
    
    rawrxd_kernel_validation* val = rawrxd_validate_kernel_q8_0_mat_vec(4096, 4096);
    if (!val) {
        printf("FAIL (allocation error)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    bool passed = val->passed;
    if (passed) {
        printf("PASS (max_err=%.6f, speedup=%.2fx)\n",
               val->max_abs_error, val->speedup);
    } else {
        printf("FAIL (max_err=%.6f)\n", val->max_abs_error);
    }
    
    rawrxd_free(val, sizeof(*val));
    return passed ? RAWRXD_TEST_PASS : RAWRXD_TEST_FAIL;
}

rawrxd_test_suite* rawrxd_validate_extended_kernel_suite(void) {
    rawrxd_test_suite* suite = rawrxd_alloc(sizeof(rawrxd_test_suite));
    if (!suite) return NULL;
    
    memset(suite, 0, sizeof(*suite));
    suite->name = "Extended Kernel Validation";
    
    printf("\n[SUITE] %s\n", suite->name);
    
    rawrxd_timer t = rawrxd_timer_start();
    
    // Run extended kernel tests
    rawrxd_test_result results[4];
    results[0] = test_kernel_softmax();
    results[1] = test_kernel_silu();
    results[2] = test_kernel_gelu();
    results[3] = test_kernel_q8_0();
    
    // Count results
    for (int i = 0; i < 4; i++) {
        suite->total++;
        if (results[i] == RAWRXD_TEST_PASS) suite->passed++;
        else if (results[i] == RAWRXD_TEST_FAIL) suite->failed++;
        else suite->skipped++;
    }
    
    suite->total_time_ms = rawrxd_timer_elapsed_ms(&t);
    
    printf("  Summary: %u/%u passed, %u failed, %u skipped (%.2f ms)\n\n",
           suite->passed, suite->total, suite->failed, suite->skipped, suite->total_time_ms);
    
    return suite;
}
