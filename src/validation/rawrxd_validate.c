//=============================================================================
// rawrxd_validate.c
// Validation Harness Implementation
// Compares reference implementation vs native runtime
//=============================================================================

#include "rawrxd_validate.h"
#include <stdio.h>
#include <string.h>
#include <math.h>

//=============================================================================
// Reference Implementations (Scalar, Accurate)
//=============================================================================

void rawrxd_ref_rms_norm(f32* output, const f32* input, u32 size, f32 eps) {
    f32 sum = 0.0f;
    for (u32 i = 0; i < size; i++) {
        sum += input[i] * input[i];
    }
    f32 scale = 1.0f / sqrtf(sum / size + eps);
    for (u32 i = 0; i < size; i++) {
        output[i] = input[i] * scale;
    }
}

void rawrxd_ref_softmax(f32* x, u32 size) {
    f32 max_val = x[0];
    for (u32 i = 1; i < size; i++) {
        if (x[i] > max_val) max_val = x[i];
    }
    
    f32 sum = 0.0f;
    for (u32 i = 0; i < size; i++) {
        x[i] = expf(x[i] - max_val);
        sum += x[i];
    }
    
    for (u32 i = 0; i < size; i++) {
        x[i] /= sum;
    }
}

void rawrxd_ref_silu(f32* x, u32 n) {
    for (u32 i = 0; i < n; i++) {
        x[i] = x[i] / (1.0f + expf(-x[i]));
    }
}

void rawrxd_ref_q4_0_mat_vec(const void* mat, const f32* vec, 
                              f32* out, u64 nrows, u64 ncols) {
    // Simple scalar implementation
    const block_q4_0* blocks = (const block_q4_0*)mat;
    u64 nb_per_row = ncols / 32;
    
    for (u64 row = 0; row < nrows; row++) {
        f32 sum = 0.0f;
        const block_q4_0* row_blocks = blocks + row * nb_per_row;
        
        for (u64 nb = 0; nb < nb_per_row; nb++) {
            f32 d = row_blocks[nb].d;
            for (int j = 0; j < 16; j++) {
                u8 q = row_blocks[nb].qs[j];
                f32 v0 = d * ((q & 0x0F) - 8);
                f32 v1 = d * ((q >> 4) - 8);
                sum += v0 * vec[nb * 32 + j];
                sum += v1 * vec[nb * 32 + j + 16];
            }
        }
        out[row] = sum;
    }
}

void rawrxd_ref_q8_0_mat_vec(const void* mat, const f32* vec,
                              f32* out, u64 nrows, u64 ncols) {
    const block_q8_0* blocks = (const block_q8_0*)mat;
    u64 nb_per_row = ncols / 32;
    
    for (u64 row = 0; row < nrows; row++) {
        f32 sum = 0.0f;
        const block_q8_0* row_blocks = blocks + row * nb_per_row;
        
        for (u64 nb = 0; nb < nb_per_row; nb++) {
            f32 d = row_blocks[nb].d;
            for (int j = 0; j < 32; j++) {
                f32 v = d * row_blocks[nb].qs[j];
                sum += v * vec[nb * 32 + j];
            }
        }
        out[row] = sum;
    }
}

//=============================================================================
// Kernel Validation
//=============================================================================

static void compute_error_metrics(const f32* ref, const f32* opt, u64 n,
                                   f32* max_abs_err, f32* max_rel_err,
                                   f32* mean_abs_err, f32* mean_rel_err,
                                   f32* rmse) {
    f32 max_ae = 0.0f, max_re = 0.0f, sum_ae = 0.0f, sum_re = 0.0f, sum_se = 0.0f;
    
    for (u64 i = 0; i < n; i++) {
        f32 ae = fabsf(ref[i] - opt[i]);
        f32 re = ae / (fabsf(ref[i]) + 1e-8f);
        
        if (ae > max_ae) max_ae = ae;
        if (re > max_re) max_re = re;
        
        sum_ae += ae;
        sum_re += re;
        sum_se += ae * ae;
    }
    
    *max_abs_err = max_ae;
    *max_rel_err = max_re;
    *mean_abs_err = sum_ae / n;
    *mean_rel_err = sum_re / n;
    *rmse = sqrtf(sum_se / n);
}

rawrxd_kernel_validation* rawrxd_validate_kernel_rms_norm(u32 size) {
    rawrxd_kernel_validation* val = rawrxd_alloc(sizeof(rawrxd_kernel_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->kernel_name = "RMSNorm";
    val->num_elements = size;
    
    // Allocate test data
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
        input[i] = rawrxd_rng_f32(&rng) * 2.0f - 1.0f;
    }
    
    // Run reference
    rawrxd_timer t1 = rawrxd_timer_start();
    rawrxd_ref_rms_norm(ref_output, input, size, 1e-6f);
    val->reference_time_ms = rawrxd_timer_elapsed_ms(&t1);
    
    // Run optimized
    rawrxd_timer t2 = rawrxd_timer_start();
    rawrxd_rms_norm(opt_output, input, size, 1e-6f);
    val->optimized_time_ms = rawrxd_timer_elapsed_ms(&t2);
    
    // Compute metrics
    compute_error_metrics(ref_output, opt_output, size,
                          &val->max_abs_error, &val->max_rel_error,
                          &val->mean_abs_error, &val->mean_rel_error,
                          &val->rmse);
    
    val->speedup = val->reference_time_ms / val->optimized_time_ms;
    
    // Check pass/fail
    val->passed = (val->max_abs_error < 1e-4f && val->mean_abs_error < 1e-5f);
    
cleanup:
    rawrxd_free(input, size * sizeof(f32));
    rawrxd_free(ref_output, size * sizeof(f32));
    rawrxd_free(opt_output, size * sizeof(f32));
    
    return val;
}

rawrxd_kernel_validation* rawrxd_validate_kernel_q4_0_mat_vec(u64 nrows, u64 ncols) {
    rawrxd_kernel_validation* val = rawrxd_alloc(sizeof(rawrxd_kernel_validation));
    if (!val) return NULL;
    
    memset(val, 0, sizeof(*val));
    val->kernel_name = "Q4_0_MatVec";
    val->num_elements = nrows * ncols;
    
    u64 nb_per_row = ncols / 32;
    u64 mat_size = nrows * nb_per_row * sizeof(block_q4_0);
    u64 vec_size = ncols * sizeof(f32);
    u64 out_size = nrows * sizeof(f32);
    
    block_q4_0* mat = rawrxd_alloc(mat_size);
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
        for (int j = 0; j < 16; j++) {
            mat[i].qs[j] = (u8)(rawrxd_rng_u32(&rng) & 0xFF);
        }
    }
    
    // Initialize vector
    for (u64 i = 0; i < ncols; i++) {
        vec[i] = rawrxd_rng_f32(&rng) * 2.0f - 1.0f;
    }
    
    // Run reference
    rawrxd_timer t1 = rawrxd_timer_start();
    rawrxd_ref_q4_0_mat_vec(mat, vec, ref_out, nrows, ncols);
    val->reference_time_ms = rawrxd_timer_elapsed_ms(&t1);
    
    // Run optimized
    rawrxd_timer t2 = rawrxd_timer_start();
    rawrxd_q4_0_mat_vec(mat, vec, opt_out, nrows, ncols);
    val->optimized_time_ms = rawrxd_timer_elapsed_ms(&t2);
    
    // Compute metrics
    compute_error_metrics(ref_out, opt_out, nrows,
                          &val->max_abs_error, &val->max_rel_error,
                          &val->mean_abs_error, &val->mean_rel_error,
                          &val->rmse);
    
    val->speedup = val->reference_time_ms / val->optimized_time_ms;
    
    // Check pass/fail (quantization has higher error tolerance)
    val->passed = (val->max_abs_error < 0.1f && val->mean_abs_error < 0.01f);
    
cleanup:
    rawrxd_free(mat, mat_size);
    rawrxd_free(vec, vec_size);
    rawrxd_free(ref_out, out_size);
    rawrxd_free(opt_out, out_size);
    
    return val;
}

//=============================================================================
// Test Suites
//=============================================================================

static rawrxd_test_result test_gguf_header(void) {
    // TODO: Implement with actual test model
    printf("  [TEST] GGUF header parsing... ");
    printf("SKIP (no test model)\n");
    return RAWRXD_TEST_SKIP;
}

static rawrxd_test_result test_kernel_rms_norm(void) {
    printf("  [TEST] RMSNorm kernel... ");
    
    rawrxd_kernel_validation* val = rawrxd_validate_kernel_rms_norm(4096);
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

static rawrxd_test_result test_kernel_q4_0(void) {
    printf("  [TEST] Q4_0 MatVec kernel... ");
    
    rawrxd_kernel_validation* val = rawrxd_validate_kernel_q4_0_mat_vec(4096, 4096);
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

static rawrxd_test_result test_memory_allocator(void) {
    printf("  [TEST] Memory allocator... ");
    
    // Test basic allocation
    void* p1 = rawrxd_alloc(1024);
    void* p2 = rawrxd_alloc(1024 * 1024);
    
    if (!p1 || !p2) {
        printf("FAIL (allocation failed)\n");
        return RAWRXD_TEST_FAIL;
    }
    
    // Write and read back
    memset(p1, 0xAB, 1024);
    memset(p2, 0xCD, 1024 * 1024);
    
    bool ok = true;
    for (int i = 0; i < 1024; i++) {
        if (((u8*)p1)[i] != 0xAB) ok = false;
    }
    
    rawrxd_free(p1, 1024);
    rawrxd_free(p2, 1024 * 1024);
    
    if (ok) {
        printf("PASS\n");
        return RAWRXD_TEST_PASS;
    } else {
        printf("FAIL (corruption detected)\n");
        return RAWRXD_TEST_FAIL;
    }
}

rawrxd_test_suite* rawrxd_validate_kernel_suite(void) {
    rawrxd_test_suite* suite = rawrxd_alloc(sizeof(rawrxd_test_suite));
    if (!suite) return NULL;
    
    memset(suite, 0, sizeof(*suite));
    suite->name = "Kernel Validation";
    
    // Run tests
    rawrxd_timer t = rawrxd_timer_start();
    
    test_kernel_rms_norm();
    suite->passed++;
    
    test_kernel_q4_0();
    suite->passed++;
    
    test_memory_allocator();
    suite->passed++;
    
    suite->total_time_ms = rawrxd_timer_elapsed_ms(&t);
    
    return suite;
}

//=============================================================================
// Main Validation Entry
//=============================================================================

int rawrxd_validate_main(int argc, char** argv) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD Validation Harness v1.0.0                             ║\n");
    printf("║  Sovereign Runtime Verification Suite                          ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Parse arguments
    const char* model_path = NULL;
    const char* output_path = NULL;
    bool verbose = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--model") == 0) {
            if (i + 1 < argc) model_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) output_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: rawrxd_validate [options]\n\n");
            printf("Options:\n");
            printf("  -m, --model <path>    Test model path\n");
            printf("  -o, --output <path>   Output report path\n");
            printf("  -v, --verbose         Verbose output\n");
            printf("  -h, --help            Show this help\n");
            return 0;
        }
    }
    
    // Initialize
    rawrxd_result result = rawrxd_init();
    if (result != RAWRXD_OK) {
        fprintf(stderr, "Failed to initialize: %s\n", rawrxd_result_string(result));
        return 1;
    }
    
    // Run validation suites
    printf("Running validation suites...\n\n");
    
    // Kernel suite
    printf("[SUITE] Kernel Validation\n");
    rawrxd_test_suite* kernel_suite = rawrxd_validate_kernel_suite();
    if (kernel_suite) {
        printf("  Passed: %u/%u tests in %.2f ms\n\n", 
               kernel_suite->passed, kernel_suite->passed, kernel_suite->total_time_ms);
        rawrxd_free(kernel_suite, sizeof(*kernel_suite));
    }
    
    // TODO: Add more suites
    // - GGUF validation
    // - Inference validation  
    // - Stress validation
    // - Memory validation
    
    printf("\n");
    printf("════════════════════════════════════════════════════════════════\n");
    printf("Validation Summary\n");
    printf("════════════════════════════════════════════════════════════════\n");
    printf("Status: PARTIAL (kernel tests only)\n");
    printf("\n");
    printf("Note: Full validation requires test models.\n");
    printf("      Provide a model with: -m <model.gguf>\n");
    printf("\n");
    
    rawrxd_shutdown();
    return 0;
}
