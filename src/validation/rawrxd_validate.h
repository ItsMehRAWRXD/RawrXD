//=============================================================================
// rawrxd_validate.h
// Validation Harness for RawrXD Sovereign Runtime
// Compares reference implementation vs native runtime
//=============================================================================
#pragma once

#include "../core/rawrxd_inference.h"
#include "../core/rawrxd_model_stream.h"

#ifdef __cplusplus
extern "C" {
#endif

//=============================================================================
// Validation Result Types
//=============================================================================

typedef enum {
    RAWRXD_TEST_PASS = 0,
    RAWRXD_TEST_FAIL = 1,
    RAWRXD_TEST_SKIP = 2,
    RAWRXD_TEST_ERROR = 3
} rawrxd_test_result;

typedef struct rawrxd_test_case {
    const char* name;
    const char* category;
    rawrxd_test_result (*run)(void);
    const char* description;
} rawrxd_test_case;

typedef struct rawrxd_test_suite {
    const char* name;
    rawrxd_test_case* cases;
    u32 num_cases;
    u32 passed;
    u32 failed;
    u32 skipped;
    double total_time_ms;
} rawrxd_test_suite;

//=============================================================================
// Validation Configuration
//=============================================================================

typedef struct rawrxd_validate_config {
    // Tolerance thresholds
    f32 max_abs_error;          // Maximum absolute error allowed
    f32 max_rel_error;          // Maximum relative error allowed
    f32 mean_error_threshold;   // Mean error threshold
    
    // Performance thresholds
    f32 min_throughput_mbps;    // Minimum loading throughput
    f32 min_tokens_per_sec;     // Minimum inference speed
    u32 max_latency_ms;         // Maximum latency
    
    // Test selection
    bool test_gguf_parsing;
    bool test_quantization;
    bool test_kernels;
    bool test_inference;
    bool test_stress;
    bool test_memory;
    
    // Paths
    const char* model_path;     // Path to test model
    const char* output_dir;     // Where to write results
    const char* reference_path; // Reference implementation output (optional)
    
    // Stress parameters
    u32 stress_iterations;
    u32 stress_duration_sec;
} rawrxd_validate_config;

//=============================================================================
// GGUF Validation
//=============================================================================

typedef struct rawrxd_gguf_validation {
    const char* model_name;
    const char* quant_type;
    
    // Parsing results
    bool header_valid;
    bool metadata_valid;
    bool tensors_valid;
    u32 tensor_count;
    u64 data_offset;
    
    // Tensor validation
    u32 tensors_checked;
    u32 tensors_passed;
    u32 tensors_failed;
    
    // Errors
    char error_msg[256];
} rawrxd_gguf_validation;

RAWRXD_EXPORT rawrxd_test_result rawrxd_validate_gguf_header(const char* path);
RAWRXD_EXPORT rawrxd_test_result rawrxd_validate_gguf_metadata(const char* path);
RAWRXD_EXPORT rawrxd_test_result rawrxd_validate_gguf_tensors(const char* path);
RAWRXD_EXPORT rawrxd_gguf_validation* rawrxd_validate_gguf_full(const char* path);

// Test matrix validation
RAWRXD_EXPORT rawrxd_test_suite* rawrxd_validate_gguf_matrix(void);

//=============================================================================
// Kernel Validation
//=============================================================================

typedef struct rawrxd_kernel_validation {
    const char* kernel_name;
    u64 num_elements;
    
    // Error metrics
    f32 max_abs_error;
    f32 max_rel_error;
    f32 mean_abs_error;
    f32 mean_rel_error;
    f32 rmse;
    
    // Performance
    f32 reference_time_ms;
    f32 optimized_time_ms;
    f32 speedup;
    
    // Result
    bool passed;
    char error_msg[256];
} rawrxd_kernel_validation;

// Reference implementations (scalar, accurate)
RAWRXD_EXPORT void rawrxd_ref_rms_norm(f32* output, const f32* input, u32 size, f32 eps);
RAWRXD_EXPORT void rawrxd_ref_softmax(f32* x, u32 size);
RAWRXD_EXPORT void rawrxd_ref_silu(f32* x, u32 n);
RAWRXD_EXPORT void rawrxd_ref_q4_0_mat_vec(const void* mat, const f32* vec, 
                                            f32* out, u64 nrows, u64 ncols);
RAWRXD_EXPORT void rawrxd_ref_q8_0_mat_vec(const void* mat, const f32* vec,
                                            f32* out, u64 nrows, u64 ncols);

// Validation functions
RAWRXD_EXPORT rawrxd_kernel_validation* rawrxd_validate_kernel_rms_norm(u32 size);
RAWRXD_EXPORT rawrxd_kernel_validation* rawrxd_validate_kernel_softmax(u32 size);
RAWRXD_EXPORT rawrxd_kernel_validation* rawrxd_validate_kernel_silu(u32 n);
RAWRXD_EXPORT rawrxd_kernel_validation* rawrxd_validate_kernel_q4_0_mat_vec(u64 nrows, u64 ncols);
RAWRXD_EXPORT rawrxd_kernel_validation* rawrxd_validate_kernel_q8_0_mat_vec(u64 nrows, u64 ncols);

// Full kernel suite
RAWRXD_EXPORT rawrxd_test_suite* rawrxd_validate_kernel_suite(void);

//=============================================================================
// End-to-End Inference Validation
//=============================================================================

typedef struct rawrxd_inference_validation {
    // Model info
    const char* model_path;
    const char* architecture;
    const char* quantization;
    
    // Test parameters
    const char* prompt;
    u32 max_tokens;
    f32 temperature;
    
    // Results
    bool load_success;
    double load_time_ms;
    double first_token_ms;
    double tokens_per_sec;
    u32 tokens_generated;
    
    // Output verification
    char* output_text;
    bool output_valid;
    
    // Comparison with reference (if available)
    f32 logits_max_diff;
    f32 logits_mean_diff;
    bool logits_match;
    
    // Resource usage
    u64 peak_memory_bytes;
    u64 kv_cache_bytes;
    
    // Result
    bool passed;
    char error_msg[256];
} rawrxd_inference_validation;

RAWRXD_EXPORT rawrxd_inference_validation* rawrxd_validate_inference(
    const char* model_path,
    const char* prompt,
    u32 max_tokens,
    const rawrxd_validate_config* config
);

// Standard inference tests
RAWRXD_EXPORT rawrxd_test_result rawrxd_validate_inference_tiny(void);
RAWRXD_EXPORT rawrxd_test_result rawrxd_validate_inference_small(void);
RAWRXD_EXPORT rawrxd_test_result rawrxd_validate_inference_medium(void);

//=============================================================================
// Stress Validation
//=============================================================================

typedef struct rawrxd_stress_validation {
    u32 iterations_completed;
    u32 iterations_failed;
    double duration_sec;
    
    // Memory tracking
    u64 initial_memory;
    u64 peak_memory;
    u64 final_memory;
    u64 memory_leak_bytes;
    
    // Error tracking
    u32 load_errors;
    u32 inference_errors;
    u32 stream_errors;
    u32 allocator_errors;
    
    // Stability
    bool stable;
    char error_msg[256];
} rawrxd_stress_validation;

RAWRXD_EXPORT rawrxd_stress_validation* rawrxd_validate_stress_load_unload(
    const char* model_path,
    u32 iterations
);

RAWRXD_EXPORT rawrxd_stress_validation* rawrxd_validate_stress_inference(
    const char* model_path,
    u32 iterations
);

RAWRXD_EXPORT rawrxd_stress_validation* rawrxd_validate_stress_streaming(
    const char* model_path,
    u32 iterations
);

RAWRXD_EXPORT rawrxd_stress_validation* rawrxd_validate_stress_memory(
    const char* model_path,
    u32 duration_sec
);

//=============================================================================
// Memory Validation
//=============================================================================

typedef struct rawrxd_memory_validation {
    // Allocator tests
    bool small_alloc_passed;
    bool large_alloc_passed;
    bool realloc_passed;
    bool alignment_passed;
    
    // Arena tests
    bool arena_passed;
    bool arena_alignment_passed;
    
    // Pool tests
    bool pool_passed;
    bool pool_exhaustion_passed;
    
    // Leak detection
    u64 leaked_bytes;
    u32 leaked_blocks;
    
    // Fragmentation
    f32 fragmentation_ratio;
    
    // Result
    bool passed;
} rawrxd_memory_validation;

RAWRXD_EXPORT rawrxd_memory_validation* rawrxd_validate_memory(void);

//=============================================================================
// Report Generation
//=============================================================================

typedef struct rawrxd_validation_report {
    // Summary
    u32 total_tests;
    u32 passed;
    u32 failed;
    u32 skipped;
    double total_time_sec;
    
    // Suites
    rawrxd_test_suite** suites;
    u32 num_suites;
    
    // Detailed results
    rawrxd_gguf_validation** gguf_results;
    u32 num_gguf_results;
    
    rawrxd_kernel_validation** kernel_results;
    u32 num_kernel_results;
    
    rawrxd_inference_validation** inference_results;
    u32 num_inference_results;
    
    rawrxd_stress_validation** stress_results;
    u32 num_stress_results;
    
    rawrxd_memory_validation* memory_result;
    
    // Overall
    bool passed;
    char summary[1024];
} rawrxd_validation_report;

// Run full validation
RAWRXD_EXPORT rawrxd_validation_report* rawrxd_validate_full(
    const rawrxd_validate_config* config
);

// Report output
RAWRXD_EXPORT void rawrxd_validate_report_print(const rawrxd_validation_report* report);
RAWRXD_EXPORT void rawrxd_validate_report_json(const rawrxd_validation_report* report, 
                                               const char* path);
RAWRXD_EXPORT void rawrxd_validate_report_html(const rawrxd_validation_report* report,
                                                const char* path);

// Cleanup
RAWRXD_EXPORT void rawrxd_validate_report_free(rawrxd_validation_report* report);

//=============================================================================
// CLI Entry Point
//=============================================================================

RAWRXD_EXPORT int rawrxd_validate_main(int argc, char** argv);

#ifdef __cplusplus
}
#endif
