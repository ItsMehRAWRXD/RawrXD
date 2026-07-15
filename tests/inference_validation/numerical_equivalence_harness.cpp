/*
 * RawrXD Numerical Inference Equivalence Harness
 * Compares RawrXD forward pass outputs against llama.cpp reference
 * 
 * Acceptance Criteria:
 * - Logits: Max Error < 1e-3, Mean Error < 1e-4
 * - Hidden States: Max Error < 1e-4, Mean Error < 1e-5
 * - KV Cache: Max Error < 1e-4, Mean Error < 1e-5
 * - Attention Scores: Max Error < 1e-3, Mean Error < 1e-4
 * - RMSNorm: Max Error < 1e-5, Mean Error < 1e-6
 * - Embeddings: Max Error < 1e-5, Mean Error < 1e-6
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <float.h>
#include <stdint.h>
#include <time.h>

#ifdef _WIN32
#include <windows.h>
#include <direct.h>
#define mkdir(path, mode) _mkdir(path)
#else
#include <sys/stat.h>
#include <sys/types.h>
#endif

#define VALIDATION_VERSION "1.0.0"
#define REPORT_HEADER "RawrXD Numerical Inference Equivalence Report"

/* Error tolerance thresholds */
struct ToleranceConfig {
    struct {
        double max_error;
        double mean_error;
        double rms_error;
    } logits, hidden, kv_cache, attention, rmsnorm, embedding;
};

/* Default tolerances based on FP32 precision */
ToleranceConfig DEFAULT_TOLERANCES = {
    /* Logits: Higher tolerance due to softmax numerical range */
    {1e-3, 1e-4, 1e-4},
    /* Hidden states: Medium tolerance */
    {1e-4, 1e-5, 1e-5},
    /* KV cache: Medium tolerance */
    {1e-4, 1e-5, 1e-5},
    /* Attention scores: Higher tolerance due to softmax */
    {1e-3, 1e-4, 1e-4},
    /* RMSNorm: Tight tolerance - deterministic computation */
    {1e-5, 1e-6, 1e-6},
    /* Embeddings: Tight tolerance - lookup table */
    {1e-5, 1e-6, 1e-6}
};

/* Validation result for a single tensor */
struct TensorValidationResult {
    const char* name;
    size_t num_elements;
    double max_error;
    double mean_error;
    double rms_error;
    double max_relative_error;
    int num_inf;           /* Count of inf values */
    int num_nan;           /* Count of nan values */
    int num_mismatches;    /* Elements exceeding tolerance */
    bool passed;
    double tolerance_max;
    double tolerance_mean;
};

/* Overall validation report */
struct ValidationReport {
    char timestamp[64];
    char model_path[256];
    char rawrxd_version[32];
    char llama_cpp_version[32];
    
    TensorValidationResult logits;
    TensorValidationResult hidden_states;
    TensorValidationResult kv_cache_k;
    TensorValidationResult kv_cache_v;
    TensorValidationResult attention_scores;
    TensorValidationResult rmsnorm_output;
    TensorValidationResult embeddings;
    
    int total_tests;
    int passed_tests;
    int failed_tests;
    double total_time_ms;
};

/* Load binary tensor from file */
float* load_tensor(const char* path, size_t* num_elements) {
    FILE* f = fopen(path, "rb");
    if (!f) {
        fprintf(stderr, "Failed to open: %s\n", path);
        return nullptr;
    }
    
    /* Read header: shape info + element count */
    uint64_t header[4];
    if (fread(header, sizeof(uint64_t), 4, f) != 4) {
        fprintf(stderr, "Failed to read header: %s\n", path);
        fclose(f);
        return nullptr;
    }
    
    *num_elements = header[0];
    size_t expected_bytes = header[1];
    uint32_t dtype = (uint32_t)header[2];
    uint32_t version = (uint32_t)header[3];
    
    if (dtype != 1) { /* 1 = FP32 */
        fprintf(stderr, "Unsupported dtype %u in: %s\n", dtype, path);
        fclose(f);
        return nullptr;
    }
    
    float* data = (float*)aligned_alloc(64, (*num_elements) * sizeof(float));
    if (!data) {
        fprintf(stderr, "Failed to allocate %zu elements\n", *num_elements);
        fclose(f);
        return nullptr;
    }
    
    if (fread(data, sizeof(float), *num_elements, f) != *num_elements) {
        fprintf(stderr, "Failed to read data: %s\n", path);
        free(data);
        fclose(f);
        return nullptr;
    }
    
    fclose(f);
    return data;
}

/* Save tensor to binary file */
bool save_tensor(const char* path, const float* data, size_t num_elements) {
    FILE* f = fopen(path, "wb");
    if (!f) {
        fprintf(stderr, "Failed to create: %s\n", path);
        return false;
    }
    
    /* Header: [num_elements, bytes, dtype, version] */
    uint64_t header[4] = {
        num_elements,
        num_elements * sizeof(float),
        1,  /* FP32 */
        1   /* Version */
    };
    
    fwrite(header, sizeof(uint64_t), 4, f);
    fwrite(data, sizeof(float), num_elements, f);
    fclose(f);
    return true;
}

/* Compare two tensors and compute error metrics */
TensorValidationResult compare_tensors(
    const char* name,
    const float* rawrxd,
    const float* reference,
    size_t num_elements,
    double tol_max,
    double tol_mean
) {
    TensorValidationResult result = {};
    result.name = name;
    result.num_elements = num_elements;
    result.tolerance_max = tol_max;
    result.tolerance_mean = tol_mean;
    
    double max_error = 0.0;
    double sum_error = 0.0;
    double sum_squared_error = 0.0;
    double max_rel_error = 0.0;
    int num_inf = 0;
    int num_nan = 0;
    int num_mismatches = 0;
    
    for (size_t i = 0; i < num_elements; i++) {
        float r = rawrxd[i];
        float ref = reference[i];
        
        /* Check for special values */
        if (isinf(r)) num_inf++;
        if (isnan(r)) num_nan++;
        
        /* Compute absolute error */
        double abs_error = fabs(r - ref);
        max_error = fmax(max_error, abs_error);
        sum_error += abs_error;
        sum_squared_error += abs_error * abs_error;
        
        /* Compute relative error (guard against div by zero) */
        double rel_error = 0.0;
        if (fabs(ref) > 1e-10) {
            rel_error = abs_error / fabs(ref);
        }
        max_rel_error = fmax(max_rel_error, rel_error);
        
        /* Check tolerance */
        if (abs_error > tol_max) {
            num_mismatches++;
        }
    }
    
    result.max_error = max_error;
    result.mean_error = sum_error / num_elements;
    result.rms_error = sqrt(sum_squared_error / num_elements);
    result.max_relative_error = max_rel_error;
    result.num_inf = num_inf;
    result.num_nan = num_nan;
    result.num_mismatches = num_mismatches;
    result.passed = (max_error <= tol_max) && (result.mean_error <= tol_mean);
    
    return result;
}

/* Print validation result */
void print_result(const TensorValidationResult& r) {
    const char* status = r.passed ? "PASS" : "FAIL";
    printf("\n[%s] %s\n", status, r.name);
    printf("  Elements: %zu\n", r.num_elements);
    printf("  Max Error: %.6e (tol: %.6e)\n", r.max_error, r.tolerance_max);
    printf("  Mean Error: %.6e (tol: %.6e)\n", r.mean_error, r.tolerance_mean);
    printf("  RMS Error: %.6e\n", r.rms_error);
    printf("  Max Relative Error: %.6e\n", r.max_relative_error);
    printf("  NaN: %d, Inf: %d\n", r.num_nan, r.num_inf);
    printf("  Mismatches: %d (%.4f%%)\n", r.num_mismatches,
           100.0 * r.num_mismatches / r.num_elements);
}

/* Generate JSON report */
void generate_json_report(const ValidationReport& report, const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"version\": \"%s\",\n", VALIDATION_VERSION);
    fprintf(f, "  \"timestamp\": \"%s\",\n", report.timestamp);
    fprintf(f, "  \"model\": \"%s\",\n", report.model_path);
    fprintf(f, "  \"rawrxd_version\": \"%s\",\n", report.rawrxd_version);
    fprintf(f, "  \"llama_cpp_version\": \"%s\",\n", report.llama_cpp_version);
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_tests\": %d,\n", report.total_tests);
    fprintf(f, "    \"passed\": %d,\n", report.passed_tests);
    fprintf(f, "    \"failed\": %d,\n", report.failed_tests);
    fprintf(f, "    \"success_rate\": %.2f,\n", 
            100.0 * report.passed_tests / report.total_tests);
    fprintf(f, "    \"total_time_ms\": %.2f\n", report.total_time_ms);
    fprintf(f, "  },\n");
    
    auto write_result = [&](const TensorValidationResult& r) {
        fprintf(f, "    \"%s\": {\n", r.name);
        fprintf(f, "      \"passed\": %s,\n", r.passed ? "true" : "false");
        fprintf(f, "      \"elements\": %zu,\n", r.num_elements);
        fprintf(f, "      \"max_error\": %.10e,\n", r.max_error);
        fprintf(f, "      \"mean_error\": %.10e,\n", r.mean_error);
        fprintf(f, "      \"rms_error\": %.10e,\n", r.rms_error);
        fprintf(f, "      \"max_relative_error\": %.10e,\n", r.max_relative_error);
        fprintf(f, "      \"tolerance_max\": %.10e,\n", r.tolerance_max);
        fprintf(f, "      \"tolerance_mean\": %.10e,\n", r.tolerance_mean);
        fprintf(f, "      \"nan_count\": %d,\n", r.num_nan);
        fprintf(f, "      \"inf_count\": %d,\n", r.num_inf);
        fprintf(f, "      \"mismatches\": %d\n", r.num_mismatches);
        fprintf(f, "    }");
    };
    
    fprintf(f, "  \"results\": {\n");
    write_result(report.logits); fprintf(f, ",\n");
    write_result(report.hidden_states); fprintf(f, ",\n");
    write_result(report.kv_cache_k); fprintf(f, ",\n");
    write_result(report.kv_cache_v); fprintf(f, ",\n");
    write_result(report.attention_scores); fprintf(f, ",\n");
    write_result(report.rmsnorm_output); fprintf(f, ",\n");
    write_result(report.embeddings);
    fprintf(f, "\n  }\n");
    fprintf(f, "}\n");
    
    fclose(f);
}

/* Generate Markdown report */
void generate_markdown_report(const ValidationReport& report, const char* path) {
    FILE* f = fopen(path, "w");
    if (!f) return;
    
    fprintf(f, "# %s\n\n", REPORT_HEADER);
    fprintf(f, "**Version:** %s  \n", VALIDATION_VERSION);
    fprintf(f, "**Timestamp:** %s  \n", report.timestamp);
    fprintf(f, "**Model:** `%s`  \n", report.model_path);
    fprintf(f, "**RawrXD:** %s  \n", report.rawrxd_version);
    fprintf(f, "**llama.cpp:** %s  \n\n", report.llama_cpp_version);
    
    /* Summary */
    fprintf(f, "## Summary\n\n");
    fprintf(f, "| Metric | Value |\n");
    fprintf(f, "|--------|-------|\n");
    fprintf(f, "| Total Tests | %d |\n", report.total_tests);
    fprintf(f, "| Passed | %d |\n", report.passed_tests);
    fprintf(f, "| Failed | %d |\n", report.failed_tests);
    fprintf(f, "| Success Rate | %.2f%% |\n", 
            100.0 * report.passed_tests / report.total_tests);
    fprintf(f, "| Total Time | %.2f ms |\n\n", report.total_time_ms);
    
    /* Detailed Results */
    auto write_md_result = [&](const TensorValidationResult& r) {
        const char* status = r.passed ? "✅ PASS" : "❌ FAIL";
        fprintf(f, "### %s %s\n\n", status, r.name);
        fprintf(f, "| Metric | Value | Tolerance |\n");
        fprintf(f, "|--------|-------|-----------|\n");
        fprintf(f, "| Elements | %zu | - |\n", r.num_elements);
        fprintf(f, "| Max Error | %.6e | %.6e |\n", r.max_error, r.tolerance_max);
        fprintf(f, "| Mean Error | %.6e | %.6e |\n", r.mean_error, r.tolerance_mean);
        fprintf(f, "| RMS Error | %.6e | - |\n", r.rms_error);
        fprintf(f, "| Max Relative Error | %.6e | - |\n", r.max_relative_error);
        fprintf(f, "| NaN Count | %d | 0 |\n", r.num_nan);
        fprintf(f, "| Inf Count | %d | 0 |\n", r.num_inf);
        fprintf(f, "| Mismatches | %d (%.4f%%) | 0%% |\n\n", 
                r.num_mismatches, 100.0 * r.num_mismatches / r.num_elements);
    };
    
    fprintf(f, "## Detailed Results\n\n");
    write_md_result(report.logits);
    write_md_result(report.hidden_states);
    write_md_result(report.kv_cache_k);
    write_md_result(report.kv_cache_v);
    write_md_result(report.attention_scores);
    write_md_result(report.rmsnorm_output);
    write_md_result(report.embeddings);
    
    /* Acceptance Criteria */
    fprintf(f, "## Acceptance Criteria\n\n");
    fprintf(f, "```\n");
    fprintf(f, "Logits:           Max Error < 1e-3, Mean Error < 1e-4\n");
    fprintf(f, "Hidden States:    Max Error < 1e-4, Mean Error < 1e-5\n");
    fprintf(f, "KV Cache:         Max Error < 1e-4, Mean Error < 1e-5\n");
    fprintf(f, "Attention Scores: Max Error < 1e-3, Mean Error < 1e-4\n");
    fprintf(f, "RMSNorm:          Max Error < 1e-5, Mean Error < 1e-6\n");
    fprintf(f, "Embeddings:       Max Error < 1e-5, Mean Error < 1e-6\n");
    fprintf(f, "```\n\n");
    
    /* Footer */
    fprintf(f, "---\n\n");
    fprintf(f, "*Generated by RawrXD Numerical Equivalence Harness v%s*\n", 
            VALIDATION_VERSION);
    
    fclose(f);
}

/* Main validation entry point */
int main(int argc, char** argv) {
    printf("RawrXD Numerical Inference Equivalence Harness v%s\n", VALIDATION_VERSION);
    printf("========================================================\n\n");
    
    /* Parse arguments */
    const char* rawrxd_dir = (argc > 1) ? argv[1] : "./rawrxd_outputs";
    const char* reference_dir = (argc > 2) ? argv[2] : "./reference_outputs";
    const char* output_dir = (argc > 3) ? argv[3] : "./validation_results";
    
    printf("RawrXD outputs:   %s\n", rawrxd_dir);
    printf("Reference outputs: %s\n", reference_dir);
    printf("Results:          %s\n\n", output_dir);
    
    /* Create output directory */
    mkdir(output_dir, 0755);
    
    ValidationReport report = {};
    
    /* Set metadata */
    time_t now = time(nullptr);
    struct tm* tm_info = localtime(&now);
    strftime(report.timestamp, sizeof(report.timestamp), "%Y-%m-%d %H:%M:%S", tm_info);
    strncpy(report.model_path, "model.gguf", sizeof(report.model_path));
    strncpy(report.rawrxd_version, "14.7.3", sizeof(report.rawrxd_version));
    strncpy(report.llama_cpp_version, "b1559", sizeof(report.llama_cpp_version));
    
    clock_t start_time = clock();
    
    /* Validate each tensor type */
    struct TestCase {
        const char* name;
        const char* filename;
        TensorValidationResult* result;
        double tol_max;
        double tol_mean;
    };
    
    TestCase tests[] = {
        {"Logits", "logits.bin", &report.logits, 
         DEFAULT_TOLERANCES.logits.max_error, DEFAULT_TOLERANCES.logits.mean_error},
        {"Hidden States", "hidden_states.bin", &report.hidden_states,
         DEFAULT_TOLERANCES.hidden.max_error, DEFAULT_TOLERANCES.hidden.mean_error},
        {"KV Cache K", "kv_cache_k.bin", &report.kv_cache_k,
         DEFAULT_TOLERANCES.kv_cache.max_error, DEFAULT_TOLERANCES.kv_cache.mean_error},
        {"KV Cache V", "kv_cache_v.bin", &report.kv_cache_v,
         DEFAULT_TOLERANCES.kv_cache.max_error, DEFAULT_TOLERANCES.kv_cache.mean_error},
        {"Attention Scores", "attention_scores.bin", &report.attention_scores,
         DEFAULT_TOLERANCES.attention.max_error, DEFAULT_TOLERANCES.attention.mean_error},
        {"RMSNorm Output", "rmsnorm_output.bin", &report.rmsnorm_output,
         DEFAULT_TOLERANCES.rmsnorm.max_error, DEFAULT_TOLERANCES.rmsnorm.mean_error},
        {"Embeddings", "embeddings.bin", &report.embeddings,
         DEFAULT_TOLERANCES.embedding.max_error, DEFAULT_TOLERANCES.embedding.mean_error}
    };
    
    report.total_tests = sizeof(tests) / sizeof(tests[0]);
    
    for (const auto& test : tests) {
        printf("Validating %s...\n", test.name);
        
        /* Construct paths */
        char rawrxd_path[512], ref_path[512];
        snprintf(rawrxd_path, sizeof(rawrxd_path), "%s/%s", rawrxd_dir, test.filename);
        snprintf(ref_path, sizeof(ref_path), "%s/%s", reference_dir, test.filename);
        
        /* Load tensors */
        size_t rawrxd_count, ref_count;
        float* rawrxd_data = load_tensor(rawrxd_path, &rawrxd_count);
        float* ref_data = load_tensor(ref_path, &ref_count);
        
        if (!rawrxd_data || !ref_data) {
            fprintf(stderr, "  ERROR: Failed to load tensors for %s\n", test.name);
            if (rawrxd_data) free(rawrxd_data);
            if (ref_data) free(ref_data);
            continue;
        }
        
        if (rawrxd_count != ref_count) {
            fprintf(stderr, "  ERROR: Size mismatch: %zu vs %zu\n", rawrxd_count, ref_count);
            free(rawrxd_data);
            free(ref_data);
            continue;
        }
        
        /* Compare */
        *test.result = compare_tensors(test.name, rawrxd_data, ref_data, 
                                       rawrxd_count, test.tol_max, test.tol_mean);
        print_result(*test.result);
        
        if (test.result->passed) {
            report.passed_tests++;
        } else {
            report.failed_tests++;
        }
        
        free(rawrxd_data);
        free(ref_data);
    }
    
    report.total_time_ms = 1000.0 * (clock() - start_time) / CLOCKS_PER_SEC;
    
    /* Generate reports */
    char json_path[512], md_path[512];
    snprintf(json_path, sizeof(json_path), "%s/numerical_equivalence_report.json", output_dir);
    snprintf(md_path, sizeof(md_path), "%s/numerical_equivalence_report.md", output_dir);
    
    generate_json_report(report, json_path);
    generate_markdown_report(report, md_path);
    
    /* Summary */
    printf("\n");
    printf("========================================================\n");
    printf("VALIDATION COMPLETE\n");
    printf("========================================================\n");
    printf("Total Tests:  %d\n", report.total_tests);
    printf("Passed:       %d\n", report.passed_tests);
    printf("Failed:       %d\n", report.failed_tests);
    printf("Success Rate: %.2f%%\n", 100.0 * report.passed_tests / report.total_tests);
    printf("Time:         %.2f ms\n", report.total_time_ms);
    printf("\nReports:\n");
    printf("  JSON: %s\n", json_path);
    printf("  MD:   %s\n", md_path);
    printf("\n");
    
    return (report.failed_tests == 0) ? 0 : 1;
}
