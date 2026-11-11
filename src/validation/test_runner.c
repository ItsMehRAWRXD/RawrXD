//=============================================================================
// test_runner.c
// Standalone Test Runner for RawrXD Validation
// Can be built and run independently
//=============================================================================

#include "rawrxd_validate.h"
#include <stdio.h>
#include <string.h>

//=============================================================================
// Test Runner Entry Point
//=============================================================================

int main(int argc, char** argv) {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD Test Runner v1.0.0                                    ║\n");
    printf("║  Standalone Validation Suite                                  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Parse arguments
    const char* model_path = NULL;
    const char* output_path = NULL;
    bool verbose = false;
    bool kernel_only = false;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-m") == 0 || strcmp(argv[i], "--model") == 0) {
            if (i + 1 < argc) model_path = argv[++i];
        } else if (strcmp(argv[i], "-o") == 0 || strcmp(argv[i], "--output") == 0) {
            if (i + 1 < argc) output_path = argv[++i];
        } else if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            verbose = true;
        } else if (strcmp(argv[i], "--kernel-only") == 0) {
            kernel_only = true;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            printf("Usage: test_runner [options]\n\n");
            printf("Options:\n");
            printf("  -m, --model <path>    Test model path\n");
            printf("  -o, --output <path>   Output report path\n");
            printf("  -v, --verbose         Verbose output\n");
            printf("  --kernel-only         Run only kernel tests\n");
            printf("  -h, --help            Show this help\n");
            return 0;
        }
    }
    
    // Initialize
    printf("Initializing RawrXD runtime...\n");
    rawrxd_result result = rawrxd_init();
    if (result != RAWRXD_OK) {
        fprintf(stderr, "Failed to initialize: %d\n", result);
        return 1;
    }
    printf("Initialized successfully.\n\n");
    
    // Create report
    rawrxd_validation_report* report = rawrxd_validate_create_report();
    if (!report) {
        fprintf(stderr, "Failed to create validation report\n");
        rawrxd_shutdown();
        return 1;
    }
    
    // Run validation suites
    printf("Running validation suites...\n\n");
    
    // Always run unit tests
    rawrxd_test_suite* unit_suite = rawrxd_validate_unit_suite();
    if (unit_suite) {
        rawrxd_validate_add_suite_to_report(report, unit_suite);
        rawrxd_free(unit_suite, sizeof(*unit_suite));
    }
    
    // Always run kernel tests
    rawrxd_test_suite* kernel_suite = rawrxd_validate_kernel_suite();
    if (kernel_suite) {
        rawrxd_validate_add_suite_to_report(report, kernel_suite);
        rawrxd_free(kernel_suite, sizeof(*kernel_suite));
    }
    
    // Extended kernel tests
    rawrxd_test_suite* ext_kernel_suite = rawrxd_validate_extended_kernel_suite();
    if (ext_kernel_suite) {
        rawrxd_validate_add_suite_to_report(report, ext_kernel_suite);
        rawrxd_free(ext_kernel_suite, sizeof(*ext_kernel_suite));
    }
    
    if (!kernel_only) {
        // GGUF suite (if model provided)
        if (model_path) {
            rawrxd_test_suite* gguf_suite = rawrxd_validate_gguf_suite(model_path);
            if (gguf_suite) {
                rawrxd_validate_add_suite_to_report(report, gguf_suite);
                rawrxd_free(gguf_suite, sizeof(*gguf_suite));
            }
            
            // Inference suite
            rawrxd_test_suite* inference_suite = rawrxd_validate_inference_suite(model_path);
            if (inference_suite) {
                rawrxd_validate_add_suite_to_report(report, inference_suite);
                rawrxd_free(inference_suite, sizeof(*inference_suite));
            }
        } else {
            printf("[INFO] No model provided, skipping GGUF and inference tests.\n");
            printf("       Use -m <model.gguf> for full validation.\n\n");
        }
        
        // Stress suite
        rawrxd_test_suite* stress_suite = rawrxd_validate_stress_suite(model_path);
        if (stress_suite) {
            rawrxd_validate_add_suite_to_report(report, stress_suite);
            rawrxd_free(stress_suite, sizeof(*stress_suite));
        }
    }
    
    // Print and export report
    rawrxd_validate_print_report(report);
    
    if (output_path) {
        // Export JSON
        char json_path[512];
        snprintf(json_path, sizeof(json_path), "%s.json", output_path);
        rawrxd_validate_export_json(report, json_path);
        
        // Export HTML
        char html_path[512];
        snprintf(html_path, sizeof(html_path), "%s.html", output_path);
        rawrxd_validate_export_html(report, html_path);
        
        printf("Reports exported to:\n");
        printf("  JSON: %s\n", json_path);
        printf("  HTML: %s\n", html_path);
    }
    
    int exit_code = (report->failed_tests > 0) ? 1 : 0;
    rawrxd_validate_free_report(report);
    rawrxd_shutdown();
    
    printf("\nTest runner exiting with code %d\n", exit_code);
    return exit_code;
}
