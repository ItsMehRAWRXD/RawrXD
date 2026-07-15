//=============================================================================
// rawrxd_validate_report.c
// Report Generation Module
//=============================================================================

#include "rawrxd_validate.h"
#include <stdio.h>
#include <string.h>
#include <time.h>

static void get_timestamp(char* buf, size_t len) {
    time_t now = time(NULL);
    struct tm* tm_info = localtime(&now);
    strftime(buf, len, "%Y-%m-%d %H:%M:%S", tm_info);
}

static void get_cpu_info(char* buf, size_t len) {
    // Simplified CPU info - would query actual CPU on real implementation
    strncpy(buf, "x86_64 (AVX2 supported)", len);
}

rawrxd_validation_report* rawrxd_validate_create_report(void) {
    rawrxd_validation_report* report = rawrxd_alloc(sizeof(rawrxd_validation_report));
    if (!report) return NULL;
    
    memset(report, 0, sizeof(*report));
    
    get_timestamp(report->timestamp, sizeof(report->timestamp));
    strncpy(report->rawrxd_version, "1.0.0", sizeof(report->rawrxd_version));
    get_cpu_info(report->cpu_info, sizeof(report->cpu_info));
    
    // Allocate space for suites (max 10)
    report->suites = rawrxd_alloc(10 * sizeof(rawrxd_test_suite));
    if (!report->suites) {
        rawrxd_free(report, sizeof(*report));
        return NULL;
    }
    
    return report;
}

void rawrxd_validate_add_suite_to_report(rawrxd_validation_report* report, 
                                          rawrxd_test_suite* suite) {
    if (!report || !suite || report->num_suites >= 10) return;
    
    rawrxd_test_suite* suites = (rawrxd_test_suite*)report->suites;
    memcpy(&suites[report->num_suites], suite, sizeof(rawrxd_test_suite));
    report->num_suites++;
    
    // Update totals
    report->total_tests += suite->total;
    report->passed_tests += suite->passed;
    report->failed_tests += suite->failed;
    report->skipped_tests += suite->skipped;
    report->total_time_ms += suite->total_time_ms;
}

void rawrxd_validate_export_json(const rawrxd_validation_report* report, const char* path) {
    if (!report || !path) return;
    
    FILE* f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", path);
        return;
    }
    
    fprintf(f, "{\n");
    fprintf(f, "  \"timestamp\": \"%s\",\n", report->timestamp);
    fprintf(f, "  \"rawrxd_version\": \"%s\",\n", report->rawrxd_version);
    fprintf(f, "  \"cpu_info\": \"%s\",\n", report->cpu_info);
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_tests\": %u,\n", report->total_tests);
    fprintf(f, "    \"passed_tests\": %u,\n", report->passed_tests);
    fprintf(f, "    \"failed_tests\": %u,\n", report->failed_tests);
    fprintf(f, "    \"skipped_tests\": %u,\n", report->skipped_tests);
    fprintf(f, "    \"pass_rate\": %.2f,\n", 
            report->total_tests > 0 ? (100.0f * report->passed_tests / report->total_tests) : 0);
    fprintf(f, "    \"total_time_ms\": %.2f\n", report->total_time_ms);
    fprintf(f, "  },\n");
    fprintf(f, "  \"suites\": [\n");
    
    rawrxd_test_suite* suites = (rawrxd_test_suite*)report->suites;
    for (u32 i = 0; i < report->num_suites; i++) {
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", suites[i].name);
        fprintf(f, "      \"total\": %u,\n", suites[i].total);
        fprintf(f, "      \"passed\": %u,\n", suites[i].passed);
        fprintf(f, "      \"failed\": %u,\n", suites[i].failed);
        fprintf(f, "      \"skipped\": %u,\n", suites[i].skipped);
        fprintf(f, "      \"time_ms\": %.2f\n", suites[i].total_time_ms);
        fprintf(f, "    }%s\n", i < report->num_suites - 1 ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("JSON report exported to: %s\n", path);
}

void rawrxd_validate_export_html(const rawrxd_validation_report* report, const char* path) {
    if (!report || !path) return;
    
    FILE* f = fopen(path, "w");
    if (!f) {
        fprintf(stderr, "Failed to open %s for writing\n", path);
        return;
    }
    
    float pass_rate = report->total_tests > 0 ? 
        (100.0f * report->passed_tests / report->total_tests) : 0;
    
    const char* status_color = report->failed_tests == 0 ? "#28a745" : "#dc3545";
    const char* status_text = report->failed_tests == 0 ? "PASSED" : "FAILED";
    
    fprintf(f, "<!DOCTYPE html>\n");
    fprintf(f, "<html>\n");
    fprintf(f, "<head>\n");
    fprintf(f, "<title>RawrXD Validation Report</title>\n");
    fprintf(f, "<style>\n");
    fprintf(f, "body { font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 40px; background: #f5f5f5; }\n");
    fprintf(f, ".container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; border-radius: 8px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
    fprintf(f, "h1 { color: #333; border-bottom: 2px solid #e0e0e0; padding-bottom: 10px; }\n");
    fprintf(f, ".status { display: inline-block; padding: 10px 20px; border-radius: 4px; color: white; font-weight: bold; font-size: 18px; }\n");
    fprintf(f, ".summary { display: grid; grid-template-columns: repeat(auto-fit, minmax(200px, 1fr)); gap: 20px; margin: 20px 0; }\n");
    fprintf(f, ".metric { background: #f8f9fa; padding: 15px; border-radius: 6px; text-align: center; }\n");
    fprintf(f, ".metric-value { font-size: 32px; font-weight: bold; color: #333; }\n");
    fprintf(f, ".metric-label { font-size: 14px; color: #666; margin-top: 5px; }\n");
    fprintf(f, ".suite { background: #f8f9fa; margin: 10px 0; padding: 15px; border-radius: 6px; border-left: 4px solid #007bff; }\n");
    fprintf(f, ".suite-header { font-weight: bold; margin-bottom: 10px; }\n");
    fprintf(f, ".suite-stats { display: flex; gap: 20px; font-size: 14px; color: #666; }\n");
    fprintf(f, ".pass { color: #28a745; }\n");
    fprintf(f, ".fail { color: #dc3545; }\n");
    fprintf(f, ".skip { color: #ffc107; }\n");
    fprintf(f, "</style>\n");
    fprintf(f, "</head>\n");
    fprintf(f, "<body>\n");
    fprintf(f, "<div class='container'>\n");
    
    // Header
    fprintf(f, "<h1>RawrXD Validation Report</h1>\n");
    fprintf(f, "<div class='status' style='background: %s;'>%s</div>\n", status_color, status_text);
    fprintf(f, "<p><strong>Timestamp:</strong> %s</p>\n", report->timestamp);
    fprintf(f, "<p><strong>Version:</strong> %s</p>\n", report->rawrxd_version);
    fprintf(f, "<p><strong>CPU:</strong> %s</p>\n", report->cpu_info);
    
    // Summary metrics
    fprintf(f, "<div class='summary'>\n");
    fprintf(f, "<div class='metric'><div class='metric-value'>%u</div><div class='metric-label'>Total Tests</div></div>\n", report->total_tests);
    fprintf(f, "<div class='metric'><div class='metric-value pass'>%u</div><div class='metric-label'>Passed</div></div>\n", report->passed_tests);
    fprintf(f, "<div class='metric'><div class='metric-value fail'>%u</div><div class='metric-label'>Failed</div></div>\n", report->failed_tests);
    fprintf(f, "<div class='metric'><div class='metric-value skip'>%u</div><div class='metric-label'>Skipped</div></div>\n", report->skipped_tests);
    fprintf(f, "<div class='metric'><div class='metric-value'>%.1f%%</div><div class='metric-label'>Pass Rate</div></div>\n", pass_rate);
    fprintf(f, "<div class='metric'><div class='metric-value'>%.2f</div><div class='metric-label'>Time (ms)</div></div>\n", report->total_time_ms);
    fprintf(f, "</div>\n");
    
    // Suites
    fprintf(f, "<h2>Test Suites</h2>\n");
    rawrxd_test_suite* suites = (rawrxd_test_suite*)report->suites;
    for (u32 i = 0; i < report->num_suites; i++) {
        float suite_pass_rate = suites[i].total > 0 ? 
            (100.0f * suites[i].passed / suites[i].total) : 0;
        fprintf(f, "<div class='suite'>\n");
        fprintf(f, "<div class='suite-header'>%s</div>\n", suites[i].name);
        fprintf(f, "<div class='suite-stats'>\n");
        fprintf(f, "<span><strong>Total:</strong> %u</span>\n", suites[i].total);
        fprintf(f, "<span class='pass'><strong>Passed:</strong> %u</span>\n", suites[i].passed);
        fprintf(f, "<span class='fail'><strong>Failed:</strong> %u</span>\n", suites[i].failed);
        fprintf(f, "<span class='skip'><strong>Skipped:</strong> %u</span>\n", suites[i].skipped);
        fprintf(f, "<span><strong>Pass Rate:</strong> %.1f%%</span>\n", suite_pass_rate);
        fprintf(f, "<span><strong>Time:</strong> %.2f ms</span>\n", suites[i].total_time_ms);
        fprintf(f, "</div>\n");
        fprintf(f, "</div>\n");
    }
    
    fprintf(f, "</div>\n");
    fprintf(f, "</body>\n");
    fprintf(f, "</html>\n");
    
    fclose(f);
    printf("HTML report exported to: %s\n", path);
}

void rawrxd_validate_print_report(const rawrxd_validation_report* report) {
    if (!report) return;
    
    float pass_rate = report->total_tests > 0 ? 
        (100.0f * report->passed_tests / report->total_tests) : 0;
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║                 VALIDATION REPORT SUMMARY                      ║\n");
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ Timestamp: %-51s ║\n", report->timestamp);
    printf("║ Version:   %-51s ║\n", report->rawrxd_version);
    printf("║ CPU:       %-51s ║\n", report->cpu_info);
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ Total Tests:  %5u                                            ║\n", report->total_tests);
    printf("║ Passed:      %5u  ✓                                          ║\n", report->passed_tests);
    printf("║ Failed:      %5u  %s                                          ║\n", 
           report->failed_tests, report->failed_tests > 0 ? "✗" : " ");
    printf("║ Skipped:     %5u  ⊘                                          ║\n", report->skipped_tests);
    printf("║ Pass Rate:   %5.1f%%                                          ║\n", pass_rate);
    printf("║ Time:        %8.2f ms                                       ║\n", report->total_time_ms);
    printf("╠════════════════════════════════════════════════════════════════╣\n");
    printf("║ Status: %-56s ║\n", report->failed_tests == 0 ? "✓ ALL TESTS PASSED" : "✗ SOME TESTS FAILED");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
}

void rawrxd_validate_free_report(rawrxd_validation_report* report) {
    if (!report) return;
    if (report->suites) {
        rawrxd_free(report->suites, 10 * sizeof(rawrxd_test_suite));
    }
    rawrxd_free(report, sizeof(*report));
}
