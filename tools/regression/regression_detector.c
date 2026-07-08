//=============================================================================
// regression_detector.c - Performance Regression Detector
// Production-ready performance regression detection and alerting
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <math.h>
#include <time.h>

//=============================================================================
// Regression Detection Types
//=============================================================================

#define MAX_BENCHMARKS 256
#define MAX_HISTORY 100
#define REGRESSION_THRESHOLD 1.15  // 15% slowdown threshold

typedef struct {
    char name[256];
    double current_value;
    double baseline_value;
    double change_percent;
    int is_regression;
    int is_improvement;
    double severity;  // 0-1 scale
} BenchmarkComparison;

typedef struct {
    char name[256];
    double values[MAX_HISTORY];
    int value_count;
    double mean;
    double stddev;
    double trend;  // positive = getting slower
} BenchmarkHistory;

typedef struct {
    BenchmarkComparison comparisons[MAX_BENCHMARKS];
    int comparison_count;
    
    BenchmarkHistory histories[MAX_BENCHMARKS];
    int history_count;
    
    int regression_count;
    int improvement_count;
    int stable_count;
    
    time_t analysis_time;
    char baseline_version[64];
    char current_version[64];
} RegressionReport;

//=============================================================================
// Regression Analysis
//=============================================================================

RegressionReport* regression_create_report(const char* baseline_ver, const char* current_ver) {
    RegressionReport* report = (RegressionReport*)calloc(1, sizeof(RegressionReport));
    strncpy(report->baseline_version, baseline_ver, sizeof(report->baseline_version) - 1);
    strncpy(report->current_version, current_ver, sizeof(report->current_version) - 1);
    report->analysis_time = time(NULL);
    return report;
}

void regression_destroy_report(RegressionReport* report) {
    free(report);
}

BenchmarkHistory* get_or_create_history(RegressionReport* report, const char* name) {
    for (int i = 0; i < report->history_count; i++) {
        if (strcmp(report->histories[i].name, name) == 0) {
            return &report->histories[i];
        }
    }
    
    if (report->history_count >= MAX_BENCHMARKS) return NULL;
    
    BenchmarkHistory* hist = &report->histories[report->history_count++];
    strncpy(hist->name, name, sizeof(hist->name) - 1);
    return hist;
}

void add_benchmark_result(RegressionReport* report, const char* name, 
                         double baseline, double current) {
    if (report->comparison_count >= MAX_BENCHMARKS) return;
    
    BenchmarkComparison* comp = &report->comparisons[report->comparison_count++];
    strncpy(comp->name, name, sizeof(comp->name) - 1);
    comp->baseline_value = baseline;
    comp->current_value = current;
    
    // Calculate change
    if (baseline > 0) {
        comp->change_percent = ((current - baseline) / baseline) * 100.0;
    } else {
        comp->change_percent = 0;
    }
    
    // Determine status
    if (comp->change_percent > 15.0) {
        comp->is_regression = 1;
        comp->is_improvement = 0;
        comp->severity = fmin(comp->change_percent / 100.0, 1.0);
        report->regression_count++;
    } else if (comp->change_percent < -15.0) {
        comp->is_regression = 0;
        comp->is_improvement = 1;
        comp->severity = fmin(-comp->change_percent / 100.0, 1.0);
        report->improvement_count++;
    } else {
        comp->is_regression = 0;
        comp->is_improvement = 0;
        comp->severity = 0;
        report->stable_count++;
    }
    
    // Update history
    BenchmarkHistory* hist = get_or_create_history(report, name);
    if (hist && hist->value_count < MAX_HISTORY) {
        hist->values[hist->value_count++] = current;
    }
}

void calculate_trends(RegressionReport* report) {
    for (int i = 0; i < report->history_count; i++) {
        BenchmarkHistory* hist = &report->histories[i];
        
        if (hist->value_count < 2) continue;
        
        // Calculate mean
        double sum = 0;
        for (int j = 0; j < hist->value_count; j++) {
            sum += hist->values[j];
        }
        hist->mean = sum / hist->value_count;
        
        // Calculate stddev
        double variance = 0;
        for (int j = 0; j < hist->value_count; j++) {
            double diff = hist->values[j] - hist->mean;
            variance += diff * diff;
        }
        hist->stddev = sqrt(variance / hist->value_count);
        
        // Calculate trend (linear regression slope)
        if (hist->value_count >= 5) {
            double n = hist->value_count;
            double sum_x = 0, sum_y = 0, sum_xy = 0, sum_x2 = 0;
            
            for (int j = 0; j < hist->value_count; j++) {
                sum_x += j;
                sum_y += hist->values[j];
                sum_xy += j * hist->values[j];
                sum_x2 += j * j;
            }
            
            hist->trend = (n * sum_xy - sum_x * sum_y) / (n * sum_x2 - sum_x * sum_x);
        }
    }
}

//=============================================================================
// Report Generation
//=============================================================================

void print_regression_summary(RegressionReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Performance Regression Analysis\n");
    printf("=============================================================================\n");
    printf("  Baseline:   %s\n", report->baseline_version);
    printf("  Current:    %s\n", report->current_version);
    printf("  Time:       %s", ctime(&report->analysis_time));
    printf("\n");
    printf("  Summary:\n");
    printf("    Regressions:   %d\n", report->regression_count);
    printf("    Improvements:  %d\n", report->improvement_count);
    printf("    Stable:        %d\n", report->stable_count);
    printf("    Total:         %d\n", report->comparison_count);
    printf("=============================================================================\n");
}

void print_regressions(RegressionReport* report) {
    if (report->regression_count == 0) {
        printf("\n✅ No performance regressions detected!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  ⚠️  Performance Regressions (%d)\n", report->regression_count);
    printf("=============================================================================\n");
    printf("  %-40s %10s %10s %10s\n", "Benchmark", "Baseline", "Current", "Change");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->comparison_count; i++) {
        BenchmarkComparison* comp = &report->comparisons[i];
        if (comp->is_regression) {
            printf("  %-40s %10.2f %10.2f %+.1f%%\n",
                   comp->name, comp->baseline_value, 
                   comp->current_value, comp->change_percent);
        }
    }
    
    printf("=============================================================================\n");
}

void print_improvements(RegressionReport* report) {
    if (report->improvement_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  ✅ Performance Improvements (%d)\n", report->improvement_count);
    printf("=============================================================================\n");
    printf("  %-40s %10s %10s %10s\n", "Benchmark", "Baseline", "Current", "Change");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->comparison_count; i++) {
        BenchmarkComparison* comp = &report->comparisons[i];
        if (comp->is_improvement) {
            printf("  %-40s %10.2f %10.2f %+.1f%%\n",
                   comp->name, comp->baseline_value,
                   comp->current_value, comp->change_percent);
        }
    }
    
    printf("=============================================================================\n");
}

void export_regression_json(RegressionReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"baseline_version\": \"%s\",\n", report->baseline_version);
    fprintf(f, "  \"current_version\": \"%s\",\n", report->current_version);
    fprintf(f, "  \"analysis_time\": %ld,\n", (long)report->analysis_time);
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_benchmarks\": %d,\n", report->comparison_count);
    fprintf(f, "    \"regressions\": %d,\n", report->regression_count);
    fprintf(f, "    \"improvements\": %d,\n", report->improvement_count);
    fprintf(f, "    \"stable\": %d\n", report->stable_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"comparisons\": [\n");
    
    for (int i = 0; i < report->comparison_count; i++) {
        BenchmarkComparison* comp = &report->comparisons[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", comp->name);
        fprintf(f, "      \"baseline\": %.6f,\n", comp->baseline_value);
        fprintf(f, "      \"current\": %.6f,\n", comp->current_value);
        fprintf(f, "      \"change_percent\": %.2f,\n", comp->change_percent);
        fprintf(f, "      \"is_regression\": %s,\n", comp->is_regression ? "true" : "false");
        fprintf(f, "      \"is_improvement\": %s,\n", comp->is_improvement ? "true" : "false");
        fprintf(f, "      \"severity\": %.2f\n", comp->severity);
        fprintf(f, "    }%s\n", (i < report->comparison_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Regression report exported: %s\n", filename);
}

void generate_html_report(RegressionReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "<!DOCTYPE html>\n");
    fprintf(f, "<html>\u003chead>\u003ctitle>Performance Regression Report</title>\u003c/head>\u003cbody>\n");
    fprintf(f, "<h1>Performance Regression Report</h1>\n");
    fprintf(f, "<p>Baseline: %s -> Current: %s</p>\n", 
            report->baseline_version, report->current_version);
    
    fprintf(f, "<h2>Summary</h2>\n");
    fprintf(f, "<ul>\n");
    fprintf(f, "  <li>Regressions: %d</li>\n", report->regression_count);
    fprintf(f, "  <li>Improvements: %d</li>\n", report->improvement_count);
    fprintf(f, "  <li>Stable: %d</li>\n", report->stable_count);
    fprintf(f, "</ul>\n");
    
    if (report->regression_count > 0) {
        fprintf(f, "<h2 style='color: red'>⚠️ Regressions</h2>\n");
        fprintf(f, "<table border='1'>\n");
        fprintf(f, "<tr><th>Benchmark</th><th>Baseline</th><th>Current</th><th>Change</th></tr>\n");
        
        for (int i = 0; i < report->comparison_count; i++) {
            if (report->comparisons[i].is_regression) {
                BenchmarkComparison* comp = &report->comparisons[i];
                fprintf(f, "<tr><td>%s</td><td>%.2f</td><td>%.2f</td><td style='color: red'>+%.1f%%</td></tr>\n",
                        comp->name, comp->baseline_value, comp->current_value, comp->change_percent);
            }
        }
        fprintf(f, "</table>\n");
    }
    
    fprintf(f, "</body></html>\n");
    fclose(f);
    printf("  HTML report generated: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Performance Regression Detector\n");
    printf("=======================================\n\n");
    
    RegressionReport* report = regression_create_report("v1.0.0", "v1.1.0");
    
    // Simulate benchmark comparisons
    add_benchmark_result(report, "assembler_100_lines", 45.2, 48.5);
    add_benchmark_result(report, "assembler_500_lines", 210.5, 215.3);
    add_benchmark_result(report, "linker_single_obj", 12.3, 12.1);
    add_benchmark_result(report, "linker_multi_obj", 45.7, 38.2);
    add_benchmark_result(report, "pipeline_small", 120.0, 125.4);
    add_benchmark_result(report, "pipeline_large", 4500.0, 4200.0);
    add_benchmark_result(report, "test_framework_init", 5.2, 5.3);
    add_benchmark_result(report, "parser_expression", 0.8, 1.2);
    add_benchmark_result(report, "memory_allocation", 2.5, 2.4);
    add_benchmark_result(report, "file_io", 15.3, 15.5);
    
    calculate_trends(report);
    
    // Generate reports
    print_regression_summary(report);
    print_regressions(report);
    print_improvements(report);
    
    export_regression_json(report, "regression_report.json");
    generate_html_report(report, "regression_report.html");
    
    printf("\nRegression detection complete!\n");
    
    int exit_code = (report->regression_count > 0) ? 1 : 0;
    regression_destroy_report(report);
    
    return exit_code;
}
