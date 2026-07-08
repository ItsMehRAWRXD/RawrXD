//=============================================================================
// report_aggregator.c - Report Aggregator
// Production-ready aggregation of all tool outputs with dashboard generation
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Report Aggregation Types
//=============================================================================

#define MAX_REPORTS 50
#define MAX_METRICS 100
#define MAX_ALERTS 50

typedef enum {
    REPORT_BUILD,
    REPORT_TEST,
    REPORT_SECURITY,
    REPORT_PERFORMANCE,
    REPORT_COVERAGE,
    REPORT_DEPLOYMENT,
    REPORT_CUSTOM
} ReportType;

typedef struct {
    char name[128];
    char file[512];
    ReportType type;
    time_t timestamp;
    int success;
    int warnings;
    int errors;
    double duration_ms;
    char summary[1024];
} ToolReport;

typedef struct {
    char name[128];
    double value;
    char unit[32];
    int status;  // 0=fail, 1=warn, 2=pass
    double threshold_warn;
    double threshold_fail;
    char description[512];
} Metric;

typedef struct {
    char message[1024];
    char source[128];
    int severity;  // 0=info, 1=warn, 2=error, 3=critical
    time_t timestamp;
} Alert;

typedef struct {
    ToolReport* reports;
    int report_count;
    int report_capacity;
    
    Metric* metrics;
    int metric_count;
    int metric_capacity;
    
    Alert* alerts;
    int alert_count;
    int alert_capacity;
    
    // Aggregated stats
    int total_reports;
    int successful_reports;
    int failed_reports;
    int warning_reports;
    
    int total_tests;
    int passed_tests;
    int failed_tests;
    
    int security_issues;
    int critical_issues;
    int high_issues;
    int medium_issues;
    int low_issues;
    
    double total_build_time;
    double avg_test_duration;
    double code_coverage_percent;
    double test_success_rate;
    
    int overall_health;  // 0=fail, 1=degraded, 2=healthy
    char health_summary[1024];
    
    time_t generated_at;
} AggregationReport;

//=============================================================================
// Report Aggregation Implementation
//=============================================================================

AggregationReport* aggregation_create(void) {
    AggregationReport* report = (AggregationReport*)calloc(1, sizeof(AggregationReport));
    report->report_capacity = MAX_REPORTS;
    report->reports = (ToolReport*)calloc(report->report_capacity, sizeof(ToolReport));
    report->metric_capacity = MAX_METRICS;
    report->metrics = (Metric*)calloc(report->metric_capacity, sizeof(Metric));
    report->alert_capacity = MAX_ALERTS;
    report->alerts = (Alert*)calloc(report->alert_capacity, sizeof(Alert));
    report->generated_at = time(NULL);
    report->overall_health = 2;  // Start healthy
    return report;
}

void aggregation_destroy(AggregationReport* report) {
    if (!report) return;
    free(report->reports);
    free(report->metrics);
    free(report->alerts);
    free(report);
}

void add_report(AggregationReport* report, const char* name, ReportType type,
                int success, int warnings, int errors, double duration) {
    if (report->report_count >= report->report_capacity) return;
    
    ToolReport* tr = &report->reports[report->report_count++];
    strncpy(tr->name, name, sizeof(tr->name) - 1);
    tr->type = type;
    tr->success = success;
    tr->warnings = warnings;
    tr->errors = errors;
    tr->duration_ms = duration;
    tr->timestamp = time(NULL);
    
    // Update aggregated stats
    report->total_reports++;
    if (success) {
        report->successful_reports++;
    } else {
        report->failed_reports++;
    }
    if (warnings > 0) {
        report->warning_reports++;
    }
    
    // Update health
    if (!success) {
        report->overall_health = 0;  // Fail
    } else if (warnings > 0 && report->overall_health == 2) {
        report->overall_health = 1;  // Degraded
    }
}

void add_metric(AggregationReport* report, const char* name, double value,
                const char* unit, double threshold_warn, double threshold_fail) {
    if (report->metric_count >= report->metric_capacity) return;
    
    Metric* m = &report->metrics[report->metric_count++];
    strncpy(m->name, name, sizeof(m->name) - 1);
    m->value = value;
    strncpy(m->unit, unit, sizeof(m->unit) - 1);
    m->threshold_warn = threshold_warn;
    m->threshold_fail = threshold_fail;
    
    // Determine status
    if (threshold_fail > 0 && value >= threshold_fail) {
        m->status = 0;  // Fail
    } else if (threshold_warn > 0 && value >= threshold_warn) {
        m->status = 1;  // Warn
    } else {
        m->status = 2;  // Pass
    }
}

void add_alert(AggregationReport* report, const char* message, const char* source, int severity) {
    if (report->alert_count >= report->alert_capacity) return;
    
    Alert* a = &report->alerts[report->alert_count++];
    strncpy(a->message, message, sizeof(a->message) - 1);
    strncpy(a->source, source, sizeof(a->source) - 1);
    a->severity = severity;
    a->timestamp = time(NULL);
    
    // Update health based on severity
    if (severity >= 2 && report->overall_health > 0) {
        report->overall_health = 0;
    } else if (severity == 1 && report->overall_health == 2) {
        report->overall_health = 1;
    }
}

void simulate_reports(AggregationReport* report) {
    // Simulate various tool reports
    add_report(report, "Build System", REPORT_BUILD, 1, 0, 0, 45000.0);
    add_report(report, "Unit Tests", REPORT_TEST, 1, 2, 0, 12000.0);
    add_report(report, "Security Scan", REPORT_SECURITY, 1, 5, 0, 8000.0);
    add_report(report, "Performance Benchmark", REPORT_PERFORMANCE, 1, 0, 0, 25000.0);
    add_report(report, "Code Coverage", REPORT_COVERAGE, 1, 0, 0, 5000.0);
    add_report(report, "Deployment", REPORT_DEPLOYMENT, 1, 0, 0, 30000.0);
    
    // Add metrics
    add_metric(report, "Build Time", 45.0, "s", 60.0, 120.0);
    add_metric(report, "Test Success Rate", 98.5, "%", 95.0, 90.0);
    add_metric(report, "Code Coverage", 87.3, "%", 80.0, 70.0);
    add_metric(report, "Security Issues", 5.0, "count", 10.0, 20.0);
    add_metric(report, "Avg Response Time", 45.2, "ms", 100.0, 500.0);
    add_metric(report, "Memory Usage", 512.0, "MB", 1024.0, 2048.0);
    add_metric(report, "Bundle Size", 2.4, "MB", 5.0, 10.0);
    
    // Add alerts
    add_alert(report, "2 tests have warnings", "Unit Tests", 1);
    add_alert(report, "5 low severity security findings", "Security Scan", 0);
    add_alert(report, "Code coverage above threshold", "Code Coverage", 2);
}

void calculate_aggregates(AggregationReport* report) {
    // Calculate derived metrics
    if (report->total_reports > 0) {
        report->test_success_rate = (double)report->successful_reports / report->total_reports * 100.0;
    }
    
    // Count issues by severity
    for (int i = 0; i < report->alert_count; i++) {
        switch (report->alerts[i].severity) {
            case 3: report->critical_issues++; break;
            case 2: report->high_issues++; break;
            case 1: report->medium_issues++; break;
            case 0: report->low_issues++; break;
        }
        report->security_issues++;
    }
    
    // Generate health summary
    switch (report->overall_health) {
        case 2:
            strncpy(report->health_summary, "✅ All systems operational", sizeof(report->health_summary) - 1);
            break;
        case 1:
            strncpy(report->health_summary, "⚠️ Degraded performance - warnings present", 
                    sizeof(report->health_summary) - 1);
            break;
        case 0:
            strncpy(report->health_summary, "❌ Critical issues detected", 
                    sizeof(report->health_summary) - 1);
            break;
    }
}

//=============================================================================
// Report Generation
//=============================================================================

const char* report_type_to_string(ReportType type) {
    switch (type) {
        case REPORT_BUILD: return "Build";
        case REPORT_TEST: return "Test";
        case REPORT_SECURITY: return "Security";
        case REPORT_PERFORMANCE: return "Performance";
        case REPORT_COVERAGE: return "Coverage";
        case REPORT_DEPLOYMENT: return "Deployment";
        case REPORT_CUSTOM: return "Custom";
        default: return "Unknown";
    }
}

const char* health_status_to_string(int health) {
    switch (health) {
        case 2: return "✅ HEALTHY";
        case 1: return "⚠️ DEGRADED";
        case 0: return "❌ FAILED";
        default: return "❓ UNKNOWN";
    }
}

const char* severity_to_string(int severity) {
    switch (severity) {
        case 3: return "CRITICAL";
        case 2: return "ERROR";
        case 1: return "WARNING";
        case 0: return "INFO";
        default: return "UNKNOWN";
    }
}

void print_aggregation_summary(AggregationReport* report) {
    calculate_aggregates(report);
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  RawrXD Report Aggregation Summary\n");
    printf("=============================================================================\n");
    printf("  Generated:              %s", ctime(&report->generated_at));
    printf("  Overall Health:         %s\n", health_status_to_string(report->overall_health));
    printf("  Health Summary:         %s\n", report->health_summary);
    printf("\n");
    printf("  Reports:\n");
    printf("    Total:                %d\n", report->total_reports);
    printf("    Successful:           %d\n", report->successful_reports);
    printf("    Failed:               %d\n", report->failed_reports);
    printf("    With Warnings:        %d\n", report->warning_reports);
    printf("    Success Rate:         %.1f%%\n", report->test_success_rate);
    printf("\n");
    printf("  Issues:\n");
    printf("    Critical:             %d\n", report->critical_issues);
    printf("    High:                 %d\n", report->high_issues);
    printf("    Medium:               %d\n", report->medium_issues);
    printf("    Low:                  %d\n", report->low_issues);
    printf("=============================================================================\n");
}

void print_metrics_dashboard(AggregationReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Metrics Dashboard\n");
    printf("=============================================================================\n");
    
    if (report->metric_count == 0) {
        printf("\n  No metrics available.\n");
        return;
    }
    
    printf("\n  %-25s %-12s %-10s %-10s\n", "Metric", "Value", "Status", "Threshold");
    printf("  %-25s %-12s %-10s %-10s\n", "------", "-----", "------", "---------");
    
    for (int i = 0; i < report->metric_count; i++) {
        Metric* m = &report->metrics[i];
        char value_str[64];
        snprintf(value_str, sizeof(value_str), "%.2f %s", m->value, m->unit);
        
        const char* status = m->status == 2 ? "✓ PASS" : 
                             m->status == 1 ? "⚠ WARN" : "✗ FAIL";
        
        char threshold_str[32];
        if (m->threshold_fail > 0) {
            snprintf(threshold_str, sizeof(threshold_str), "<%.1f", m->threshold_fail);
        } else {
            strcpy(threshold_str, "N/A");
        }
        
        printf("  %-25s %-12s %-10s %-10s\n", m->name, value_str, status, threshold_str);
    }
    
    printf("\n=============================================================================\n");
}

void print_alerts(AggregationReport* report) {
    if (report->alert_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Active Alerts (%d)\n", report->alert_count);
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->alert_count; i++) {
        Alert* a = &report->alerts[i];
        printf("\n  [%s] %s\n", severity_to_string(a->severity), a->source);
        printf("       %s\n", a->message);
    }
    
    printf("\n=============================================================================\n");
}

void generate_html_dashboard(AggregationReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "<!DOCTYPE html>\n");
    fprintf(f, "<html>\n");
    fprintf(f, "<head>\n");
    fprintf(f, "  <title>RawrXD Dashboard</title>\n");
    fprintf(f, "  <style>\n");
    fprintf(f, "    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }\n");
    fprintf(f, "    .header { background: #333; color: white; padding: 20px; border-radius: 5px; }\n");
    fprintf(f, "    .card { background: white; margin: 10px 0; padding: 20px; border-radius: 5px; box-shadow: 0 2px 4px rgba(0,0,0,0.1); }\n");
    fprintf(f, "    .metric { display: inline-block; margin: 10px 20px; text-align: center; }\n");
    fprintf(f, "    .metric-value { font-size: 24px; font-weight: bold; }\n");
    fprintf(f, "    .metric-label { font-size: 12px; color: #666; }\n");
    fprintf(f, "    .pass { color: #28a745; }\n");
    fprintf(f, "    .warn { color: #ffc107; }\n");
    fprintf(f, "    .fail { color: #dc3545; }\n");
    fprintf(f, "    table { width: 100%%; border-collapse: collapse; }\n");
    fprintf(f, "    th, td { padding: 10px; text-align: left; border-bottom: 1px solid #ddd; }\n");
    fprintf(f, "    th { background: #f8f9fa; }\n");
    fprintf(f, "  </style>\n");
    fprintf(f, "</head>\n");
    fprintf(f, "<body>\n");
    
    // Header
    fprintf(f, "  <div class='header'>\n");
    fprintf(f, "    <h1>RawrXD Production Dashboard</h1>\n");
    fprintf(f, "    <p>Generated: %s</p>\n", ctime(&report->generated_at));
    fprintf(f, "    <p>Status: %s</p>\n", health_status_to_string(report->overall_health));
    fprintf(f, "  </div>\n");
    
    // Summary metrics
    fprintf(f, "  <div class='card'>\n");
    fprintf(f, "    <h2>Summary</h2>\n");
    fprintf(f, "    <div class='metric'>\n");
    fprintf(f, "      <div class='metric-value'>%d</div>\n", report->total_reports);
    fprintf(f, "      <div class='metric-label'>Reports</div>\n");
    fprintf(f, "    </div>\n");
    fprintf(f, "    <div class='metric'>\n");
    fprintf(f, "      <div class='metric-value %s'>%.1f%%</div>\n",
            report->test_success_rate >= 90 ? "pass" : "warn", report->test_success_rate);
    fprintf(f, "      <div class='metric-label'>Success Rate</div>\n");
    fprintf(f, "    </div>\n");
    fprintf(f, "    <div class='metric'>\n");
    fprintf(f, "      <div class='metric-value %s'>%d</div>\n",
            report->security_issues == 0 ? "pass" : "warn", report->security_issues);
    fprintf(f, "      <div class='metric-label'>Issues</div>\n");
    fprintf(f, "    </div>\n");
    fprintf(f, "  </div>\n");
    
    // Metrics table
    fprintf(f, "  <div class='card'>\n");
    fprintf(f, "    <h2>Metrics</h2>\n");
    fprintf(f, "    <table>\n");
    fprintf(f, "      <tr><th>Metric</th><th>Value</th><th>Status</th></tr>\n");
    
    for (int i = 0; i < report->metric_count; i++) {
        Metric* m = &report->metrics[i];
        const char* status_class = m->status == 2 ? "pass" : 
                                   m->status == 1 ? "warn" : "fail";
        const char* status_text = m->status == 2 ? "PASS" : 
                                  m->status == 1 ? "WARN" : "FAIL";
        
        fprintf(f, "      <tr>\n");
        fprintf(f, "        <td>%s</td>\n", m->name);
        fprintf(f, "        <td>%.2f %s</td>\n", m->value, m->unit);
        fprintf(f, "        <td class='%s'>%s</td>\n", status_class, status_text);
        fprintf(f, "      </tr>\n");
    }
    
    fprintf(f, "    </table>\n");
    fprintf(f, "  </div>\n");
    
    // Alerts
    if (report->alert_count > 0) {
        fprintf(f, "  <div class='card'>\n");
        fprintf(f, "    <h2>Alerts (%d)</h2>\n", report->alert_count);
        fprintf(f, "    <ul>\n");
        
        for (int i = 0; i < report->alert_count; i++) {
            Alert* a = &report->alerts[i];
            fprintf(f, "      <li>[%s] %s: %s</li>\n", 
                    severity_to_string(a->severity), a->source, a->message);
        }
        
        fprintf(f, "    </ul>\n");
        fprintf(f, "  </div>\n");
    }
    
    fprintf(f, "</body>\n");
    fprintf(f, "</html>\n");
    
    fclose(f);
    printf("  HTML dashboard exported: %s\n", filename);
}

void export_aggregation_json(AggregationReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"generated_at\": %ld,\n", (long)report->generated_at);
    fprintf(f, "  \"overall_health\": %d,\n", report->overall_health);
    fprintf(f, "  \"health_summary\": \"%s\",\n", report->health_summary);
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_reports\": %d,\n", report->total_reports);
    fprintf(f, "    \"successful_reports\": %d,\n", report->successful_reports);
    fprintf(f, "    \"failed_reports\": %d,\n", report->failed_reports);
    fprintf(f, "    \"success_rate\": %.2f,\n", report->test_success_rate);
    fprintf(f, "    \"critical_issues\": %d,\n", report->critical_issues);
    fprintf(f, "    \"high_issues\": %d,\n", report->high_issues);
    fprintf(f, "    \"medium_issues\": %d,\n", report->medium_issues);
    fprintf(f, "    \"low_issues\": %d\n", report->low_issues);
    fprintf(f, "  },\n");
    fprintf(f, "  \"metrics\": [\n");
    
    for (int i = 0; i < report->metric_count; i++) {
        Metric* m = &report->metrics[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", m->name);
        fprintf(f, "      \"value\": %.2f,\n", m->value);
        fprintf(f, "      \"unit\": \"%s\",\n", m->unit);
        fprintf(f, "      \"status\": %d\n", m->status);
        fprintf(f, "    }%s\n", (i < report->metric_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ],\n");
    fprintf(f, "  \"alerts\": [\n");
    
    for (int i = 0; i < report->alert_count; i++) {
        Alert* a = &report->alerts[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"message\": \"%s\",\n", a->message);
        fprintf(f, "      \"source\": \"%s\",\n", a->source);
        fprintf(f, "      \"severity\": %d\n", a->severity);
        fprintf(f, "    }%s\n", (i < report->alert_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Aggregation JSON exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Report Aggregator\n");
    printf("========================\n\n");
    
    AggregationReport* report = aggregation_create();
    
    // Simulate loading reports from various tools
    printf("Loading reports from tools...\n");
    simulate_reports(report);
    
    // Generate reports
    print_aggregation_summary(report);
    print_metrics_dashboard(report);
    print_alerts(report);
    
    export_aggregation_json(report, "aggregated_report.json");
    generate_html_dashboard(report, "dashboard.html");
    
    printf("\nReport aggregation complete!\n");
    printf("Open dashboard.html in a browser to view the interactive dashboard.\n");
    
    int exit_code = (report->overall_health == 0) ? 1 : 0;
    aggregation_destroy(report);
    
    return exit_code;
}
