//=============================================================================
// metrics_dashboard.c - Metrics Dashboard Generator
// Production-ready metrics visualization and reporting
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Metrics Types
//=============================================================================

#define MAX_METRICS 100
#define MAX_CATEGORIES 10

typedef enum {
    METRIC_TYPE_COUNTER,
    METRIC_TYPE_GAUGE,
    METRIC_TYPE_HISTOGRAM,
    METRIC_TYPE_TIMER
} MetricType;

typedef struct {
    char name[256];
    char description[512];
    char category[64];
    MetricType type;
    double value;
    double min;
    double max;
    double avg;
    int count;
    time_t timestamp;
} Metric;

typedef struct {
    Metric metrics[MAX_METRICS];
    int metric_count;
    char project_name[256];
    time_t generated_at;
} MetricsDashboard;

//=============================================================================
// Dashboard Lifecycle
//=============================================================================

MetricsDashboard* dashboard_create(const char* project_name) {
    MetricsDashboard* db = (MetricsDashboard*)calloc(1, sizeof(MetricsDashboard));
    strncpy(db->project_name, project_name, sizeof(db->project_name) - 1);
    db->generated_at = time(NULL);
    return db;
}

void dashboard_destroy(MetricsDashboard* db) {
    free(db);
}

void dashboard_add_metric(MetricsDashboard* db, const char* name, const char* description,
                         const char* category, MetricType type, double value) {
    if (db->metric_count >= MAX_METRICS) return;
    
    Metric* m = &db->metrics[db->metric_count++];
    strncpy(m->name, name, sizeof(m->name) - 1);
    strncpy(m->description, description, sizeof(m->description) - 1);
    strncpy(m->category, category, sizeof(m->category) - 1);
    m->type = type;
    m->value = value;
    m->min = value;
    m->max = value;
    m->avg = value;
    m->count = 1;
    m->timestamp = time(NULL);
}

//=============================================================================
// HTML Dashboard Generation
//=============================================================================

void generate_html_dashboard(MetricsDashboard* db, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "<!DOCTYPE html>\n");
    fprintf(f, "<html>\n");
    fprintf(f, "<head>\n");
    fprintf(f, "  <title>%s - Metrics Dashboard</title>\n", db->project_name);
    fprintf(f, "  <style>\n");
    fprintf(f, "    body { font-family: 'Segoe UI', Arial, sans-serif; margin: 0; background: #f5f7fa; }\n");
    fprintf(f, "    .header { background: linear-gradient(135deg, #667eea 0%%, #764ba2 100%%); color: white; padding: 30px; text-align: center; }\n");
    fprintf(f, "    .header h1 { margin: 0; font-size: 2.5em; }\n");
    fprintf(f, "    .header p { margin: 10px 0 0 0; opacity: 0.9; }\n");
    fprintf(f, "    .container { max-width: 1400px; margin: 0 auto; padding: 20px; }\n");
    fprintf(f, "    .metrics-grid { display: grid; grid-template-columns: repeat(auto-fit, minmax(300px, 1fr)); gap: 20px; margin-top: 20px; }\n");
    fprintf(f, "    .metric-card { background: white; border-radius: 10px; padding: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); transition: transform 0.2s; }\n");
    fprintf(f, "    .metric-card:hover { transform: translateY(-5px); box-shadow: 0 5px 20px rgba(0,0,0,0.15); }\n");
    fprintf(f, "    .metric-category { color: #667eea; font-size: 0.85em; text-transform: uppercase; letter-spacing: 1px; margin-bottom: 5px; }\n");
    fprintf(f, "    .metric-name { font-size: 1.1em; color: #333; margin-bottom: 10px; }\n");
    fprintf(f, "    .metric-value { font-size: 2.5em; font-weight: bold; color: #764ba2; }\n");
    fprintf(f, "    .metric-description { color: #666; font-size: 0.9em; margin-top: 10px; }\n");
    fprintf(f, "    .summary { background: white; border-radius: 10px; padding: 20px; margin-bottom: 20px; box-shadow: 0 2px 10px rgba(0,0,0,0.1); }\n");
    fprintf(f, "    .summary-grid { display: grid; grid-template-columns: repeat(4, 1fr); gap: 20px; margin-top: 15px; }\n");
    fprintf(f, "    .summary-item { text-align: center; padding: 15px; background: #f8f9fa; border-radius: 8px; }\n");
    fprintf(f, "    .summary-value { font-size: 2em; font-weight: bold; color: #667eea; }\n");
    fprintf(f, "    .summary-label { color: #666; font-size: 0.9em; margin-top: 5px; }\n");
    fprintf(f, "    .status-good { color: #28a745; }\n");
    fprintf(f, "    .status-warning { color: #ffc107; }\n");
    fprintf(f, "    .status-error { color: #dc3545; }\n");
    fprintf(f, "  </style>\n");
    fprintf(f, "</head>\n");
    fprintf(f, "<body>\n");
    
    // Header
    fprintf(f, "  <div class='header'>\n");
    fprintf(f, "    <h1>%s</h1>\n", db->project_name);
    fprintf(f, "    <p>Metrics Dashboard - Generated: %s</p>\n", ctime(&db->generated_at));
    fprintf(f, "  </div>\n");
    
    fprintf(f, "  <div class='container'>\n");
    
    // Summary
    fprintf(f, "    <div class='summary'>\n");
    fprintf(f, "      <h2>Summary</h2>\n");
    fprintf(f, "      <div class='summary-grid'>\n");
    
    // Calculate summary stats
    int total_tests = 0, passed = 0, failed = 0;
    double coverage = 0;
    
    for (int i = 0; i < db->metric_count; i++) {
        if (strstr(db->metrics[i].name, "test")) {
            total_tests += (int)db->metrics[i].value;
        }
        if (strstr(db->metrics[i].name, "pass")) {
            passed = (int)db->metrics[i].value;
        }
        if (strstr(db->metrics[i].name, "fail")) {
            failed = (int)db->metrics[i].value;
        }
        if (strstr(db->metrics[i].name, "coverage")) {
            coverage = db->metrics[i].value;
        }
    }
    
    fprintf(f, "        <div class='summary-item'>\n");
    fprintf(f, "          <div class='summary-value'>%d</div>\n", db->metric_count);
    fprintf(f, "          <div class='summary-label'>Total Metrics</div>\n");
    fprintf(f, "        </div>\n");
    
    fprintf(f, "        <div class='summary-item'>\n");
    fprintf(f, "          <div class='summary-value'>%d</div>\n", total_tests);
    fprintf(f, "          <div class='summary-label'>Tests</div>\n");
    fprintf(f, "        </div>\n");
    
    fprintf(f, "        <div class='summary-item'>\n");
    fprintf(f, "          <div class='summary-value %s'>%.1f%%</div>\n",
            coverage >= 80 ? "status-good" : (coverage >= 60 ? "status-warning" : "status-error"),
            coverage);
    fprintf(f, "          <div class='summary-label'>Coverage</div>\n");
    fprintf(f, "        </div>\n");
    
    fprintf(f, "        <div class='summary-item'>\n");
    fprintf(f, "          <div class='summary-value'>%d</div>\n", passed);
    fprintf(f, "          <div class='summary-label'>Passed</div>\n");
    fprintf(f, "        </div>\n");
    
    fprintf(f, "      </div>\n");
    fprintf(f, "    </div>\n");
    
    // Metrics Grid
    fprintf(f, "    <h2>Detailed Metrics</h2>\n");
    fprintf(f, "    <div class='metrics-grid'>\n");
    
    for (int i = 0; i < db->metric_count; i++) {
        Metric* m = &db->metrics[i];
        fprintf(f, "      <div class='metric-card'>\n");
        fprintf(f, "        <div class='metric-category'>%s</div>\n", m->category);
        fprintf(f, "        <div class='metric-name'>%s</div>\n", m->name);
        fprintf(f, "        <div class='metric-value'>%.2f</div>\n", m->value);
        fprintf(f, "        <div class='metric-description'>%s</div>\n", m->description);
        fprintf(f, "      </div>\n");
    }
    
    fprintf(f, "    </div>\n");
    fprintf(f, "  </div>\n");
    fprintf(f, "</body>\n");
    fprintf(f, "</html>\n");
    
    fclose(f);
    printf("  HTML dashboard generated: %s\n", filename);
}

//=============================================================================
// JSON Export
//=============================================================================

void export_metrics_json(MetricsDashboard* db, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"project\": \"%s\",\n", db->project_name);
    fprintf(f, "  \"generated_at\": %ld,\n", (long)db->generated_at);
    fprintf(f, "  \"metric_count\": %d,\n", db->metric_count);
    fprintf(f, "  \"metrics\": [\n");
    
    for (int i = 0; i < db->metric_count; i++) {
        Metric* m = &db->metrics[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", m->name);
        fprintf(f, "      \"description\": \"%s\",\n", m->description);
        fprintf(f, "      \"category\": \"%s\",\n", m->category);
        fprintf(f, "      \"type\": \"%s\",\n",
                m->type == METRIC_TYPE_COUNTER ? "counter" :
                m->type == METRIC_TYPE_GAUGE ? "gauge" :
                m->type == METRIC_TYPE_HISTOGRAM ? "histogram" : "timer");
        fprintf(f, "      \"value\": %.2f,\n", m->value);
        fprintf(f, "      \"timestamp\": %ld\n", (long)m->timestamp);
        fprintf(f, "    }%s\n", (i < db->metric_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  JSON metrics exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Metrics Dashboard Generator\n");
    printf("===================================\n\n");
    
    MetricsDashboard* db = dashboard_create("RawrXD Toolchain");
    
    // Add sample metrics
    dashboard_add_metric(db, "total_tests", "Total number of tests", "tests", 
                        METRIC_TYPE_COUNTER, 1040);
    dashboard_add_metric(db, "tests_passed", "Tests that passed", "tests", 
                        METRIC_TYPE_COUNTER, 1040);
    dashboard_add_metric(db, "tests_failed", "Tests that failed", "tests", 
                        METRIC_TYPE_COUNTER, 0);
    dashboard_add_metric(db, "code_coverage", "Code coverage percentage", "quality", 
                        METRIC_TYPE_GAUGE, 87.5);
    dashboard_add_metric(db, "build_time_ms", "Build time in milliseconds", "performance", 
                        METRIC_TYPE_TIMER, 12500);
    dashboard_add_metric(db, "test_time_ms", "Test execution time", "performance", 
                        METRIC_TYPE_TIMER, 8500);
    dashboard_add_metric(db, "files_compiled", "Number of files compiled", "build", 
                        METRIC_TYPE_COUNTER, 28);
    dashboard_add_metric(db, "lines_of_code", "Total lines of code", "code", 
                        METRIC_TYPE_GAUGE, 15000);
    dashboard_add_metric(db, "documentation_coverage", "Documentation coverage", "quality", 
                        METRIC_TYPE_GAUGE, 95.0);
    dashboard_add_metric(db, "static_analysis_issues", "Issues found by static analysis", "quality", 
                        METRIC_TYPE_COUNTER, 3);
    
    printf("Generated %d metrics\n\n", db->metric_count);
    
    // Generate outputs
    generate_html_dashboard(db, "metrics_dashboard.html");
    export_metrics_json(db, "metrics.json");
    
    printf("\nDashboard generation complete!\n");
    printf("Open metrics_dashboard.html in a browser to view.\n");
    
    dashboard_destroy(db);
    
    return 0;
}
