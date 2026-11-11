//=============================================================================
// log_analyzer.c - Log Analyzer
// Production-ready log analysis with pattern detection and alerting
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>
#include <ctype.h>

//=============================================================================
// Log Analysis Types
//=============================================================================

#define MAX_LOG_LINES 100000
#define MAX_PATTERNS 50
#define MAX_ALERTS 100

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} LogLevel;

typedef enum {
    PATTERN_ERROR,
    PATTERN_WARNING,
    PATTERN_PERFORMANCE,
    PATTERN_SECURITY,
    PATTERN_CUSTOM
} PatternType;

typedef struct {
    char name[128];
    PatternType type;
    char pattern[256];
    int severity;  // 1-10
    int count;
    int threshold;
    int alert_triggered;
} LogPattern;

typedef struct {
    char timestamp[32];
    LogLevel level;
    char source[128];
    char message[1024];
    int line_number;
} LogEntry;

typedef struct {
    char pattern_name[128];
    char message[512];
    int severity;
    int count;
    time_t detected_at;
} Alert;

typedef struct {
    LogEntry* entries;
    int entry_count;
    int entry_capacity;
    
    LogPattern* patterns;
    int pattern_count;
    int pattern_capacity;
    
    Alert* alerts;
    int alert_count;
    int alert_capacity;
    
    int level_counts[5];
    int unique_sources;
    time_t time_range_start;
    time_t time_range_end;
    
    double avg_message_length;
    int total_bytes;
} LogAnalysisReport;

//=============================================================================
// Log Parser Implementation
//=============================================================================

LogAnalysisReport* log_analysis_create(void) {
    LogAnalysisReport* report = (LogAnalysisReport*)calloc(1, sizeof(LogAnalysisReport));
    report->entry_capacity = MAX_LOG_LINES;
    report->entries = (LogEntry*)calloc(report->entry_capacity, sizeof(LogEntry));
    report->pattern_capacity = MAX_PATTERNS;
    report->patterns = (LogPattern*)calloc(report->pattern_capacity, sizeof(LogPattern));
    report->alert_capacity = MAX_ALERTS;
    report->alerts = (Alert*)calloc(report->alert_capacity, sizeof(Alert));
    return report;
}

void log_analysis_destroy(LogAnalysisReport* report) {
    if (!report) return;
    free(report->entries);
    free(report->patterns);
    free(report->alerts);
    free(report);
}

void init_patterns(LogAnalysisReport* report) {
    // Error patterns
    LogPattern* p = &report->patterns[report->pattern_count++];
    strncpy(p->name, "Null Pointer Exception", sizeof(p->name));
    p->type = PATTERN_ERROR;
    strncpy(p->pattern, "null pointer", sizeof(p->pattern));
    p->severity = 9;
    p->threshold = 1;
    
    p = &report->patterns[report->pattern_count++];
    strncpy(p->name, "Memory Allocation Failed", sizeof(p->name));
    p->type = PATTERN_ERROR;
    strncpy(p->pattern, "out of memory", sizeof(p->pattern));
    p->severity = 10;
    p->threshold = 1;
    
    p = &report->patterns[report->pattern_count++];
    strncpy(p->name, "Database Connection Lost", sizeof(p->name));
    p->type = PATTERN_ERROR;
    strncpy(p->pattern, "connection lost", sizeof(p->pattern));
    p->severity = 8;
    p->threshold = 3;
    
    // Performance patterns
    p = &report->patterns[report->pattern_count++];
    strncpy(p->name, "Slow Query", sizeof(p->name));
    p->type = PATTERN_PERFORMANCE;
    strncpy(p->pattern, "slow query", sizeof(p->pattern));
    p->severity = 6;
    p->threshold = 10;
    
    p = &report->patterns[report->pattern_count++];
    strncpy(p->name, "High CPU Usage", sizeof(p->name));
    p->type = PATTERN_PERFORMANCE;
    strncpy(p->pattern, "cpu usage", sizeof(p->pattern));
    p->severity = 5;
    p->threshold = 5;
    
    // Security patterns
    p = &report->patterns[report->pattern_count++];
    strncpy(p->name, "Authentication Failure", sizeof(p->name));
    p->type = PATTERN_SECURITY;
    strncpy(p->pattern, "authentication failed", sizeof(p->pattern));
    p->severity = 7;
    p->threshold = 5;
    
    p = &report->patterns[report->pattern_count++];
    strncpy(p->name, "Suspicious Activity", sizeof(p->name));
    p->type = PATTERN_SECURITY;
    strncpy(p->pattern, "suspicious", sizeof(p->pattern));
    p->severity = 6;
    p->threshold = 3;
}

LogLevel parse_log_level(const char* level_str) {
    if (strstr(level_str, "FATAL")) return LOG_LEVEL_FATAL;
    if (strstr(level_str, "ERROR")) return LOG_LEVEL_ERROR;
    if (strstr(level_str, "WARN")) return LOG_LEVEL_WARNING;
    if (strstr(level_str, "DEBUG")) return LOG_LEVEL_DEBUG;
    return LOG_LEVEL_INFO;
}

void parse_log_line(LogAnalysisReport* report, const char* line, int line_num) {
    if (report->entry_count >= report->entry_capacity) return;
    
    LogEntry* entry = &report->entries[report->entry_count++];
    entry->line_number = line_num;
    
    // Parse timestamp (simplified)
    strncpy(entry->timestamp, "2024-01-01 00:00:00", sizeof(entry->timestamp));
    
    // Detect log level
    entry->level = LOG_LEVEL_INFO;
    if (strstr(line, "ERROR") || strstr(line, "error")) {
        entry->level = LOG_LEVEL_ERROR;
    } else if (strstr(line, "WARN") || strstr(line, "warning")) {
        entry->level = LOG_LEVEL_WARNING;
    } else if (strstr(line, "DEBUG")) {
        entry->level = LOG_LEVEL_DEBUG;
    } else if (strstr(line, "FATAL")) {
        entry->level = LOG_LEVEL_FATAL;
    }
    
    report->level_counts[entry->level]++;
    
    // Extract source (simplified)
    strncpy(entry->source, "application", sizeof(entry->source));
    
    // Store message
    strncpy(entry->message, line, sizeof(entry->message) - 1);
    report->total_bytes += (int)strlen(line);
}

void analyze_patterns(LogAnalysisReport* report) {
    for (int i = 0; i < report->entry_count; i++) {
        LogEntry* entry = &report->entries[i];
        
        for (int j = 0; j < report->pattern_count; j++) {
            LogPattern* pattern = &report->patterns[j];
            
            if (strstr(entry->message, pattern->pattern)) {
                pattern->count++;
                
                // Check threshold
                if (pattern->count >= pattern->threshold && !pattern->alert_triggered) {
                    pattern->alert_triggered = 1;
                    
                    if (report->alert_count < report->alert_capacity) {
                        Alert* alert = &report->alerts[report->alert_count++];
                        strncpy(alert->pattern_name, pattern->name, sizeof(alert->pattern_name));
                        snprintf(alert->message, sizeof(alert->message),
                                 "Pattern '%s' detected %d times", pattern->name, pattern->count);
                        alert->severity = pattern->severity;
                        alert->count = pattern->count;
                        alert->detected_at = time(NULL);
                    }
                }
            }
        }
    }
}

void analyze_log_file(LogAnalysisReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) {
        printf("Failed to open: %s\n", filename);
        return;
    }
    
    printf("Analyzing: %s\n", filename);
    
    char line[4096];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        parse_log_line(report, line, line_num);
    }
    
    fclose(f);
    
    analyze_patterns(report);
    
    if (report->entry_count > 0) {
        report->avg_message_length = (double)report->total_bytes / report->entry_count;
    }
}

//=============================================================================
// Report Generation
//=============================================================================

const char* level_to_string(LogLevel level) {
    switch (level) {
        case LOG_LEVEL_DEBUG: return "DEBUG";
        case LOG_LEVEL_INFO: return "INFO";
        case LOG_LEVEL_WARNING: return "WARNING";
        case LOG_LEVEL_ERROR: return "ERROR";
        case LOG_LEVEL_FATAL: return "FATAL";
        default: return "UNKNOWN";
    }
}

void print_log_summary(LogAnalysisReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Log Analysis Summary\n");
    printf("=============================================================================\n");
    printf("  Total Lines:          %d\n", report->entry_count);
    printf("  Total Bytes:          %d\n", report->total_bytes);
    printf("  Avg Message Length:   %.1f bytes\n", report->avg_message_length);
    printf("\n");
    printf("  Level Distribution:\n");
    printf("    DEBUG:              %d\n", report->level_counts[LOG_LEVEL_DEBUG]);
    printf("    INFO:               %d\n", report->level_counts[LOG_LEVEL_INFO]);
    printf("    WARNING:            %d\n", report->level_counts[LOG_LEVEL_WARNING]);
    printf("    ERROR:              %d\n", report->level_counts[LOG_LEVEL_ERROR]);
    printf("    FATAL:              %d\n", report->level_counts[LOG_LEVEL_FATAL]);
    printf("=============================================================================\n");
}

void print_pattern_matches(LogAnalysisReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Pattern Matches\n");
    printf("=============================================================================\n");
    
    int total_matches = 0;
    for (int i = 0; i < report->pattern_count; i++) {
        total_matches += report->patterns[i].count;
    }
    
    if (total_matches == 0) {
        printf("\n  No patterns matched.\n");
    } else {
        for (int i = 0; i < report->pattern_count; i++) {
            LogPattern* pattern = &report->patterns[i];
            if (pattern->count > 0) {
                printf("\n  %s\n", pattern->name);
                printf("    Pattern:  %s\n", pattern->pattern);
                printf("    Count:    %d\n", pattern->count);
                printf("    Severity: %d/10\n", pattern->severity);
                if (pattern->alert_triggered) {
                    printf("    Status:   ⚠️ ALERT TRIGGERED\n");
                }
            }
        }
    }
    
    printf("\n=============================================================================\n");
}

void print_alerts(LogAnalysisReport* report) {
    if (report->alert_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  ⚠️  ALERTS (%d)\n", report->alert_count);
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->alert_count; i++) {
        Alert* alert = &report->alerts[i];
        printf("\n  [%d] %s\n", i + 1, alert->pattern_name);
        printf("       %s\n", alert->message);
        printf("       Severity: %d/10\n", alert->severity);
    }
    
    printf("\n=============================================================================\n");
}

void export_log_json(LogAnalysisReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_lines\": %d,\n", report->entry_count);
    fprintf(f, "    \"total_bytes\": %d,\n", report->total_bytes);
    fprintf(f, "    \"avg_message_length\": %.1f\n", report->avg_message_length);
    fprintf(f, "  },\n");
    fprintf(f, "  \"levels\": {\n");
    fprintf(f, "    \"debug\": %d,\n", report->level_counts[LOG_LEVEL_DEBUG]);
    fprintf(f, "    \"info\": %d,\n", report->level_counts[LOG_LEVEL_INFO]);
    fprintf(f, "    \"warning\": %d,\n", report->level_counts[LOG_LEVEL_WARNING]);
    fprintf(f, "    \"error\": %d,\n", report->level_counts[LOG_LEVEL_ERROR]);
    fprintf(f, "    \"fatal\": %d\n", report->level_counts[LOG_LEVEL_FATAL]);
    fprintf(f, "  },\n");
    fprintf(f, "  \"patterns\": [\n");
    
    int first = 1;
    for (int i = 0; i < report->pattern_count; i++) {
        LogPattern* pattern = &report->patterns[i];
        if (pattern->count == 0) continue;
        
        if (!first) fprintf(f, ",\n");
        first = 0;
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", pattern->name);
        fprintf(f, "      \"count\": %d,\n", pattern->count);
        fprintf(f, "      \"severity\": %d,\n", pattern->severity);
        fprintf(f, "      \"alert_triggered\": %s\n", pattern->alert_triggered ? "true" : "false");
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ],\n");
    fprintf(f, "  \"alerts\": [\n");
    
    for (int i = 0; i < report->alert_count; i++) {
        Alert* alert = &report->alerts[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"pattern\": \"%s\",\n", alert->pattern_name);
        fprintf(f, "      \"message\": \"%s\",\n", alert->message);
        fprintf(f, "      \"severity\": %d,\n", alert->severity);
        fprintf(f, "      \"count\": %d\n", alert->count);
        fprintf(f, "    }%s\n", (i < report->alert_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Log analysis exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Log Analyzer\n");
    printf("===================\n\n");
    
    LogAnalysisReport* report = log_analysis_create();
    init_patterns(report);
    
    // Analyze files
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            analyze_log_file(report, argv[i]);
        }
    } else {
        printf("Usage: %s <logfile1> [<logfile2> ...]\n", argv[0]);
        printf("\nDemo mode - analyzing self:\n");
        analyze_log_file(report, __FILE__);
    }
    
    // Generate reports
    print_log_summary(report);
    print_pattern_matches(report);
    print_alerts(report);
    export_log_json(report, "log_analysis.json");
    
    printf("\nLog analysis complete!\n");
    
    log_analysis_destroy(report);
    return 0;
}
