//=============================================================================
// log_analyzer.c - Log File Analyzer
// Production-ready log parsing and analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <time.h>

//=============================================================================
// Log Analysis Types
//=============================================================================

#define MAX_LOG_ENTRIES 100000
#define MAX_PATTERNS 100
#define MAX_LINE_LENGTH 4096

typedef enum {
    LOG_LEVEL_DEBUG,
    LOG_LEVEL_INFO,
    LOG_LEVEL_WARNING,
    LOG_LEVEL_ERROR,
    LOG_LEVEL_FATAL
} LogLevel;

typedef struct {
    time_t timestamp;
    LogLevel level;
    char source[256];
    char message[MAX_LINE_LENGTH];
    int line_number;
} LogEntry;

typedef struct {
    char pattern[256];
    int count;
    int is_error;
} LogPattern;

typedef struct {
    LogEntry* entries;
    int entry_count;
    int entry_capacity;
    
    LogPattern patterns[MAX_PATTERNS];
    int pattern_count;
    
    int level_counts[5];
    time_t first_timestamp;
    time_t last_timestamp;
} LogAnalysis;

//=============================================================================
// Log Analysis Lifecycle
//=============================================================================

LogAnalysis* log_analysis_create(void) {
    LogAnalysis* analysis = (LogAnalysis*)calloc(1, sizeof(LogAnalysis));
    analysis->entry_capacity = MAX_LOG_ENTRIES;
    analysis->entries = (LogEntry*)calloc(analysis->entry_capacity, sizeof(LogEntry));
    analysis->first_timestamp = (time_t)-1;
    return analysis;
}

void log_analysis_destroy(LogAnalysis* analysis) {
    if (!analysis) return;
    free(analysis->entries);
    free(analysis);
}

//=============================================================================
// Log Parsing
//=============================================================================

LogLevel parse_log_level(const char* level_str) {
    if (strstr(level_str, "DEBUG") || strstr(level_str, "debug")) return LOG_LEVEL_DEBUG;
    if (strstr(level_str, "INFO") || strstr(level_str, "info")) return LOG_LEVEL_INFO;
    if (strstr(level_str, "WARN") || strstr(level_str, "warning")) return LOG_LEVEL_WARNING;
    if (strstr(level_str, "ERROR") || strstr(level_str, "error")) return LOG_LEVEL_ERROR;
    if (strstr(level_str, "FATAL") || strstr(level_str, "fatal")) return LOG_LEVEL_FATAL;
    return LOG_LEVEL_INFO;
}

time_t parse_timestamp(const char* timestamp_str) {
    // Simplified - would need proper parsing for various formats
    struct tm tm = {0};
    sscanf(timestamp_str, "%d-%d-%d %d:%d:%d",
          &tm.tm_year, &tm.tm_mon, &tm.tm_mday,
          &tm.tm_hour, &tm.tm_min, &tm.tm_sec);
    tm.tm_year -= 1900;
    tm.tm_mon -= 1;
    return mktime(&tm);
}

void add_pattern(LogAnalysis* analysis, const char* message, LogLevel level) {
    // Extract pattern (simplified)
    char pattern[256];
    strncpy(pattern, message, sizeof(pattern) - 1);
    pattern[sizeof(pattern) - 1] = '\0';
    
    // Truncate to first 50 chars for pattern matching
    if (strlen(pattern) > 50) {
        pattern[50] = '\0';
        strcat(pattern, "...");
    }
    
    // Check if pattern exists
    for (int i = 0; i < analysis->pattern_count; i++) {
        if (strcmp(analysis->patterns[i].pattern, pattern) == 0) {
            analysis->patterns[i].count++;
            return;
        }
    }
    
    // Add new pattern
    if (analysis->pattern_count < MAX_PATTERNS) {
        LogPattern* p = &analysis->patterns[analysis->pattern_count++];
        strncpy(p->pattern, pattern, sizeof(p->pattern) - 1);
        p->count = 1;
        p->is_error = (level >= LOG_LEVEL_ERROR);
    }
}

void analyze_log_file(LogAnalysis* analysis, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        if (analysis->entry_count >= analysis->entry_capacity) break;
        
        LogEntry* entry = &analysis->entries[analysis->entry_count++];
        entry->line_number = line_num;
        entry->timestamp = time(NULL); // Simplified
        entry->level = LOG_LEVEL_INFO;
        strncpy(entry->source, filename, sizeof(entry->source) - 1);
        strncpy(entry->message, line, sizeof(entry->message) - 1);
        
        // Try to parse log level
        if (strstr(line, "ERROR") || strstr(line, "error")) {
            entry->level = LOG_LEVEL_ERROR;
        } else if (strstr(line, "WARN") || strstr(line, "warning")) {
            entry->level = LOG_LEVEL_WARNING;
        } else if (strstr(line, "DEBUG") || strstr(line, "debug")) {
            entry->level = LOG_LEVEL_DEBUG;
        } else if (strstr(line, "FATAL") || strstr(line, "fatal")) {
            entry->level = LOG_LEVEL_FATAL;
        }
        
        // Update counts
        analysis->level_counts[entry->level]++;
        
        // Update timestamps
        if (analysis->first_timestamp == (time_t)-1) {
            analysis->first_timestamp = entry->timestamp;
        }
        analysis->last_timestamp = entry->timestamp;
        
        // Add pattern
        add_pattern(analysis, entry->message, entry->level);
    }
    
    fclose(f);
}

//=============================================================================
// Report Generation
//=============================================================================

void print_summary(LogAnalysis* analysis) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Log Analysis Summary\n");
    printf("=============================================================================\n");
    printf("  Total Entries:    %d\n", analysis->entry_count);
    printf("\n");
    printf("  By Level:\n");
    printf("    DEBUG:   %d\n", analysis->level_counts[LOG_LEVEL_DEBUG]);
    printf("    INFO:    %d\n", analysis->level_counts[LOG_LEVEL_INFO]);
    printf("    WARNING: %d\n", analysis->level_counts[LOG_LEVEL_WARNING]);
    printf("    ERROR:   %d\n", analysis->level_counts[LOG_LEVEL_ERROR]);
    printf("    FATAL:   %d\n", analysis->level_counts[LOG_LEVEL_FATAL]);
    printf("=============================================================================\n");
}

void print_patterns(LogAnalysis* analysis) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Common Patterns\n");
    printf("=============================================================================\n");
    printf("  %-50s %8s\n", "Pattern", "Count");
    printf("  -------------------------------------------------------------------------\n");
    
    // Sort by count
    for (int i = 0; i < analysis->pattern_count - 1; i++) {
        for (int j = i + 1; j < analysis->pattern_count; j++) {
            if (analysis->patterns[j].count > analysis->patterns[i].count) {
                LogPattern temp = analysis->patterns[i];
                analysis->patterns[i] = analysis->patterns[j];
                analysis->patterns[j] = temp;
            }
        }
    }
    
    for (int i = 0; i < analysis->pattern_count && i < 20; i++) {
        LogPattern* p = &analysis->patterns[i];
        printf("  %-50s %8d\n", p->pattern, p->count);
    }
    
    printf("=============================================================================\n");
}

void print_errors(LogAnalysis* analysis) {
    int error_count = analysis->level_counts[LOG_LEVEL_ERROR] + 
                      analysis->level_counts[LOG_LEVEL_FATAL];
    
    if (error_count == 0) {
        printf("\nNo errors found!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Errors and Fatal Messages\n");
    printf("=============================================================================\n");
    
    int printed = 0;
    for (int i = 0; i < analysis->entry_count && printed < 50; i++) {
        if (analysis->entries[i].level >= LOG_LEVEL_ERROR) {
            printf("  Line %d: %s\n", analysis->entries[i].line_number, 
                   analysis->entries[i].message);
            printed++;
        }
    }
    
    if (error_count > 50) {
        printf("  ... and %d more\n", error_count - 50);
    }
    
    printf("=============================================================================\n");
}

void export_json(LogAnalysis* analysis, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_entries\": %d,\n", analysis->entry_count);
    fprintf(f, "    \"debug\": %d,\n", analysis->level_counts[LOG_LEVEL_DEBUG]);
    fprintf(f, "    \"info\": %d,\n", analysis->level_counts[LOG_LEVEL_INFO]);
    fprintf(f, "    \"warning\": %d,\n", analysis->level_counts[LOG_LEVEL_WARNING]);
    fprintf(f, "    \"error\": %d,\n", analysis->level_counts[LOG_LEVEL_ERROR]);
    fprintf(f, "    \"fatal\": %d\n", analysis->level_counts[LOG_LEVEL_FATAL]);
    fprintf(f, "  },\n");
    fprintf(f, "  \"patterns\": [\n");
    
    for (int i = 0; i < analysis->pattern_count && i < 50; i++) {
        LogPattern* p = &analysis->patterns[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"pattern\": \"%s\",\n", p->pattern);
        fprintf(f, "      \"count\": %d,\n", p->count);
        fprintf(f, "      \"is_error\": %s\n", p->is_error ? "true" : "false");
        fprintf(f, "    }%s\n", (i < analysis->pattern_count - 1 && i < 49) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Analysis exported to: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Log Analyzer\n");
    printf("===================\n\n");
    
    if (argc < 2) {
        printf("Usage: log_analyzer <logfile> [options]\n");
        printf("\nOptions:\n");
        printf("  --json    Export results to JSON\n");
        printf("  --errors  Show only errors\n");
        return 1;
    }
    
    const char* logfile = argv[1];
    int export_json_flag = 0;
    int errors_only = 0;
    
    for (int i = 2; i < argc; i++) {
        if (strcmp(argv[i], "--json") == 0) export_json_flag = 1;
        if (strcmp(argv[i], "--errors") == 0) errors_only = 1;
    }
    
    printf("Analyzing: %s\n\n", logfile);
    
    LogAnalysis* analysis = log_analysis_create();
    analyze_log_file(analysis, logfile);
    
    if (errors_only) {
        print_errors(analysis);
    } else {
        print_summary(analysis);
        print_patterns(analysis);
        print_errors(analysis);
    }
    
    if (export_json_flag) {
        export_json(analysis, "log_analysis.json");
    }
    
    log_analysis_destroy(analysis);
    
    return 0;
}
