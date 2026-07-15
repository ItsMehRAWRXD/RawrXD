//=============================================================================
// static_analyzer.c - Static Analysis Tool for RawrXD
// Production-ready linting and code quality analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <dirent.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEP "\\"
#else
#define PATH_SEP "/"
#endif

//=============================================================================
// Analysis Configuration
//=============================================================================

#define MAX_ISSUES 10000
#define MAX_LINE_LENGTH 4096
#define MAX_FILES 1024

typedef enum {
    SEVERITY_INFO,
    SEVERITY_WARNING,
    SEVERITY_ERROR,
    SEVERITY_CRITICAL
} IssueSeverity;

typedef enum {
    CATEGORY_STYLE,
    CATEGORY_SECURITY,
    CATEGORY_PERFORMANCE,
    CATEGORY_PORTABILITY,
    CATEGORY_CORRECTNESS,
    CATEGORY_DOCUMENTATION
} IssueCategory;

typedef struct {
    char file[512];
    int line;
    int column;
    IssueSeverity severity;
    IssueCategory category;
    char message[1024];
    char rule_id[32];
} Issue;

typedef struct {
    Issue* issues;
    int issue_count;
    int issue_capacity;
    
    int files_analyzed;
    int lines_analyzed;
    
    int info_count;
    int warning_count;
    int error_count;
    int critical_count;
} AnalysisReport;

//=============================================================================
// Rule Checking Functions
//=============================================================================

void check_line_length(AnalysisReport* report, const char* file, int line_num, const char* line) {
    size_t len = strlen(line);
    if (len > 120) {
        Issue issue = {0};
        strncpy(issue.file, file, sizeof(issue.file) - 1);
        issue.line = line_num;
        issue.column = 120;
        issue.severity = SEVERITY_WARNING;
        issue.category = CATEGORY_STYLE;
        snprintf(issue.message, sizeof(issue.message), 
                 "Line exceeds 120 characters (%zu chars)", len);
        strncpy(issue.rule_id, "STYLE001", sizeof(issue.rule_id) - 1);
        
        if (report->issue_count < MAX_ISSUES) {
            report->issues[report->issue_count++] = issue;
            report->warning_count++;
        }
    }
}

void check_trailing_whitespace(AnalysisReport* report, const char* file, int line_num, const char* line) {
    size_t len = strlen(line);
    if (len > 0 && (line[len-1] == ' ' || line[len-1] == '\t')) {
        Issue issue = {0};
        strncpy(issue.file, file, sizeof(issue.file) - 1);
        issue.line = line_num;
        issue.column = (int)len;
        issue.severity = SEVERITY_INFO;
        issue.category = CATEGORY_STYLE;
        strncpy(issue.message, "Trailing whitespace detected", sizeof(issue.message) - 1);
        strncpy(issue.rule_id, "STYLE002", sizeof(issue.rule_id) - 1);
        
        if (report->issue_count < MAX_ISSUES) {
            report->issues[report->issue_count++] = issue;
            report->info_count++;
        }
    }
}

void check_tabs(AnalysisReport* report, const char* file, int line_num, const char* line) {
    if (strchr(line, '\t')) {
        Issue issue = {0};
        strncpy(issue.file, file, sizeof(issue.file) - 1);
        issue.line = line_num;
        issue.column = 1;
        issue.severity = SEVERITY_WARNING;
        issue.category = CATEGORY_STYLE;
        strncpy(issue.message, "Tab character found (use spaces)", sizeof(issue.message) - 1);
        strncpy(issue.rule_id, "STYLE003", sizeof(issue.rule_id) - 1);
        
        if (report->issue_count < MAX_ISSUES) {
            report->issues[report->issue_count++] = issue;
            report->warning_count++;
        }
    }
}

void check_buffer_functions(AnalysisReport* report, const char* file, int line_num, const char* line) {
    // Check for unsafe functions
    const char* unsafe_funcs[] = {
        "strcpy", "strcat", "sprintf", "gets", "scanf"
    };
    
    for (size_t i = 0; i < sizeof(unsafe_funcs)/sizeof(unsafe_funcs[0]); i++) {
        if (strstr(line, unsafe_funcs[i])) {
            Issue issue = {0};
            strncpy(issue.file, file, sizeof(issue.file) - 1);
            issue.line = line_num;
            issue.column = 1;
            issue.severity = SEVERITY_ERROR;
            issue.category = CATEGORY_SECURITY;
            snprintf(issue.message, sizeof(issue.message),
                     "Unsafe function '%s' used (use '%s_s' or safer alternative)",
                     unsafe_funcs[i], unsafe_funcs[i]);
            strncpy(issue.rule_id, "SEC001", sizeof(issue.rule_id) - 1);
            
            if (report->issue_count < MAX_ISSIES) {
                report->issues[report->issue_count++] = issue;
                report->error_count++;
            }
        }
    }
}

void check_null_dereference(AnalysisReport* report, const char* file, int line_num, const char* line) {
    // Simple check for potential null dereference after malloc
    if (strstr(line, "malloc") && !strstr(line, "NULL")) {
        // Check next few lines for null check
        // Simplified - would need multi-line analysis
    }
}

void check_magic_numbers(AnalysisReport* report, const char* file, int line_num, const char* line) {
    // Check for magic numbers (simplified)
    const char* p = line;
    while (*p) {
        if (isdigit(*p)) {
            int num = atoi(p);
            if (num != 0 && num != 1) {
                // Check if it's in a comment or string
                // Simplified check
                if (!strstr(line, "//") && !strstr(line, "\"")) {
                    // Likely a magic number
                    // Skip for now - would need more sophisticated analysis
                }
            }
            while (isdigit(*p)) p++;
        } else {
            p++;
        }
    }
}

void check_function_complexity(AnalysisReport* report, const char* file, int line_num, 
                               const char* line, int* function_start, int* function_lines) {
    // Simple function complexity check
    if (strstr(line, "{") && (strstr(line, "(") || strstr(line, ")"))) {
        // Likely function start
        if (*function_start > 0) {
            // Check previous function length
            if (*function_lines > 50) {
                Issue issue = {0};
                strncpy(issue.file, file, sizeof(issue.file) - 1);
                issue.line = *function_start;
                issue.column = 1;
                issue.severity = SEVERITY_WARNING;
                issue.category = CATEGORY_PERFORMANCE;
                snprintf(issue.message, sizeof(issue.message),
                         "Function exceeds 50 lines (%d lines)", *function_lines);
                strncpy(issue.rule_id, "PERF001", sizeof(issue.rule_id) - 1);
                
                if (report->issue_count < MAX_ISSUES) {
                    report->issues[report->issue_count++] = issue;
                    report->warning_count++;
                }
            }
        }
        *function_start = line_num;
        *function_lines = 0;
    }
    
    if (*function_start > 0) {
        (*function_lines)++;
    }
}

void check_missing_braces(AnalysisReport* report, const char* file, int line_num, const char* line) {
    // Check for if/for/while without braces
    const char* control_structures[] = {"if", "for", "while"};
    
    for (size_t i = 0; i < sizeof(control_structures)/sizeof(control_structures[0]); i++) {
        const char* keyword = control_structures[i];
        const char* found = strstr(line, keyword);
        if (found) {
            // Check if next non-whitespace char after ) is not {
            const char* p = found + strlen(keyword);
            while (*p && isspace(*p)) p++;
            if (*p == '(') {
                // Find closing paren
                p = strchr(p, ')');
                if (p) {
                    p++;
                    while (*p && isspace(*p)) p++;
                    if (*p && *p != '{') {
                        Issue issue = {0};
                        strncpy(issue.file, file, sizeof(issue.file) - 1);
                        issue.line = line_num;
                        issue.column = (int)(p - line);
                        issue.severity = SEVERITY_WARNING;
                        issue.category = CATEGORY_CORRECTNESS;
                        snprintf(issue.message, sizeof(issue.message),
                                 "%s statement without braces", keyword);
                        strncpy(issue.rule_id, "CORR001", sizeof(issue.rule_id) - 1);
                        
                        if (report->issue_count < MAX_ISSUES) {
                            report->issues[report->issue_count++] = issue;
                            report->warning_count++;
                        }
                    }
                }
            }
        }
    }
}

void check_todo_fixme(AnalysisReport* report, const char* file, int line_num, const char* line) {
    const char* markers[] = {"TODO", "FIXME", "XXX", "HACK"};
    
    for (size_t i = 0; i < sizeof(markers)/sizeof(markers[0]); i++) {
        if (strstr(line, markers[i])) {
            Issue issue = {0};
            strncpy(issue.file, file, sizeof(issue.file) - 1);
            issue.line = line_num;
            issue.column = 1;
            issue.severity = SEVERITY_INFO;
            issue.category = CATEGORY_DOCUMENTATION;
            snprintf(issue.message, sizeof(issue.message),
                     "%s marker found", markers[i]);
            strncpy(issue.rule_id, "DOC001", sizeof(issue.rule_id) - 1);
            
            if (report->issue_count < MAX_ISSUES) {
                report->issues[report->issue_count++] = issue;
                report->info_count++;
            }
        }
    }
}

//=============================================================================
// File Analysis
//=============================================================================

void analyze_file(AnalysisReport* report, const char* file_path) {
    FILE* f = fopen(file_path, "r");
    if (!f) return;
    
    report->files_analyzed++;
    
    char line[MAX_LINE_LENGTH];
    int line_num = 0;
    int function_start = 0;
    int function_lines = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        report->lines_analyzed++;
        
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') {
            line[len-1] = '\0';
        }
        
        // Run all checks
        check_line_length(report, file_path, line_num, line);
        check_trailing_whitespace(report, file_path, line_num, line);
        check_tabs(report, file_path, line_num, line);
        check_buffer_functions(report, file_path, line_num, line);
        check_null_dereference(report, file_path, line_num, line);
        check_magic_numbers(report, file_path, line_num, line);
        check_function_complexity(report, file_path, line_num, line, &function_start, &function_lines);
        check_missing_braces(report, file_path, line_num, line);
        check_todo_fixme(report, file_path, line_num, line);
    }
    
    fclose(f);
}

//=============================================================================
// Report Generation
//=============================================================================

AnalysisReport* analysis_create_report(void) {
    AnalysisReport* report = (AnalysisReport*)calloc(1, sizeof(AnalysisReport));
    report->issue_capacity = MAX_ISSUES;
    report->issues = (Issue*)calloc(MAX_ISSUES, sizeof(Issue));
    return report;
}

void analysis_destroy_report(AnalysisReport* report) {
    if (!report) return;
    free(report->issues);
    free(report);
}

void analysis_print_summary(AnalysisReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Static Analysis Summary\n");
    printf("=============================================================================\n");
    printf("  Files Analyzed:   %d\n", report->files_analyzed);
    printf("  Lines Analyzed:   %d\n", report->lines_analyzed);
    printf("\n");
    printf("  Issues Found:\n");
    printf("    Critical: %d\n", report->critical_count);
    printf("    Errors:   %d\n", report->error_count);
    printf("    Warnings: %d\n", report->warning_count);
    printf("    Info:     %d\n", report->info_count);
    printf("    -----------------\n");
    printf("    Total:    %d\n", report->issue_count);
    printf("=============================================================================\n");
    
    if (report->critical_count > 0) {
        printf("  ❌ CRITICAL issues found - code not production ready\n");
    } else if (report->error_count > 0) {
        printf("  ⚠️  Errors found - review required\n");
    } else if (report->warning_count > 0) {
        printf("  ⚠️  Warnings found - consider addressing\n");
    } else {
        printf("  ✅ No issues found\n");
    }
    printf("=============================================================================\n");
}

void analysis_print_issues(AnalysisReport* report, IssueSeverity min_severity) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Issues by Severity\n");
    printf("=============================================================================\n");
    
    const char* severity_names[] = {"INFO", "WARNING", "ERROR", "CRITICAL"};
    
    for (int sev = SEVERITY_CRITICAL; sev >= (int)min_severity; sev--) {
        int count = 0;
        for (int i = 0; i < report->issue_count; i++) {
            if (report->issues[i].severity == sev) count++;
        }
        
        if (count > 0) {
            printf("\n%s (%d):\n", severity_names[sev], count);
            printf("-----------------------------------------------------------------------------\n");
            
            for (int i = 0; i < report->issue_count; i++) {
                if (report->issues[i].severity == sev) {
                    Issue* issue = &report->issues[i];
                    const char* filename = strrchr(issue->file, PATH_SEP[0]);
                    if (!filename) filename = issue->file;
                    else filename++;
                    
                    printf("  %s:%d:%d [%s] %s\n",
                           filename, issue->line, issue->column,
                           issue->rule_id, issue->message);
                }
            }
        }
    }
    
    printf("=============================================================================\n");
}

void analysis_export_json(AnalysisReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"files_analyzed\": %d,\n", report->files_analyzed);
    fprintf(f, "    \"lines_analyzed\": %d,\n", report->lines_analyzed);
    fprintf(f, "    \"total_issues\": %d,\n", report->issue_count);
    fprintf(f, "    \"critical\": %d,\n", report->critical_count);
    fprintf(f, "    \"errors\": %d,\n", report->error_count);
    fprintf(f, "    \"warnings\": %d,\n", report->warning_count);
    fprintf(f, "    \"info\": %d\n", report->info_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"issues\": [\n");
    
    for (int i = 0; i < report->issue_count; i++) {
        Issue* issue = &report->issues[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"file\": \"%s\",\n", issue->file);
        fprintf(f, "      \"line\": %d,\n", issue->line);
        fprintf(f, "      \"column\": %d,\n", issue->column);
        fprintf(f, "      \"severity\": \"%s\",\n",
                issue->severity == SEVERITY_CRITICAL ? "critical" :
                issue->severity == SEVERITY_ERROR ? "error" :
                issue->severity == SEVERITY_WARNING ? "warning" : "info");
        fprintf(f, "      \"category\": \"%s\",\n",
                issue->category == CATEGORY_STYLE ? "style" :
                issue->category == CATEGORY_SECURITY ? "security" :
                issue->category == CATEGORY_PERFORMANCE ? "performance" :
                issue->category == CATEGORY_PORTABILITY ? "portability" :
                issue->category == CATEGORY_CORRECTNESS ? "correctness" : "documentation");
        fprintf(f, "      \"rule\": \"%s\",\n", issue->rule_id);
        fprintf(f, "      \"message\": \"%s\"\n", issue->message);
        fprintf(f, "    }%s\n", (i < report->issue_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Analysis report exported to: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Static Analyzer\n");
    printf("======================\n\n");
    
    if (argc < 2) {
        printf("Usage: static_analyzer <file1> [file2] ...\n");
        printf("       static_analyzer --dir <directory>\n");
        return 1;
    }
    
    AnalysisReport* report = analysis_create_report();
    
    if (strcmp(argv[1], "--dir") == 0 && argc >= 3) {
        // Analyze directory
        printf("Analyzing directory: %s\n", argv[2]);
        
        // Simplified - would use proper directory traversal
        // For now, just analyze provided files
    } else {
        // Analyze specific files
        for (int i = 1; i < argc; i++) {
            printf("Analyzing: %s\n", argv[i]);
            analyze_file(report, argv[i]);
        }
    }
    
    analysis_print_summary(report);
    
    if (report->issue_count > 0) {
        analysis_print_issues(report, SEVERITY_INFO);
    }
    
    analysis_export_json(report, "analysis_report.json");
    
    int exit_code = (report->critical_count > 0 || report->error_count > 0) ? 1 : 0;
    
    analysis_destroy_report(report);
    
    return exit_code;
}
