//=============================================================================
// code_review_assistant.c - Automated Code Review Assistant
// Production-ready code review with style and quality checks
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Review Types
//=============================================================================

#define MAX_ISSUES 1000
#define MAX_RULES 50
#define MAX_FILES 100

typedef enum {
    SEVERITY_ERROR,
    SEVERITY_WARNING,
    SEVERITY_INFO,
    SEVERITY_STYLE
} IssueSeverity;

typedef enum {
    CATEGORY_STYLE,
    CATEGORY_SECURITY,
    CATEGORY_PERFORMANCE,
    CATEGORY_MAINTAINABILITY,
    CATEGORY_DOCUMENTATION,
    CATEGORY_PORTABILITY
} IssueCategory;

typedef struct {
    char id[16];
    char name[256];
    char description[1024];
    IssueSeverity severity;
    IssueCategory category;
    char pattern[512];
    char suggestion[1024];
} ReviewRule;

typedef struct {
    char rule_id[16];
    char message[1024];
    char file[512];
    int line;
    int column;
    IssueSeverity severity;
    IssueCategory category;
    char suggestion[1024];
    char code_snippet[256];
} ReviewIssue;

typedef struct {
    ReviewRule rules[MAX_RULES];
    int rule_count;
    
    ReviewIssue issues[MAX_ISSUES];
    int issue_count;
    
    int error_count;
    int warning_count;
    int info_count;
    int style_count;
    
    int files_reviewed;
    int lines_reviewed;
} ReviewReport;

//=============================================================================
// Review Rules
//=============================================================================

void init_review_rules(ReviewReport* report) {
    // Style rules
    ReviewRule* rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "STYLE001", sizeof(rule->id));
    strncpy(rule->name, "Line too long", sizeof(rule->name));
    strncpy(rule->description, "Line exceeds 120 characters", sizeof(rule->description));
    rule->severity = SEVERITY_STYLE;
    rule->category = CATEGORY_STYLE;
    strncpy(rule->suggestion, "Break line into multiple lines", sizeof(rule->suggestion));
    
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "STYLE002", sizeof(rule->id));
    strncpy(rule->name, "Trailing whitespace", sizeof(rule->name));
    strncpy(rule->description, "Line has trailing whitespace", sizeof(rule->description));
    rule->severity = SEVERITY_STYLE;
    rule->category = CATEGORY_STYLE;
    strncpy(rule->suggestion, "Remove trailing whitespace", sizeof(rule->suggestion));
    
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "STYLE003", sizeof(rule->id));
    strncpy(rule->name, "Mixed tabs and spaces", sizeof(rule->name));
    strncpy(rule->description, "Line uses both tabs and spaces for indentation", sizeof(rule->description));
    rule->severity = SEVERITY_STYLE;
    rule->category = CATEGORY_STYLE;
    strncpy(rule->suggestion, "Use consistent indentation (prefer spaces)", sizeof(rule->suggestion));
    
    // Security rules
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC001", sizeof(rule->id));
    strncpy(rule->name, "Unsafe function", sizeof(rule->name));
    strncpy(rule->description, "Use of potentially unsafe function", sizeof(rule->description));
    rule->severity = SEVERITY_WARNING;
    rule->category = CATEGORY_SECURITY;
    strncpy(rule->pattern, "strcpy|strcat|gets|sprintf", sizeof(rule->pattern));
    strncpy(rule->suggestion, "Use strncpy, strncat, snprintf instead", sizeof(rule->suggestion));
    
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC002", sizeof(rule->id));
    strncpy(rule->name, "Unchecked return", sizeof(rule->name));
    strncpy(rule->description, "Return value not checked", sizeof(rule->description));
    rule->severity = SEVERITY_WARNING;
    rule->category = CATEGORY_SECURITY;
    strncpy(rule->suggestion, "Check return value for errors", sizeof(rule->suggestion));
    
    // Performance rules
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "PERF001", sizeof(rule->id));
    strncpy(rule->name, "Inefficient loop", sizeof(rule->name));
    strncpy(rule->description, "Function call in loop condition", sizeof(rule->description));
    rule->severity = SEVERITY_INFO;
    rule->category = CATEGORY_PERFORMANCE;
    strncpy(rule->suggestion, "Cache result before loop", sizeof(rule->suggestion));
    
    // Maintainability rules
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "MAINT001", sizeof(rule->id));
    strncpy(rule->name, "Magic number", sizeof(rule->name));
    strncpy(rule->description, "Use of unexplained numeric literal", sizeof(rule->description));
    rule->severity = SEVERITY_INFO;
    rule->category = CATEGORY_MAINTAINABILITY;
    strncpy(rule->suggestion, "Define as named constant", sizeof(rule->suggestion));
    
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "MAINT002", sizeof(rule->id));
    strncpy(rule->name, "TODO comment", sizeof(rule->name));
    strncpy(rule->description, "TODO comment found", sizeof(rule->description));
    rule->severity = SEVERITY_INFO;
    rule->category = CATEGORY_MAINTAINABILITY;
    strncpy(rule->suggestion, "Address TODO before merging", sizeof(rule->suggestion));
    
    // Documentation rules
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "DOC001", sizeof(rule->id));
    strncpy(rule->name, "Missing documentation", sizeof(rule->name));
    strncpy(rule->description, "Public function lacks documentation", sizeof(rule->description));
    rule->severity = SEVERITY_INFO;
    rule->category = CATEGORY_DOCUMENTATION;
    strncpy(rule->suggestion, "Add function documentation", sizeof(rule->suggestion));
}

//=============================================================================
// Code Review
//=============================================================================

ReviewReport* review_create_report(void) {
    ReviewReport* report = (ReviewReport*)calloc(1, sizeof(ReviewReport));
    init_review_rules(report);
    return report;
}

void review_destroy_report(ReviewReport* report) {
    free(report);
}

void add_issue(ReviewReport* report, ReviewRule* rule, const char* file, 
               int line, int column, const char* code_snippet) {
    if (report->issue_count >= MAX_ISSUES) return;
    
    ReviewIssue* issue = &report->issues[report->issue_count++];
    strncpy(issue->rule_id, rule->id, sizeof(issue->rule_id));
    snprintf(issue->message, sizeof(issue->message), "%s: %s", rule->name, rule->description);
    strncpy(issue->file, file, sizeof(issue->file) - 1);
    issue->line = line;
    issue->column = column;
    issue->severity = rule->severity;
    issue->category = rule->category;
    strncpy(issue->suggestion, rule->suggestion, sizeof(issue->suggestion) - 1);
    strncpy(issue->code_snippet, code_snippet, sizeof(issue->code_snippet) - 1);
    
    // Update counts
    switch (rule->severity) {
        case SEVERITY_ERROR: report->error_count++; break;
        case SEVERITY_WARNING: report->warning_count++; break;
        case SEVERITY_INFO: report->info_count++; break;
        case SEVERITY_STYLE: report->style_count++; break;
    }
}

void check_line_length(ReviewReport* report, const char* file, int line_num, const char* line) {
    size_t len = strlen(line);
    // Remove newline for counting
    if (len > 0 && line[len-1] == '\n') len--;
    
    if (len > 120) {
        for (int i = 0; i < report->rule_count; i++) {
            if (strcmp(report->rules[i].id, "STYLE001") == 0) {
                add_issue(report, &report->rules[i], file, line_num, 121, line);
                break;
            }
        }
    }
}

void check_trailing_whitespace(ReviewReport* report, const char* file, int line_num, const char* line) {
    size_t len = strlen(line);
    if (len > 0 && (line[len-1] == ' ' || line[len-1] == '\t' || line[len-1] == '\r')) {
        for (int i = 0; i < report->rule_count; i++) {
            if (strcmp(report->rules[i].id, "STYLE002") == 0) {
                add_issue(report, &report->rules[i], file, line_num, (int)len, line);
                break;
            }
        }
    }
}

void check_mixed_indentation(ReviewReport* report, const char* file, int line_num, const char* line) {
    int has_tabs = 0;
    int has_spaces = 0;
    
    for (const char* p = line; *p && (*p == ' ' || *p == '\t'); p++) {
        if (*p == '\t') has_tabs = 1;
        if (*p == ' ') has_spaces = 1;
    }
    
    if (has_tabs && has_spaces) {
        for (int i = 0; i < report->rule_count; i++) {
            if (strcmp(report->rules[i].id, "STYLE003") == 0) {
                add_issue(report, &report->rules[i], file, line_num, 1, line);
                break;
            }
        }
    }
}

void check_unsafe_functions(ReviewReport* report, const char* file, int line_num, const char* line) {
    if (strstr(line, "strcpy") || strstr(line, "strcat") || strstr(line, "gets")) {
        for (int i = 0; i < report->rule_count; i++) {
            if (strcmp(report->rules[i].id, "SEC001") == 0) {
                add_issue(report, &report->rules[i], file, line_num, 1, line);
                break;
            }
        }
    }
}

void check_todo_comments(ReviewReport* report, const char* file, int line_num, const char* line) {
    if (strstr(line, "TODO") || strstr(line, "FIXME") || strstr(line, "XXX")) {
        for (int i = 0; i < report->rule_count; i++) {
            if (strcmp(report->rules[i].id, "MAINT002") == 0) {
                add_issue(report, &report->rules[i], file, line_num, 1, line);
                break;
            }
        }
    }
}

void review_file(ReviewReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    report->files_reviewed++;
    
    char line[2048];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        report->lines_reviewed++;
        
        // Run all checks
        check_line_length(report, filename, line_num, line);
        check_trailing_whitespace(report, filename, line_num, line);
        check_mixed_indentation(report, filename, line_num, line);
        check_unsafe_functions(report, filename, line_num, line);
        check_todo_comments(report, filename, line_num, line);
    }
    
    fclose(f);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* severity_to_string(IssueSeverity severity) {
    switch (severity) {
        case SEVERITY_ERROR: return "ERROR";
        case SEVERITY_WARNING: return "WARNING";
        case SEVERITY_INFO: return "INFO";
        case SEVERITY_STYLE: return "STYLE";
        default: return "UNKNOWN";
    }
}

const char* category_to_string(IssueCategory category) {
    switch (category) {
        case CATEGORY_STYLE: return "Style";
        case CATEGORY_SECURITY: return "Security";
        case CATEGORY_PERFORMANCE: return "Performance";
        case CATEGORY_MAINTAINABILITY: return "Maintainability";
        case CATEGORY_DOCUMENTATION: return "Documentation";
        case CATEGORY_PORTABILITY: return "Portability";
        default: return "Unknown";
    }
}

void print_review_summary(ReviewReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Code Review Summary\n");
    printf("=============================================================================\n");
    printf("  Files Reviewed:     %d\n", report->files_reviewed);
    printf("  Lines Reviewed:     %d\n", report->lines_reviewed);
    printf("\n");
    printf("  Issues Found:\n");
    printf("    Errors:           %d\n", report->error_count);
    printf("    Warnings:         %d\n", report->warning_count);
    printf("    Info:             %d\n", report->info_count);
    printf("    Style:            %d\n", report->style_count);
    printf("    -----------------\n");
    printf("    Total:            %d\n", report->issue_count);
    printf("=============================================================================\n");
}

void print_review_issues(ReviewReport* report) {
    if (report->issue_count == 0) {
        printf("\n✅ No issues found!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Review Issues\n");
    printf("=============================================================================\n");
    
    // Group by severity
    IssueSeverity severities[] = {SEVERITY_ERROR, SEVERITY_WARNING, SEVERITY_INFO, SEVERITY_STYLE};
    const char* severity_names[] = {"ERRORS", "WARNINGS", "INFO", "STYLE"};
    
    for (int s = 0; s < 4; s++) {
        int count = 0;
        for (int i = 0; i < report->issue_count; i++) {
            if (report->issues[i].severity == severities[s]) count++;
        }
        
        if (count > 0) {
            printf("\n%s (%d):\n", severity_names[s], count);
            printf("-----------------------------------------------------------------------------\n");
            
            for (int i = 0; i < report->issue_count; i++) {
                ReviewIssue* issue = &report->issues[i];
                if (issue->severity == severities[s]) {
                    printf("  [%s] %s:%d\n", issue->rule_id, issue->file, issue->line);
                    printf("       %s\n", issue->message);
                    printf("       Category: %s\n", category_to_string(issue->category));
                    printf("       Suggestion: %s\n", issue->suggestion);
                    printf("\n");
                }
            }
        }
    }
    
    printf("=============================================================================\n");
}

void export_review_json(ReviewReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"files_reviewed\": %d,\n", report->files_reviewed);
    fprintf(f, "    \"lines_reviewed\": %d,\n", report->lines_reviewed);
    fprintf(f, "    \"total_issues\": %d,\n", report->issue_count);
    fprintf(f, "    \"errors\": %d,\n", report->error_count);
    fprintf(f, "    \"warnings\": %d,\n", report->warning_count);
    fprintf(f, "    \"info\": %d,\n", report->info_count);
    fprintf(f, "    \"style\": %d\n", report->style_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"issues\": [\n");
    
    for (int i = 0; i < report->issue_count; i++) {
        ReviewIssue* issue = &report->issues[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"rule_id\": \"%s\",\n", issue->rule_id);
        fprintf(f, "      \"severity\": \"%s\",\n", severity_to_string(issue->severity));
        fprintf(f, "      \"category\": \"%s\",\n", category_to_string(issue->category));
        fprintf(f, "      \"file\": \"%s\",\n", issue->file);
        fprintf(f, "      \"line\": %d,\n", issue->line);
        fprintf(f, "      \"message\": \"%s\",\n", issue->message);
        fprintf(f, "      \"suggestion\": \"%s\"\n", issue->suggestion);
        fprintf(f, "    }%s\n", (i < report->issue_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Review report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Code Review Assistant\n");
    printf("=============================\n\n");
    
    ReviewReport* report = review_create_report();
    
    // Review files
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            printf("Reviewing: %s\n", argv[i]);
            review_file(report, argv[i]);
        }
    } else {
        // Demo with current file
        printf("Reviewing: %s\n", __FILE__);
        review_file(report, __FILE__);
    }
    
    // Generate reports
    print_review_summary(report);
    print_review_issues(report);
    export_review_json(report, "code_review_report.json");
    
    printf("\nCode review complete!\n");
    
    int exit_code = report->error_count > 0 ? 1 : 0;
    review_destroy_report(report);
    
    return exit_code;
}
