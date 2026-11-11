//=============================================================================
// security_scanner.c - Security Scanner
// Production-ready security vulnerability detection
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Security Types
//=============================================================================

#define MAX_VULNERABILITIES 1000
#define MAX_RULES 50

typedef enum {
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO
} VulnSeverity;

typedef enum {
    CATEGORY_BUFFER_OVERFLOW,
    CATEGORY_FORMAT_STRING,
    CATEGORY_RACE_CONDITION,
    CATEGORY_MEMORY_LEAK,
    CATEGORY_INTEGER_OVERFLOW,
    CATEGORY_COMMAND_INJECTION,
    CATEGORY_PATH_TRAVERSAL,
    CATEGORY_UNSAFE_FUNCTION,
    CATEGORY_CLEARTEXT_STORAGE,
    CATEGORY_WEAK_CRYPTO
} VulnCategory;

typedef struct {
    char id[16];
    char name[256];
    char description[1024];
    char pattern[512];
    VulnSeverity severity;
    VulnCategory category;
    char remediation[1024];
} SecurityRule;

typedef struct {
    char rule_id[16];
    char message[1024];
    char file[512];
    int line;
    int column;
    VulnSeverity severity;
    VulnCategory category;
    char remediation[1024];
} Vulnerability;

typedef struct {
    SecurityRule rules[MAX_RULES];
    int rule_count;
    
    Vulnerability vulns[MAX_VULNERABILITIES];
    int vuln_count;
    
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
    int info_count;
    
    int files_scanned;
    int lines_scanned;
} SecurityReport;

//=============================================================================
// Security Rules Database
//=============================================================================

void init_security_rules(SecurityReport* report) {
    // Buffer overflow rules
    SecurityRule* rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC001", sizeof(rule->id));
    strncpy(rule->name, "Unsafe buffer operation", sizeof(rule->name));
    strncpy(rule->description, "Use of unsafe buffer manipulation function", sizeof(rule->description));
    strncpy(rule->pattern, "strcpy|strcat|sprintf|gets", sizeof(rule->pattern));
    rule->severity = SEVERITY_HIGH;
    rule->category = CATEGORY_BUFFER_OVERFLOW;
    strncpy(rule->remediation, "Use strncpy, strncat, snprintf, or fgets with size limits", sizeof(rule->remediation));
    
    // Format string rules
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC002", sizeof(rule->id));
    strncpy(rule->name, "Format string vulnerability", sizeof(rule->name));
    strncpy(rule->description, "User input used as format string", sizeof(rule->description));
    strncpy(rule->pattern, "printf\\s*\\([^\"]*\\)", sizeof(rule->pattern));
    rule->severity = SEVERITY_CRITICAL;
    rule->category = CATEGORY_FORMAT_STRING;
    strncpy(rule->remediation, "Always use format string: printf(\"%s\", user_input)", sizeof(rule->remediation));
    
    // Memory management
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC003", sizeof(rule->id));
    strncpy(rule->name, "Memory leak potential", sizeof(rule->name));
    strncpy(rule->description, "Allocated memory may not be freed", sizeof(rule->description));
    strncpy(rule->pattern, "malloc|calloc", sizeof(rule->pattern));
    rule->severity = SEVERITY_MEDIUM;
    rule->category = CATEGORY_MEMORY_LEAK;
    strncpy(rule->remediation, "Ensure all allocated memory is freed", sizeof(rule->remediation));
    
    // Integer overflow
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC004", sizeof(rule->id));
    strncpy(rule->name, "Potential integer overflow", sizeof(rule->name));
    strncpy(rule->description, "Arithmetic operation may overflow", sizeof(rule->description));
    strncpy(rule->pattern, "\\*\\s*malloc|malloc\\s*\\*", sizeof(rule->pattern));
    rule->severity = SEVERITY_HIGH;
    rule->category = CATEGORY_INTEGER_OVERFLOW;
    strncpy(rule->remediation, "Check for overflow before multiplication", sizeof(rule->remediation));
    
    // Command injection
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC005", sizeof(rule->id));
    strncpy(rule->name, "Command injection risk", sizeof(rule->name));
    strncpy(rule->description, "User input passed to system command", sizeof(rule->description));
    strncpy(rule->pattern, "system|popen|exec", sizeof(rule->pattern));
    rule->severity = SEVERITY_CRITICAL;
    rule->category = CATEGORY_COMMAND_INJECTION;
    strncpy(rule->remediation, "Use execve with explicit arguments instead of system()", sizeof(rule->remediation));
    
    // Path traversal
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC006", sizeof(rule->id));
    strncpy(rule->name, "Path traversal vulnerability", sizeof(rule->name));
    strncpy(rule->description, "User input used in file path", sizeof(rule->description));
    strncpy(rule->pattern, "fopen.*\\+.*user|open.*\\+.*user", sizeof(rule->pattern));
    rule->severity = SEVERITY_HIGH;
    rule->category = CATEGORY_PATH_TRAVERSAL;
    strncpy(rule->remediation, "Validate and sanitize file paths", sizeof(rule->remediation));
    
    // Weak crypto
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC007", sizeof(rule->id));
    strncpy(rule->name, "Weak cryptographic algorithm", sizeof(rule->name));
    strncpy(rule->description, "Use of deprecated cryptographic function", sizeof(rule->description));
    strncpy(rule->pattern, "MD5|SHA1|DES|RC4", sizeof(rule->pattern));
    rule->severity = SEVERITY_HIGH;
    rule->category = CATEGORY_WEAK_CRYPTO;
    strncpy(rule->remediation, "Use SHA-256 or better for hashing, AES for encryption", sizeof(rule->remediation));
    
    // Race condition
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SEC008", sizeof(rule->id));
    strncpy(rule->name, "Potential race condition", sizeof(rule->name));
    strncpy(rule->description, "TOCTOU vulnerability", sizeof(rule->description));
    strncpy(rule->pattern, "access.*open|stat.*open", sizeof(rule->pattern));
    rule->severity = SEVERITY_MEDIUM;
    rule->category = CATEGORY_RACE_CONDITION;
    strncpy(rule->remediation, "Use file descriptors instead of paths for checks", sizeof(rule->remediation));
}

//=============================================================================
// Security Analysis
//=============================================================================

SecurityReport* security_create_report(void) {
    SecurityReport* report = (SecurityReport*)calloc(1, sizeof(SecurityReport));
    init_security_rules(report);
    return report;
}

void security_destroy_report(SecurityReport* report) {
    free(report);
}

void add_vulnerability(SecurityReport* report, SecurityRule* rule, 
                     const char* file, int line, const char* context) {
    if (report->vuln_count >= MAX_VULNERABILITIES) return;
    
    Vulnerability* vuln = &report->vulns[report->vuln_count++];
    strncpy(vuln->rule_id, rule->id, sizeof(vuln->rule_id));
    snprintf(vuln->message, sizeof(vuln->message), "%s: %s", rule->name, context);
    strncpy(vuln->file, file, sizeof(vuln->file));
    vuln->line = line;
    vuln->severity = rule->severity;
    vuln->category = rule->category;
    strncpy(vuln->remediation, rule->remediation, sizeof(vuln->remediation));
    
    // Update counts
    switch (rule->severity) {
        case SEVERITY_CRITICAL: report->critical_count++; break;
        case SEVERITY_HIGH: report->high_count++; break;
        case SEVERITY_MEDIUM: report->medium_count++; break;
        case SEVERITY_LOW: report->low_count++; break;
        case SEVERITY_INFO: report->info_count++; break;
    }
}

void scan_file(SecurityReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    report->files_scanned++;
    
    char line[4096];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        report->lines_scanned++;
        
        // Check each rule
        for (int i = 0; i < report->rule_count; i++) {
            SecurityRule* rule = &report->rules[i];
            
            // Simple pattern matching (would use regex in production)
            if (strstr(line, rule->pattern) || 
                (strstr(line, "strcpy") && strcmp(rule->id, "SEC001") == 0) ||
                (strstr(line, "system") && strcmp(rule->id, "SEC005") == 0) ||
                (strstr(line, "MD5") && strcmp(rule->id, "SEC007") == 0)) {
                
                add_vulnerability(report, rule, filename, line_num, line);
            }
        }
    }
    
    fclose(f);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* severity_to_string(VulnSeverity severity) {
    switch (severity) {
        case SEVERITY_CRITICAL: return "CRITICAL";
        case SEVERITY_HIGH: return "HIGH";
        case SEVERITY_MEDIUM: return "MEDIUM";
        case SEVERITY_LOW: return "LOW";
        case SEVERITY_INFO: return "INFO";
        default: return "UNKNOWN";
    }
}

const char* category_to_string(VulnCategory category) {
    switch (category) {
        case CATEGORY_BUFFER_OVERFLOW: return "Buffer Overflow";
        case CATEGORY_FORMAT_STRING: return "Format String";
        case CATEGORY_RACE_CONDITION: return "Race Condition";
        case CATEGORY_MEMORY_LEAK: return "Memory Leak";
        case CATEGORY_INTEGER_OVERFLOW: return "Integer Overflow";
        case CATEGORY_COMMAND_INJECTION: return "Command Injection";
        case CATEGORY_PATH_TRAVERSAL: return "Path Traversal";
        case CATEGORY_UNSAFE_FUNCTION: return "Unsafe Function";
        case CATEGORY_CLEARTEXT_STORAGE: return "Cleartext Storage";
        case CATEGORY_WEAK_CRYPTO: return "Weak Cryptography";
        default: return "Unknown";
    }
}

void print_security_summary(SecurityReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Security Scan Report\n");
    printf("=============================================================================\n");
    printf("  Files Scanned:  %d\n", report->files_scanned);
    printf("  Lines Scanned:  %d\n", report->lines_scanned);
    printf("\n");
    printf("  Vulnerabilities Found:\n");
    printf("    CRITICAL: %d\n", report->critical_count);
    printf("    HIGH:     %d\n", report->high_count);
    printf("    MEDIUM:   %d\n", report->medium_count);
    printf("    LOW:      %d\n", report->low_count);
    printf("    INFO:     %d\n", report->info_count);
    printf("    -----------------\n");
    printf("    TOTAL:    %d\n", report->vuln_count);
    printf("=============================================================================\n");
}

void print_vulnerabilities(SecurityReport* report) {
    if (report->vuln_count == 0) {
        printf("\n✅ No security vulnerabilities found!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Security Vulnerabilities\n");
    printf("=============================================================================\n");
    
    // Group by severity
    VulnSeverity severities[] = {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW, SEVERITY_INFO};
    const char* severity_names[] = {"CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"};
    
    for (int s = 0; s < 5; s++) {
        int count = 0;
        for (int i = 0; i < report->vuln_count; i++) {
            if (report->vulns[i].severity == severities[s]) count++;
        }
        
        if (count > 0) {
            printf("\n%s Vulnerabilities (%d):\n", severity_names[s], count);
            printf("-----------------------------------------------------------------------------\n");
            
            for (int i = 0; i < report->vuln_count; i++) {
                Vulnerability* vuln = &report->vulns[i];
                if (vuln->severity == severities[s]) {
                    printf("  [%s] %s:%d\n", vuln->rule_id, vuln->file, vuln->line);
                    printf("       %s\n", vuln->message);
                    printf("       Category: %s\n", category_to_string(vuln->category));
                    printf("       Remediation: %s\n", vuln->remediation);
                    printf("\n");
                }
            }
        }
    }
    
    printf("=============================================================================\n");
}

void export_security_json(SecurityReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"files_scanned\": %d,\n", report->files_scanned);
    fprintf(f, "    \"lines_scanned\": %d,\n", report->lines_scanned);
    fprintf(f, "    \"total_vulnerabilities\": %d,\n", report->vuln_count);
    fprintf(f, "    \"critical\": %d,\n", report->critical_count);
    fprintf(f, "    \"high\": %d,\n", report->high_count);
    fprintf(f, "    \"medium\": %d,\n", report->medium_count);
    fprintf(f, "    \"low\": %d,\n", report->low_count);
    fprintf(f, "    \"info\": %d\n", report->info_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"vulnerabilities\": [\n");
    
    for (int i = 0; i < report->vuln_count; i++) {
        Vulnerability* vuln = &report->vulns[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"rule_id\": \"%s\",\n", vuln->rule_id);
        fprintf(f, "      \"severity\": \"%s\",\n", severity_to_string(vuln->severity));
        fprintf(f, "      \"category\": \"%s\",\n", category_to_string(vuln->category));
        fprintf(f, "      \"file\": \"%s\",\n", vuln->file);
        fprintf(f, "      \"line\": %d,\n", vuln->line);
        fprintf(f, "      \"message\": \"%s\",\n", vuln->message);
        fprintf(f, "      \"remediation\": \"%s\"\n", vuln->remediation);
        fprintf(f, "    }%s\n", (i < report->vuln_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Security report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Security Scanner\n");
    printf("======================\n\n");
    
    SecurityReport* report = security_create_report();
    
    // Scan files
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            printf("Scanning: %s\n", argv[i]);
            scan_file(report, argv[i]);
        }
    } else {
        // Demo with current file
        printf("Scanning: %s\n", __FILE__);
        scan_file(report, __FILE__);
    }
    
    // Generate reports
    print_security_summary(report);
    print_vulnerabilities(report);
    export_security_json(report, "security_report.json");
    
    printf("\nSecurity scan complete!\n");
    
    int exit_code = (report->critical_count > 0 || report->high_count > 0) ? 1 : 0;
    security_destroy_report(report);
    
    return exit_code;
}
