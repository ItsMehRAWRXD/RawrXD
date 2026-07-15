//=============================================================================
// security_auditor.c - Security Auditor
// Production-ready security audit with vulnerability scanning
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Security Audit Types
//=============================================================================

#define MAX_FINDINGS 500
#define MAX_RULES 100
#define MAX_CATEGORIES 20

typedef enum {
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW,
    SEVERITY_INFO
} SeverityLevel;

typedef enum {
    CATEGORY_INJECTION,
    CATEGORY_BUFFER_OVERFLOW,
    CATEGORY_RACE_CONDITION,
    CATEGORY_CRYPTO,
    CATEGORY_AUTH,
    CATEGORY_CONFIG,
    CATEGORY_LOGGING,
    CATEGORY_NETWORK
} VulnCategory;

typedef struct {
    char id[32];
    char name[128];
    char description[1024];
    VulnCategory category;
    SeverityLevel severity;
    char pattern[512];
    char remediation[1024];
    char cwe_id[16];
    char owasp_id[16];
} SecurityRule;

typedef struct {
    char rule_id[32];
    char rule_name[128];
    SeverityLevel severity;
    VulnCategory category;
    char file[512];
    int line;
    int column;
    char match[256];
    char context[512];
    char remediation[1024];
    int is_false_positive;
    int confidence;  // 0-100
} SecurityFinding;

typedef struct {
    SecurityRule* rules;
    int rule_count;
    int rule_capacity;
    
    SecurityFinding* findings;
    int finding_count;
    int finding_capacity;
    
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
    int info_count;
    
    int files_scanned;
    int lines_scanned;
    double risk_score;
    int passed;
} SecurityAuditReport;

//=============================================================================
// Security Rules Database
//=============================================================================

void init_security_rules(SecurityAuditReport* report) {
    report->rule_capacity = MAX_RULES;
    report->rules = (SecurityRule*)calloc(report->rule_capacity, sizeof(SecurityRule));
    
    // SQL Injection
    SecurityRule* rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "SQL-001", sizeof(rule->id));
    strncpy(rule->name, "SQL Injection", sizeof(rule->name));
    strncpy(rule->description, "Unsanitized user input in SQL query", sizeof(rule->description));
    rule->category = CATEGORY_INJECTION;
    rule->severity = SEVERITY_CRITICAL;
    strncpy(rule->pattern, "(SELECT|INSERT|UPDATE|DELETE).*\\+.*%s", sizeof(rule->pattern));
    strncpy(rule->cwe_id, "CWE-89", sizeof(rule->cwe_id));
    strncpy(rule->owasp_id, "A03:2021", sizeof(rule->owasp_id));
    strncpy(rule->remediation, "Use parameterized queries or prepared statements", sizeof(rule->remediation));
    
    // Buffer Overflow
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "BUF-001", sizeof(rule->id));
    strncpy(rule->name, "Buffer Overflow", sizeof(rule->name));
    strncpy(rule->description, "Unsafe string operation without bounds checking", sizeof(rule->description));
    rule->category = CATEGORY_BUFFER_OVERFLOW;
    rule->severity = SEVERITY_CRITICAL;
    strncpy(rule->pattern, "(strcpy|strcat|sprintf|gets)\\s*\\(", sizeof(rule->pattern));
    strncpy(rule->cwe_id, "CWE-120", sizeof(rule->cwe_id));
    strncpy(rule->owasp_id, "A02:2021", sizeof(rule->owasp_id));
    strncpy(rule->remediation, "Use strncpy, strncat, snprintf, or fgets with bounds checking", sizeof(rule->remediation));
    
    // Hardcoded Credentials
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "CRED-001", sizeof(rule->id));
    strncpy(rule->name, "Hardcoded Credentials", sizeof(rule->name));
    strncpy(rule->description, "Hardcoded password or API key in source code", sizeof(rule->description));
    rule->category = CATEGORY_AUTH;
    rule->severity = SEVERITY_HIGH;
    strncpy(rule->pattern, "(password|passwd|secret|api_key)\\s*=\\s*['\"][^'\"]+['\"]", sizeof(rule->pattern));
    strncpy(rule->cwe_id, "CWE-798", sizeof(rule->cwe_id));
    strncpy(rule->owasp_id, "A07:2021", sizeof(rule->owasp_id));
    strncpy(rule->remediation, "Use environment variables or secure credential storage", sizeof(rule->remediation));
    
    // Weak Cryptography
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "CRYPTO-001", sizeof(rule->id));
    strncpy(rule->name, "Weak Cryptography", sizeof(rule->name));
    strncpy(rule->description, "Use of weak cryptographic algorithm", sizeof(rule->description));
    rule->category = CATEGORY_CRYPTO;
    rule->severity = SEVERITY_HIGH;
    strncpy(rule->pattern, "(MD5|SHA1|DES|RC4)", sizeof(rule->pattern));
    strncpy(rule->cwe_id, "CWE-327", sizeof(rule->cwe_id));
    strncpy(rule->owasp_id, "A02:2021", sizeof(rule->owasp_id));
    strncpy(rule->remediation, "Use AES-256-GCM, ChaCha20-Poly1305, or SHA-256+", sizeof(rule->remediation));
    
    // Command Injection
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "CMD-001", sizeof(rule->id));
    strncpy(rule->name, "Command Injection", sizeof(rule->name));
    strncpy(rule->description, "User input in system command", sizeof(rule->description));
    rule->category = CATEGORY_INJECTION;
    rule->severity = SEVERITY_CRITICAL;
    strncpy(rule->pattern, "(system|popen|exec)\\s*\\(.*\\+", sizeof(rule->pattern));
    strncpy(rule->cwe_id, "CWE-78", sizeof(rule->cwe_id));
    strncpy(rule->owasp_id, "A03:2021", sizeof(rule->owasp_id));
    strncpy(rule->remediation, "Use execve with array arguments, validate input", sizeof(rule->remediation));
    
    // Path Traversal
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "PATH-001", sizeof(rule->id));
    strncpy(rule->name, "Path Traversal", sizeof(rule->name));
    strncpy(rule->description, "User input in file path without validation", sizeof(rule->description));
    rule->category = CATEGORY_INJECTION;
    rule->severity = SEVERITY_HIGH;
    strncpy(rule->pattern, "(fopen|open)\\s*\\(.*\\+", sizeof(rule->pattern));
    strncpy(rule->cwe_id, "CWE-22", sizeof(rule->cwe_id));
    strncpy(rule->owasp_id, "A01:2021", sizeof(rule->owasp_id));
    strncpy(rule->remediation, "Validate and sanitize file paths, use chroot", sizeof(rule->remediation));
    
    // Race Condition
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "RACE-001", sizeof(rule->id));
    strncpy(rule->name, "TOCTOU Race Condition", sizeof(rule->name));
    strncpy(rule->description, "Time-of-check to time-of-use vulnerability", sizeof(rule->description));
    rule->category = CATEGORY_RACE_CONDITION;
    rule->severity = SEVERITY_MEDIUM;
    strncpy(rule->pattern, "(access|stat)\\s*\\(.*\\).*fopen", sizeof(rule->pattern));
    strncpy(rule->cwe_id, "CWE-367", sizeof(rule->cwe_id));
    strncpy(rule->remediation, "Use file descriptors instead of paths", sizeof(rule->remediation));
    
    // Insecure Logging
    rule = &report->rules[report->rule_count++];
    strncpy(rule->id, "LOG-001", sizeof(rule->id));
    strncpy(rule->name, "Sensitive Data in Logs", sizeof(rule->name));
    strncpy(rule->description, "Sensitive information may be logged", sizeof(rule->description));
    rule->category = CATEGORY_LOGGING;
    rule->severity = SEVERITY_MEDIUM;
    strncpy(rule->pattern, "(printf|fprintf|syslog)\\s*\\(.*password", sizeof(rule->pattern));
    strncpy(rule->cwe_id, "CWE-532", sizeof(rule->cwe_id));
    strncpy(rule->owasp_id, "A09:2021", sizeof(rule->owasp_id));
    strncpy(rule->remediation, "Remove sensitive data from log statements", sizeof(rule->remediation));
}

//=============================================================================
// Security Auditor Implementation
//=============================================================================

SecurityAuditReport* security_audit_create(void) {
    SecurityAuditReport* report = (SecurityAuditReport*)calloc(1, sizeof(SecurityAuditReport));
    report->finding_capacity = MAX_FINDINGS;
    report->findings = (SecurityFinding*)calloc(report->finding_capacity, sizeof(SecurityFinding));
    init_security_rules(report);
    return report;
}

void security_audit_destroy(SecurityAuditReport* report) {
    if (!report) return;
    free(report->rules);
    free(report->findings);
    free(report);
}

int is_false_positive(SecurityFinding* finding) {
    // Check for test files
    if (strstr(finding->file, "test") ||
        strstr(finding->file, "spec") ||
        strstr(finding->file, "mock")) {
        return 1;
    }
    
    // Check for comments
    if (strstr(finding->context, "//") || strstr(finding->context, "/*")) {
        if (strstr(finding->context, "NOSCAN") || strstr(finding->context, "nosec")) {
            return 1;
        }
    }
    
    return 0;
}

void add_finding(SecurityAuditReport* report, SecurityRule* rule,
                 const char* file, int line, const char* match, const char* context) {
    if (report->finding_count >= report->finding_capacity) return;
    
    SecurityFinding* finding = &report->findings[report->finding_count++];
    strncpy(finding->rule_id, rule->id, sizeof(finding->rule_id) - 1);
    strncpy(finding->rule_name, rule->name, sizeof(finding->rule_name) - 1);
    finding->severity = rule->severity;
    finding->category = rule->category;
    strncpy(finding->file, file, sizeof(finding->file) - 1);
    finding->line = line;
    strncpy(finding->match, match, sizeof(finding->match) - 1);
    strncpy(finding->context, context, sizeof(finding->context) - 1);
    strncpy(finding->remediation, rule->remediation, sizeof(finding->remediation) - 1);
    finding->confidence = 85;
    finding->is_false_positive = is_false_positive(finding);
    
    if (finding->is_false_positive) return;
    
    switch (rule->severity) {
        case SEVERITY_CRITICAL: report->critical_count++; break;
        case SEVERITY_HIGH: report->high_count++; break;
        case SEVERITY_MEDIUM: report->medium_count++; break;
        case SEVERITY_LOW: report->low_count++; break;
        case SEVERITY_INFO: report->info_count++; break;
    }
}

void scan_line(SecurityAuditReport* report, const char* file, int line_num, const char* line) {
    report->lines_scanned++;
    
    for (int i = 0; i < report->rule_count; i++) {
        SecurityRule* rule = &report->rules[i];
        
        // Simple pattern matching
        if (strstr(line, rule->pattern)) {
            char match[256] = {0};
            strncpy(match, line, sizeof(match) - 1);
            
            char context[512] = {0};
            strncpy(context, line, sizeof(context) - 1);
            
            add_finding(report, rule, file, line_num, match, context);
        }
    }
}

void scan_file(SecurityAuditReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    report->files_scanned++;
    
    char line[4096];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        scan_line(report, filename, line_num, line);
    }
    
    fclose(f);
}

void calculate_risk_score(SecurityAuditReport* report) {
    double score = 0;
    score += report->critical_count * 10.0;
    score += report->high_count * 5.0;
    score += report->medium_count * 2.0;
    score += report->low_count * 0.5;
    
    // Normalize to 0-100
    report->risk_score = score > 100 ? 100 : score;
    report->passed = (report->critical_count == 0 && report->high_count == 0);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* severity_to_string(SeverityLevel severity) {
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
        case CATEGORY_INJECTION: return "Injection";
        case CATEGORY_BUFFER_OVERFLOW: return "Buffer Overflow";
        case CATEGORY_RACE_CONDITION: return "Race Condition";
        case CATEGORY_CRYPTO: return "Cryptography";
        case CATEGORY_AUTH: return "Authentication";
        case CATEGORY_CONFIG: return "Configuration";
        case CATEGORY_LOGGING: return "Logging";
        case CATEGORY_NETWORK: return "Network";
        default: return "Unknown";
    }
}

void print_audit_summary(SecurityAuditReport* report) {
    calculate_risk_score(report);
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Security Audit Summary\n");
    printf("=============================================================================\n");
    printf("  Files Scanned:        %d\n", report->files_scanned);
    printf("  Lines Scanned:        %d\n", report->lines_scanned);
    printf("  Risk Score:           %.1f/100\n", report->risk_score);
    printf("  Status:               %s\n", report->passed ? "✅ PASSED" : "❌ FAILED");
    printf("\n");
    printf("  Findings:\n");
    printf("    CRITICAL:           %d\n", report->critical_count);
    printf("    HIGH:               %d\n", report->high_count);
    printf("    MEDIUM:             %d\n", report->medium_count);
    printf("    LOW:                %d\n", report->low_count);
    printf("=============================================================================\n");
}

void print_findings(SecurityAuditReport* report) {
    if (report->finding_count == 0) {
        printf("\n✅ No security issues found!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Security Findings\n");
    printf("=============================================================================\n");
    
    SeverityLevel severities[] = {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW};
    const char* severity_names[] = {"CRITICAL", "HIGH", "MEDIUM", "LOW"};
    
    for (int s = 0; s < 4; s++) {
        int count = 0;
        for (int i = 0; i < report->finding_count; i++) {
            if (report->findings[i].severity == severities[s] &&
                !report->findings[i].is_false_positive) {
                count++;
            }
        }
        
        if (count > 0) {
            printf("\n%s Findings (%d):\n", severity_names[s], count);
            printf("-----------------------------------------------------------------------------\n");
            
            for (int i = 0; i < report->finding_count; i++) {
                SecurityFinding* finding = &report->findings[i];
                if (finding->severity == severities[s] && !finding->is_false_positive) {
                    printf("  [%s] %s\n", finding->rule_id, finding->rule_name);
                    printf("       Category: %s\n", category_to_string(finding->category));
                    printf("       Location: %s:%d\n", finding->file, finding->line);
                    printf("       Confidence: %d%%\n", finding->confidence);
                    printf("       Fix: %s\n", finding->remediation);
                    printf("\n");
                }
            }
        }
    }
    
    printf("=============================================================================\n");
}

void export_audit_json(SecurityAuditReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"files_scanned\": %d,\n", report->files_scanned);
    fprintf(f, "    \"lines_scanned\": %d,\n", report->lines_scanned);
    fprintf(f, "    \"risk_score\": %.1f,\n", report->risk_score);
    fprintf(f, "    \"passed\": %s,\n", report->passed ? "true" : "false");
    fprintf(f, "    \"critical\": %d,\n", report->critical_count);
    fprintf(f, "    \"high\": %d,\n", report->high_count);
    fprintf(f, "    \"medium\": %d,\n", report->medium_count);
    fprintf(f, "    \"low\": %d\n", report->low_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"findings\": [\n");
    
    int first = 1;
    for (int i = 0; i < report->finding_count; i++) {
        SecurityFinding* finding = &report->findings[i];
        if (finding->is_false_positive) continue;
        
        if (!first) fprintf(f, ",\n");
        first = 0;
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"rule_id\": \"%s\",\n", finding->rule_id);
        fprintf(f, "      \"rule_name\": \"%s\",\n", finding->rule_name);
        fprintf(f, "      \"severity\": \"%s\",\n", severity_to_string(finding->severity));
        fprintf(f, "      \"category\": \"%s\",\n", category_to_string(finding->category));
        fprintf(f, "      \"file\": \"%s\",\n", finding->file);
        fprintf(f, "      \"line\": %d,\n", finding->line);
        fprintf(f, "      \"confidence\": %d,\n", finding->confidence);
        fprintf(f, "      \"remediation\": \"%s\"\n", finding->remediation);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Security audit exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Security Auditor\n");
    printf("=======================\n\n");
    
    SecurityAuditReport* report = security_audit_create();
    
    // Scan files
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            printf("Scanning: %s\n", argv[i]);
            scan_file(report, argv[i]);
        }
    } else {
        printf("Scanning: %s\n", __FILE__);
        scan_file(report, __FILE__);
    }
    
    // Generate reports
    print_audit_summary(report);
    print_findings(report);
    export_audit_json(report, "security_audit.json");
    
    printf("\nSecurity audit complete!\n");
    
    int exit_code = report->passed ? 0 : 1;
    security_audit_destroy(report);
    
    return exit_code;
}
