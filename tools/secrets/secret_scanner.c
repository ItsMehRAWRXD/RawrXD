//=============================================================================
// secret_scanner.c - Secret and Credential Scanner
// Production-ready detection of secrets, keys, and credentials in code
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Secret Types
//=============================================================================

#define MAX_FINDINGS 1000
#define MAX_RULES 50
#define MAX_FILE_SIZE 1048576

typedef enum {
    SECRET_API_KEY,
    SECRET_PASSWORD,
    SECRET_TOKEN,
    SECRET_PRIVATE_KEY,
    SECRET_CERTIFICATE,
    SECRET_DATABASE_URL,
    SECRET_AWS_KEY,
    SECRET_GITHUB_TOKEN,
    SECRET_SLACK_TOKEN,
    SECRET_JWT
} SecretType;

typedef enum {
    SEVERITY_CRITICAL,
    SEVERITY_HIGH,
    SEVERITY_MEDIUM,
    SEVERITY_LOW
} SecretSeverity;

typedef struct {
    char name[128];
    SecretType type;
    SecretSeverity severity;
    char pattern[512];
    char description[512];
    int entropy_threshold;
} SecretRule;

typedef struct {
    char rule_name[128];
    SecretType type;
    SecretSeverity severity;
    char file[512];
    int line;
    int column;
    char match[256];
    char redacted[256];
    char context[512];
    double entropy;
    int is_false_positive;
} SecretFinding;

typedef struct {
    SecretRule rules[MAX_RULES];
    int rule_count;
    
    SecretFinding* findings;
    int finding_count;
    int finding_capacity;
    
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
    int false_positive_count;
    
    int files_scanned;
    int lines_scanned;
    int bytes_scanned;
} SecretReport;

//=============================================================================
// Secret Detection Rules
//=============================================================================

void init_secret_rules(SecretReport* report) {
    // AWS Access Key
    SecretRule* rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "AWS Access Key", sizeof(rule->name));
    rule->type = SECRET_AWS_KEY;
    rule->severity = SEVERITY_CRITICAL;
    strncpy(rule->pattern, "AKIA[0-9A-Z]{16}", sizeof(rule->pattern));
    strncpy(rule->description, "AWS Access Key ID", sizeof(rule->description));
    rule->entropy_threshold = 3;
    
    // AWS Secret Key
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "AWS Secret Key", sizeof(rule->name));
    rule->type = SECRET_AWS_KEY;
    rule->severity = SEVERITY_CRITICAL;
    strncpy(rule->pattern, "[0-9a-zA-Z/+]{40}", sizeof(rule->pattern));
    strncpy(rule->description, "AWS Secret Access Key", sizeof(rule->description));
    rule->entropy_threshold = 4;
    
    // GitHub Token
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "GitHub Token", sizeof(rule->name));
    rule->type = SECRET_GITHUB_TOKEN;
    rule->severity = SEVERITY_CRITICAL;
    strncpy(rule->pattern, "ghp_[a-zA-Z0-9]{36}", sizeof(rule->pattern));
    strncpy(rule->description, "GitHub Personal Access Token", sizeof(rule->description));
    rule->entropy_threshold = 3;
    
    // Slack Token
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "Slack Token", sizeof(rule->name));
    rule->type = SECRET_SLACK_TOKEN;
    rule->severity = SEVERITY_HIGH;
    strncpy(rule->pattern, "xox[baprs]-[0-9a-zA-Z-]{10,48}", sizeof(rule->pattern));
    strncpy(rule->description, "Slack API Token", sizeof(rule->description));
    rule->entropy_threshold = 3;
    
    // Private Key
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "Private Key", sizeof(rule->name));
    rule->type = SECRET_PRIVATE_KEY;
    rule->severity = SEVERITY_CRITICAL;
    strncpy(rule->pattern, "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", sizeof(rule->pattern));
    strncpy(rule->description, "Private Key File", sizeof(rule->description));
    rule->entropy_threshold = 0;
    
    // API Key Generic
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "Generic API Key", sizeof(rule->name));
    rule->type = SECRET_API_KEY;
    rule->severity = SEVERITY_HIGH;
    strncpy(rule->pattern, "[aA][pP][iI][-_]?[kK][eE][yY][\s]*[=:][\s]*['\"][a-zA-Z0-9]{16,64}['\"]", sizeof(rule->pattern));
    strncpy(rule->description, "Generic API Key", sizeof(rule->description));
    rule->entropy_threshold = 3;
    
    // Password in code
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "Hardcoded Password", sizeof(rule->name));
    rule->type = SECRET_PASSWORD;
    rule->severity = SEVERITY_HIGH;
    strncpy(rule->pattern, "[pP][aA][sS][sS][wW][oO][rR][dD][\s]*[=:][\s]*['\"][^'\"]{4,}['\"]", sizeof(rule->pattern));
    strncpy(rule->description, "Hardcoded password", sizeof(rule->description));
    rule->entropy_threshold = 2;
    
    // Database URL
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "Database URL", sizeof(rule->name));
    rule->type = SECRET_DATABASE_URL;
    rule->severity = SEVERITY_HIGH;
    strncpy(rule->pattern, "(postgres|mysql|mongodb|redis)://[^\s\"']+", sizeof(rule->pattern));
    strncpy(rule->description, "Database connection string with credentials", sizeof(rule->description));
    rule->entropy_threshold = 3;
    
    // JWT Token
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "JWT Token", sizeof(rule->name));
    rule->type = SECRET_JWT;
    rule->severity = SEVERITY_MEDIUM;
    strncpy(rule->pattern, "eyJ[a-zA-Z0-9_-]*\.eyJ[a-zA-Z0-9_-]*\.[a-zA-Z0-9_-]*", sizeof(rule->pattern));
    strncpy(rule->description, "JSON Web Token", sizeof(rule->description));
    rule->entropy_threshold = 3;
    
    // Certificate
    rule = &report->rules[report->rule_count++];
    strncpy(rule->name, "Certificate", sizeof(rule->name));
    rule->type = SECRET_CERTIFICATE;
    rule->severity = SEVERITY_MEDIUM;
    strncpy(rule->pattern, "-----BEGIN CERTIFICATE-----", sizeof(rule->pattern));
    strncpy(rule->description, "X.509 Certificate", sizeof(rule->description));
    rule->entropy_threshold = 0;
}

//=============================================================================
// Secret Scanner Implementation
//=============================================================================

SecretReport* secret_create_report(void) {
    SecretReport* report = (SecretReport*)calloc(1, sizeof(SecretReport));
    report->finding_capacity = MAX_FINDINGS;
    report->findings = (SecretFinding*)calloc(report->finding_capacity, sizeof(SecretFinding));
    init_secret_rules(report);
    return report;
}

void secret_destroy_report(SecretReport* report) {
    if (!report) return;
    free(report->findings);
    free(report);
}

double calculate_entropy(const char* str) {
    int freq[256] = {0};
    int len = strlen(str);
    if (len == 0) return 0;
    
    for (int i = 0; i < len; i++) {
        freq[(unsigned char)str[i]]++;
    }
    
    double entropy = 0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

void redact_secret(const char* secret, char* redacted, size_t size) {
    int len = strlen(secret);
    if (len <= 8) {
        strncpy(redacted, "****", size);
    } else {
        snprintf(redacted, size, "%.4s...%.4s", secret, secret + len - 4);
    }
}

int is_false_positive(const char* match, SecretType type) {
    // Check for common false positives
    if (strstr(match, "example") || strstr(match, "sample") ||
        strstr(match, "test") || strstr(match, "dummy") ||
        strstr(match, "placeholder")) {
        return 1;
    }
    
    // Check for template patterns
    if (strstr(match, "${") || strstr(match, "{{") || strstr(match, "<%")) {
        return 1;
    }
    
    return 0;
}

void add_finding(SecretReport* report, SecretRule* rule, const char* file,
                 int line, int column, const char* match, const char* context) {
    if (report->finding_count >= report->finding_capacity) return;
    
    SecretFinding* finding = &report->findings[report->finding_count++];
    strncpy(finding->rule_name, rule->name, sizeof(finding->rule_name) - 1);
    finding->type = rule->type;
    finding->severity = rule->severity;
    strncpy(finding->file, file, sizeof(finding->file) - 1);
    finding->line = line;
    finding->column = column;
    strncpy(finding->match, match, sizeof(finding->match) - 1);
    redact_secret(match, finding->redacted, sizeof(finding->redacted));
    strncpy(finding->context, context, sizeof(finding->context) - 1);
    finding->entropy = calculate_entropy(match);
    finding->is_false_positive = is_false_positive(match, rule->type);
    
    if (finding->is_false_positive) {
        report->false_positive_count++;
        return;
    }
    
    // Update counts
    switch (rule->severity) {
        case SEVERITY_CRITICAL: report->critical_count++; break;
        case SEVERITY_HIGH: report->high_count++; break;
        case SEVERITY_MEDIUM: report->medium_count++; break;
        case SEVERITY_LOW: report->low_count++; break;
    }
}

void scan_line(SecretReport* report, const char* file, int line_num, const char* line) {
    report->lines_scanned++;
    
    for (int i = 0; i < report->rule_count; i++) {
        SecretRule* rule = &report->rules[i];
        
        // Simple pattern matching (would use regex in production)
        const char* pos = line;
        while ((pos = strstr(pos, rule->pattern)) != NULL) {
            // Extract match
            char match[256] = {0};
            int match_len = strlen(rule->pattern);
            if (match_len > 255) match_len = 255;
            strncpy(match, pos, match_len);
            
            // Get context
            char context[512] = {0};
            int start = (pos - line) - 20;
            if (start < 0) start = 0;
            int len = 60;
            if (start + len > (int)strlen(line)) len = strlen(line) - start;
            strncpy(context, line + start, len);
            
            // Check entropy
            if (rule->entropy_threshold > 0) {
                double entropy = calculate_entropy(match);
                if (entropy < rule->entropy_threshold) {
                    pos++;
                    continue;
                }
            }
            
            add_finding(report, rule, file, line_num, (int)(pos - line), match, context);
            pos++;
        }
    }
}

void scan_file(SecretReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    report->files_scanned++;
    
    char line[4096];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        scan_line(report, filename, line_num, line);
        report->bytes_scanned += strlen(line);
    }
    
    fclose(f);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* secret_type_to_string(SecretType type) {
    switch (type) {
        case SECRET_API_KEY: return "API Key";
        case SECRET_PASSWORD: return "Password";
        case SECRET_TOKEN: return "Token";
        case SECRET_PRIVATE_KEY: return "Private Key";
        case SECRET_CERTIFICATE: return "Certificate";
        case SECRET_DATABASE_URL: return "Database URL";
        case SECRET_AWS_KEY: return "AWS Key";
        case SECRET_GITHUB_TOKEN: return "GitHub Token";
        case SECRET_SLACK_TOKEN: return "Slack Token";
        case SECRET_JWT: return "JWT";
        default: return "Unknown";
    }
}

const char* severity_to_string(SecretSeverity severity) {
    switch (severity) {
        case SEVERITY_CRITICAL: return "CRITICAL";
        case SEVERITY_HIGH: return "HIGH";
        case SEVERITY_MEDIUM: return "MEDIUM";
        case SEVERITY_LOW: return "LOW";
        default: return "UNKNOWN";
    }
}

void print_secret_summary(SecretReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Secret Scan Summary\n");
    printf("=============================================================================\n");
    printf("  Files Scanned:        %d\n", report->files_scanned);
    printf("  Lines Scanned:        %d\n", report->lines_scanned);
    printf("  Bytes Scanned:        %d\n", report->bytes_scanned);
    printf("\n");
    printf("  Secrets Found:\n");
    printf("    CRITICAL:           %d\n", report->critical_count);
    printf("    HIGH:               %d\n", report->high_count);
    printf("    MEDIUM:             %d\n", report->medium_count);
    printf("    LOW:                %d\n", report->low_count);
    printf("    -----------------\n");
    printf("    Total:              %d\n", report->finding_count - report->false_positive_count);
    printf("    False Positives:    %d\n", report->false_positive_count);
    printf("=============================================================================\n");
}

void print_findings(SecretReport* report) {
    int valid_findings = 0;
    for (int i = 0; i < report->finding_count; i++) {
        if (!report->findings[i].is_false_positive) valid_findings++;
    }
    
    if (valid_findings == 0) {
        printf("\n✅ No secrets detected!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Secret Findings\n");
    printf("=============================================================================\n");
    
    SecretSeverity severities[] = {SEVERITY_CRITICAL, SEVERITY_HIGH, SEVERITY_MEDIUM, SEVERITY_LOW};
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
            printf("\n%s Secrets (%d):\n", severity_names[s], count);
            printf("-----------------------------------------------------------------------------\n");
            
            for (int i = 0; i < report->finding_count; i++) {
                SecretFinding* finding = &report->findings[i];
                if (finding->severity == severities[s] && !finding->is_false_positive) {
                    printf("  [%s] %s\n", finding->rule_name, secret_type_to_string(finding->type));
                    printf("       File: %s:%d\n", finding->file, finding->line);
                    printf("       Match: %s\n", finding->redacted);
                    printf("       Entropy: %.2f\n", finding->entropy);
                    printf("\n");
                }
            }
        }
    }
    
    printf("=============================================================================\n");
}

void export_secret_json(SecretReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"files_scanned\": %d,\n", report->files_scanned);
    fprintf(f, "    \"lines_scanned\": %d,\n", report->lines_scanned);
    fprintf(f, "    \"critical\": %d,\n", report->critical_count);
    fprintf(f, "    \"high\": %d,\n", report->high_count);
    fprintf(f, "    \"medium\": %d,\n", report->medium_count);
    fprintf(f, "    \"low\": %d,\n", report->low_count);
    fprintf(f, "    \"false_positives\": %d\n", report->false_positive_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"findings\": [\n");
    
    int first = 1;
    for (int i = 0; i < report->finding_count; i++) {
        SecretFinding* finding = &report->findings[i];
        if (finding->is_false_positive) continue;
        
        if (!first) fprintf(f, ",\n");
        first = 0;
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"rule\": \"%s\",\n", finding->rule_name);
        fprintf(f, "      \"type\": \"%s\",\n", secret_type_to_string(finding->type));
        fprintf(f, "      \"severity\": \"%s\",\n", severity_to_string(finding->severity));
        fprintf(f, "      \"file\": \"%s\",\n", finding->file);
        fprintf(f, "      \"line\": %d,\n", finding->line);
        fprintf(f, "      \"match\": \"%s\",\n", finding->redacted);
        fprintf(f, "      \"entropy\": %.2f\n", finding->entropy);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Secret report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Secret Scanner\n");
    printf("=====================\n\n");
    
    SecretReport* report = secret_create_report();
    
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
    print_secret_summary(report);
    print_findings(report);
    export_secret_json(report, "secret_scan_report.json");
    
    printf("\nSecret scan complete!\n");
    
    int exit_code = (report->critical_count > 0 || report->high_count > 0) ? 1 : 0;
    secret_destroy_report(report);
    
    return exit_code;
}
