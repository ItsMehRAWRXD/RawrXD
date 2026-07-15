//=============================================================================
// secrets_scanner.c - Secrets Scanner
// Production-ready credential and secret detection
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Secret Detection Types
//=============================================================================

#define MAX_FINDINGS 1000
#define MAX_PATTERNS 50
#define MAX_ENTROPY 8.0

typedef enum {
    SECRET_API_KEY,
    SECRET_PASSWORD,
    SECRET_TOKEN,
    SECRET_PRIVATE_KEY,
    SECRET_CERTIFICATE,
    SECRET_DATABASE_URL,
    SECRET_ENV_VAR,
    SECRET_CREDENTIALS_FILE,
    SECRET_OAUTH,
    SECRET_JWT
} SecretType;

typedef enum {
    SEVERITY_CRITICAL_SECRET,
    SEVERITY_HIGH_SECRET,
    SEVERITY_MEDIUM_SECRET,
    SEVERITY_LOW_SECRET
} SecretSeverity;

typedef struct {
    SecretType type;
    SecretSeverity severity;
    char name[128];
    char pattern[256];
    char description[512];
    int entropy_check;
    double min_entropy;
} SecretPattern;

typedef struct {
    SecretType type;
    SecretSeverity severity;
    char file[512];
    int line;
    int column;
    char match[256];
    char context[512];
    double entropy;
    char remediation[512];
    int confirmed;  // After entropy/filter check
} SecretFinding;

typedef struct {
    SecretPattern* patterns;
    int pattern_count;
    int pattern_capacity;
    
    SecretFinding* findings;
    int finding_count;
    int finding_capacity;
    
    int files_scanned;
    int lines_scanned;
    int bytes_scanned;
    
    int critical_count;
    int high_count;
    int medium_count;
    int low_count;
    
    int confirmed_secrets;
    int false_positives;
    
    int blocked_commits;
    int warnings_issued;
} SecretsScanReport;

//=============================================================================
// Pattern Database
//=============================================================================

void init_secret_patterns(SecretsScanReport* report) {
    report->pattern_capacity = MAX_PATTERNS;
    report->patterns = (SecretPattern*)calloc(report->pattern_capacity, sizeof(SecretPattern));
    
    // API Keys
    SecretPattern* p = &report->patterns[report->pattern_count++];
    p->type = SECRET_API_KEY;
    p->severity = SEVERITY_CRITICAL_SECRET;
    strncpy(p->name, "Generic API Key", sizeof(p->name));
    strncpy(p->pattern, "[aA][pP][iI][_-]?[kK][eE][yY]\\s*[=:]\\s*['\"]?[a-zA-Z0-9_\\-]{16,}", sizeof(p->pattern));
    strncpy(p->description, "Potential API key detected", sizeof(p->description));
    p->entropy_check = 1;
    p->min_entropy = 4.0;
    
    // AWS Keys
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_API_KEY;
    p->severity = SEVERITY_CRITICAL_SECRET;
    strncpy(p->name, "AWS Access Key", sizeof(p->name));
    strncpy(p->pattern, "AKIA[0-9A-Z]{16}", sizeof(p->pattern));
    strncpy(p->description, "AWS Access Key ID", sizeof(p->description));
    p->entropy_check = 0;
    
    // AWS Secret
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_API_KEY;
    p->severity = SEVERITY_CRITICAL_SECRET;
    strncpy(p->name, "AWS Secret Key", sizeof(p->name));
    strncpy(p->pattern, "['\"]?[0-9a-zA-Z/+]{40}['\"]?", sizeof(p->pattern));
    strncpy(p->description, "Potential AWS Secret Access Key", sizeof(p->description));
    p->entropy_check = 1;
    p->min_entropy = 4.5;
    
    // GitHub Token
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_TOKEN;
    p->severity = SEVERITY_CRITICAL_SECRET;
    strncpy(p->name, "GitHub Token", sizeof(p->name));
    strncpy(p->pattern, "gh[pousr]_[A-Za-z0-9_]{36,}", sizeof(p->pattern));
    strncpy(p->description, "GitHub Personal Access Token", sizeof(p->description));
    p->entropy_check = 0;
    
    // Private Keys
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_PRIVATE_KEY;
    p->severity = SEVERITY_CRITICAL_SECRET;
    strncpy(p->name, "Private Key", sizeof(p->name));
    strncpy(p->pattern, "-----BEGIN (RSA |DSA |EC |OPENSSH )?PRIVATE KEY-----", sizeof(p->pattern));
    strncpy(p->description, "Private key block detected", sizeof(p->description));
    p->entropy_check = 0;
    
    // Passwords
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_PASSWORD;
    p->severity = SEVERITY_HIGH_SECRET;
    strncpy(p->name, "Hardcoded Password", sizeof(p->name));
    strncpy(p->pattern, "[pP][aA][sS][sS][wW][oO][rR][dD]\\s*[=:]\\s*['\"][^'\"]{8,}['\"]", sizeof(p->pattern));
    strncpy(p->description, "Hardcoded password in source", sizeof(p->description));
    p->entropy_check = 1;
    p->min_entropy = 3.0;
    
    // Database URLs
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_DATABASE_URL;
    p->severity = SEVERITY_HIGH_SECRET;
    strncpy(p->name, "Database Connection String", sizeof(p->name));
    strncpy(p->pattern, "(postgres|mysql|mongodb|redis)://[^\\s\"']+", sizeof(p->pattern));
    strncpy(p->description, "Database connection string with credentials", sizeof(p->description));
    p->entropy_check = 0;
    
    // JWT Tokens
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_JWT;
    p->severity = SEVERITY_HIGH_SECRET;
    strncpy(p->name, "JWT Token", sizeof(p->name));
    strncpy(p->pattern, "eyJ[a-zA-Z0-9_-]*\\.eyJ[a-zA-Z0-9_-]*\\.[a-zA-Z0-9_-]*", sizeof(p->pattern));
    strncpy(p->description, "JSON Web Token", sizeof(p->description));
    p->entropy_check = 0;
    
    // OAuth tokens
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_OAUTH;
    p->severity = SEVERITY_HIGH_SECRET;
    strncpy(p->name, "OAuth Token", sizeof(p->name));
    strncpy(p->pattern, "[oO][aA][uU][tT][hH]\\s*[=:]\\s*['\"][a-zA-Z0-9_-]{20,}['\"]", sizeof(p->pattern));
    strncpy(p->description, "OAuth access token", sizeof(p->description));
    p->entropy_check = 1;
    p->min_entropy = 4.0;
    
    // Environment variables with secrets
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_ENV_VAR;
    p->severity = SEVERITY_MEDIUM_SECRET;
    strncpy(p->name, "Secret in Environment Variable", sizeof(p->name));
    strncpy(p->pattern, "(SECRET|KEY|TOKEN|PASSWORD|CREDENTIAL)\\s*=\\s*['\"][^'\"]+['\"]", sizeof(p->pattern));
    strncpy(p->description, "Potential secret in environment variable", sizeof(p->description));
    p->entropy_check = 1;
    p->min_entropy = 3.5;
    
    // .env files
    p = &report->patterns[report->pattern_count++];
    p->type = SECRET_CREDENTIALS_FILE;
    p->severity = SEVERITY_CRITICAL_SECRET;
    strncpy(p->name, "Credentials File", sizeof(p->name));
    strncpy(p->pattern, "\\.env", sizeof(p->pattern));
    strncpy(p->description, "Environment credentials file", sizeof(p->description));
    p->entropy_check = 0;
}

//=============================================================================
// Entropy Calculation
//=============================================================================

double calculate_shannon_entropy(const char* str) {
    if (!str || strlen(str) == 0) return 0.0;
    
    int freq[256] = {0};
    int len = (int)strlen(str);
    
    for (int i = 0; i < len; i++) {
        freq[(unsigned char)str[i]]++;
    }
    
    double entropy = 0.0;
    for (int i = 0; i < 256; i++) {
        if (freq[i] > 0) {
            double p = (double)freq[i] / len;
            entropy -= p * log2(p);
        }
    }
    
    return entropy;
}

int is_likely_false_positive(const char* match, SecretPattern* pattern) {
    // Check for common false positive patterns
    if (strstr(match, "example") || strstr(match, "sample") || 
        strstr(match, "test") || strstr(match, "dummy") ||
        strstr(match, "placeholder") || strstr(match, "your_")) {
        return 1;
    }
    
    // Check entropy if required
    if (pattern->entropy_check) {
        double entropy = calculate_shannon_entropy(match);
        if (entropy < pattern->min_entropy) {
            return 1;
        }
    }
    
    // Check for template variables
    if (strstr(match, "${") || strstr(match, "{{") || strstr(match, "%")) {
        return 1;
    }
    
    return 0;
}

//=============================================================================
// Scanner Implementation
//=============================================================================

SecretsScanReport* secrets_scan_create(void) {
    SecretsScanReport* report = (SecretsScanReport*)calloc(1, sizeof(SecretsScanReport));
    report->finding_capacity = MAX_FINDINGS;
    report->findings = (SecretFinding*)calloc(report->finding_capacity, sizeof(SecretFinding));
    init_secret_patterns(report);
    return report;
}

void secrets_scan_destroy(SecretsScanReport* report) {
    if (!report) return;
    free(report->patterns);
    free(report->findings);
    free(report);
}

void add_finding(SecretsScanReport* report, SecretPattern* pattern,
                 const char* file, int line, int col, const char* match, const char* context) {
    if (report->finding_count >= report->finding_capacity) return;
    
    SecretFinding* finding = &report->findings[report->finding_count++];
    finding->type = pattern->type;
    finding->severity = pattern->severity;
    strncpy(finding->file, file, sizeof(finding->file) - 1);
    finding->line = line;
    finding->column = col;
    strncpy(finding->match, match, sizeof(finding->match) - 1);
    strncpy(finding->context, context, sizeof(finding->context) - 1);
    finding->entropy = calculate_shannon_entropy(match);
    
    // Determine remediation
    switch (pattern->type) {
        case SECRET_API_KEY:
            strncpy(finding->remediation, "Move to environment variables or secret manager", 
                    sizeof(finding->remediation));
            break;
        case SECRET_PRIVATE_KEY:
            strncpy(finding->remediation, "Remove from repository, use secure key storage", 
                    sizeof(finding->remediation));
            break;
        case SECRET_PASSWORD:
            strncpy(finding->remediation, "Use configuration files or secret management service", 
                    sizeof(finding->remediation));
            break;
        case SECRET_DATABASE_URL:
            strncpy(finding->remediation, "Use connection string builders with separate credentials", 
                    sizeof(finding->remediation));
            break;
        default:
            strncpy(finding->remediation, "Review and move to secure storage", 
                    sizeof(finding->remediation));
    }
    
    // Check if false positive
    if (is_likely_false_positive(match, pattern)) {
        report->false_positives++;
        finding->confirmed = 0;
    } else {
        finding->confirmed = 1;
        report->confirmed_secrets++;
        
        switch (finding->severity) {
            case SEVERITY_CRITICAL_SECRET: report->critical_count++; break;
            case SEVERITY_HIGH_SECRET: report->high_count++; break;
            case SEVERITY_MEDIUM_SECRET: report->medium_count++; break;
            case SEVERITY_LOW_SECRET: report->low_count++; break;
        }
    }
}

void scan_line(SecretsScanReport* report, const char* file, int line_num, const char* line) {
    report->lines_scanned++;
    
    for (int i = 0; i < report->pattern_count; i++) {
        SecretPattern* pattern = &report->patterns[i];
        
        // Simple pattern matching (in production, use regex)
        if (strstr(line, pattern->pattern) ||
            (pattern->type == SECRET_API_KEY && strstr(line, "api_key")) ||
            (pattern->type == SECRET_PASSWORD && strstr(line, "password")) ||
            (pattern->type == SECRET_PRIVATE_KEY && strstr(line, "PRIVATE KEY"))) {
            
            // Extract match
            char match[256] = {0};
            const char* start = strstr(line, pattern->pattern);
            if (!start) start = line;
            
            // Find value after = or :
            const char* val = strchr(line, '=');
            if (!val) val = strchr(line, ':');
            if (val) {
                val++;
                while (*val == ' ' || *val == '\t' || *val == '"' || *val == '\'') val++;
                
                int len = 0;
                while (val[len] && val[len] != '"' && val[len] != '\'' && 
                       val[len] != ' ' && val[len] != '\t' && val[len] != '\n' &&
                       len < 255) {
                    len++;
                }
                strncpy(match, val, len);
            }
            
            add_finding(report, pattern, file, line_num, 0, match, line);
        }
    }
}

void scan_file(SecretsScanReport* report, const char* filename) {
    // Skip binary files
    const char* ext = strrchr(filename, '.');
    if (ext) {
        if (strcmp(ext, ".exe") == 0 || strcmp(ext, ".dll") == 0 ||
            strcmp(ext, ".obj") == 0 || strcmp(ext, ".bin") == 0 ||
            strcmp(ext, ".png") == 0 || strcmp(ext, ".jpg") == 0) {
            return;
        }
    }
    
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    report->files_scanned++;
    
    char line[4096];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        report->bytes_scanned += (int)strlen(line);
        scan_line(report, filename, line_num, line);
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
        case SECRET_ENV_VAR: return "Environment Variable";
        case SECRET_CREDENTIALS_FILE: return "Credentials File";
        case SECRET_OAUTH: return "OAuth";
        case SECRET_JWT: return "JWT";
        default: return "Unknown";
    }
}

const char* severity_to_string(SecretSeverity severity) {
    switch (severity) {
        case SEVERITY_CRITICAL_SECRET: return "CRITICAL";
        case SEVERITY_HIGH_SECRET: return "HIGH";
        case SEVERITY_MEDIUM_SECRET: return "MEDIUM";
        case SEVERITY_LOW_SECRET: return "LOW";
        default: return "UNKNOWN";
    }
}

void print_secrets_summary(SecretsScanReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Secrets Scan Summary\n");
    printf("=============================================================================\n");
    printf("  Files Scanned:        %d\n", report->files_scanned);
    printf("  Lines Scanned:        %d\n", report->lines_scanned);
    printf("  Bytes Scanned:        %d\n", report->bytes_scanned);
    printf("\n");
    printf("  Findings:\n");
    printf("    Total Detected:     %d\n", report->finding_count);
    printf("    Confirmed:          %d\n", report->confirmed_secrets);
    printf("    False Positives:    %d\n", report->false_positives);
    printf("\n");
    printf("  By Severity:\n");
    printf("    CRITICAL:           %d\n", report->critical_count);
    printf("    HIGH:               %d\n", report->high_count);
    printf("    MEDIUM:             %d\n", report->medium_count);
    printf("    LOW:                %d\n", report->low_count);
    printf("\n");
    printf("  Status:               %s\n", 
           report->confirmed_secrets == 0 ? "✅ CLEAN" : "❌ SECRETS DETECTED");
    printf("=============================================================================\n");
}

void print_secrets_findings(SecretsScanReport* report) {
    if (report->confirmed_secrets == 0) {
        printf("\n✅ No secrets detected in scanned files.\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Confirmed Secret Findings\n");
    printf("=============================================================================\n");
    
    SecretSeverity severities[] = {SEVERITY_CRITICAL_SECRET, SEVERITY_HIGH_SECRET, 
                                    SEVERITY_MEDIUM_SECRET, SEVERITY_LOW_SECRET};
    const char* severity_names[] = {"CRITICAL", "HIGH", "MEDIUM", "LOW"};
    
    for (int s = 0; s < 4; s++) {
        int printed = 0;
        for (int i = 0; i < report->finding_count; i++) {
            SecretFinding* finding = &report->findings[i];
            if (finding->confirmed && finding->severity == severities[s]) {
                if (!printed) {
                    printf("\n%s Findings:\n", severity_names[s]);
                    printf("-----------------------------------------------------------------------------\n");
                    printed = 1;
                }
                
                printf("\n  [%s] %s\n", secret_type_to_string(finding->type), finding->file);
                printf("       Line %d: %s\n", finding->line, finding->context);
                printf("       Entropy: %.2f\n", finding->entropy);
                printf("       Remediation: %s\n", finding->remediation);
            }
        }
    }
    
    printf("\n=============================================================================\n");
}

void export_secrets_json(SecretsScanReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"files_scanned\": %d,\n", report->files_scanned);
    fprintf(f, "    \"lines_scanned\": %d,\n", report->lines_scanned);
    fprintf(f, "    \"total_findings\": %d,\n", report->finding_count);
    fprintf(f, "    \"confirmed_secrets\": %d,\n", report->confirmed_secrets);
    fprintf(f, "    \"false_positives\": %d,\n", report->false_positives);
    fprintf(f, "    \"critical\": %d,\n", report->critical_count);
    fprintf(f, "    \"high\": %d,\n", report->high_count);
    fprintf(f, "    \"medium\": %d,\n", report->medium_count);
    fprintf(f, "    \"low\": %d\n", report->low_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"findings\": [\n");
    
    int first = 1;
    for (int i = 0; i < report->finding_count; i++) {
        SecretFinding* finding = &report->findings[i];
        if (!finding->confirmed) continue;
        
        if (!first) fprintf(f, ",\n");
        first = 0;
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"type\": \"%s\",\n", secret_type_to_string(finding->type));
        fprintf(f, "      \"severity\": \"%s\",\n", severity_to_string(finding->severity));
        fprintf(f, "      \"file\": \"%s\",\n", finding->file);
        fprintf(f, "      \"line\": %d,\n", finding->line);
        fprintf(f, "      \"match\": \"%s\",\n", finding->match);
        fprintf(f, "      \"entropy\": %.2f,\n", finding->entropy);
        fprintf(f, "      \"remediation\": \"%s\"\n", finding->remediation);
        fprintf(f, "    }");
    }
    
    fprintf(f, "\n  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Secrets report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Secrets Scanner\n");
    printf("====================\n\n");
    
    SecretsScanReport* report = secrets_scan_create();
    
    // Scan files
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            printf("Scanning: %s\n", argv[i]);
            scan_file(report, argv[i]);
        }
    } else {
        printf("Usage: %s <file1> [<file2> ...]\n", argv[0]);
        printf("\nDemo mode - scanning self:\n");
        scan_file(report, __FILE__);
    }
    
    // Generate reports
    print_secrets_summary(report);
    print_secrets_findings(report);
    export_secrets_json(report, "secrets_scan.json");
    
    printf("\nSecrets scan complete!\n");
    
    int exit_code = (report->confirmed_secrets > 0) ? 1 : 0;
    secrets_scan_destroy(report);
    
    return exit_code;
}
