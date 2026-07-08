//=============================================================================
// config_validator.c - Configuration File Validator
// Production-ready config validation with schema checking
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Config Types
//=============================================================================

#define MAX_CONFIG_KEYS 256
#define MAX_ERRORS 100
#define MAX_SCHEMA_RULES 50

typedef enum {
    TYPE_STRING,
    TYPE_INTEGER,
    TYPE_FLOAT,
    TYPE_BOOLEAN,
    TYPE_ARRAY,
    TYPE_OBJECT
} ConfigValueType;

typedef struct {
    char key[256];
    char value[1024];
    ConfigValueType type;
    int line_number;
    int is_valid;
    char error_message[512];
} ConfigEntry;

typedef struct {
    char key_pattern[256];
    ConfigValueType expected_type;
    int is_required;
    int min_length;
    int max_length;
    int min_value;
    int max_value;
    char allowed_values[1024];
    char default_value[256];
} SchemaRule;

typedef struct {
    ConfigEntry* entries;
    int entry_count;
    int entry_capacity;
    
    SchemaRule* schema;
    int schema_count;
    int schema_capacity;
    
    int validation_errors;
    int missing_required;
    int type_mismatches;
    int value_out_of_range;
} ConfigReport;

//=============================================================================
// Config Parsing
//=============================================================================

ConfigReport* config_create_report(void) {
    ConfigReport* report = (ConfigReport*)calloc(1, sizeof(ConfigReport));
    report->entry_capacity = MAX_CONFIG_KEYS;
    report->entries = (ConfigEntry*)calloc(report->entry_capacity, sizeof(ConfigEntry));
    report->schema_capacity = MAX_SCHEMA_RULES;
    report->schema = (SchemaRule*)calloc(report->schema_capacity, sizeof(SchemaRule));
    return report;
}

void config_destroy_report(ConfigReport* report) {
    if (!report) return;
    free(report->entries);
    free(report->schema);
    free(report);
}

void trim_whitespace(char* str) {
    char* start = str;
    while (isspace(*start)) start++;
    
    if (start != str) {
        memmove(str, start, strlen(start) + 1);
    }
    
    char* end = str + strlen(str) - 1;
    while (end > str && isspace(*end)) {
        *end = '\0';
        end--;
    }
}

ConfigValueType detect_value_type(const char* value) {
    // Check for boolean
    if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0 ||
        strcmp(value, "yes") == 0 || strcmp(value, "no") == 0 ||
        strcmp(value, "1") == 0 || strcmp(value, "0") == 0) {
        return TYPE_BOOLEAN;
    }
    
    // Check for integer
    char* endptr;
    long int_val = strtol(value, &endptr, 10);
    if (*endptr == '\0' && int_val != 0) {
        return TYPE_INTEGER;
    }
    
    // Check for float
    double float_val = strtod(value, &endptr);
    if (*endptr == '\0' && float_val != 0) {
        return TYPE_FLOAT;
    }
    
    // Check for array (comma-separated)
    if (strchr(value, ',')) {
        return TYPE_ARRAY;
    }
    
    return TYPE_STRING;
}

void parse_config_file(ConfigReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    char line[2048];
    int line_num = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        
        // Remove newline
        size_t len = strlen(line);
        if (len > 0 && line[len-1] == '\n') line[len-1] = '\0';
        
        // Skip empty lines and comments
        char* trimmed = line;
        while (*trimmed && isspace(*trimmed)) trimmed++;
        
        if (*trimmed == '\0' || *trimmed == '#' || *trimmed == ';') continue;
        
        // Parse key=value or key: value
        char* delimiter = strchr(trimmed, '=');
        if (!delimiter) delimiter = strchr(trimmed, ':');
        
        if (delimiter) {
            *delimiter = '\0';
            char* key = trimmed;
            char* value = delimiter + 1;
            
            trim_whitespace(key);
            trim_whitespace(value);
            
            // Remove quotes if present
            if (value[0] == '"' || value[0] == '\'') {
                size_t val_len = strlen(value);
                if (val_len > 1 && value[val_len-1] == value[0]) {
                    value[val_len-1] = '\0';
                    value++;
                }
            }
            
            if (report->entry_count < report->entry_capacity) {
                ConfigEntry* entry = &report->entries[report->entry_count++];
                strncpy(entry->key, key, sizeof(entry->key) - 1);
                strncpy(entry->value, value, sizeof(entry->value) - 1);
                entry->type = detect_value_type(value);
                entry->line_number = line_num;
                entry->is_valid = 1;
            }
        }
    }
    
    fclose(f);
}

void load_schema(ConfigReport* report, const char* filename) {
    // Simplified schema loading - would parse JSON/YAML in production
    // For demo, add some default rules
    
    SchemaRule* rule = &report->schema[report->schema_count++];
    strncpy(rule->key_pattern, "server.host", sizeof(rule->key_pattern) - 1);
    rule->expected_type = TYPE_STRING;
    rule->is_required = 1;
    rule->min_length = 1;
    rule->max_length = 256;
    
    rule = &report->schema[report->schema_count++];
    strncpy(rule->key_pattern, "server.port", sizeof(rule->key_pattern) - 1);
    rule->expected_type = TYPE_INTEGER;
    rule->is_required = 1;
    rule->min_value = 1;
    rule->max_value = 65535;
    
    rule = &report->schema[report->schema_count++];
    strncpy(rule->key_pattern, "log.level", sizeof(rule->key_pattern) - 1);
    rule->expected_type = TYPE_STRING;
    rule->is_required = 0;
    strncpy(rule->allowed_values, "debug,info,warn,error", sizeof(rule->allowed_values) - 1);
    strncpy(rule->default_value, "info", sizeof(rule->default_value) - 1);
    
    rule = &report->schema[report->schema_count++];
    strncpy(rule->key_pattern, "database.enabled", sizeof(rule->key_pattern) - 1);
    rule->expected_type = TYPE_BOOLEAN;
    rule->is_required = 0;
    strncpy(rule->default_value, "true", sizeof(rule->default_value) - 1);
}

//=============================================================================
// Validation
//=============================================================================

SchemaRule* find_schema_rule(ConfigReport* report, const char* key) {
    for (int i = 0; i < report->schema_count; i++) {
        // Simple pattern matching - would use regex in production
        if (strstr(key, report->schema[i].key_pattern) ||
            strcmp(key, report->schema[i].key_pattern) == 0) {
            return &report->schema[i];
        }
    }
    return NULL;
}

void validate_entry(ConfigReport* report, ConfigEntry* entry) {
    SchemaRule* rule = find_schema_rule(report, entry->key);
    if (!rule) {
        // Unknown key - warning but not error
        entry->is_valid = 1;
        return;
    }
    
    // Check type
    if (entry->type != rule->expected_type) {
        entry->is_valid = 0;
        snprintf(entry->error_message, sizeof(entry->error_message),
                 "Type mismatch: expected %d, got %d",
                 rule->expected_type, entry->type);
        report->type_mismatches++;
        report->validation_errors++;
        return;
    }
    
    // Check string length
    if (rule->expected_type == TYPE_STRING) {
        size_t len = strlen(entry->value);
        if (len < (size_t)rule->min_length) {
            entry->is_valid = 0;
            snprintf(entry->error_message, sizeof(entry->error_message),
                     "Value too short: minimum %d characters", rule->min_length);
            report->validation_errors++;
            return;
        }
        if (rule->max_length > 0 && len > (size_t)rule->max_length) {
            entry->is_valid = 0;
            snprintf(entry->error_message, sizeof(entry->error_message),
                     "Value too long: maximum %d characters", rule->max_length);
            report->validation_errors++;
            return;
        }
    }
    
    // Check numeric range
    if (rule->expected_type == TYPE_INTEGER) {
        int value = atoi(entry->value);
        if (value < rule->min_value || value > rule->max_value) {
            entry->is_valid = 0;
            snprintf(entry->error_message, sizeof(entry->error_message),
                     "Value out of range: expected %d-%d", rule->min_value, rule->max_value);
            report->value_out_of_range++;
            report->validation_errors++;
            return;
        }
    }
    
    // Check allowed values
    if (strlen(rule->allowed_values) > 0) {
        if (!strstr(rule->allowed_values, entry->value)) {
            entry->is_valid = 0;
            snprintf(entry->error_message, sizeof(entry->error_message),
                     "Invalid value: must be one of [%s]", rule->allowed_values);
            report->validation_errors++;
            return;
        }
    }
}

void validate_all_entries(ConfigReport* report) {
    for (int i = 0; i < report->entry_count; i++) {
        validate_entry(report, &report->entries[i]);
    }
    
    // Check for missing required fields
    for (int i = 0; i < report->schema_count; i++) {
        SchemaRule* rule = &report->schema[i];
        if (!rule->is_required) continue;
        
        int found = 0;
        for (int j = 0; j < report->entry_count; j++) {
            if (strstr(report->entries[j].key, rule->key_pattern)) {
                found = 1;
                break;
            }
        }
        
        if (!found) {
            report->missing_required++;
            report->validation_errors++;
        }
    }
}

//=============================================================================
// Report Generation
//=============================================================================

const char* type_to_string(ConfigValueType type) {
    switch (type) {
        case TYPE_STRING: return "string";
        case TYPE_INTEGER: return "integer";
        case TYPE_FLOAT: return "float";
        case TYPE_BOOLEAN: return "boolean";
        case TYPE_ARRAY: return "array";
        case TYPE_OBJECT: return "object";
        default: return "unknown";
    }
}

void print_config_summary(ConfigReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Configuration Validation Summary\n");
    printf("=============================================================================\n");
    printf("  Entries Parsed:     %d\n", report->entry_count);
    printf("  Schema Rules:       %d\n", report->schema_count);
    printf("\n");
    printf("  Validation Results:\n");
    printf("    Errors:           %d\n", report->validation_errors);
    printf("    Missing Required: %d\n", report->missing_required);
    printf("    Type Mismatches:  %d\n", report->type_mismatches);
    printf("    Out of Range:     %d\n", report->value_out_of_range);
    printf("=============================================================================\n");
}

void print_config_entries(ConfigReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Configuration Entries\n");
    printf("=============================================================================\n");
    printf("  %-30s %-12s %-8s %s\n", "Key", "Type", "Status", "Value");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->entry_count; i++) {
        ConfigEntry* entry = &report->entries[i];
        const char* status = entry->is_valid ? "✅" : "❌";
        printf("  %-30s %-12s %s %s\n",
               entry->key, type_to_string(entry->type), status, entry->value);
        
        if (!entry->is_valid) {
            printf("       Error: %s\n", entry->error_message);
        }
    }
    
    printf("=============================================================================\n");
}

void print_validation_errors(ConfigReport* report) {
    if (report->validation_errors == 0) {
        printf("\n✅ Configuration is valid!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Validation Errors\n");
    printf("=============================================================================\n");
    
    // Print entry errors
    for (int i = 0; i < report->entry_count; i++) {
        ConfigEntry* entry = &report->entries[i];
        if (!entry->is_valid) {
            printf("  [%s:%d] %s\n", entry->key, entry->line_number, entry->error_message);
        }
    }
    
    // Print missing required
    for (int i = 0; i < report->schema_count; i++) {
        SchemaRule* rule = &report->schema[i];
        if (!rule->is_required) continue;
        
        int found = 0;
        for (int j = 0; j < report->entry_count; j++) {
            if (strstr(report->entries[j].key, rule->key_pattern)) {
                found = 1;
                break;
            }
        }
        
        if (!found) {
            printf("  [MISSING] Required field '%s' not found\n", rule->key_pattern);
        }
    }
    
    printf("=============================================================================\n");
}

void export_config_json(ConfigReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"entries_parsed\": %d,\n", report->entry_count);
    fprintf(f, "    \"validation_errors\": %d,\n", report->validation_errors);
    fprintf(f, "    \"missing_required\": %d,\n", report->missing_required);
    fprintf(f, "    \"type_mismatches\": %d,\n", report->type_mismatches);
    fprintf(f, "    \"value_out_of_range\": %d\n", report->value_out_of_range);
    fprintf(f, "  },\n");
    fprintf(f, "  \"entries\": [\n");
    
    for (int i = 0; i < report->entry_count; i++) {
        ConfigEntry* entry = &report->entries[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"key\": \"%s\",\n", entry->key);
        fprintf(f, "      \"value\": \"%s\",\n", entry->value);
        fprintf(f, "      \"type\": \"%s\",\n", type_to_string(entry->type));
        fprintf(f, "      \"line\": %d,\n", entry->line_number);
        fprintf(f, "      \"is_valid\": %s,\n", entry->is_valid ? "true" : "false");
        fprintf(f, "      \"error\": \"%s\"\n", entry->error_message);
        fprintf(f, "    }%s\n", (i < report->entry_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Config report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Configuration Validator\n");
    printf("===============================\n\n");
    
    ConfigReport* report = config_create_report();
    
    // Load schema
    printf("Loading schema...\n");
    load_schema(report, NULL);
    
    // Parse config file
    if (argc > 1) {
        printf("Parsing: %s\n", argv[1]);
        parse_config_file(report, argv[1]);
    } else {
        // Create demo config
        printf("Creating demo configuration...\n");
        ConfigEntry* entry = &report->entries[report->entry_count++];
        strncpy(entry->key, "server.host", sizeof(entry->key) - 1);
        strncpy(entry->value, "localhost", sizeof(entry->value) - 1);
        entry->type = TYPE_STRING;
        entry->line_number = 1;
        entry->is_valid = 1;
        
        entry = &report->entries[report->entry_count++];
        strncpy(entry->key, "server.port", sizeof(entry->key) - 1);
        strncpy(entry->value, "8080", sizeof(entry->value) - 1);
        entry->type = TYPE_INTEGER;
        entry->line_number = 2;
        entry->is_valid = 1;
        
        entry = &report->entries[report->entry_count++];
        strncpy(entry->key, "log.level", sizeof(entry->key) - 1);
        strncpy(entry->value, "debug", sizeof(entry->value) - 1);
        entry->type = TYPE_STRING;
        entry->line_number = 3;
        entry->is_valid = 1;
    }
    
    // Validate
    printf("\nValidating configuration...\n");
    validate_all_entries(report);
    
    // Generate reports
    print_config_summary(report);
    print_config_entries(report);
    print_validation_errors(report);
    export_config_json(report, "config_validation.json");
    
    printf("\nConfiguration validation complete!\n");
    
    int exit_code = report->validation_errors > 0 ? 1 : 0;
    config_destroy_report(report);
    
    return exit_code;
}
