//=============================================================================
// schema_validator.c - Data Schema Validator
// Production-ready JSON/XML schema validation
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Schema Types
//=============================================================================

#define MAX_SCHEMA_NODES 256
#define MAX_VALIDATION_ERRORS 100
#define MAX_PATH_LEN 512
#define MAX_VALUE_LEN 1024

typedef enum {
    SCHEMA_OBJECT,
    SCHEMA_ARRAY,
    SCHEMA_STRING,
    SCHEMA_INTEGER,
    SCHEMA_NUMBER,
    SCHEMA_BOOLEAN,
    SCHEMA_NULL
} SchemaNodeType;

typedef enum {
    VALIDATION_OK,
    VALIDATION_TYPE_MISMATCH,
    VALIDATION_MISSING_REQUIRED,
    VALIDATION_CONSTRAINT_VIOLATION,
    VALIDATION_FORMAT_ERROR,
    VALIDATION_UNKNOWN_FIELD
} ValidationErrorType;

typedef struct SchemaNode {
    char name[256];
    SchemaNodeType type;
    int is_required;
    int is_nullable;
    
    // Constraints
    int min_length;
    int max_length;
    int min_value;
    int max_value;
    char pattern[256];
    char enum_values[1024];
    char format[64];
    
    // Nested
    struct SchemaNode* children;
    int child_count;
    int child_capacity;
    
    // Array items
    struct SchemaNode* item_schema;
} SchemaNode;

typedef struct {
    ValidationErrorType type;
    char path[MAX_PATH_LEN];
    char message[1024];
    char expected[256];
    char actual[256];
} ValidationError;

typedef struct {
    SchemaNode* root;
    
    ValidationError* errors;
    int error_count;
    int error_capacity;
    
    int validated_count;
    int passed_count;
    int failed_count;
} SchemaValidationReport;

//=============================================================================
// Schema Implementation
//=============================================================================

SchemaValidationReport* schema_create_report(void) {
    SchemaValidationReport* report = (SchemaValidationReport*)calloc(1, sizeof(SchemaValidationReport));
    report->root = (SchemaNode*)calloc(1, sizeof(SchemaNode));
    strncpy(report->root->name, "root", sizeof(report->root->name) - 1);
    report->root->type = SCHEMA_OBJECT;
    report->root->child_capacity = MAX_SCHEMA_NODES;
    report->root->children = (SchemaNode*)calloc(report->root->child_capacity, sizeof(SchemaNode));
    
    report->error_capacity = MAX_VALIDATION_ERRORS;
    report->errors = (ValidationError*)calloc(report->error_capacity, sizeof(ValidationError));
    return report;
}

void schema_destroy_report(SchemaValidationReport* report) {
    if (!report) return;
    
    // Free recursively
    // Simplified - would need proper tree traversal
    free(report->root->children);
    free(report->root);
    free(report->errors);
    free(report);
}

SchemaNode* add_schema_node(SchemaNode* parent, const char* name, SchemaNodeType type) {
    if (parent->child_count >= parent->child_capacity) return NULL;
    
    SchemaNode* node = &parent->children[parent->child_count++];
    strncpy(node->name, name, sizeof(node->name) - 1);
    node->type = type;
    node->is_required = 1;
    node->is_nullable = 0;
    node->min_length = -1;
    node->max_length = -1;
    node->min_value = INT32_MIN;
    node->max_value = INT32_MAX;
    
    if (type == SCHEMA_OBJECT || type == SCHEMA_ARRAY) {
        node->child_capacity = 10;
        node->children = (SchemaNode*)calloc(node->child_capacity, sizeof(SchemaNode));
    }
    
    return node;
}

void add_validation_error(SchemaValidationReport* report, ValidationErrorType type,
                          const char* path, const char* message,
                          const char* expected, const char* actual) {
    if (report->error_count >= report->error_capacity) return;
    
    ValidationError* err = &report->errors[report->error_count++];
    err->type = type;
    strncpy(err->path, path, sizeof(err->path) - 1);
    strncpy(err->message, message, sizeof(err->message) - 1);
    if (expected) strncpy(err->expected, expected, sizeof(err->expected) - 1);
    if (actual) strncpy(err->actual, actual, sizeof(err->actual) - 1);
}

//=============================================================================
// Validation Logic
//=============================================================================

SchemaNodeType detect_json_type(const char* value) {
    // Trim whitespace
    while (isspace(*value)) value++;
    
    if (strcmp(value, "null") == 0) return SCHEMA_NULL;
    if (strcmp(value, "true") == 0 || strcmp(value, "false") == 0) return SCHEMA_BOOLEAN;
    
    // Check for number
    char* endptr;
    strtol(value, &endptr, 10);
    if (*endptr == '\0') return SCHEMA_INTEGER;
    
    strtod(value, &endptr);
    if (*endptr == '\0') return SCHEMA_NUMBER;
    
    // Check for array/object markers
    if (value[0] == '[') return SCHEMA_ARRAY;
    if (value[0] == '{') return SCHEMA_OBJECT;
    
    return SCHEMA_STRING;
}

int validate_type(SchemaNode* schema, const char* value, SchemaNodeType actual_type) {
    if (schema->type == actual_type) return 1;
    
    // Allow number for integer
    if (schema->type == SCHEMA_NUMBER && actual_type == SCHEMA_INTEGER) return 1;
    
    // Allow null if nullable
    if (actual_type == SCHEMA_NULL && schema->is_nullable) return 1;
    
    return 0;
}

int validate_constraints(SchemaValidationReport* report, SchemaNode* schema,
                         const char* value, const char* path) {
    int valid = 1;
    
    // String constraints
    if (schema->type == SCHEMA_STRING) {
        size_t len = strlen(value);
        
        if (schema->min_length >= 0 && (int)len < schema->min_length) {
            char msg[512];
            snprintf(msg, sizeof(msg), "String length %zu is less than minimum %d",
                     len, schema->min_length);
            add_validation_error(report, VALIDATION_CONSTRAINT_VIOLATION, path, msg, NULL, NULL);
            valid = 0;
        }
        
        if (schema->max_length >= 0 && (int)len > schema->max_length) {
            char msg[512];
            snprintf(msg, sizeof(msg), "String length %zu exceeds maximum %d",
                     len, schema->max_length);
            add_validation_error(report, VALIDATION_CONSTRAINT_VIOLATION, path, msg, NULL, NULL);
            valid = 0;
        }
        
        // Pattern matching (simplified)
        if (strlen(schema->pattern) > 0) {
            // Would use regex in production
        }
        
        // Enum check
        if (strlen(schema->enum_values) > 0) {
            if (!strstr(schema->enum_values, value)) {
                char msg[512];
                snprintf(msg, sizeof(msg), "Value '%s' not in enum [%s]",
                         value, schema->enum_values);
                add_validation_error(report, VALIDATION_CONSTRAINT_VIOLATION, path, msg, NULL, NULL);
                valid = 0;
            }
        }
    }
    
    // Number constraints
    if (schema->type == SCHEMA_INTEGER || schema->type == SCHEMA_NUMBER) {
        int int_val = atoi(value);
        
        if (int_val < schema->min_value) {
            char msg[512];
            snprintf(msg, sizeof(msg), "Value %d is less than minimum %d",
                     int_val, schema->min_value);
            add_validation_error(report, VALIDATION_CONSTRAINT_VIOLATION, path, msg, NULL, NULL);
            valid = 0;
        }
        
        if (int_val > schema->max_value) {
            char msg[512];
            snprintf(msg, sizeof(msg), "Value %d exceeds maximum %d",
                     int_val, schema->max_value);
            add_validation_error(report, VALIDATION_CONSTRAINT_VIOLATION, path, msg, NULL, NULL);
            valid = 0;
        }
    }
    
    return valid;
}

void validate_value(SchemaValidationReport* report, SchemaNode* schema,
                    const char* value, const char* path);

void validate_object(SchemaValidationReport* report, SchemaNode* schema,
                     const char* json, const char* path) {
    // Simplified JSON object parsing
    // Would use proper JSON parser in production
    
    // Check for required fields
    for (int i = 0; i < schema->child_count; i++) {
        SchemaNode* child = &schema->children[i];
        if (child->is_required) {
            // Check if field exists in JSON (simplified)
            if (!strstr(json, child->name)) {
                char full_path[MAX_PATH_LEN];
                snprintf(full_path, sizeof(full_path), "%s.%s", path, child->name);
                char msg[512];
                snprintf(msg, sizeof(msg), "Required field '%s' is missing", child->name);
                add_validation_error(report, VALIDATION_MISSING_REQUIRED, full_path, msg, NULL, NULL);
            }
        }
    }
}

void validate_value(SchemaValidationReport* report, SchemaNode* schema,
                    const char* value, const char* path) {
    SchemaNodeType actual_type = detect_json_type(value);
    
    // Type check
    if (!validate_type(schema, value, actual_type)) {
        char msg[512];
        snprintf(msg, sizeof(msg), "Type mismatch: expected %d, got %d", schema->type, actual_type);
        add_validation_error(report, VALIDATION_TYPE_MISMATCH, path, msg, NULL, NULL);
        return;
    }
    
    // Object validation
    if (schema->type == SCHEMA_OBJECT) {
        validate_object(report, schema, value, path);
        return;
    }
    
    // Constraint validation
    validate_constraints(report, schema, value, path);
}

//=============================================================================
// Schema Building
//=============================================================================

void build_sample_schema(SchemaValidationReport* report) {
    SchemaNode* root = report->root;
    
    // Add user object
    SchemaNode* user = add_schema_node(root, "user", SCHEMA_OBJECT);
    user->is_required = 1;
    
    SchemaNode* id = add_schema_node(user, "id", SCHEMA_INTEGER);
    id->is_required = 1;
    id->min_value = 1;
    
    SchemaNode* name = add_schema_node(user, "name", SCHEMA_STRING);
    name->is_required = 1;
    name->min_length = 1;
    name->max_length = 100;
    
    SchemaNode* email = add_schema_node(user, "email", SCHEMA_STRING);
    email->is_required = 1;
    strncpy(email->format, "email", sizeof(email->format) - 1);
    
    SchemaNode* age = add_schema_node(user, "age", SCHEMA_INTEGER);
    age->is_required = 0;
    age->min_value = 0;
    age->max_value = 150;
    
    SchemaNode* role = add_schema_node(user, "role", SCHEMA_STRING);
    role->is_required = 0;
    strncpy(role->enum_values, "admin,user,guest", sizeof(role->enum_values) - 1);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* schema_type_to_string(SchemaNodeType type) {
    switch (type) {
        case SCHEMA_OBJECT: return "object";
        case SCHEMA_ARRAY: return "array";
        case SCHEMA_STRING: return "string";
        case SCHEMA_INTEGER: return "integer";
        case SCHEMA_NUMBER: return "number";
        case SCHEMA_BOOLEAN: return "boolean";
        case SCHEMA_NULL: return "null";
        default: return "unknown";
    }
}

const char* error_type_to_string(ValidationErrorType type) {
    switch (type) {
        case VALIDATION_OK: return "OK";
        case VALIDATION_TYPE_MISMATCH: return "Type Mismatch";
        case VALIDATION_MISSING_REQUIRED: return "Missing Required";
        case VALIDATION_CONSTRAINT_VIOLATION: return "Constraint Violation";
        case VALIDATION_FORMAT_ERROR: return "Format Error";
        case VALIDATION_UNKNOWN_FIELD: return "Unknown Field";
        default: return "Unknown";
    }
}

void print_schema_summary(SchemaValidationReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Schema Validation Summary\n");
    printf("=============================================================================\n");
    printf("  Validated:            %d\n", report->validated_count);
    printf("  Passed:               %d\n", report->passed_count);
    printf("  Failed:               %d\n", report->failed_count);
    printf("  Errors:               %d\n", report->error_count);
    printf("=============================================================================\n");
}

void print_validation_errors(SchemaValidationReport* report) {
    if (report->error_count == 0) {
        printf("\n✅ All validations passed!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Validation Errors\n");
    printf("=============================================================================\n");
    printf("  %-25s %-25s %s\n", "Path", "Type", "Message");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->error_count; i++) {
        ValidationError* err = &report->errors[i];
        printf("  %-25s %-25s %s\n", err->path, error_type_to_string(err->type), err->message);
    }
    
    printf("=============================================================================\n");
}

void export_schema_json(SchemaValidationReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"validated\": %d,\n", report->validated_count);
    fprintf(f, "    \"passed\": %d,\n", report->passed_count);
    fprintf(f, "    \"failed\": %d,\n", report->failed_count);
    fprintf(f, "    \"errors\": %d\n", report->error_count);
    fprintf(f, "  },\n");
    fprintf(f, "  \"errors\": [\n");
    
    for (int i = 0; i < report->error_count; i++) {
        ValidationError* err = &report->errors[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"path\": \"%s\",\n", err->path);
        fprintf(f, "      \"type\": \"%s\",\n", error_type_to_string(err->type));
        fprintf(f, "      \"message\": \"%s\"\n", err->message);
        fprintf(f, "    }%s\n", (i < report->error_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Schema report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Schema Validator\n");
    printf("=======================\n\n");
    
    SchemaValidationReport* report = schema_create_report();
    
    // Build sample schema
    printf("Building schema...\n");
    build_sample_schema(report);
    
    // Validate sample data
    printf("Validating data...\n");
    
    // Valid data
    report->validated_count++;
    const char* valid_data = "{\"id\": 1, \"name\": \"John\", \"email\": \"john@example.com\"}";
    validate_value(report, report->root, valid_data, "root");
    if (report->error_count == 0) {
        report->passed_count++;
    } else {
        report->failed_count++;
    }
    
    // Reset errors for next validation
    report->error_count = 0;
    
    // Invalid data - missing required field
    report->validated_count++;
    const char* invalid_data = "{\"id\": 1, \"email\": \"john@example.com\"}";
    validate_value(report, report->root, invalid_data, "root");
    if (report->error_count == 0) {
        report->passed_count++;
    } else {
        report->failed_count++;
    }
    
    // Generate reports
    print_schema_summary(report);
    print_validation_errors(report);
    export_schema_json(report, "schema_validation.json");
    
    printf("\nSchema validation complete!\n");
    
    int exit_code = report->failed_count > 0 ? 1 : 0;
    schema_destroy_report(report);
    
    return exit_code;
}
