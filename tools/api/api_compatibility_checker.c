//=============================================================================
// api_compatibility_checker.c - API Compatibility Checker
// Production-ready API compatibility analysis and versioning
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//=============================================================================
// API Types
//=============================================================================

#define MAX_APIS 500
#define MAX_VERSIONS 50
#define MAX_BREAKING 100
#define MAX_DEPRECATED 100

typedef enum {
    API_FUNCTION,
    API_TYPE,
    API_CONSTANT,
    API_MACRO,
    API_STRUCT,
    API_ENUM
} APIElementType;

typedef enum {
    CHANGE_NONE,
    CHANGE_ADDED,
    CHANGE_MODIFIED,
    CHANGE_DEPRECATED,
    CHANGE_REMOVED
} ChangeType;

typedef enum {
    COMPAT_FULL,
    COMPAT_BACKWARD,
    COMPAT_BREAKING,
    COMPAT_INCOMPATIBLE
} CompatibilityLevel;

typedef struct {
    char name[256];
    char signature[1024];
    APIElementType type;
    char version_introduced[32];
    char version_deprecated[32];
    char version_removed[32];
    int is_deprecated;
    int is_experimental;
    int is_internal;
    char deprecation_reason[512];
    char replacement[256];
} APIElement;

typedef struct {
    char version[32];
    char release_date[32];
    char changelog[4096];
    
    APIElement* elements;
    int element_count;
    int element_capacity;
} APIVersion;

typedef struct {
    char element_name[256];
    char old_signature[1024];
    char new_signature[1024];
    ChangeType change;
    char description[1024];
    char migration_guide[2048];
} APIChange;

typedef struct {
    char api_name[256];
    char current_version[32];
    char baseline_version[32];
    
    APIVersion* versions;
    int version_count;
    int version_capacity;
    
    APIChange* changes;
    int change_count;
    int change_capacity;
    
    int added_count;
    int modified_count;
    int deprecated_count;
    int removed_count;
    
    CompatibilityLevel compatibility;
    double compatibility_score;
    
    int breaking_changes;
    int warnings;
} APICompatibilityReport;

//=============================================================================
// API Compatibility Implementation
//=============================================================================

APICompatibilityReport* api_create_report(void) {
    APICompatibilityReport* report = (APICompatibilityReport*)calloc(1, sizeof(APICompatibilityReport));
    report->version_capacity = MAX_VERSIONS;
    report->versions = (APIVersion*)calloc(report->version_capacity, sizeof(APIVersion));
    report->change_capacity = MAX_BREAKING;
    report->changes = (APIChange*)calloc(report->change_capacity, sizeof(APIChange));
    strncpy(report->api_name, "RawrXD API", sizeof(report->api_name));
    strncpy(report->current_version, "2.0.0", sizeof(report->current_version));
    strncpy(report->baseline_version, "1.0.0", sizeof(report->baseline_version));
    return report;
}

void api_destroy_report(APICompatibilityReport* report) {
    if (!report) return;
    
    for (int i = 0; i < report->version_count; i++) {
        free(report->versions[i].elements);
    }
    
    free(report->versions);
    free(report->changes);
    free(report);
}

APIVersion* add_version(APICompatibilityReport* report, const char* version) {
    if (report->version_count >= report->version_capacity) return NULL;
    
    APIVersion* ver = &report->versions[report->version_count++];
    strncpy(ver->version, version, sizeof(ver->version) - 1);
    ver->element_capacity = MAX_APIS;
    ver->elements = (APIElement*)calloc(ver->element_capacity, sizeof(APIElement));
    return ver;
}

APIElement* add_api_element(APIVersion* version, const char* name,
                            APIElementType type, const char* signature) {
    if (version->element_count >= version->element_capacity) return NULL;
    
    APIElement* elem = &version->elements[version->element_count++];
    strncpy(elem->name, name, sizeof(elem->name) - 1);
    elem->type = type;
    strncpy(elem->signature, signature, sizeof(elem->signature) - 1);
    return elem;
}

void add_change(APICompatibilityReport* report, const char* element,
                ChangeType type, const char* description) {
    if (report->change_count >= report->change_capacity) return NULL;
    
    APIChange* change = &report->changes[report->change_count++];
    strncpy(change->element_name, element, sizeof(change->element_name) - 1);
    change->change = type;
    strncpy(change->description, description, sizeof(change->description) - 1);
    
    switch (type) {
        case CHANGE_ADDED: report->added_count++; break;
        case CHANGE_MODIFIED: report->modified_count++; break;
        case CHANGE_DEPRECATED: report->deprecated_count++; break;
        case CHANGE_REMOVED: report->removed_count++; break;
        default: break;
    }
}

void compare_apis(APICompatibilityReport* report) {
    if (report->version_count < 2) return;
    
    APIVersion* old_ver = &report->versions[0];
    APIVersion* new_ver = &report->versions[report->version_count - 1];
    
    // Check for removed elements
    for (int i = 0; i < old_ver->element_count; i++) {
        APIElement* old_elem = &old_ver->elements[i];
        int found = 0;
        
        for (int j = 0; j < new_ver->element_count; j++) {
            if (strcmp(old_elem->name, new_ver->elements[j].name) == 0) {
                found = 1;
                
                // Check for modifications
                if (strcmp(old_elem->signature, new_ver->elements[j].signature) != 0) {
                    add_change(report, old_elem->name, CHANGE_MODIFIED,
                               "Signature changed");
                    report->breaking_changes++;
                }
                
                // Check for deprecation
                if (!old_elem->is_deprecated && new_ver->elements[j].is_deprecated) {
                    add_change(report, old_elem->name, CHANGE_DEPRECATED,
                               "API element deprecated");
                }
                break;
            }
        }
        
        if (!found) {
            add_change(report, old_elem->name, CHANGE_REMOVED,
                       "API element removed");
            report->breaking_changes++;
        }
    }
    
    // Check for added elements
    for (int i = 0; i < new_ver->element_count; i++) {
        APIElement* new_elem = &new_ver->elements[i];
        int found = 0;
        
        for (int j = 0; j < old_ver->element_count; j++) {
            if (strcmp(new_elem->name, old_ver->elements[j].name) == 0) {
                found = 1;
                break;
            }
        }
        
        if (!found) {
            add_change(report, new_elem->name, CHANGE_ADDED,
                       "New API element added");
        }
    }
    
    // Calculate compatibility
    if (report->breaking_changes == 0) {
        report->compatibility = COMPAT_FULL;
        report->compatibility_score = 100.0;
    } else if (report->breaking_changes <= 5) {
        report->compatibility = COMPAT_BACKWARD;
        report->compatibility_score = 80.0;
    } else if (report->breaking_changes <= 10) {
        report->compatibility = COMPAT_BREAKING;
        report->compatibility_score = 50.0;
    } else {
        report->compatibility = COMPAT_INCOMPATIBLE;
        report->compatibility_score = 0.0;
    }
}

void load_api_versions(APICompatibilityReport* report) {
    // Version 1.0.0
    APIVersion* v1 = add_version(report, "1.0.0");
    
    APIElement* elem = add_api_element(v1, "init_system", API_FUNCTION,
                                       "int init_system(const char* config)");
    strncpy(elem->version_introduced, "1.0.0", sizeof(elem->version_introduced));
    
    elem = add_api_element(v1, "process_data", API_FUNCTION,
                           "int process_data(void* data, size_t len)");
    strncpy(elem->version_introduced, "1.0.0", sizeof(elem->version_introduced));
    
    elem = add_api_element(v1, "cleanup", API_FUNCTION,
                           "void cleanup(void)");
    strncpy(elem->version_introduced, "1.0.0", sizeof(elem->version_introduced));
    
    elem = add_api_element(v1, "MAX_BUFFER_SIZE", API_CONSTANT, "#define MAX_BUFFER_SIZE 4096");
    strncpy(elem->version_introduced, "1.0.0", sizeof(elem->version_introduced));
    
    // Version 2.0.0
    APIVersion* v2 = add_version(report, "2.0.0");
    
    elem = add_api_element(v2, "init_system", API_FUNCTION,
                           "int init_system(const char* config, int flags)");
    strncpy(elem->version_introduced, "1.0.0", sizeof(elem->version_introduced));
    
    elem = add_api_element(v2, "process_data", API_FUNCTION,
                           "int process_data(void* data, size_t len)");
    strncpy(elem->version_introduced, "1.0.0", sizeof(elem->version_introduced));
    elem->is_deprecated = 1;
    strncpy(elem->version_deprecated, "2.0.0", sizeof(elem->version_deprecated));
    strncpy(elem->deprecation_reason, "Use process_data_ex instead", sizeof(elem->deprecation_reason));
    
    elem = add_api_element(v2, "process_data_ex", API_FUNCTION,
                           "int process_data_ex(void* data, size_t len, uint32_t opts)");
    strncpy(elem->version_introduced, "2.0.0", sizeof(elem->version_introduced));
    
    elem = add_api_element(v2, "cleanup", API_FUNCTION,
                           "void cleanup(void)");
    strncpy(elem->version_introduced, "1.0.0", sizeof(elem->version_introduced));
    
    elem = add_api_element(v2, "MAX_BUFFER_SIZE", API_CONSTANT, "#define MAX_BUFFER_SIZE 8192");
    strncpy(elem->version_introduced, "1.0.0", sizeof(elem->version_introduced));
}

//=============================================================================
// Report Generation
//=============================================================================

const char* change_type_to_string(ChangeType type) {
    switch (type) {
        case CHANGE_ADDED: return "Added";
        case CHANGE_MODIFIED: return "Modified";
        case CHANGE_DEPRECATED: return "Deprecated";
        case CHANGE_REMOVED: return "Removed";
        default: return "None";
    }
}

const char* compatibility_to_string(CompatibilityLevel level) {
    switch (level) {
        case COMPAT_FULL: return "Full Compatibility";
        case COMPAT_BACKWARD: return "Backward Compatible";
        case COMPAT_BREAKING: return "Breaking Changes";
        case COMPAT_INCOMPATIBLE: return "Incompatible";
        default: return "Unknown";
    }
}

void print_api_summary(APICompatibilityReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  API Compatibility Summary\n");
    printf("=============================================================================\n");
    printf("  API:                  %s\n", report->api_name);
    printf("  Baseline:             %s\n", report->baseline_version);
    printf("  Current:              %s\n", report->current_version);
    printf("  Compatibility:        %s\n", compatibility_to_string(report->compatibility));
    printf("  Score:                %.1f%%\n", report->compatibility_score);
    printf("\n");
    printf("  Changes:\n");
    printf("    Added:              %d\n", report->added_count);
    printf("    Modified:           %d\n", report->modified_count);
    printf("    Deprecated:         %d\n", report->deprecated_count);
    printf("    Removed:            %d\n", report->removed_count);
    printf("\n");
    printf("    Breaking Changes:   %d\n", report->breaking_changes);
    printf("=============================================================================\n");
}

void print_api_changes(APICompatibilityReport* report) {
    if (report->change_count == 0) {
        printf("\n✅ No API changes detected!\n");
        return;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  API Changes\n");
    printf("=============================================================================\n");
    
    ChangeType types[] = {CHANGE_REMOVED, CHANGE_MODIFIED, CHANGE_DEPRECATED, CHANGE_ADDED};
    const char* type_names[] = {"REMOVED", "MODIFIED", "DEPRECATED", "ADDED"};
    
    for (int t = 0; t < 4; t++) {
        int count = 0;
        for (int i = 0; i < report->change_count; i++) {
            if (report->changes[i].change == types[t]) count++;
        }
        
        if (count > 0) {
            printf("\n%s (%d):\n", type_names[t], count);
            printf("-----------------------------------------------------------------------------\n");
            
            for (int i = 0; i < report->change_count; i++) {
                APIChange* change = &report->changes[i];
                if (change->change == types[t]) {
                    printf("  %s\n", change->element_name);
                    printf("    %s\n", change->description);
                    if (strlen(change->migration_guide) > 0) {
                        printf("    Migration: %s\n", change->migration_guide);
                    }
                    printf("\n");
                }
            }
        }
    }
    
    printf("=============================================================================\n");
}

void export_api_json(APICompatibilityReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"api\": \"%s\",\n", report->api_name);
    fprintf(f, "  \"baseline\": \"%s\",\n", report->baseline_version);
    fprintf(f, "  \"current\": \"%s\",\n", report->current_version);
    fprintf(f, "  \"compatibility\": \"%s\",\n", compatibility_to_string(report->compatibility));
    fprintf(f, "  \"score\": %.1f,\n", report->compatibility_score);
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"added\": %d,\n", report->added_count);
    fprintf(f, "    \"modified\": %d,\n", report->modified_count);
    fprintf(f, "    \"deprecated\": %d,\n", report->deprecated_count);
    fprintf(f, "    \"removed\": %d,\n", report->removed_count);
    fprintf(f, "    \"breaking\": %d\n", report->breaking_changes);
    fprintf(f, "  },\n");
    fprintf(f, "  \"changes\": [\n");
    
    for (int i = 0; i < report->change_count; i++) {
        APIChange* change = &report->changes[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"element\": \"%s\",\n", change->element_name);
        fprintf(f, "      \"type\": \"%s\",\n", change_type_to_string(change->change));
        fprintf(f, "      \"description\": \"%s\"\n", change->description);
        fprintf(f, "    }%s\n", (i < report->change_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  API compatibility report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD API Compatibility Checker\n");
    printf("================================\n\n");
    
    APICompatibilityReport* report = api_create_report();
    
    // Load API versions
    printf("Loading API versions...\n");
    load_api_versions(report);
    
    // Compare APIs
    printf("Comparing APIs...\n");
    compare_apis(report);
    
    // Generate reports
    print_api_summary(report);
    print_api_changes(report);
    export_api_json(report, "api_compatibility.json");
    
    printf("\nAPI compatibility check complete!\n");
    
    int exit_code = (report->compatibility == COMPAT_INCOMPATIBLE) ? 1 : 0;
    api_destroy_report(report);
    
    return exit_code;
}
