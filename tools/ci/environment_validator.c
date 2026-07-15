//=============================================================================
// environment_validator.c - Environment Validator
// Production-ready build environment validation and setup
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <windows.h>

//=============================================================================
// Environment Types
//=============================================================================

#define MAX_CHECKS 100
#define MAX_TOOLS 50
#define MAX_VARIABLES 100

typedef enum {
    CHECK_PASS,
    CHECK_FAIL,
    CHECK_WARNING,
    CHECK_SKIP
} CheckStatus;

typedef enum {
    REQ_REQUIRED,
    REQ_OPTIONAL
} RequirementLevel;

typedef struct {
    char name[128];
    char command[256];
    char version_arg[32];
    char min_version[32];
    char max_version[32];
    char detected_version[32];
    int is_installed;
    int is_compatible;
    RequirementLevel required;
    char install_url[512];
} ToolCheck;

typedef struct {
    char name[128];
    char expected_value[256];
    char actual_value[256];
    CheckStatus status;
    RequirementLevel required;
    char description[512];
} EnvVariableCheck;

typedef struct {
    char name[128];
    char path[512];
    int exists;
    int readable;
    int writable;
    size_t free_space;
    size_t total_space;
} PathCheck;

typedef struct {
    ToolCheck* tools;
    int tool_count;
    int tool_capacity;
    
    EnvVariableCheck* variables;
    int variable_count;
    int variable_capacity;
    
    PathCheck* paths;
    int path_count;
    int path_capacity;
    
    int passed_checks;
    int failed_checks;
    int warning_checks;
    int skipped_checks;
    
    int is_valid;
    char recommendations[10][512];
    int recommendation_count;
} EnvironmentReport;

//=============================================================================
// Environment Validator Implementation
//=============================================================================

EnvironmentReport* env_create_report(void) {
    EnvironmentReport* report = (EnvironmentReport*)calloc(1, sizeof(EnvironmentReport));
    report->tool_capacity = MAX_TOOLS;
    report->tools = (ToolCheck*)calloc(report->tool_capacity, sizeof(ToolCheck));
    report->variable_capacity = MAX_VARIABLES;
    report->variables = (EnvVariableCheck*)calloc(report->variable_capacity, sizeof(EnvVariableCheck));
    report->path_capacity = 20;
    report->paths = (PathCheck*)calloc(report->path_capacity, sizeof(PathCheck));
    report->is_valid = 1;
    return report;
}

void env_destroy_report(EnvironmentReport* report) {
    if (!report) return;
    free(report->tools);
    free(report->variables);
    free(report->paths);
    free(report);
}

ToolCheck* env_add_tool(EnvironmentReport* report, const char* name,
                        const char* command, RequirementLevel required) {
    if (report->tool_count >= report->tool_capacity) return NULL;
    
    ToolCheck* tool = &report->tools[report->tool_count++];
    strncpy(tool->name, name, sizeof(tool->name) - 1);
    strncpy(tool->command, command, sizeof(tool->command) - 1);
    tool->required = required;
    strncpy(tool->version_arg, "--version", sizeof(tool->version_arg) - 1);
    return tool;
}

EnvVariableCheck* env_add_variable(EnvironmentReport* report, const char* name,
                                   const char* expected, RequirementLevel required) {
    if (report->variable_count >= report->variable_capacity) return NULL;
    
    EnvVariableCheck* var = &report->variables[report->variable_count++];
    strncpy(var->name, name, sizeof(var->name) - 1);
    strncpy(var->expected_value, expected, sizeof(var->expected_value) - 1);
    var->required = required;
    return var;
}

PathCheck* env_add_path(EnvironmentReport* report, const char* name, const char* path) {
    if (report->path_count >= report->path_capacity) return NULL;
    
    PathCheck* pc = &report->paths[report->path_count++];
    strncpy(pc->name, name, sizeof(pc->name) - 1);
    strncpy(pc->path, path, sizeof(pc->path) - 1);
    return pc;
}

void check_tool(ToolCheck* tool) {
    // Check if tool exists in PATH
    char full_path[MAX_PATH];
    DWORD result = SearchPathA(NULL, tool->command, ".exe", MAX_PATH, full_path, NULL);
    
    if (result == 0) {
        tool->is_installed = 0;
        tool->is_compatible = 0;
        return;
    }
    
    tool->is_installed = 1;
    
    // Try to get version
    char cmd[512];
    snprintf(cmd, sizeof(cmd), "\"%s\" %s 2>&1", full_path, tool->version_arg);
    
    FILE* pipe = _popen(cmd, "r");
    if (pipe) {
        char buffer[256];
        if (fgets(buffer, sizeof(buffer), pipe)) {
            // Simple version extraction
            char* v = strstr(buffer, "version");
            if (v) {
                sscanf(v, "version %31s", tool->detected_version);
            } else {
                strncpy(tool->detected_version, buffer, sizeof(tool->detected_version) - 1);
            }
        }
        _pclose(pipe);
    }
    
    // Check version compatibility
    if (strlen(tool->min_version) > 0 && strlen(tool->detected_version) > 0) {
        tool->is_compatible = (strcmp(tool->detected_version, tool->min_version) >= 0);
    } else {
        tool->is_compatible = 1;
    }
}

void check_variable(EnvVariableCheck* var) {
    const char* value = getenv(var->name);
    if (value) {
        strncpy(var->actual_value, value, sizeof(var->actual_value) - 1);
        if (strlen(var->expected_value) > 0) {
            var->status = (strcmp(value, var->expected_value) == 0) ? CHECK_PASS : CHECK_WARNING;
        } else {
            var->status = CHECK_PASS;
        }
    } else {
        strncpy(var->actual_value, "(not set)", sizeof(var->actual_value) - 1);
        var->status = (var->required == REQ_REQUIRED) ? CHECK_FAIL : CHECK_WARNING;
    }
}

void check_path(PathCheck* pc) {
    DWORD attrs = GetFileAttributesA(pc->path);
    pc->exists = (attrs != INVALID_FILE_ATTRIBUTES);
    
    if (pc->exists) {
        pc->readable = 1; // Simplified
        pc->writable = 1; // Simplified
        
        // Get disk space
        ULARGE_INTEGER freeBytes, totalBytes;
        if (GetDiskFreeSpaceExA(pc->path, &freeBytes, &totalBytes, NULL)) {
            pc->free_space = (size_t)freeBytes.QuadPart;
            pc->total_space = (size_t)totalBytes.QuadPart;
        }
    }
}

void run_environment_checks(EnvironmentReport* report) {
    // Check tools
    for (int i = 0; i < report->tool_count; i++) {
        check_tool(&report->tools[i]);
        
        if (report->tools[i].is_installed && report->tools[i].is_compatible) {
            report->passed_checks++;
        } else if (!report->tools[i].is_installed && report->tools[i].required == REQ_REQUIRED) {
            report->failed_checks++;
            report->is_valid = 0;
        } else {
            report->warning_checks++;
        }
    }
    
    // Check variables
    for (int i = 0; i < report->variable_count; i++) {
        check_variable(&report->variables[i]);
        
        switch (report->variables[i].status) {
            case CHECK_PASS: report->passed_checks++; break;
            case CHECK_FAIL: report->failed_checks++; report->is_valid = 0; break;
            case CHECK_WARNING: report->warning_checks++; break;
            default: break;
        }
    }
    
    // Check paths
    for (int i = 0; i < report->path_count; i++) {
        check_path(&report->paths[i]);
        if (report->paths[i].exists) {
            report->passed_checks++;
        } else {
            report->failed_checks++;
            report->is_valid = 0;
        }
    }
}

void setup_default_checks(EnvironmentReport* report) {
    // Required tools
    ToolCheck* tool = env_add_tool(report, "CMake", "cmake", REQ_REQUIRED);
    strncpy(tool->min_version, "3.20", sizeof(tool->min_version));
    strncpy(tool->install_url, "https://cmake.org/download/", sizeof(tool->install_url));
    
    tool = env_add_tool(report, "Git", "git", REQ_REQUIRED);
    strncpy(tool->min_version, "2.30", sizeof(tool->min_version));
    
    tool = env_add_tool(report, "Python", "python", REQ_REQUIRED);
    strncpy(tool->min_version, "3.9", sizeof(tool->min_version));
    
    tool = env_add_tool(report, "Visual Studio", "cl", REQ_REQUIRED);
    strncpy(tool->version_arg, "", sizeof(tool->version_arg));
    
    // Optional tools
    tool = env_add_tool(report, "Ninja", "ninja", REQ_OPTIONAL);
    tool = env_add_tool(report, "vcpkg", "vcpkg", REQ_OPTIONAL);
    
    // Environment variables
    env_add_variable(report, "CMAKE_GENERATOR", "", REQ_OPTIONAL);
    env_add_variable(report, "VCPKG_ROOT", "", REQ_OPTIONAL);
    
    // Paths
    env_add_path(report, "Source Directory", ".");
    env_add_path(report, "Build Directory", "./build");
    env_add_path(report, "Install Directory", "C:/Program Files/RawrXD");
}

//=============================================================================
// Report Generation
//=============================================================================

const char* status_to_icon(CheckStatus status) {
    switch (status) {
        case CHECK_PASS: return "✅";
        case CHECK_FAIL: return "❌";
        case CHECK_WARNING: return "⚠️";
        case CHECK_SKIP: return "⏭️";
        default: return "❓";
    }
}

void print_env_summary(EnvironmentReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Environment Validation Summary\n");
    printf("=============================================================================\n");
    printf("  Overall Status:       %s\n", report->is_valid ? "✅ Valid" : "❌ Invalid");
    printf("\n");
    printf("  Checks Passed:        %d\n", report->passed_checks);
    printf("  Checks Failed:        %d\n", report->failed_checks);
    printf("  Warnings:             %d\n", report->warning_checks);
    printf("=============================================================================\n");
}

void print_tool_checks(EnvironmentReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Tool Checks\n");
    printf("=============================================================================\n");
    printf("  %-20s %-12s %-15s %-10s\n", "Tool", "Required", "Installed", "Version");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->tool_count; i++) {
        ToolCheck* tool = &report->tools[i];
        const char* icon = tool->is_installed ?
                          (tool->is_compatible ? "✅" : "⚠️") :
                          (tool->required == REQ_REQUIRED ? "❌" : "⚠️");
        
        printf("  %-20s %-12s %s %-15s %-10s\n",
               tool->name,
               tool->required == REQ_REQUIRED ? "Required" : "Optional",
               icon,
               tool->is_installed ? "Yes" : "No",
               tool->detected_version);
        
        if (!tool->is_installed && strlen(tool->install_url) > 0) {
            printf("       Install: %s\n", tool->install_url);
        }
    }
    
    printf("=============================================================================\n");
}

void print_variable_checks(EnvironmentReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Environment Variables\n");
    printf("=============================================================================\n");
    printf("  %-25s %-12s %-30s\n", "Variable", "Required", "Value");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->variable_count; i++) {
        EnvVariableCheck* var = &report->variables[i];
        printf("  %-25s %-12s %s %s\n",
               var->name,
               var->required == REQ_REQUIRED ? "Required" : "Optional",
               status_to_icon(var->status),
               var->actual_value);
    }
    
    printf("=============================================================================\n");
}

void print_path_checks(EnvironmentReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Path Checks\n");
    printf("=============================================================================\n");
    printf("  %-25s %-10s %-15s %-15s\n", "Path", "Exists", "Free Space", "Total Space");
    printf("  ---------------------------------------------------------------------------\n");
    
    for (int i = 0; i < report->path_count; i++) {
        PathCheck* pc = &report->paths[i];
        char free_str[32], total_str[32];
        
        if (pc->free_space > 1024 * 1024 * 1024) {
            snprintf(free_str, sizeof(free_str), "%.1f GB",
                     pc->free_space / (1024.0 * 1024 * 1024));
        } else {
            snprintf(free_str, sizeof(free_str), "%.1f MB",
                     pc->free_space / (1024.0 * 1024));
        }
        
        if (pc->total_space > 1024 * 1024 * 1024) {
            snprintf(total_str, sizeof(total_str), "%.1f GB",
                     pc->total_space / (1024.0 * 1024 * 1024));
        } else {
            snprintf(total_str, sizeof(total_str), "%.1f MB",
                     pc->total_space / (1024.0 * 1024));
        }
        
        printf("  %-25s %-10s %-15s %-15s\n",
               pc->name,
               pc->exists ? "✅ Yes" : "❌ No",
               pc->exists ? free_str : "N/A",
               pc->exists ? total_str : "N/A");
    }
    
    printf("=============================================================================\n");
}

void export_env_json(EnvironmentReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"is_valid\": %s,\n", report->is_valid ? "true" : "false");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"passed\": %d,\n", report->passed_checks);
    fprintf(f, "    \"failed\": %d,\n", report->failed_checks);
    fprintf(f, "    \"warnings\": %d\n", report->warning_checks);
    fprintf(f, "  },\n");
    fprintf(f, "  \"tools\": [\n");
    
    for (int i = 0; i < report->tool_count; i++) {
        ToolCheck* tool = &report->tools[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", tool->name);
        fprintf(f, "      \"installed\": %s,\n", tool->is_installed ? "true" : "false");
        fprintf(f, "      \"compatible\": %s,\n", tool->is_compatible ? "true" : "false");
        fprintf(f, "      \"version\": \"%s\",\n", tool->detected_version);
        fprintf(f, "      \"required\": %s\n", tool->required == REQ_REQUIRED ? "true" : "false");
        fprintf(f, "    }%s\n", (i < report->tool_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Environment report exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Environment Validator\n");
    printf("==========================\n\n");
    
    EnvironmentReport* report = env_create_report();
    
    // Setup checks
    setup_default_checks(report);
    
    // Run checks
    printf("Running environment checks...\n");
    run_environment_checks(report);
    
    // Generate reports
    print_env_summary(report);
    print_tool_checks(report);
    print_variable_checks(report);
    print_path_checks(report);
    export_env_json(report, "environment_report.json");
    
    printf("\nEnvironment validation complete!\n");
    
    int exit_code = report->is_valid ? 0 : 1;
    env_destroy_report(report);
    
    return exit_code;
}
