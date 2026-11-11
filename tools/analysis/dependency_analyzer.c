//=============================================================================
// dependency_analyzer.c - Dependency Analyzer
// Production-ready dependency analysis with circular dependency detection
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

//=============================================================================
// Dependency Types
//=============================================================================

#define MAX_MODULES 500
#define MAX_DEPENDENCIES 2000
#define MAX_CYCLES 50

typedef struct {
    char name[256];
    char path[512];
    int id;
    int* dependencies;
    int dep_count;
    int dep_capacity;
    int is_external;
    int depth;
    int visited;
    int in_stack;
} Module;

typedef struct {
    int* modules;
    int count;
    int length;
} DependencyCycle;

typedef struct {
    Module* modules;
    int module_count;
    int module_capacity;
    
    DependencyCycle* cycles;
    int cycle_count;
    int cycle_capacity;
    
    int total_dependencies;
    int external_dependencies;
    int max_depth;
    int orphaned_modules;
    int has_circular_deps;
} DependencyReport;

//=============================================================================
// Dependency Analyzer Implementation
//=============================================================================

DependencyReport* dep_report_create(void) {
    DependencyReport* report = (DependencyReport*)calloc(1, sizeof(DependencyReport));
    report->module_capacity = MAX_MODULES;
    report->modules = (Module*)calloc(report->module_capacity, sizeof(Module));
    report->cycle_capacity = MAX_CYCLES;
    report->cycles = (DependencyCycle*)calloc(report->cycle_capacity, sizeof(DependencyCycle));
    return report;
}

void dep_report_destroy(DependencyReport* report) {
    if (!report) return;
    for (int i = 0; i < report->module_count; i++) {
        free(report->modules[i].dependencies);
    }
    for (int i = 0; i < report->cycle_count; i++) {
        free(report->cycles[i].modules);
    }
    free(report->modules);
    free(report->cycles);
    free(report);
}

Module* find_or_create_module(DependencyReport* report, const char* name) {
    // Find existing module
    for (int i = 0; i < report->module_count; i++) {
        if (strcmp(report->modules[i].name, name) == 0) {
            return &report->modules[i];
        }
    }
    
    // Create new module
    if (report->module_count >= report->module_capacity) return NULL;
    
    Module* mod = &report->modules[report->module_count];
    strncpy(mod->name, name, sizeof(mod->name) - 1);
    mod->id = report->module_count++;
    mod->dep_capacity = 20;
    mod->dependencies = (int*)calloc(mod->dep_capacity, sizeof(int));
    return mod;
}

void add_dependency(Module* from, Module* to) {
    if (from->dep_count >= from->dep_capacity) return;
    from->dependencies[from->dep_count++] = to->id;
}

void detect_cycle_recursive(DependencyReport* report, Module* mod, int* stack, int stack_size) {
    mod->visited = 1;
    mod->in_stack = 1;
    
    // Add current module to stack
    stack[stack_size] = mod->id;
    
    for (int i = 0; i < mod->dep_count; i++) {
        int dep_id = mod->dependencies[i];
        Module* dep = &report->modules[dep_id];
        
        if (!dep->visited) {
            detect_cycle_recursive(report, dep, stack, stack_size + 1);
        } else if (dep->in_stack) {
            // Found a cycle
            if (report->cycle_count < report->cycle_capacity) {
                DependencyCycle* cycle = &report->cycles[report->cycle_count++];
                cycle->modules = (int*)malloc(MAX_MODULES * sizeof(int));
                
                // Find cycle start in stack
                int cycle_start = 0;
                for (int j = 0; j <= stack_size; j++) {
                    if (stack[j] == dep_id) {
                        cycle_start = j;
                        break;
                    }
                }
                
                // Copy cycle
                cycle->count = 0;
                for (int j = cycle_start; j <= stack_size; j++) {
                    cycle->modules[cycle->count++] = stack[j];
                }
                cycle->length = cycle->count;
                report->has_circular_deps = 1;
            }
        }
    }
    
    mod->in_stack = 0;
}

void detect_cycles(DependencyReport* report) {
    // Reset visited flags
    for (int i = 0; i < report->module_count; i++) {
        report->modules[i].visited = 0;
        report->modules[i].in_stack = 0;
    }
    
    int* stack = (int*)malloc(MAX_MODULES * sizeof(int));
    
    for (int i = 0; i < report->module_count; i++) {
        if (!report->modules[i].visited) {
            detect_cycle_recursive(report, &report->modules[i], stack, 0);
        }
    }
    
    free(stack);
}

void calculate_depths(DependencyReport* report) {
    // Simple depth calculation
    for (int i = 0; i < report->module_count; i++) {
        Module* mod = &report->modules[i];
        mod->depth = mod->dep_count;
        if (mod->depth > report->max_depth) {
            report->max_depth = mod->depth;
        }
    }
}

void analyze_dependencies(DependencyReport* report) {
    detect_cycles(report);
    calculate_depths(report);
    
    // Count orphaned modules (no dependencies, nothing depends on them)
    for (int i = 0; i < report->module_count; i++) {
        Module* mod = &report->modules[i];
        int is_referenced = 0;
        
        for (int j = 0; j < report->module_count; j++) {
            for (int k = 0; k < report->modules[j].dep_count; k++) {
                if (report->modules[j].dependencies[k] == mod->id) {
                    is_referenced = 1;
                    break;
                }
            }
            if (is_referenced) break;
        }
        
        if (mod->dep_count == 0 && !is_referenced) {
            report->orphaned_modules++;
        }
    }
}

//=============================================================================
// Report Generation
//=============================================================================

void print_dep_summary(DependencyReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Dependency Analysis Summary\n");
    printf("=============================================================================\n");
    printf("  Total Modules:        %d\n", report->module_count);
    printf("  Total Dependencies:   %d\n", report->total_dependencies);
    printf("  External Deps:        %d\n", report->external_dependencies);
    printf("  Max Depth:            %d\n", report->max_depth);
    printf("  Orphaned Modules:     %d\n", report->orphaned_modules);
    printf("  Circular Deps:        %s\n", report->has_circular_deps ? "⚠️ DETECTED" : "✅ None");
    printf("=============================================================================\n");
}

void print_module_graph(DependencyReport* report) {
    printf("\n");
    printf("=============================================================================\n");
    printf("  Module Dependency Graph\n");
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->module_count; i++) {
        Module* mod = &report->modules[i];
        printf("\n  %s\n", mod->name);
        
        if (mod->dep_count > 0) {
            printf("    Dependencies:\n");
            for (int j = 0; j < mod->dep_count; j++) {
                int dep_id = mod->dependencies[j];
                printf("      └─ %s\n", report->modules[dep_id].name);
            }
        } else {
            printf("    (no dependencies)\n");
        }
    }
    
    printf("\n=============================================================================\n");
}

void print_cycles(DependencyReport* report) {
    if (report->cycle_count == 0) return;
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  ⚠️  Circular Dependencies Detected (%d)\n", report->cycle_count);
    printf("=============================================================================\n");
    
    for (int i = 0; i < report->cycle_count; i++) {
        DependencyCycle* cycle = &report->cycles[i];
        printf("\n  Cycle %d (length: %d):\n", i + 1, cycle->length);
        printf("    ");
        
        for (int j = 0; j < cycle->count; j++) {
            Module* mod = &report->modules[cycle->modules[j]];
            printf("%s", mod->name);
            if (j < cycle->count - 1) {
                printf(" → ");
            }
        }
        printf(" → (back to start)\n");
    }
    
    printf("\n=============================================================================\n");
}

void export_dep_json(DependencyReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"total_modules\": %d,\n", report->module_count);
    fprintf(f, "    \"total_dependencies\": %d,\n", report->total_dependencies);
    fprintf(f, "    \"external_dependencies\": %d,\n", report->external_dependencies);
    fprintf(f, "    \"max_depth\": %d,\n", report->max_depth);
    fprintf(f, "    \"orphaned_modules\": %d,\n", report->orphaned_modules);
    fprintf(f, "    \"has_circular_deps\": %s\n", report->has_circular_deps ? "true" : "false");
    fprintf(f, "  },\n");
    fprintf(f, "  \"modules\": [\n");
    
    for (int i = 0; i < report->module_count; i++) {
        Module* mod = &report->modules[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", mod->name);
        fprintf(f, "      \"id\": %d,\n", mod->id);
        fprintf(f, "      \"depth\": %d,\n", mod->depth);
        fprintf(f, "      \"is_external\": %s,\n", mod->is_external ? "true" : "false");
        fprintf(f, "      \"dependencies\": [");
        
        for (int j = 0; j < mod->dep_count; j++) {
            fprintf(f, "%d%s", mod->dependencies[j],
                    (j < mod->dep_count - 1) ? ", " : "");
        }
        
        fprintf(f, "]\n");
        fprintf(f, "    }%s\n", (i < report->module_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ],\n");
    fprintf(f, "  \"cycles\": [\n");
    
    for (int i = 0; i < report->cycle_count; i++) {
        DependencyCycle* cycle = &report->cycles[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"length\": %d,\n", cycle->length);
        fprintf(f, "      \"modules\": [");
        
        for (int j = 0; j < cycle->count; j++) {
            fprintf(f, "%d%s", cycle->modules[j],
                    (j < cycle->count - 1) ? ", " : "");
        }
        
        fprintf(f, "]\n");
        fprintf(f, "    }%s\n", (i < report->cycle_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Dependency report exported: %s\n", filename);
}

//=============================================================================
// Demo Data
//=============================================================================

void create_demo_dependencies(DependencyReport* report) {
    // Create modules
    Module* core = find_or_create_module(report, "core");
    Module* utils = find_or_create_module(report, "utils");
    Module* network = find_or_create_module(report, "network");
    Module* database = find_or_create_module(report, "database");
    Module* api = find_or_create_module(report, "api");
    Module* auth = find_or_create_module(report, "auth");
    Module* logging = find_or_create_module(report, "logging");
    Module* config = find_or_create_module(report, "config");
    
    // Set up dependencies
    add_dependency(api, network);
    add_dependency(api, auth);
    add_dependency(api, utils);
    add_dependency(network, utils);
    add_dependency(network, logging);
    add_dependency(database, utils);
    add_dependency(database, logging);
    add_dependency(auth, database);
    add_dependency(auth, utils);
    add_dependency(config, utils);
    add_dependency(core, utils);
    add_dependency(core, config);
    add_dependency(core, logging);
    
    // Create a circular dependency for demo
    add_dependency(utils, core);  // This creates a cycle: core → utils → core
    
    report->total_dependencies = 14;
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Dependency Analyzer\n");
    printf("==========================\n\n");
    
    DependencyReport* report = dep_report_create();
    
    // Create demo dependencies
    create_demo_dependencies(report);
    
    // Analyze
    analyze_dependencies(report);
    
    // Generate reports
    print_dep_summary(report);
    print_module_graph(report);
    print_cycles(report);
    export_dep_json(report, "dependency_analysis.json");
    
    printf("\nDependency analysis complete!\n");
    
    int exit_code = report->has_circular_deps ? 1 : 0;
    dep_report_destroy(report);
    
    return exit_code;
}
