//=============================================================================
// documentation_generator.c - Documentation Generator
// Production-ready documentation generation from source code analysis
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>

//=============================================================================
// Documentation Types
//=============================================================================

#define MAX_SYMBOLS 5000
#define MAX_FILES 1000
#define MAX_PARAMS 50
#define MAX_SEE_ALSO 20

typedef enum {
    SYMBOL_FUNCTION,
    SYMBOL_VARIABLE,
    SYMBOL_TYPEDEF,
    SYMBOL_STRUCT,
    SYMBOL_ENUM,
    SYMBOL_MACRO,
    SYMBOL_CONSTANT
} SymbolType;

typedef struct {
    char name[128];
    char type[128];
    char description[512];
    int is_optional;
    char default_value[128];
} ParameterDoc;

typedef struct {
    char name[256];
    SymbolType type;
    char file[512];
    int line;
    
    char signature[1024];
    char brief[512];
    char description[2048];
    char return_type[256];
    char return_description[512];
    
    ParameterDoc* params;
    int param_count;
    int param_capacity;
    
    char see_also[MAX_SEE_ALSO][256];
    int see_also_count;
    
    char examples[4096];
    char notes[1024];
    char warnings[1024];
    
    int is_deprecated;
    char deprecation_reason[512];
    char since_version[32];
    
    char author[128];
    char copyright[512];
} SymbolDoc;

typedef struct {
    char name[256];
    char path[512];
    char description[1024];
    char brief[512];
    char version[32];
    char author[256];
    char license[64];
    
    SymbolDoc* symbols;
    int symbol_count;
    int symbol_capacity;
    
    int function_count;
    int type_count;
    int macro_count;
    int constant_count;
} ModuleDoc;

typedef struct {
    ModuleDoc* modules;
    int module_count;
    int module_capacity;
    
    char project_name[256];
    char project_version[32];
    char project_description[1024];
    char output_dir[512];
    
    int total_symbols;
    int documented_symbols;
    int undocumented_symbols;
    double coverage_percent;
} DocumentationReport;

//=============================================================================
// Documentation Parser
//=============================================================================

DocumentationReport* docs_create_report(void) {
    DocumentationReport* report = (DocumentationReport*)calloc(1, sizeof(DocumentationReport));
    report->module_capacity = MAX_FILES;
    report->modules = (ModuleDoc*)calloc(report->module_capacity, sizeof(ModuleDoc));
    strncpy(report->project_name, "RawrXD", sizeof(report->project_name));
    strncpy(report->project_version, "1.0.0", sizeof(report->project_version));
    strncpy(report->output_dir, "./docs", sizeof(report->output_dir));
    return report;
}

void docs_destroy_report(DocumentationReport* report) {
    if (!report) return;
    
    for (int i = 0; i < report->module_count; i++) {
        ModuleDoc* mod = &report->modules[i];
        for (int j = 0; j < mod->symbol_count; j++) {
            free(mod->symbols[j].params);
        }
        free(mod->symbols);
    }
    
    free(report->modules);
    free(report);
}

ModuleDoc* add_module(DocumentationReport* report, const char* name, const char* path) {
    if (report->module_count >= report->module_capacity) return NULL;
    
    ModuleDoc* mod = &report->modules[report->module_count++];
    strncpy(mod->name, name, sizeof(mod->name) - 1);
    strncpy(mod->path, path, sizeof(mod->path) - 1);
    mod->symbol_capacity = MAX_SYMBOLS;
    mod->symbols = (SymbolDoc*)calloc(mod->symbol_capacity, sizeof(SymbolDoc));
    return mod;
}

SymbolDoc* add_symbol(ModuleDoc* module, const char* name, SymbolType type,
                       const char* file, int line) {
    if (module->symbol_count >= module->symbol_capacity) return NULL;
    
    SymbolDoc* sym = &module->symbols[module->symbol_count++];
    strncpy(sym->name, name, sizeof(sym->name) - 1);
    sym->type = type;
    strncpy(sym->file, file, sizeof(sym->file) - 1);
    sym->line = line;
    sym->param_capacity = MAX_PARAMS;
    sym->params = (ParameterDoc*)calloc(sym->param_capacity, sizeof(ParameterDoc));
    return sym;
}

void parse_doxygen_comment(const char* comment, SymbolDoc* sym) {
    // Parse @brief
    const char* brief = strstr(comment, "@brief");
    if (brief) {
        brief += 7;
        const char* end = strchr(brief, '\n');
        if (end) {
            int len = end - brief;
            if (len > 511) len = 511;
            strncpy(sym->brief, brief, len);
            sym->brief[len] = '\0';
        }
    }
    
    // Parse @param
    const char* param = strstr(comment, "@param");
    while (param && sym->param_count < sym->param_capacity) {
        param += 7;
        ParameterDoc* p = &sym->params[sym->param_count++];
        
        // Parse parameter name
        int name_len = 0;
        while (param[name_len] && !isspace(param[name_len]) && param[name_len] != '\n') {
            name_len++;
        }
        if (name_len > 127) name_len = 127;
        strncpy(p->name, param, name_len);
        p->name[name_len] = '\0';
        
        // Parse description
        param += name_len;
        while (*param && isspace(*param)) param++;
        const char* end = strchr(param, '\n');
        if (end) {
            int desc_len = end - param;
            if (desc_len > 511) desc_len = 511;
            strncpy(p->description, param, desc_len);
            p->description[desc_len] = '\0';
        }
        
        param = strstr(param, "@param");
    }
    
    // Parse @return
    const char* ret = strstr(comment, "@return");
    if (ret) {
        ret += 8;
        const char* end = strchr(ret, '\n');
        if (end) {
            int len = end - ret;
            if (len > 511) len = 511;
            strncpy(sym->return_description, ret, len);
            sym->return_description[len] = '\0';
        }
    }
    
    // Parse @deprecated
    if (strstr(comment, "@deprecated")) {
        sym->is_deprecated = 1;
        const char* dep = strstr(comment, "@deprecated");
        dep += 12;
        const char* end = strchr(dep, '\n');
        if (end) {
            int len = end - dep;
            if (len > 511) len = 511;
            strncpy(sym->deprecation_reason, dep, len);
            sym->deprecation_reason[len] = '\0';
        }
    }
    
    // Parse @since
    const char* since = strstr(comment, "@since");
    if (since) {
        since += 7;
        const char* end = strchr(since, '\n');
        if (end) {
            int len = end - since;
            if (len > 31) len = 31;
            strncpy(sym->since_version, since, len);
            sym->since_version[len] = '\0';
        }
    }
}

void scan_source_file(DocumentationReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    // Create module for this file
    char basename[256];
    const char* slash = strrchr(filename, '/');
    const char* backslash = strrchr(filename, '\\');
    const char* name_start = slash > backslash ? slash + 1 : (backslash ? backslash + 1 : filename);
    strncpy(basename, name_start, sizeof(basename) - 1);
    char* dot = strrchr(basename, '.');
    if (dot) *dot = '\0';
    
    ModuleDoc* module = add_module(report, basename, filename);
    
    char line[4096];
    int line_num = 0;
    char comment_buffer[8192] = {0};
    int in_comment = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        
        // Check for comment start
        if (strstr(line, "/**")) {
            in_comment = 1;
            comment_buffer[0] = '\0';
        }
        
        // Accumulate comment
        if (in_comment) {
            strcat(comment_buffer, line);
        }
        
        // Check for comment end
        if (strstr(line, "*/")) {
            in_comment = 0;
            // Next non-empty line should be the declaration
            continue;
        }
        
        // Parse function declarations (simplified)
        if (!in_comment && strlen(comment_buffer) > 0) {
            // Check for function pattern
            char* paren = strchr(line, '(');
            if (paren && !strstr(line, "//") && !strstr(line, "typedef")) {
                // Extract function name
                char* name_end = paren;
                while (name_end > line && isspace(*(name_end - 1))) name_end--;
                
                char* name_start = name_end;
                while (name_start > line && (isalnum(*(name_start - 1)) || *(name_start - 1) == '_')) {
                    name_start--;
                }
                
                int name_len = name_end - name_start;
                if (name_len > 0 && name_len < 256) {
                    char func_name[256];
                    strncpy(func_name, name_start, name_len);
                    func_name[name_len] = '\0';
                    
                    SymbolDoc* sym = add_symbol(module, func_name, SYMBOL_FUNCTION, filename, line_num);
                    strncpy(sym->signature, line, sizeof(sym->signature) - 1);
                    parse_doxygen_comment(comment_buffer, sym);
                    
                    report->total_symbols++;
                    if (strlen(sym->brief) > 0) {
                        report->documented_symbols++;
                    } else {
                        report->undocumented_symbols++;
                    }
                    
                    module->function_count++;
                }
            }
            
            comment_buffer[0] = '\0';
        }
    }
    
    fclose(f);
}

//=============================================================================
// Report Generation
//=============================================================================

const char* symbol_type_to_string(SymbolType type) {
    switch (type) {
        case SYMBOL_FUNCTION: return "Function";
        case SYMBOL_VARIABLE: return "Variable";
        case SYMBOL_TYPEDEF: return "Typedef";
        case SYMBOL_STRUCT: return "Struct";
        case SYMBOL_ENUM: return "Enum";
        case SYMBOL_MACRO: return "Macro";
        case SYMBOL_CONSTANT: return "Constant";
        default: return "Unknown";
    }
}

void print_docs_summary(DocumentationReport* report) {
    if (report->total_symbols > 0) {
        report->coverage_percent = (double)report->documented_symbols / report->total_symbols * 100;
    }
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Documentation Generation Summary\n");
    printf("=============================================================================\n");
    printf("  Project:              %s v%s\n", report->project_name, report->project_version);
    printf("  Modules:              %d\n", report->module_count);
    printf("  Total Symbols:        %d\n", report->total_symbols);
    printf("  Documented:           %d\n", report->documented_symbols);
    printf("  Undocumented:       %d\n", report->undocumented_symbols);
    printf("  Coverage:           %.1f%%\n", report->coverage_percent);
    printf("=============================================================================\n");
}

void export_markdown(DocumentationReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "# %s Documentation\n\n", report->project_name);
    fprintf(f, "**Version:** %s\n\n", report->project_version);
    fprintf(f, "**Coverage:** %.1f%% (%d/%d symbols documented)\n\n",
            report->coverage_percent, report->documented_symbols, report->total_symbols);
    
    fprintf(f, "## Table of Contents\n\n");
    for (int i = 0; i < report->module_count; i++) {
        ModuleDoc* mod = &report->modules[i];
        fprintf(f, "- [%s](#%s)\n", mod->name, mod->name);
    }
    
    fprintf(f, "\n");
    
    // Module documentation
    for (int i = 0; i < report->module_count; i++) {
        ModuleDoc* mod = &report->modules[i];
        fprintf(f, "## %s\n\n", mod->name);
        fprintf(f, "**File:** `%s`\n\n", mod->path);
        
        if (mod->symbol_count > 0) {
            fprintf(f, "### Functions\n\n");
            for (int j = 0; j < mod->symbol_count; j++) {
                SymbolDoc* sym = &mod->symbols[j];
                if (sym->type == SYMBOL_FUNCTION) {
                    fprintf(f, "#### %s\n\n", sym->name);
                    fprintf(f, "```c\n%s```\n\n", sym->signature);
                    
                    if (strlen(sym->brief) > 0) {
                        fprintf(f, "%s\n\n", sym->brief);
                    }
                    
                    if (sym->param_count > 0) {
                        fprintf(f, "**Parameters:**\n\n");
                        for (int k = 0; k < sym->param_count; k++) {
                            ParameterDoc* p = &sym->params[k];
                            fprintf(f, "- `%s`: %s\n", p->name, p->description);
                        }
                        fprintf(f, "\n");
                    }
                    
                    if (strlen(sym->return_description) > 0) {
                        fprintf(f, "**Returns:** %s\n\n", sym->return_description);
                    }
                    
                    if (sym->is_deprecated) {
                        fprintf(f, "⚠️ **Deprecated:** %s\n\n", sym->deprecation_reason);
                    }
                    
                    fprintf(f, "---\n\n");
                }
            }
        }
    }
    
    fclose(f);
    printf("  Markdown documentation exported: %s\n", filename);
}

void export_html(DocumentationReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "<!DOCTYPE html>\n");
    fprintf(f, "<html>\n");
    fprintf(f, "<head>\n");
    fprintf(f, "  <title>%s Documentation</title>\n", report->project_name);
    fprintf(f, "  <style>\n");
    fprintf(f, "    body { font-family: Arial, sans-serif; margin: 40px; background: #f5f5f5; }\n");
    fprintf(f, "    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 30px; }\n");
    fprintf(f, "    h1 { color: #333; border-bottom: 3px solid #4CAF50; padding-bottom: 10px; }\n");
    fprintf(f, "    h2 { color: #555; margin-top: 30px; }\n");
    fprintf(f, "    h3 { color: #666; }\n");
    fprintf(f, "    .summary { background: #e8f5e9; padding: 15px; border-radius: 5px; margin: 20px 0; }\n");
    fprintf(f, "    .function { background: #f9f9f9; padding: 15px; margin: 10px 0; border-left: 4px solid #4CAF50; }\n");
    fprintf(f, "    .deprecated { border-left-color: #ff9800; }\n");
    fprintf(f, "    .signature { background: #263238; color: #aed581; padding: 10px; font-family: monospace; }\n");
    fprintf(f, "    .param { margin: 5px 0; }\n");
    fprintf(f, "    .coverage { font-size: 24px; font-weight: bold; color: #4CAF50; }\n");
    fprintf(f, "  </style>\n");
    fprintf(f, "</head>\n");
    fprintf(f, "<body>\n");
    fprintf(f, "  <div class='container'>\n");
    fprintf(f, "    <h1>%s Documentation</h1>\n", report->project_name);
    fprintf(f, "    <div class='summary'>\n");
    fprintf(f, "      <p><strong>Version:</strong> %s</p>\n", report->project_version);
    fprintf(f, "      <p><strong>Coverage:</strong> <span class='coverage'>%.1f%%</span> (%d/%d symbols)</p>\n",
            report->coverage_percent, report->documented_symbols, report->total_symbols);
    fprintf(f, "    </div>\n");
    
    for (int i = 0; i < report->module_count; i++) {
        ModuleDoc* mod = &report->modules[i];
        fprintf(f, "    <h2>%s</h2>\n", mod->name);
        fprintf(f, "    <p><code>%s</code></p>\n", mod->path);
        
        for (int j = 0; j < mod->symbol_count; j++) {
            SymbolDoc* sym = &mod->symbols[j];
            if (sym->type == SYMBOL_FUNCTION) {
                fprintf(f, "    <div class='function%s'>\n", sym->is_deprecated ? " deprecated" : "");
                fprintf(f, "      <h3>%s</h3>\n", sym->name);
                fprintf(f, "      <div class='signature'>%s</div>\n", sym->signature);
                if (strlen(sym->brief) > 0) {
                    fprintf(f, "      <p>%s</p>\n", sym->brief);
                }
                if (sym->is_deprecated) {
                    fprintf(f, "      <p><strong>Deprecated:</strong> %s</p>\n", sym->deprecation_reason);
                }
                fprintf(f, "    </div>\n");
            }
        }
    }
    
    fprintf(f, "  </div>\n");
    fprintf(f, "</body>\n");
    fprintf(f, "</html>\n");
    
    fclose(f);
    printf("  HTML documentation exported: %s\n", filename);
}

void export_docs_json(DocumentationReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"project\": {\n");
    fprintf(f, "    \"name\": \"%s\",\n", report->project_name);
    fprintf(f, "    \"version\": \"%s\",\n", report->project_version);
    fprintf(f, "    \"coverage\": %.2f,\n", report->coverage_percent);
    fprintf(f, "    \"total_symbols\": %d,\n", report->total_symbols);
    fprintf(f, "    \"documented\": %d,\n", report->documented_symbols);
    fprintf(f, "    \"undocumented\": %d\n", report->undocumented_symbols);
    fprintf(f, "  },\n");
    fprintf(f, "  \"modules\": [\n");
    
    for (int i = 0; i < report->module_count; i++) {
        ModuleDoc* mod = &report->modules[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", mod->name);
        fprintf(f, "      \"path\": \"%s\",\n", mod->path);
        fprintf(f, "      \"symbols\": %d,\n", mod->symbol_count);
        fprintf(f, "      \"functions\": %d\n", mod->function_count);
        fprintf(f, "    }%s\n", (i < report->module_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  JSON documentation exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Documentation Generator\n");
    printf("==============================\n\n");
    
    DocumentationReport* report = docs_create_report();
    
    // Scan source files
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            printf("Scanning: %s\n", argv[i]);
            scan_source_file(report, argv[i]);
        }
    } else {
        printf("Scanning: %s\n", __FILE__);
        scan_source_file(report, __FILE__);
    }
    
    // Generate reports
    print_docs_summary(report);
    export_markdown(report, "API.md");
    export_html(report, "docs.html");
    export_docs_json(report, "documentation_report.json");
    
    printf("\nDocumentation generation complete!\n");
    
    int exit_code = (report->coverage_percent < 50.0) ? 1 : 0;
    docs_destroy_report(report);
    
    return exit_code;
}
