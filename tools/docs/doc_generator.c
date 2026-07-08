//=============================================================================
// doc_generator.c - Documentation Generator
// Production-ready documentation generation from source code
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Documentation Types
//=============================================================================

#define MAX_SYMBOLS 5000
#define MAX_FILES 500
#define MAX_PARAMS 20

typedef enum {
    SYMBOL_FUNCTION,
    SYMBOL_STRUCT,
    SYMBOL_TYPEDEF,
    SYMBOL_ENUM,
    SYMBOL_MACRO,
    SYMBOL_VARIABLE
} SymbolType;

typedef struct {
    char name[128];
    char type[128];
    char description[512];
    int is_optional;
    char default_value[128];
} Parameter;

typedef struct {
    char name[256];
    SymbolType type;
    char signature[1024];
    char description[2048];
    char brief[512];
    char return_type[128];
    char return_desc[512];
    
    Parameter* params;
    int param_count;
    int param_capacity;
    
    char file[512];
    int line;
    char since[32];
    char deprecated[512];
    int is_public;
    int is_static;
} Symbol;

typedef struct {
    char path[512];
    char title[256];
    char description[1024];
    int symbol_count;
} ModuleDoc;

typedef struct {
    Symbol* symbols;
    int symbol_count;
    int symbol_capacity;
    
    ModuleDoc* modules;
    int module_count;
    int module_capacity;
    
    int files_processed;
    int lines_processed;
    int undocumented_count;
    double coverage_percent;
} DocReport;

//=============================================================================
// Documentation Parser
//=============================================================================

DocReport* doc_report_create(void) {
    DocReport* report = (DocReport*)calloc(1, sizeof(DocReport));
    report->symbol_capacity = MAX_SYMBOLS;
    report->symbols = (Symbol*)calloc(report->symbol_capacity, sizeof(Symbol));
    report->module_capacity = MAX_FILES;
    report->modules = (ModuleDoc*)calloc(report->module_capacity, sizeof(ModuleDoc));
    return report;
}

void doc_report_destroy(DocReport* report) {
    if (!report) return;
    for (int i = 0; i < report->symbol_count; i++) {
        free(report->symbols[i].params);
    }
    free(report->symbols);
    free(report->modules);
    free(report);
}

Symbol* add_symbol(DocReport* report, const char* name, SymbolType type) {
    if (report->symbol_count >= report->symbol_capacity) return NULL;
    
    Symbol* sym = &report->symbols[report->symbol_count++];
    strncpy(sym->name, name, sizeof(sym->name) - 1);
    sym->type = type;
    sym->param_capacity = MAX_PARAMS;
    sym->params = (Parameter*)calloc(sym->param_capacity, sizeof(Parameter));
    sym->is_public = 1;
    return sym;
}

void parse_comment_block(const char* comment, Symbol* sym) {
    // Parse @brief
    const char* brief = strstr(comment, "@brief");
    if (brief) {
        brief += 6;
        while (*brief == ' ' || *brief == '\t') brief++;
        sscanf(brief, "%511[^\n]", sym->brief);
    }
    
    // Parse @param
    const char* param = strstr(comment, "@param");
    while (param) {
        param += 6;
        while (*param == ' ' || *param == '\t') param++;
        
        if (sym->param_count < sym->param_capacity) {
            Parameter* p = &sym->params[sym->param_count++];
            sscanf(param, "%127s %511[^\n]", p->name, p->description);
        }
        
        param = strstr(param, "@param");
    }
    
    // Parse @return
    const char* ret = strstr(comment, "@return");
    if (ret) {
        ret += 7;
        while (*ret == ' ' || *ret == '\t') ret++;
        sscanf(ret, "%511[^\n]", sym->return_desc);
    }
    
    // Parse @since
    const char* since = strstr(comment, "@since");
    if (since) {
        since += 6;
        while (*since == ' ' || *since == '\t') since++;
        sscanf(since, "%31s", sym->since);
    }
    
    // Parse @deprecated
    const char* depr = strstr(comment, "@deprecated");
    if (depr) {
        depr += 11;
        while (*depr == ' ' || *depr == '\t') depr++;
        sscanf(depr, "%511[^\n]", sym->deprecated);
    }
}

void extract_function_signature(const char* line, Symbol* sym) {
    strncpy(sym->signature, line, sizeof(sym->signature) - 1);
    
    // Extract return type
    char* paren = strchr(line, '(');
    if (paren) {
        char before[512];
        int len = (int)(paren - line);
        if (len > 0 && len < sizeof(before)) {
            strncpy(before, line, len);
            before[len] = '\0';
            
            // Last word is function name
            char* last_space = strrchr(before, ' ');
            if (last_space) {
                *last_space = '\0';
                strncpy(sym->return_type, before, sizeof(sym->return_type) - 1);
            }
        }
    }
}

void process_file(DocReport* report, const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return;
    
    report->files_processed++;
    
    ModuleDoc* mod = &report->modules[report->module_count++];
    strncpy(mod->path, filename, sizeof(mod->path) - 1);
    
    char line[4096];
    int line_num = 0;
    char comment_block[4096] = {0};
    int in_comment = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        report->lines_processed++;
        
        // Detect comment start
        if (strstr(line, "/**") || strstr(line, "/*!")) {
            in_comment = 1;
            comment_block[0] = '\0';
        }
        
        // Accumulate comment
        if (in_comment) {
            strncat(comment_block, line, sizeof(comment_block) - strlen(comment_block) - 1);
        }
        
        // Detect comment end
        if (strstr(line, "*/") && in_comment) {
            in_comment = 0;
        }
        
        // Detect function definition
        if (!in_comment && strstr(line, "(") && strstr(line, ")") &&
            !strstr(line, "if") && !strstr(line, "while") &&
            !strstr(line, "for") && !strstr(line, "switch")) {
            
            // Extract function name
            char func_name[256] = {0};
            char* paren = strchr(line, '(');
            if (paren) {
                char* start = paren - 1;
                while (start > line && (isalnum(*start) || *start == '_')) start--;
                if (start < paren - 1) {
                    strncpy(func_name, start + 1, (size_t)(paren - start - 1));
                }
            }
            
            if (strlen(func_name) > 0) {
                Symbol* sym = add_symbol(report, func_name, SYMBOL_FUNCTION);
                strncpy(sym->file, filename, sizeof(sym->file) - 1);
                sym->line = line_num;
                extract_function_signature(line, sym);
                
                if (strlen(comment_block) > 0) {
                    parse_comment_block(comment_block, sym);
                    strncpy(sym->description, comment_block, sizeof(sym->description) - 1);
                } else {
                    report->undocumented_count++;
                }
                
                mod->symbol_count++;
            }
            
            comment_block[0] = '\0';
        }
    }
    
    fclose(f);
}

void calculate_coverage(DocReport* report) {
    if (report->symbol_count > 0) {
        int documented = report->symbol_count - report->undocumented_count;
        report->coverage_percent = (double)documented / report->symbol_count * 100.0;
    }
}

//=============================================================================
// Report Generation
//=============================================================================

const char* symbol_type_to_string(SymbolType type) {
    switch (type) {
        case SYMBOL_FUNCTION: return "Function";
        case SYMBOL_STRUCT: return "Struct";
        case SYMBOL_TYPEDEF: return "Typedef";
        case SYMBOL_ENUM: return "Enum";
        case SYMBOL_MACRO: return "Macro";
        case SYMBOL_VARIABLE: return "Variable";
        default: return "Unknown";
    }
}

void print_doc_summary(DocReport* report) {
    calculate_coverage(report);
    
    printf("\n");
    printf("=============================================================================\n");
    printf("  Documentation Summary\n");
    printf("=============================================================================\n");
    printf("  Files Processed:      %d\n", report->files_processed);
    printf("  Lines Processed:      %d\n", report->lines_processed);
    printf("  Symbols Found:        %d\n", report->symbol_count);
    printf("  Undocumented:         %d\n", report->undocumented_count);
    printf("  Coverage:             %.1f%%\n", report->coverage_percent);
    printf("=============================================================================\n");
}

void generate_markdown_docs(DocReport* report, const char* output_dir) {
    char filename[1024];
    snprintf(filename, sizeof(filename), "%s/api_reference.md", output_dir);
    
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "# RawrXD API Reference\n\n");
    fprintf(f, "Generated Documentation\n\n");
    fprintf(f, "## Overview\n\n");
    fprintf(f, "- **Total Symbols**: %d\n", report->symbol_count);
    fprintf(f, "- **Documentation Coverage**: %.1f%%\n", report->coverage_percent);
    fprintf(f, "- **Files Processed**: %d\n\n", report->files_processed);
    
    // Functions
    fprintf(f, "## Functions\n\n");
    for (int i = 0; i < report->symbol_count; i++) {
        Symbol* sym = &report->symbols[i];
        if (sym->type == SYMBOL_FUNCTION) {
            fprintf(f, "### %s\n\n", sym->name);
            
            if (strlen(sym->brief) > 0) {
                fprintf(f, "%s\n\n", sym->brief);
            }
            
            fprintf(f, "```c\n%s\n```\n\n", sym->signature);
            
            if (sym->param_count > 0) {
                fprintf(f, "**Parameters:**\n\n");
                for (int j = 0; j < sym->param_count; j++) {
                    Parameter* p = &sym->params[j];
                    fprintf(f, "- `%s`: %s\n", p->name, p->description);
                }
                fprintf(f, "\n");
            }
            
            if (strlen(sym->return_desc) > 0) {
                fprintf(f, "**Returns:** %s\n\n", sym->return_desc);
            }
            
            fprintf(f, "**Source:** %s:%d\n\n", sym->file, sym->line);
            
            if (strlen(sym->since) > 0) {
                fprintf(f, "**Since:** %s\n\n", sym->since);
            }
            
            if (strlen(sym->deprecated) > 0) {
                fprintf(f, "⚠️ **Deprecated:** %s\n\n", sym->deprecated);
            }
            
            fprintf(f, "---\n\n");
        }
    }
    
    fclose(f);
    printf("  Markdown documentation generated: %s\n", filename);
}

void export_doc_json(DocReport* report, const char* filename) {
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"summary\": {\n");
    fprintf(f, "    \"files_processed\": %d,\n", report->files_processed);
    fprintf(f, "    \"lines_processed\": %d,\n", report->lines_processed);
    fprintf(f, "    \"symbol_count\": %d,\n", report->symbol_count);
    fprintf(f, "    \"undocumented\": %d,\n", report->undocumented_count);
    fprintf(f, "    \"coverage_percent\": %.1f\n", report->coverage_percent);
    fprintf(f, "  },\n");
    fprintf(f, "  \"symbols\": [\n");
    
    for (int i = 0; i < report->symbol_count; i++) {
        Symbol* sym = &report->symbols[i];
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", sym->name);
        fprintf(f, "      \"type\": \"%s\",\n", symbol_type_to_string(sym->type));
        fprintf(f, "      \"signature\": \"%s\",\n", sym->signature);
        fprintf(f, "      \"brief\": \"%s\",\n", sym->brief);
        fprintf(f, "      \"file\": \"%s\",\n", sym->file);
        fprintf(f, "      \"line\": %d\n", sym->line);
        fprintf(f, "    }%s\n", (i < report->symbol_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  Documentation JSON exported: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Documentation Generator\n");
    printf("================================\n\n");
    
    DocReport* report = doc_report_create();
    
    // Process files
    if (argc > 1) {
        for (int i = 1; i < argc; i++) {
            printf("Processing: %s\n", argv[i]);
            process_file(report, argv[i]);
        }
    } else {
        printf("Processing: %s\n", __FILE__);
        process_file(report, __FILE__);
    }
    
    // Generate reports
    print_doc_summary(report);
    generate_markdown_docs(report, ".");
    export_doc_json(report, "documentation.json");
    
    printf("\nDocumentation generation complete!\n");
    
    doc_report_destroy(report);
    return 0;
}
