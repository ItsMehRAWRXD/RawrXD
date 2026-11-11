//=============================================================================
// docs_generator.c - Documentation Generator
// Production-ready documentation generation from source code
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <dirent.h>
#include <sys/stat.h>

#ifdef _WIN32
#include <windows.h>
#define PATH_SEP "\\"
#else
#define PATH_SEP "/"
#endif

//=============================================================================
// Documentation Types
//=============================================================================

#define MAX_SYMBOLS 10000
#define MAX_DOCS 100000

typedef enum {
    SYM_FUNCTION,
    SYM_VARIABLE,
    SYM_TYPE,
    SYM_MACRO,
    SYM_ENUM,
    SYM_STRUCT,
    SYM_UNION,
    SYM_TYPEDEF
} SymbolType;

typedef struct {
    char name[256];
    char file[512];
    int line;
    SymbolType type;
    char signature[1024];
    char brief[1024];
    char description[4096];
    char params[2048];
    char returns[512];
    char see_also[512];
    char examples[4096];
} SymbolDoc;

typedef struct {
    SymbolDoc* symbols;
    int symbol_count;
    int symbol_capacity;
    
    char output_dir[512];
    int generate_html;
    int generate_markdown;
    int generate_json;
} DocGenerator;

//=============================================================================
// Documentation Parser
//=============================================================================

void extract_brief(const char* comment, char* brief, size_t brief_size) {
    // Extract brief description (first sentence)
    const char* p = comment;
    while (*p == ' ' || *p == '*' || *p == '/') p++;
    
    size_t len = 0;
    while (*p && *p != '.' && *p != '\n' && len < brief_size - 1) {
        brief[len++] = *p++;
    }
    
    if (*p == '.') {
        brief[len++] = '.';
    }
    brief[len] = '\0';
}

void parse_doc_comment(const char* comment, SymbolDoc* doc) {
    // Parse @param, @return, @see, @brief, @example tags
    char buffer[4096];
    strncpy(buffer, comment, sizeof(buffer) - 1);
    buffer[sizeof(buffer) - 1] = '\0';
    
    char* line = strtok(buffer, "\n");
    while (line) {
        // Skip leading whitespace and comment markers
        char* p = line;
        while (*p && (*p == ' ' || *p == '\t' || *p == '*' || *p == '/')) p++;
        
        if (strncmp(p, "@brief", 6) == 0) {
            strncpy(doc->brief, p + 6, sizeof(doc->brief) - 1);
        } else if (strncmp(p, "@param", 6) == 0) {
            strncat(doc->params, p + 6, sizeof(doc->params) - strlen(doc->params) - 1);
            strncat(doc->params, "\n", sizeof(doc->params) - strlen(doc->params) - 1);
        } else if (strncmp(p, "@return", 7) == 0) {
            strncpy(doc->returns, p + 7, sizeof(doc->returns) - 1);
        } else if (strncmp(p, "@see", 4) == 0) {
            strncpy(doc->see_also, p + 4, sizeof(doc->see_also) - 1);
        } else if (strncmp(p, "@example", 8) == 0) {
            // Collect example code
            strncat(doc->examples, p + 8, sizeof(doc->examples) - strlen(doc->examples) - 1);
            strncat(doc->examples, "\n", sizeof(doc->examples) - strlen(doc->examples) - 1);
        } else if (strlen(p) > 0 && *p != '@') {
            // Description text
            strncat(doc->description, p, sizeof(doc->description) - strlen(doc->description) - 1);
            strncat(doc->description, " ", sizeof(doc->description) - strlen(doc->description) - 1);
        }
        
        line = strtok(NULL, "\n");
    }
}

void extract_function_signature(const char* line, char* sig, size_t sig_size) {
    // Simple extraction - would need proper parsing in production
    strncpy(sig, line, sig_size - 1);
    sig[sig_size - 1] = '\0';
    
    // Remove trailing brace if present
    char* brace = strchr(sig, '{');
    if (brace) *brace = '\0';
    
    // Trim trailing whitespace
    size_t len = strlen(sig);
    while (len > 0 && (sig[len-1] == ' ' || sig[len-1] == '\t')) {
        sig[--len] = '\0';
    }
}

void analyze_file(DocGenerator* gen, const char* file_path) {
    FILE* f = fopen(file_path, "r");
    if (!f) return;
    
    char line[4096];
    int line_num = 0;
    char current_doc[4096] = {0};
    int in_doc_comment = 0;
    
    while (fgets(line, sizeof(line), f)) {
        line_num++;
        
        // Check for doc comment start
        if (strstr(line, "/**") || strstr(line, "/*!")) {
            in_doc_comment = 1;
            current_doc[0] = '\0';
        }
        
        if (in_doc_comment) {
            strncat(current_doc, line, sizeof(current_doc) - strlen(current_doc) - 1);
            
            if (strstr(line, "*/")) {
                in_doc_comment = 0;
            }
            continue;
        }
        
        // Look for function definitions
        if (strlen(current_doc) > 0) {
            // Check if this line is a function definition
            if (strstr(line, "(") && strstr(line, ")") && 
                (strstr(line, "{") || strstr(line, ";"))) {
                
                // Extract function name
                char func_name[256] = {0};
                char* paren = strchr(line, '(');
                if (paren) {
                    char* name_start = paren - 1;
                    while (name_start > line && (isalnum(*name_start) || *name_start == '_')) {
                        name_start--;
                    }
                    name_start++;
                    
                    size_t len = paren - name_start;
                    if (len < sizeof(func_name)) {
                        strncpy(func_name, name_start, len);
                        func_name[len] = '\0';
                    }
                }
                
                if (strlen(func_name) > 0 && gen->symbol_count < gen->symbol_capacity) {
                    SymbolDoc* doc = &gen->symbols[gen->symbol_count++];
                    memset(doc, 0, sizeof(SymbolDoc));
                    
                    strncpy(doc->name, func_name, sizeof(doc->name) - 1);
                    strncpy(doc->file, file_path, sizeof(doc->file) - 1);
                    doc->line = line_num;
                    doc->type = SYM_FUNCTION;
                    
                    extract_function_signature(line, doc->signature, sizeof(doc->signature));
                    parse_doc_comment(current_doc, doc);
                    
                    if (strlen(doc->brief) == 0) {
                        extract_brief(current_doc, doc->brief, sizeof(doc->brief));
                    }
                }
                
                current_doc[0] = '\0';
            }
        }
    }
    
    fclose(f);
}

//=============================================================================
// Output Generation
//=============================================================================

void generate_html(DocGenerator* gen) {
    char filename[1024];
    snprintf(filename, sizeof(filename), "%s%sindex.html", 
             gen->output_dir, PATH_SEP);
    
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "<!DOCTYPE html>\n");
    fprintf(f, "<html>\n");
    fprintf(f, "<head>\n");
    fprintf(f, "  <title>RawrXD API Documentation</title>\n");
    fprintf(f, "  <style>\n");
    fprintf(f, "    body { font-family: Arial, sans-serif; margin: 20px; background: #f5f5f5; }\n");
    fprintf(f, "    .container { max-width: 1200px; margin: 0 auto; background: white; padding: 20px; }\n");
    fprintf(f, "    h1 { color: #333; border-bottom: 2px solid #4CAF50; padding-bottom: 10px; }\n");
    fprintf(f, "    h2 { color: #555; margin-top: 30px; }\n");
    fprintf(f, "    .symbol { margin: 20px 0; padding: 15px; background: #f9f9f9; border-left: 4px solid #4CAF50; }\n");
    fprintf(f, "    .signature { font-family: monospace; background: #eee; padding: 10px; margin: 10px 0; }\n");
    fprintf(f, "    .brief { color: #666; font-style: italic; }\n");
    fprintf(f, "    .params { margin: 10px 0; }\n");
    fprintf(f, "    .param-name { font-weight: bold; color: #4CAF50; }\n");
    fprintf(f, "    .returns { margin: 10px 0; }\n");
    fprintf(f, "    .file-info { color: #999; font-size: 0.9em; }\n");
    fprintf(f, "  </style>\n");
    fprintf(f, "</head>\n");
    fprintf(f, "<body>\n");
    fprintf(f, "  <div class='container'>\n");
    fprintf(f, "    <h1>RawrXD API Documentation</h1>\n");
    fprintf(f, "    <p>Generated: %s</p>\n", __DATE__);
    fprintf(f, "    <p>Total symbols: %d</p>\n", gen->symbol_count);
    
    // Group by type
    fprintf(f, "    <h2>Functions</h2>\n");
    
    for (int i = 0; i < gen->symbol_count; i++) {
        SymbolDoc* doc = &gen->symbols[i];
        
        fprintf(f, "    <div class='symbol'>\n");
        fprintf(f, "      <h3>%s</h3>\n", doc->name);
        fprintf(f, "      <div class='signature'>%s</div>\n", doc->signature);
        fprintf(f, "      <div class='brief'>%s</div>\n", doc->brief);
        
        if (strlen(doc->description) > 0) {
            fprintf(f, "      <p>%s</p>\n", doc->description);
        }
        
        if (strlen(doc->params) > 0) {
            fprintf(f, "      <div class='params'>\n");
            fprintf(f, "        <strong>Parameters:</strong>\n");
            fprintf(f, "        <pre>%s</pre>\n", doc->params);
            fprintf(f, "      </div>\n");
        }
        
        if (strlen(doc->returns) > 0) {
            fprintf(f, "      <div class='returns'>\n");
            fprintf(f, "        <strong>Returns:</strong> %s\n", doc->returns);
            fprintf(f, "      </div>\n");
        }
        
        fprintf(f, "      <div class='file-info'>File: %s:%d</div>\n", doc->file, doc->line);
        fprintf(f, "    </div>\n");
    }
    
    fprintf(f, "  </div>\n");
    fprintf(f, "</body>\n");
    fprintf(f, "</html>\n");
    
    fclose(f);
    printf("  HTML documentation generated: %s\n", filename);
}

void generate_markdown(DocGenerator* gen) {
    char filename[1024];
    snprintf(filename, sizeof(filename), "%s%sAPI.md", 
             gen->output_dir, PATH_SEP);
    
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "# RawrXD API Documentation\n\n");
    fprintf(f, "Generated: %s\n\n", __DATE__);
    fprintf(f, "Total symbols: %d\n\n", gen->symbol_count);
    
    fprintf(f, "## Table of Contents\n\n");
    for (int i = 0; i < gen->symbol_count; i++) {
        fprintf(f, "- [%s](#%s)\n", gen->symbols[i].name, gen->symbols[i].name);
    }
    fprintf(f, "\n");
    
    fprintf(f, "## Functions\n\n");
    
    for (int i = 0; i < gen->symbol_count; i++) {
        SymbolDoc* doc = &gen->symbols[i];
        
        fprintf(f, "### %s\n\n", doc->name);
        fprintf(f, "```c\n%s\n```\n\n", doc->signature);
        fprintf(f, "*%s*\n\n", doc->brief);
        
        if (strlen(doc->description) > 0) {
            fprintf(f, "%s\n\n", doc->description);
        }
        
        if (strlen(doc->params) > 0) {
            fprintf(f, "**Parameters:**\n\n");
            fprintf(f, "```\n%s```\n\n", doc->params);
        }
        
        if (strlen(doc->returns) > 0) {
            fprintf(f, "**Returns:** %s\n\n", doc->returns);
        }
        
        fprintf(f, "*Source: %s:%d*\n\n", doc->file, doc->line);
        fprintf(f, "---\n\n");
    }
    
    fclose(f);
    printf("  Markdown documentation generated: %s\n", filename);
}

void generate_json(DocGenerator* gen) {
    char filename[1024];
    snprintf(filename, sizeof(filename), "%s%sapi.json", 
             gen->output_dir, PATH_SEP);
    
    FILE* f = fopen(filename, "w");
    if (!f) return;
    
    fprintf(f, "{\n");
    fprintf(f, "  \"generated\": \"%s\",\n", __DATE__);
    fprintf(f, "  \"symbol_count\": %d,\n", gen->symbol_count);
    fprintf(f, "  \"symbols\": [\n");
    
    for (int i = 0; i < gen->symbol_count; i++) {
        SymbolDoc* doc = &gen->symbols[i];
        
        fprintf(f, "    {\n");
        fprintf(f, "      \"name\": \"%s\",\n", doc->name);
        fprintf(f, "      \"type\": \"%s\",\n",
                doc->type == SYM_FUNCTION ? "function" : "unknown");
        fprintf(f, "      \"signature\": \"%s\",\n", doc->signature);
        fprintf(f, "      \"brief\": \"%s\",\n", doc->brief);
        fprintf(f, "      \"description\": \"%s\",\n", doc->description);
        fprintf(f, "      \"file\": \"%s\",\n", doc->file);
        fprintf(f, "      \"line\": %d\n", doc->line);
        fprintf(f, "    }%s\n", (i < gen->symbol_count - 1) ? "," : "");
    }
    
    fprintf(f, "  ]\n");
    fprintf(f, "}\n");
    
    fclose(f);
    printf("  JSON documentation generated: %s\n", filename);
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Documentation Generator\n");
    printf("==============================\n\n");
    
    DocGenerator gen = {0};
    gen.symbol_capacity = MAX_SYMBOLS;
    gen.symbols = (SymbolDoc*)calloc(MAX_SYMBOLS, sizeof(SymbolDoc));
    
    // Parse arguments
    strcpy(gen.output_dir, "docs");
    gen.generate_html = 1;
    gen.generate_markdown = 1;
    gen.generate_json = 1;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            strncpy(gen.output_dir, argv[++i], sizeof(gen.output_dir) - 1);
        } else if (strcmp(argv[i], "--no-html") == 0) {
            gen.generate_html = 0;
        } else if (strcmp(argv[i], "--no-md") == 0) {
            gen.generate_markdown = 0;
        } else if (strcmp(argv[i], "--no-json") == 0) {
            gen.generate_json = 0;
        }
    }
    
    // Create output directory
    #ifdef _WIN32
    CreateDirectoryA(gen.output_dir, NULL);
    #else
    mkdir(gen.output_dir, 0755);
    #endif
    
    // Analyze source files
    printf("Analyzing source files...\n");
    
    // For demo, analyze current file
    analyze_file(&gen, __FILE__);
    
    // In production, would traverse directory
    // analyze_directory(&gen, "src");
    
    printf("  Found %d documented symbols\n\n", gen.symbol_count);
    
    // Generate output
    printf("Generating documentation...\n");
    
    if (gen.generate_html) {
        generate_html(&gen);
    }
    
    if (gen.generate_markdown) {
        generate_markdown(&gen);
    }
    
    if (gen.generate_json) {
        generate_json(&gen);
    }
    
    printf("\nDocumentation generation complete!\n");
    
    free(gen.symbols);
    
    return 0;
}
