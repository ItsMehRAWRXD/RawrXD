//=============================================================================
// code_formatter.c - Code Formatter
// Production-ready C code formatting and style enforcement
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Formatting Configuration
//=============================================================================

#define MAX_INDENT_LEVEL 32
#define INDENT_SIZE 4

typedef struct {
    int indent_size;
    int use_tabs;
    int max_line_length;
    int brace_style;  // 0 = same line, 1 = new line
    int space_after_keywords;
    int space_around_operators;
    int blank_lines_between_functions;
} FormatConfig;

typedef struct {
    char* input;
    char* output;
    size_t input_pos;
    size_t output_pos;
    size_t output_capacity;
    int indent_level;
    int line_number;
} Formatter;

//=============================================================================
// Formatter Lifecycle
//=============================================================================

Formatter* formatter_create(const char* input) {
    Formatter* fmt = (Formatter*)calloc(1, sizeof(Formatter));
    fmt->input = strdup(input);
    fmt->output_capacity = strlen(input) * 2 + 1024;
    fmt->output = (char*)calloc(fmt->output_capacity, 1);
    fmt->indent_level = 0;
    fmt->line_number = 1;
    return fmt;
}

void formatter_destroy(Formatter* fmt) {
    if (!fmt) return;
    free(fmt->input);
    free(fmt->output);
    free(fmt);
}

void formatter_ensure_capacity(Formatter* fmt, size_t needed) {
    if (fmt->output_pos + needed >= fmt->output_capacity) {
        fmt->output_capacity *= 2;
        fmt->output = (char*)realloc(fmt->output, fmt->output_capacity);
    }
}

void formatter_write(Formatter* fmt, const char* text) {
    size_t len = strlen(text);
    formatter_ensure_capacity(fmt, len);
    memcpy(fmt->output + fmt->output_pos, text, len);
    fmt->output_pos += len;
}

void formatter_write_char(Formatter* fmt, char c) {
    formatter_ensure_capacity(fmt, 1);
    fmt->output[fmt->output_pos++] = c;
}

void formatter_write_indent(Formatter* fmt, FormatConfig* config) {
    int spaces = fmt->indent_level * (config->use_tabs ? 1 : config->indent_size);
    for (int i = 0; i < spaces; i++) {
        formatter_write_char(fmt, config->use_tabs ? '\t' : ' ');
    }
}

void formatter_write_newline(Formatter* fmt) {
    formatter_write(fmt, "\n");
    fmt->line_number++;
}

//=============================================================================
// Token Handling
//=============================================================================

int is_keyword(const char* word) {
    const char* keywords[] = {
        "if", "else", "while", "for", "do", "switch", "case", "default",
        "break", "continue", "return", "goto", "typedef", "struct", "union",
        "enum", "const", "volatile", "static", "extern", "inline", "void",
        "char", "short", "int", "long", "float", "double", "signed", "unsigned",
        NULL
    };
    
    for (int i = 0; keywords[i]; i++) {
        if (strcmp(word, keywords[i]) == 0) return 1;
    }
    return 0;
}

int should_space_after(const char* word) {
    const char* keywords[] = {
        "if", "while", "for", "switch", "return", "sizeof", "typedef"
    };
    
    for (size_t i = 0; i < sizeof(keywords)/sizeof(keywords[0]); i++) {
        if (strcmp(word, keywords[i]) == 0) return 1;
    }
    return 0;
}

//=============================================================================
// Formatting Logic
//=============================================================================

char* format_code(const char* input, FormatConfig* config) {
    Formatter* fmt = formatter_create(input);
    
    const char* p = input;
    int in_string = 0;
    int in_char = 0;
    int in_comment = 0;
    int in_preprocessor = 0;
    char prev_char = 0;
    
    while (*p) {
        char c = *p;
        
        // Handle strings
        if (c == '"' && !in_char && !in_comment) {
            if (!in_string || (in_string && prev_char != '\\')) {
                in_string = !in_string;
            }
        }
        
        // Handle character literals
        if (c == '\'' && !in_string && !in_comment) {
            if (!in_char || (in_char && prev_char != '\\')) {
                in_char = !in_char;
            }
        }
        
        // Handle comments
        if (!in_string && !in_char) {
            if (c == '/' && p[1] == '/' && !in_comment) {
                in_comment = 1;
            }
            if (c == '\n' && in_comment) {
                in_comment = 0;
            }
        }
        
        // Handle preprocessor
        if (c == '#' && (p == input || *(p-1) == '\n')) {
            in_preprocessor = 1;
        }
        if (c == '\n' && in_preprocessor) {
            in_preprocessor = 0;
        }
        
        // Format logic
        if (!in_string && !in_char && !in_comment) {
            // Handle braces
            if (c == '{') {
                if (config->brace_style == 0) {
                    // Same line style
                    formatter_write_char(fmt, ' ');
                } else {
                    // New line style
                    formatter_write_newline(fmt);
                    formatter_write_indent(fmt, config);
                }
                formatter_write_char(fmt, c);
                formatter_write_newline(fmt);
                fmt->indent_level++;
                formatter_write_indent(fmt, config);
                p++;
                prev_char = c;
                continue;
            }
            
            if (c == '}') {
                fmt->indent_level--;
                if (fmt->indent_level < 0) fmt->indent_level = 0;
                formatter_write_newline(fmt);
                formatter_write_indent(fmt, config);
                formatter_write_char(fmt, c);
                p++;
                prev_char = c;
                continue;
            }
            
            // Handle semicolons
            if (c == ';') {
                formatter_write_char(fmt, c);
                if (!in_preprocessor) {
                    formatter_write_newline(fmt);
                    formatter_write_indent(fmt, config);
                }
                p++;
                prev_char = c;
                continue;
            }
            
            // Handle operators
            if (config->space_around_operators) {
                const char* operators = "=+-*/%<>!&|";
                if (strchr(operators, c) && !strchr(operators, prev_char)) {
                    formatter_write_char(fmt, ' ');
                }
            }
        }
        
        // Write character
        formatter_write_char(fmt, c);
        
        // Add space after operators
        if (!in_string && !in_char && !in_comment && config->space_around_operators) {
            const char* operators = "=+-*/%<>!&|";
            if (strchr(operators, c) && !strchr(operators, p[1])) {
                formatter_write_char(fmt, ' ');
            }
        }
        
        prev_char = c;
        p++;
    }
    
    // Null terminate
    formatter_write_char(fmt, '\0');
    
    char* result = strdup(fmt->output);
    formatter_destroy(fmt);
    
    return result;
}

//=============================================================================
// File Operations
//=============================================================================

char* read_file(const char* filename) {
    FILE* f = fopen(filename, "r");
    if (!f) return NULL;
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char* buffer = (char*)malloc(size + 1);
    if (!buffer) {
        fclose(f);
        return NULL;
    }
    
    fread(buffer, 1, size, f);
    buffer[size] = '\0';
    
    fclose(f);
    return buffer;
}

int write_file(const char* filename, const char* content) {
    FILE* f = fopen(filename, "w");
    if (!f) return -1;
    
    fwrite(content, 1, strlen(content), f);
    fclose(f);
    
    return 0;
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char* argv[]) {
    printf("RawrXD Code Formatter\n");
    printf("=====================\n\n");
    
    FormatConfig config = {
        .indent_size = 4,
        .use_tabs = 0,
        .max_line_length = 120,
        .brace_style = 0,
        .space_after_keywords = 1,
        .space_around_operators = 1,
        .blank_lines_between_functions = 1
    };
    
    // Parse arguments
    int check_only = 0;
    int in_place = 0;
    const char* input_file = NULL;
    const char* output_file = NULL;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--check") == 0) {
            check_only = 1;
        } else if (strcmp(argv[i], "--in-place") == 0 || strcmp(argv[i], "-i") == 0) {
            in_place = 1;
        } else if (strcmp(argv[i], "--tabs") == 0) {
            config.use_tabs = 1;
        } else if (strcmp(argv[i], "--braces-newline") == 0) {
            config.brace_style = 1;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (!input_file) {
            input_file = argv[i];
        }
    }
    
    if (!input_file) {
        printf("Usage: code_formatter <file> [options]\n");
        printf("\nOptions:\n");
        printf("  --check              Check formatting without modifying\n");
        printf("  --in-place, -i       Format file in place\n");
        printf("  --tabs               Use tabs for indentation\n");
        printf("  --braces-newline     Put braces on new lines\n");
        printf("  -o <file>           Output to file\n");
        return 1;
    }
    
    // Read input
    printf("Reading: %s\n", input_file);
    char* input = read_file(input_file);
    if (!input) {
        printf("Error: Could not read file\n");
        return 1;
    }
    
    // Format code
    printf("Formatting...\n");
    char* formatted = format_code(input, &config);
    
    // Check if changed
    int changed = (strcmp(input, formatted) != 0);
    
    if (check_only) {
        if (changed) {
            printf("⚠️  File needs formatting\n");
            free(input);
            free(formatted);
            return 1;
        } else {
            printf("✅ File is properly formatted\n");
            free(input);
            free(formatted);
            return 0;
        }
    }
    
    // Write output
    if (in_place) {
        output_file = input_file;
    }
    
    if (output_file) {
        if (write_file(output_file, formatted) == 0) {
            printf("✅ Formatted code written to: %s\n", output_file);
        } else {
            printf("❌ Error writing output file\n");
        }
    } else {
        // Print to stdout
        printf("\nFormatted code:\n");
        printf("---------------\n");
        printf("%s\n", formatted);
    }
    
    free(input);
    free(formatted);
    
    return 0;
}
