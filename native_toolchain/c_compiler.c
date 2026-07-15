//=============================================================================
// c_compiler.c - C Language Compiler Driver
// Part of RawrXD Native Toolchain - Batch 1: C Frontend Foundation
// Ties together: lexer → parser → semantic analyzer → IR → x64 ASM → object → executable
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Include all C frontend components
#include "c_lexer.c"
#include "c_parser.c"
#include "c_semantic.c"
#include "c_to_ir.c"

//=============================================================================
// Compiler Configuration
//=============================================================================

typedef struct {
    const char* input_file;
    const char* output_file;
    const char* asm_file;
    const char* obj_file;
    int keep_asm;
    int keep_obj;
    int verbose;
    int optimize;
    int debug_info;
} CompilerConfig;

//=============================================================================
// File I/O Utilities
//=============================================================================

char* read_file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "Error: Cannot open file '%s'\n", filename);
        return NULL;
    }
    
    fseek(file, 0, SEEK_END);
    long size = ftell(file);
    fseek(file, 0, SEEK_SET);
    
    char* buffer = (char*)malloc(size + 1);
    if (!buffer) {
        fclose(file);
        return NULL;
    }
    
    size_t read = fread(buffer, 1, size, file);
    buffer[read] = '\0';
    
    fclose(file);
    return buffer;
}

int write_file(const char* filename, const char* content) {
    FILE* file = fopen(filename, "w");
    if (!file) {
        fprintf(stderr, "Error: Cannot create file '%s'\n", filename);
        return -1;
    }
    
    fputs(content, file);
    fclose(file);
    return 0;
}

//=============================================================================
// Compilation Pipeline
//=============================================================================

typedef struct {
    int stage;          // Current stage
    int errors;         // Error count
    int warnings;       // Warning count
    Lexer* lexer;
    Parser* parser;
    SemanticAnalyzer* semantic;
    ASTNode* ast;
    IRNode* ir;
    char* asm_code;
} CompilationContext;

const char* stage_name(int stage) {
    switch (stage) {
        case 0: return "Initialization";
        case 1: return "Lexical Analysis";
        case 2: return "Syntax Analysis";
        case 3: return "Semantic Analysis";
        case 4: return "IR Generation";
        case 5: return "Code Generation";
        case 6: return "Assembly";
        case 7: return "Linking";
        default: return "Unknown";
    }
}

//=============================================================================
// Stage 1: Lexical Analysis
//=============================================================================

int stage_lexical(CompilationContext* ctx, const char* source, CompilerConfig* config) {
    if (config->verbose) {
        printf("[Stage 1/7] Lexical Analysis...\n");
    }
    
    ctx->lexer = lexer_create(source);
    if (!ctx->lexer) {
        fprintf(stderr, "Error: Failed to create lexer\n");
        return -1;
    }
    
    int token_count = lexer_tokenize(ctx->lexer);
    if (token_count < 0) {
        fprintf(stderr, "Error: Tokenization failed\n");
        return -1;
    }
    
    if (config->verbose) {
        printf("  Tokenized %d tokens\n", token_count);
    }
    
    ctx->stage = 1;
    return 0;
}

//=============================================================================
// Stage 2: Syntax Analysis (Parsing)
//=============================================================================

int stage_syntax(CompilationContext* ctx, CompilerConfig* config) {
    if (config->verbose) {
        printf("[Stage 2/7] Syntax Analysis...\n");
    }
    
    ctx->parser = parser_create(ctx->lexer->tokens, ctx->lexer->token_count);
    if (!ctx->parser) {
        fprintf(stderr, "Error: Failed to create parser\n");
        return -1;
    }
    
    ctx->ast = parse_translation_unit(ctx->parser);
    
    if (ctx->parser->had_error) {
        fprintf(stderr, "Error: Parsing failed with %d errors\n", ctx->parser->error_count);
        ctx->errors += ctx->parser->error_count;
        return -1;
    }
    
    if (config->verbose) {
        printf("  Parsed successfully\n");
    }
    
    ctx->stage = 2;
    return 0;
}

//=============================================================================
// Stage 3: Semantic Analysis
//=============================================================================

int stage_semantic(CompilationContext* ctx, CompilerConfig* config) {
    if (config->verbose) {
        printf("[Stage 3/7] Semantic Analysis...\n");
    }
    
    ctx->semantic = semantic_create();
    if (!ctx->semantic) {
        fprintf(stderr, "Error: Failed to create semantic analyzer\n");
        return -1;
    }
    
    int result = semantic_analyze(ctx->semantic, ctx->ast);
    
    ctx->errors += ctx->semantic->error_count;
    ctx->warnings += ctx->semantic->warning_count;
    
    if (ctx->semantic->had_error) {
        fprintf(stderr, "Error: Semantic analysis failed\n");
        return -1;
    }
    
    if (config->verbose) {
        printf("  Semantic analysis complete\n");
        if (ctx->semantic->warning_count > 0) {
            printf("  Warnings: %d\n", ctx->semantic->warning_count);
        }
    }
    
    ctx->stage = 3;
    return 0;
}

//=============================================================================
// Stage 4: IR Generation
//=============================================================================

int stage_ir(CompilationContext* ctx, CompilerConfig* config) {
    if (config->verbose) {
        printf("[Stage 4/7] IR Generation...\n");
    }
    
    ctx->ir = c_to_ir_convert(ctx->ast);
    
    if (!ctx->ir) {
        fprintf(stderr, "Error: IR generation failed\n");
        return -1;
    }
    
    if (config->verbose) {
        printf("  IR generated successfully\n");
    }
    
    ctx->stage = 4;
    return 0;
}

//=============================================================================
// Stage 5: Code Generation (IR to x64 ASM)
//=============================================================================

int stage_codegen(CompilationContext* ctx, CompilerConfig* config) {
    if (config->verbose) {
        printf("[Stage 5/7] Code Generation...\n");
    }
    
    // Generate assembly code from IR
    // For now, use a simplified approach
    // In production, this would use the language_backend_generator
    
    // Allocate buffer for assembly
    size_t buffer_size = 65536;
    ctx->asm_code = (char*)malloc(buffer_size);
    if (!ctx->asm_code) {
        fprintf(stderr, "Error: Failed to allocate assembly buffer\n");
        return -1;
    }
    
    // Generate assembly header
    snprintf(ctx->asm_code, buffer_size,
        ";=============================================================================\n"
        "; Generated by RawrXD C Compiler\n"
        "; Source: %s\n"
        ";=============================================================================\n\n"
        ".data\n\n"
        ".code\n\n",
        config->input_file);
    
    // Generate code for each function in IR
    IRNode* func = ctx->ir;
    while (func) {
        if (func->type == IR_NODE_FUNCTION) {
            // Function prologue
            strcat(ctx->asm_code, func->name);
            strcat(ctx->asm_code, " PROC\n");
            strcat(ctx->asm_code, "    push    rbp\n");
            strcat(ctx->asm_code, "    mov     rbp, rsp\n");
            strcat(ctx->asm_code, "    sub     rsp, 32\n");
            
            // Function body (simplified)
            if (func->body) {
                strcat(ctx->asm_code, "    ; Function body\n");
            }
            
            // Function epilogue
            strcat(ctx->asm_code, "return_");
            strcat(ctx->asm_code, func->name);
            strcat(ctx->asm_code, ":\n");
            strcat(ctx->asm_code, "    mov     rsp, rbp\n");
            strcat(ctx->asm_code, "    pop     rbp\n");
            strcat(ctx->asm_code, "    ret\n");
            strcat(ctx->asm_code, func->name);
            strcat(ctx->asm_code, " ENDP\n\n");
        }
        func = func->next;
    }
    
    // Add main entry point wrapper
    strcat(ctx->asm_code, 
        ";=============================================================================\n"
        "; Entry Point\n"
        ";=============================================================================\n"
        "main PROC\n"
        "    sub     rsp, 40\n"
        "    call    _start\n"
        "    mov     rcx, rax\n"
        "    call    ExitProcess\n"
        "main ENDP\n\n"
        "extrn ExitProcess : proc\n"
        "end\n");
    
    if (config->verbose) {
        printf("  Assembly generated (%zu bytes)\n", strlen(ctx->asm_code));
    }
    
    ctx->stage = 5;
    return 0;
}

//=============================================================================
// Stage 6: Assembly
//=============================================================================

int stage_assembly(CompilationContext* ctx, CompilerConfig* config) {
    if (config->verbose) {
        printf("[Stage 6/7] Assembly...\n");
    }
    
    // Write assembly file
    if (write_file(config->asm_file, ctx->asm_code) < 0) {
        return -1;
    }
    
    // Call native assembler
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), ".\\minimal_assembler_v6.exe \"%s\" \"%s\" 2>nul",
             config->asm_file, config->obj_file);
    
    if (config->verbose) {
        printf("  Running: %s\n", cmd);
    }
    
    int result = system(cmd);
    if (result != 0) {
        fprintf(stderr, "Error: Assembly failed\n");
        return -1;
    }
    
    if (config->verbose) {
        printf("  Assembly complete: %s\n", config->obj_file);
    }
    
    ctx->stage = 6;
    return 0;
}

//=============================================================================
// Stage 7: Linking
//=============================================================================

int stage_linking(CompilationContext* ctx, CompilerConfig* config) {
    if (config->verbose) {
        printf("[Stage 7/7] Linking...\n");
    }
    
    // Call native linker
    char cmd[1024];
    snprintf(cmd, sizeof(cmd), ".\\linker_v6.exe \"%s\" /out:\"%s\" /subsystem:3 /entry:main 2>nul",
             config->obj_file, config->output_file);
    
    if (config->verbose) {
        printf("  Running: %s\n", cmd);
    }
    
    int result = system(cmd);
    if (result != 0) {
        fprintf(stderr, "Error: Linking failed\n");
        return -1;
    }
    
    if (config->verbose) {
        printf("  Linking complete: %s\n", config->output_file);
    }
    
    ctx->stage = 7;
    return 0;
}

//=============================================================================
// Cleanup
//=============================================================================

void cleanup(CompilationContext* ctx, CompilerConfig* config) {
    if (ctx->lexer) lexer_destroy(ctx->lexer);
    if (ctx->parser) parser_destroy(ctx->parser);
    if (ctx->semantic) semantic_destroy(ctx->semantic);
    if (ctx->ast) ast_destroy_node(ctx->ast);
    if (ctx->ir) ir_destroy_node(ctx->ir);
    if (ctx->asm_code) free(ctx->asm_code);
    
    // Remove temporary files if not keeping them
    if (!config->keep_asm && ctx->asm_code) {
        remove(config->asm_file);
    }
    if (!config->keep_obj) {
        remove(config->obj_file);
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

void print_usage(const char* program) {
    printf("Usage: %s [options] <input.c> [output.exe]\n\n", program);
    printf("Options:\n");
    printf("  -v, --verbose      Enable verbose output\n");
    printf("  -S                 Keep assembly file\n");
    printf("  -c                 Keep object file\n");
    printf("  -O                 Enable optimization\n");
    printf("  -g                 Generate debug info\n");
    printf("  -h, --help         Show this help\n");
    printf("\n");
    printf("Examples:\n");
    printf("  %s hello.c                    # Compile to hello.exe\n", program);
    printf("  %s hello.c output.exe        # Compile to output.exe\n", program);
    printf("  %s -v hello.c                # Verbose compilation\n", program);
    printf("  %s -S hello.c                # Keep assembly file\n", program);
}

int parse_args(int argc, char** argv, CompilerConfig* config) {
    config->input_file = NULL;
    config->output_file = NULL;
    config->keep_asm = 0;
    config->keep_obj = 0;
    config->verbose = 0;
    config->optimize = 0;
    config->debug_info = 0;
    
    int i = 1;
    while (i < argc && argv[i][0] == '-') {
        if (strcmp(argv[i], "-v") == 0 || strcmp(argv[i], "--verbose") == 0) {
            config->verbose = 1;
        } else if (strcmp(argv[i], "-S") == 0) {
            config->keep_asm = 1;
        } else if (strcmp(argv[i], "-c") == 0) {
            config->keep_obj = 1;
        } else if (strcmp(argv[i], "-O") == 0) {
            config->optimize = 1;
        } else if (strcmp(argv[i], "-g") == 0) {
            config->debug_info = 1;
        } else if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 1;
        } else {
            fprintf(stderr, "Unknown option: %s\n", argv[i]);
            return -1;
        }
        i++;
    }
    
    if (i >= argc) {
        fprintf(stderr, "Error: No input file specified\n");
        return -1;
    }
    
    config->input_file = argv[i++];
    
    if (i < argc) {
        config->output_file = argv[i];
    } else {
        // Generate output filename from input
        static char output[256];
        strncpy(output, config->input_file, 255);
        char* dot = strrchr(output, '.');
        if (dot) {
            strcpy(dot, ".exe");
        } else {
            strcat(output, ".exe");
        }
        config->output_file = output;
    }
    
    // Generate temporary filenames
    static char asm_file[256];
    static char obj_file[256];
    
    strncpy(asm_file, config->input_file, 255);
    char* dot = strrchr(asm_file, '.');
    if (dot) {
        strcpy(dot, ".asm");
    } else {
        strcat(asm_file, ".asm");
    }
    config->asm_file = asm_file;
    
    strncpy(obj_file, config->input_file, 255);
    dot = strrchr(obj_file, '.');
    if (dot) {
        strcpy(dot, ".obj");
    } else {
        strcat(obj_file, ".obj");
    }
    config->obj_file = obj_file;
    
    return 0;
}

int main(int argc, char** argv) {
    printf("RawrXD C Compiler v1.0\n");
    printf("========================\n\n");
    
    CompilerConfig config;
    int result = parse_args(argc, argv, &config);
    if (result != 0) {
        return result < 0 ? 1 : 0;
    }
    
    printf("Input:  %s\n", config.input_file);
    printf("Output: %s\n\n", config.output_file);
    
    // Read source file
    char* source = read_file(config.input_file);
    if (!source) {
        return 1;
    }
    
    // Initialize compilation context
    CompilationContext ctx = {0};
    
    // Run compilation stages
    do {
        if (stage_lexical(&ctx, source, &config) < 0) break;
        if (stage_syntax(&ctx, &config) < 0) break;
        if (stage_semantic(&ctx, &config) < 0) break;
        if (stage_ir(&ctx, &config) < 0) break;
        if (stage_codegen(&ctx, &config) < 0) break;
        if (stage_assembly(&ctx, &config) < 0) break;
        if (stage_linking(&ctx, &config) < 0) break;
        
        // Success!
        printf("\n✓ Compilation successful!\n");
        printf("  Output: %s\n", config.output_file);
        
        if (config.keep_asm) {
            printf("  Assembly: %s\n", config.asm_file);
        }
        if (config.keep_obj) {
            printf("  Object: %s\n", config.obj_file);
        }
        
        result = 0;
    } while (0);
    
    if (result != 0) {
        printf("\n✗ Compilation failed at stage: %s\n", stage_name(ctx.stage));
        printf("  Errors: %d\n", ctx.errors);
        if (ctx.warnings > 0) {
            printf("  Warnings: %d\n", ctx.warnings);
        }
        result = 1;
    }
    
    // Cleanup
    cleanup(&ctx, &config);
    free(source);
    
    return result;
}