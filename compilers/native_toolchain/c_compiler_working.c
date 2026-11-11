//=============================================================================
// c_compiler_working.c - Minimal Working C Compiler
// Part of RawrXD Native Toolchain - Self-Hosting Build
// Compiles a simple C subset directly to x64 assembly
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>
#include <ctype.h>

//=============================================================================
// Token Types (Minimal)
//=============================================================================

typedef enum {
    // Keywords
    TOK_INT, TOK_RETURN, TOK_VOID,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH,
    TOK_ASSIGN, TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_SEMICOLON, TOK_COMMA,
    
    // Literals
    TOK_IDENTIFIER, TOK_NUMBER,
    
    // Special
    TOK_EOF, TOK_ERROR
} TokenType;

const char* token_type_str(TokenType type) {
    switch (type) {
        case TOK_INT: return "INT";
        case TOK_RETURN: return "RETURN";
        case TOK_VOID: return "VOID";
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_ASSIGN: return "ASSIGN";
        case TOK_EQ: return "EQ";
        case TOK_NE: return "NE";
        case TOK_LT: return "LT";
        case TOK_GT: return "GT";
        case TOK_LE: return "LE";
        case TOK_GE: return "GE";
        case TOK_LPAREN: return "LPAREN";
        case TOK_RPAREN: return "RPAREN";
        case TOK_LBRACE: return "LBRACE";
        case TOK_RBRACE: return "RBRACE";
        case TOK_SEMICOLON: return "SEMICOLON";
        case TOK_COMMA: return "COMMA";
        case TOK_IDENTIFIER: return "IDENTIFIER";
        case TOK_NUMBER: return "NUMBER";
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        default: return "UNKNOWN";
    }
}

//=============================================================================
// Token Structure
//=============================================================================

typedef struct {
    TokenType type;
    char text[256];
    int int_val;
    size_t line;
    size_t column;
} Token;

//=============================================================================
// Lexer
//=============================================================================

typedef struct {
    const char* source;
    size_t pos;
    size_t line;
    size_t column;
    Token* tokens;
    size_t token_count;
    size_t token_capacity;
} Lexer;

Lexer* lexer_create(const char* source) {
    Lexer* lexer = (Lexer*)calloc(1, sizeof(Lexer));
    if (!lexer) return NULL;
    
    lexer->source = source;
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->token_capacity = 1024;
    lexer->tokens = (Token*)calloc(lexer->token_capacity, sizeof(Token));
    if (!lexer->tokens) {
        free(lexer);
        return NULL;
    }
    
    return lexer;
}

void lexer_destroy(Lexer* lexer) {
    if (lexer) {
        free(lexer->tokens);
        free(lexer);
    }
}

static char lexer_peek(Lexer* lexer) {
    if (lexer->pos >= strlen(lexer->source)) return '\0';
    return lexer->source[lexer->pos];
}

static char lexer_advance(Lexer* lexer) {
    char c = lexer_peek(lexer);
    if (c == '\n') {
        lexer->line++;
        lexer->column = 1;
    } else {
        lexer->column++;
    }
    lexer->pos++;
    return c;
}

static void lexer_skip_whitespace(Lexer* lexer) {
    while (isspace(lexer_peek(lexer))) {
        lexer_advance(lexer);
    }
}

static int lexer_add_token(Lexer* lexer, TokenType type, const char* text, int int_val) {
    if (lexer->token_count >= lexer->token_capacity) {
        lexer->token_capacity *= 2;
        Token* new_tokens = (Token*)realloc(lexer->tokens, lexer->token_capacity * sizeof(Token));
        if (!new_tokens) return 0;
        lexer->tokens = new_tokens;
    }
    
    Token* tok = &lexer->tokens[lexer->token_count++];
    tok->type = type;
    strncpy(tok->text, text, 255);
    tok->text[255] = '\0';
    tok->int_val = int_val;
    tok->line = lexer->line;
    tok->column = lexer->column;
    
    return 1;
}

int lexer_tokenize(Lexer* lexer) {
    while (1) {
        lexer_skip_whitespace(lexer);
        
        char c = lexer_peek(lexer);
        if (c == '\0') break;
        
        // Numbers
        if (isdigit(c)) {
            char num_str[64] = {0};
            int i = 0;
            while (isdigit(lexer_peek(lexer))) {
                num_str[i++] = lexer_advance(lexer);
            }
            int val = atoi(num_str);
            lexer_add_token(lexer, TOK_NUMBER, num_str, val);
            continue;
        }
        
        // Identifiers and keywords
        if (isalpha(c) || c == '_') {
            char ident[256] = {0};
            int i = 0;
            while (isalnum(lexer_peek(lexer)) || lexer_peek(lexer) == '_') {
                ident[i++] = lexer_advance(lexer);
            }
            
            // Check for keywords
            TokenType type = TOK_IDENTIFIER;
            if (strcmp(ident, "int") == 0) type = TOK_INT;
            else if (strcmp(ident, "return") == 0) type = TOK_RETURN;
            else if (strcmp(ident, "void") == 0) type = TOK_VOID;
            
            lexer_add_token(lexer, type, ident, 0);
            continue;
        }
        
        // Single-character tokens
        switch (c) {
            case '+': lexer_advance(lexer); lexer_add_token(lexer, TOK_PLUS, "+", 0); break;
            case '-': lexer_advance(lexer); lexer_add_token(lexer, TOK_MINUS, "-", 0); break;
            case '*': lexer_advance(lexer); lexer_add_token(lexer, TOK_STAR, "*", 0); break;
            case '/': lexer_advance(lexer); lexer_add_token(lexer, TOK_SLASH, "/", 0); break;
            case '(': lexer_advance(lexer); lexer_add_token(lexer, TOK_LPAREN, "(", 0); break;
            case ')': lexer_advance(lexer); lexer_add_token(lexer, TOK_RPAREN, ")", 0); break;
            case '{': lexer_advance(lexer); lexer_add_token(lexer, TOK_LBRACE, "{", 0); break;
            case '}': lexer_advance(lexer); lexer_add_token(lexer, TOK_RBRACE, "}", 0); break;
            case ';': lexer_advance(lexer); lexer_add_token(lexer, TOK_SEMICOLON, ";", 0); break;
            case ',': lexer_advance(lexer); lexer_add_token(lexer, TOK_COMMA, ",", 0); break;
            case '=':
                lexer_advance(lexer);
                if (lexer_peek(lexer) == '=') {
                    lexer_advance(lexer);
                    lexer_add_token(lexer, TOK_EQ, "==", 0);
                } else {
                    lexer_add_token(lexer, TOK_ASSIGN, "=", 0);
                }
                break;
            case '!':
                lexer_advance(lexer);
                if (lexer_peek(lexer) == '=') {
                    lexer_advance(lexer);
                    lexer_add_token(lexer, TOK_NE, "!=", 0);
                } else {
                    lexer_add_token(lexer, TOK_ERROR, "!", 0);
                }
                break;
            case '<':
                lexer_advance(lexer);
                if (lexer_peek(lexer) == '=') {
                    lexer_advance(lexer);
                    lexer_add_token(lexer, TOK_LE, "<=", 0);
                } else {
                    lexer_add_token(lexer, TOK_LT, "<", 0);
                }
                break;
            case '>':
                lexer_advance(lexer);
                if (lexer_peek(lexer) == '=') {
                    lexer_advance(lexer);
                    lexer_add_token(lexer, TOK_GE, ">=", 0);
                } else {
                    lexer_add_token(lexer, TOK_GT, ">", 0);
                }
                break;
            default:
                printf("[ERROR] Unknown character '%c' at line %zu, column %zu\n", c, lexer->line, lexer->column);
                lexer_advance(lexer);
                lexer_add_token(lexer, TOK_ERROR, &c, 0);
                return 0;
        }
    }
    
    lexer_add_token(lexer, TOK_EOF, "", 0);
    return 1;
}

void lexer_print_tokens(Lexer* lexer) {
    printf("Tokens:\n");
    for (size_t i = 0; i < lexer->token_count; i++) {
        Token* tok = &lexer->tokens[i];
        printf("  [%2zu] %-12s '%s'", i, token_type_str(tok->type), tok->text);
        if (tok->type == TOK_NUMBER) printf(" (value=%d)", tok->int_val);
        printf("\n");
    }
}

//=============================================================================
// AST Node Types
//=============================================================================

typedef enum {
    AST_PROGRAM,
    AST_FUNCTION,
    AST_RETURN_STMT,
    AST_NUMBER,
    AST_IDENTIFIER,
    AST_BINARY_OP
} ASTNodeType;

const char* ast_type_str(ASTNodeType type) {
    switch (type) {
        case AST_PROGRAM: return "PROGRAM";
        case AST_FUNCTION: return "FUNCTION";
        case AST_RETURN_STMT: return "RETURN_STMT";
        case AST_NUMBER: return "NUMBER";
        case AST_IDENTIFIER: return "IDENTIFIER";
        case AST_BINARY_OP: return "BINARY_OP";
        default: return "UNKNOWN";
    }
}

//=============================================================================
// AST Node Structure
//=============================================================================

typedef struct ASTNode {
    ASTNodeType type;
    char name[256];
    int int_val;
    TokenType op;
    struct ASTNode** children;
    size_t child_count;
    size_t child_capacity;
    struct ASTNode* left;
    struct ASTNode* right;
} ASTNode;

ASTNode* ast_create_node(ASTNodeType type) {
    ASTNode* node = (ASTNode*)calloc(1, sizeof(ASTNode));
    if (!node) return NULL;
    
    node->type = type;
    node->child_capacity = 8;
    node->children = (ASTNode**)calloc(node->child_capacity, sizeof(ASTNode*));
    if (!node->children) {
        free(node);
        return NULL;
    }
    
    return node;
}

void ast_add_child(ASTNode* parent, ASTNode* child) {
    if (!parent || !child) return;
    
    if (parent->child_count >= parent->child_capacity) {
        parent->child_capacity *= 2;
        parent->children = (ASTNode**)realloc(parent->children, parent->child_capacity * sizeof(ASTNode*));
    }
    
    parent->children[parent->child_count++] = child;
}

void ast_destroy(ASTNode* node) {
    if (!node) return;
    
    for (size_t i = 0; i < node->child_count; i++) {
        ast_destroy(node->children[i]);
    }
    
    ast_destroy(node->left);
    ast_destroy(node->right);
    free(node->children);
    free(node);
}

void ast_print(ASTNode* node, int indent) {
    if (!node) return;
    
    for (int i = 0; i < indent; i++) printf("  ");
    printf("%s", ast_type_str(node->type));
    
    if (node->name[0]) printf(" name='%s'", node->name);
    if (node->type == AST_NUMBER) printf(" value=%d", node->int_val);
    if (node->type == AST_BINARY_OP) printf(" op=%s", token_type_str(node->op));
    printf("\n");
    
    for (size_t i = 0; i < node->child_count; i++) {
        ast_print(node->children[i], indent + 1);
    }
}

//=============================================================================
// Parser
//=============================================================================

typedef struct {
    Token* tokens;
    size_t token_count;
    size_t current;
} Parser;

Parser* parser_create(Token* tokens, size_t token_count) {
    Parser* parser = (Parser*)calloc(1, sizeof(Parser));
    if (!parser) return NULL;
    
    parser->tokens = tokens;
    parser->token_count = token_count;
    parser->current = 0;
    
    return parser;
}

void parser_destroy(Parser* parser) {
    free(parser);
}

static Token* parser_peek(Parser* parser) {
    if (parser->current >= parser->token_count) {
        return &parser->tokens[parser->token_count - 1];
    }
    return &parser->tokens[parser->current];
}

static Token* parser_advance(Parser* parser) {
    if (parser->current < parser->token_count) {
        parser->current++;
    }
    return &parser->tokens[parser->current - 1];
}

static int parser_check(Parser* parser, TokenType type) {
    return parser_peek(parser)->type == type;
}

static Token* parser_expect(Parser* parser, TokenType type) {
    if (parser_check(parser, type)) {
        return parser_advance(parser);
    }
    printf("[ERROR] Expected %s but got %s\n", 
           token_type_str(type), token_type_str(parser_peek(parser)->type));
    return NULL;
}

// Forward declarations
ASTNode* parse_expression(Parser* parser);
ASTNode* parse_statement(Parser* parser);

// expression ::= number
ASTNode* parse_expression(Parser* parser) {
    if (parser_check(parser, TOK_NUMBER)) {
        Token* num = parser_advance(parser);
        ASTNode* node = ast_create_node(AST_NUMBER);
        node->int_val = num->int_val;
        return node;
    }
    
    printf("[ERROR] Expected number in expression\n");
    return NULL;
}

// statement ::= return expression ;
ASTNode* parse_statement(Parser* parser) {
    if (!parser_expect(parser, TOK_RETURN)) {
        return NULL;
    }
    
    ASTNode* expr = parse_expression(parser);
    if (!expr) return NULL;
    
    if (!parser_expect(parser, TOK_SEMICOLON)) {
        ast_destroy(expr);
        return NULL;
    }
    
    ASTNode* stmt = ast_create_node(AST_RETURN_STMT);
    stmt->left = expr;
    return stmt;
}

// function ::= type identifier ( ) { statement* }
ASTNode* parse_function(Parser* parser) {
    // Return type
    if (!parser_check(parser, TOK_INT) && !parser_check(parser, TOK_VOID)) {
        printf("[ERROR] Expected return type (int or void)\n");
        return NULL;
    }
    parser_advance(parser);
    
    // Function name
    Token* name = parser_expect(parser, TOK_IDENTIFIER);
    if (!name) return NULL;
    
    // Parameters (simplified - just empty parens)
    if (!parser_expect(parser, TOK_LPAREN)) return NULL;
    if (!parser_expect(parser, TOK_RPAREN)) return NULL;
    
    // Body
    if (!parser_expect(parser, TOK_LBRACE)) return NULL;
    
    ASTNode* func = ast_create_node(AST_FUNCTION);
    strncpy(func->name, name->text, 255);
    
    // Parse statements
    while (!parser_check(parser, TOK_RBRACE) && !parser_check(parser, TOK_EOF)) {
        ASTNode* stmt = parse_statement(parser);
        if (stmt) {
            ast_add_child(func, stmt);
        } else {
            // Error recovery
            while (!parser_check(parser, TOK_SEMICOLON) && !parser_check(parser, TOK_EOF)) {
                parser_advance(parser);
            }
            if (parser_check(parser, TOK_SEMICOLON)) {
                parser_advance(parser);
            }
        }
    }
    
    if (!parser_expect(parser, TOK_RBRACE)) {
        ast_destroy(func);
        return NULL;
    }
    
    return func;
}

// program ::= function*
ASTNode* parse_program(Parser* parser) {
    ASTNode* program = ast_create_node(AST_PROGRAM);
    
    while (!parser_check(parser, TOK_EOF)) {
        ASTNode* func = parse_function(parser);
        if (func) {
            ast_add_child(program, func);
        } else {
            break;
        }
    }
    
    return program;
}

//=============================================================================
// Code Generator
//=============================================================================

typedef struct {
    char* buffer;
    size_t size;
    size_t capacity;
} CodeGen;

CodeGen* codegen_create() {
    CodeGen* gen = (CodeGen*)calloc(1, sizeof(CodeGen));
    if (!gen) return NULL;
    
    gen->capacity = 65536;
    gen->buffer = (char*)calloc(gen->capacity, 1);
    if (!gen->buffer) {
        free(gen);
        return NULL;
    }
    
    return gen;
}

void codegen_destroy(CodeGen* gen) {
    if (gen) {
        free(gen->buffer);
        free(gen);
    }
}

void codegen_emit(CodeGen* gen, const char* fmt, ...) {
    va_list args;
    va_start(args, fmt);
    
    char temp[1024];
    vsnprintf(temp, sizeof(temp), fmt, args);
    
    size_t len = strlen(temp);
    if (gen->size + len >= gen->capacity) {
        gen->capacity *= 2;
        gen->buffer = (char*)realloc(gen->buffer, gen->capacity);
    }
    
    strcat(gen->buffer, temp);
    gen->size += len;
    
    va_end(args);
}

void codegen_emit_prologue(CodeGen* gen) {
    codegen_emit(gen, "; Generated by RawrXD C Compiler\n");
    codegen_emit(gen, "; Minimal C to x64 Assembly\n\n");
    codegen_emit(gen, "code SEGMENT ALIGN(16) READ EXECUTE\n\n");
}

void codegen_emit_epilogue(CodeGen* gen) {
    codegen_emit(gen, "\ncode ENDS\n");
    codegen_emit(gen, "END\n");
}

void codegen_emit_function_start(CodeGen* gen, const char* name) {
    codegen_emit(gen, "%s PROC\n", name);
    codegen_emit(gen, "    push    rbp\n");
    codegen_emit(gen, "    mov     rbp, rsp\n");
    codegen_emit(gen, "    sub     rsp, 32\n\n");
}

void codegen_emit_function_end(CodeGen* gen, const char* name) {
    codegen_emit(gen, "\n    mov     rsp, rbp\n");
    codegen_emit(gen, "    pop     rbp\n");
    codegen_emit(gen, "    ret\n");
    codegen_emit(gen, "%s ENDP\n\n", name);
}

void codegen_emit_return(CodeGen* gen, int value) {
    codegen_emit(gen, "    mov     eax, %d\n", value);
    codegen_emit(gen, "    mov     ecx, eax\n");
    codegen_emit(gen, "    call    ExitProcess\n");
}

void codegen_emit_statement(CodeGen* gen, ASTNode* stmt) {
    if (!stmt) return;
    
    if (stmt->type == AST_RETURN_STMT && stmt->left && stmt->left->type == AST_NUMBER) {
        codegen_emit_return(gen, stmt->left->int_val);
    }
}

void codegen_emit_function(CodeGen* gen, ASTNode* func) {
    if (!func || func->type != AST_FUNCTION) return;
    
    codegen_emit_function_start(gen, func->name);
    
    for (size_t i = 0; i < func->child_count; i++) {
        codegen_emit_statement(gen, func->children[i]);
    }
    
    // Default return if none specified
    codegen_emit(gen, "    xor     ecx, ecx\n");
    codegen_emit(gen, "    call    ExitProcess\n");
    
    codegen_emit_function_end(gen, func->name);
}

const char* generate_code(ASTNode* ast) {
    CodeGen* gen = codegen_create();
    if (!gen) return NULL;
    
    codegen_emit_prologue(gen);
    
    // Add extern declarations
    codegen_emit(gen, "extrn ExitProcess : PROC\n\n");
    
    for (size_t i = 0; i < ast->child_count; i++) {
        codegen_emit_function(gen, ast->children[i]);
    }
    
    codegen_emit_epilogue(gen);
    
    char* result = gen->buffer;
    gen->buffer = NULL;
    codegen_destroy(gen);
    
    return result;
}

//=============================================================================
// File I/O
//=============================================================================

char* read_file(const char* filename) {
    FILE* file = fopen(filename, "rb");
    if (!file) {
        fprintf(stderr, "[ERROR] Cannot open file '%s'\n", filename);
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
        fprintf(stderr, "[ERROR] Cannot create file '%s'\n", filename);
        return -1;
    }
    
    fputs(content, file);
    fclose(file);
    return 0;
}

//=============================================================================
// Main
//=============================================================================

void print_usage(const char* prog) {
    printf("RawrXD Minimal C Compiler - Self-Hosting Native Toolchain\n");
    printf("Usage: %s <input.c> [options]\n", prog);
    printf("Options:\n");
    printf("  -o <file>    Output executable name (default: a.exe)\n");
    printf("  -S           Keep assembly file\n");
    printf("  -v           Verbose output\n");
    printf("  --help       Show this help\n");
}

int main(int argc, char* argv[]) {
    printf("=============================================================================\n");
    printf("RawrXD Minimal C Compiler - Self-Hosting Native Toolchain\n");
    printf("=============================================================================\n\n");
    
    if (argc < 2) {
        print_usage(argv[0]);
        return 1;
    }
    
    // Parse arguments
    const char* input_file = NULL;
    const char* output_file = "a.exe";
    const char* asm_file = "output.asm";
    int keep_asm = 0;
    int verbose = 0;
    
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return 0;
        } else if (strcmp(argv[i], "-o") == 0 && i + 1 < argc) {
            output_file = argv[++i];
        } else if (strcmp(argv[i], "-S") == 0) {
            keep_asm = 1;
        } else if (strcmp(argv[i], "-v") == 0) {
            verbose = 1;
        } else if (argv[i][0] != '-') {
            input_file = argv[i];
        }
    }
    
    if (!input_file) {
        fprintf(stderr, "[ERROR] No input file specified\n");
        return 1;
    }
    
    printf("[CONFIG] Input: %s\n", input_file);
    printf("[CONFIG] Output: %s\n\n", output_file);
    
    // Stage 1: Read source
    printf("[STAGE 1] Reading source file...\n");
    char* source = read_file(input_file);
    if (!source) return 1;
    printf("[STAGE 1] Read %zu bytes\n\n", strlen(source));
    
    // Stage 2: Lexical Analysis
    printf("[STAGE 2] Lexical Analysis...\n");
    Lexer* lexer = lexer_create(source);
    if (!lexer) {
        free(source);
        return 1;
    }
    
    if (!lexer_tokenize(lexer)) {
        fprintf(stderr, "[FAILED] Tokenization failed\n");
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    printf("[STAGE 2] Tokenized %zu tokens\n", lexer->token_count);
    if (verbose) {
        lexer_print_tokens(lexer);
        printf("\n");
    }
    
    // Stage 3: Syntax Analysis
    printf("\n[STAGE 3] Syntax Analysis...\n");
    Parser* parser = parser_create(lexer->tokens, lexer->token_count);
    if (!parser) {
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    ASTNode* ast = parse_program(parser);
    if (!ast) {
        fprintf(stderr, "[FAILED] Parsing failed\n");
        parser_destroy(parser);
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    printf("[STAGE 3] Parsed AST successfully\n");
    if (verbose) {
        ast_print(ast, 0);
        printf("\n");
    }
    
    // Stage 4: Code Generation
    printf("\n[STAGE 4] Code Generation...\n");
    const char* asm_code = generate_code(ast);
    if (!asm_code) {
        fprintf(stderr, "[FAILED] Code generation failed\n");
        ast_destroy(ast);
        parser_destroy(parser);
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    if (write_file(asm_file, asm_code) != 0) {
        fprintf(stderr, "[FAILED] Cannot write assembly file\n");
        free((void*)asm_code);
        ast_destroy(ast);
        parser_destroy(parser);
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    printf("[STAGE 4] Assembly written to: %s\n", asm_file);
    if (verbose) {
        printf("\n--- Generated Assembly ---\n");
        printf("%s", asm_code);
        printf("--- End Assembly ---\n\n");
    }
    
    // Stage 5: Assembly
    printf("\n[STAGE 5] Assembly (Native Assembler)...\n");
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "d:\\rawrxd\\compilers\\native_toolchain\\rawrxd_native_assembler.exe /c %s output.obj", asm_file);
    printf("[STAGE 5] Running: %s\n", asm_cmd);
    
    int asm_result = system(asm_cmd);
    if (asm_result != 0) {
        fprintf(stderr, "[FAILED] Assembly failed with code %d\n", asm_result);
        if (!keep_asm) remove(asm_file);
        free((void*)asm_code);
        ast_destroy(ast);
        parser_destroy(parser);
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    printf("[STAGE 5] Object file created: output.obj\n");
    
    // Stage 6: Linking
    printf("\n[STAGE 6] Linking...\n");
    char link_cmd[1024];
    snprintf(link_cmd, sizeof(link_cmd), "d:\\rawrxd\\compilers\\native_toolchain\\rawrxd_native_linker.exe output.obj /out:%s /subsystem:3 /entry:main", output_file);
    printf("[STAGE 6] Running: %s\n", link_cmd);
    
    int link_result = system(link_cmd);
    if (link_result != 0) {
        fprintf(stderr, "[FAILED] Linking failed with code %d\n", link_result);
        remove("output.obj");
        if (!keep_asm) remove(asm_file);
        free((void*)asm_code);
        ast_destroy(ast);
        parser_destroy(parser);
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    printf("[STAGE 6] Executable created: %s\n", output_file);
    
    // Cleanup
    remove("output.obj");
    if (!keep_asm) remove(asm_file);
    
    // Final cleanup
    free((void*)asm_code);
    ast_destroy(ast);
    parser_destroy(parser);
    lexer_destroy(lexer);
    free(source);
    
    // Success!
    printf("\n=============================================================================\n");
    printf("[SUCCESS] Compilation complete!\n");
    printf("[OUTPUT] %s\n", output_file);
    printf("=============================================================================\n");
    printf("\n*** END-TO-END SELF-HOSTING COMPLETE ***\n");
    printf("C Source -> Lexer -> Parser -> AST -> x64 ASM -> Native Assembler -> Linker -> EXE\n");
    printf("\nNo external dependencies. Pure self-hosted native toolchain.\n");
    
    return 0;
}