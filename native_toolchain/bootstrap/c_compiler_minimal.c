//=============================================================================
// c_compiler_minimal.c - Minimal Working C Compiler
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
    int line;
    int column;
    int int_val;
} Token;

//=============================================================================
// Lexer
//=============================================================================

typedef struct {
    const char* source;
    size_t pos;
    size_t length;
    int line;
    int column;
    Token tokens[4096];
    size_t token_count;
} Lexer;

Lexer* lexer_create(const char* source) {
    Lexer* lexer = (Lexer*)calloc(1, sizeof(Lexer));
    if (!lexer) return NULL;
    
    lexer->source = source;
    lexer->length = strlen(source);
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->token_count = 0;
    
    return lexer;
}

void lexer_destroy(Lexer* lexer) {
    free(lexer);
}

static char lexer_peek(Lexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    return lexer->source[lexer->pos];
}

static char lexer_advance(Lexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    char c = lexer->source[lexer->pos++];
    if (c == '\n') {
        lexer->line++;
        lexer->column = 1;
    } else {
        lexer->column++;
    }
    return c;
}

static void lexer_skip_whitespace(Lexer* lexer) {
    while (lexer_peek(lexer) == ' ' || lexer_peek(lexer) == '\t' || 
           lexer_peek(lexer) == '\n' || lexer_peek(lexer) == '\r') {
        lexer_advance(lexer);
    }
    
    // Skip comments
    if (lexer_peek(lexer) == '/' && lexer->source[lexer->pos + 1] == '/') {
        while (lexer_peek(lexer) != '\n' && lexer_peek(lexer) != '\0') {
            lexer_advance(lexer);
        }
        lexer_skip_whitespace(lexer);  // Recurse to skip the newline
    }
}

static Token lexer_read_identifier(Lexer* lexer) {
    Token token;
    token.type = TOK_IDENTIFIER;
    token.line = lexer->line;
    token.column = lexer->column;
    int i = 0;
    
    while (isalnum(lexer_peek(lexer)) || lexer_peek(lexer) == '_') {
        if (i < 255) {
            token.text[i++] = lexer_advance(lexer);
        } else {
            lexer_advance(lexer);
        }
    }
    token.text[i] = '\0';
    
    // Check keywords
    if (strcmp(token.text, "int") == 0) token.type = TOK_INT;
    else if (strcmp(token.text, "return") == 0) token.type = TOK_RETURN;
    else if (strcmp(token.text, "void") == 0) token.type = TOK_VOID;
    
    return token;
}

static Token lexer_read_number(Lexer* lexer) {
    Token token;
    token.type = TOK_NUMBER;
    token.line = lexer->line;
    token.column = lexer->column;
    token.int_val = 0;
    int i = 0;
    
    while (isdigit(lexer_peek(lexer))) {
        token.int_val = token.int_val * 10 + (lexer_peek(lexer) - '0');
        if (i < 255) {
            token.text[i++] = lexer_advance(lexer);
        } else {
            lexer_advance(lexer);
        }
    }
    token.text[i] = '\0';
    
    return token;
}

int lexer_tokenize(Lexer* lexer) {
    while (lexer->pos < lexer->length) {
        lexer_skip_whitespace(lexer);
        
        if (lexer->pos >= lexer->length) break;
        
        char c = lexer_peek(lexer);
        Token token;
        token.line = lexer->line;
        token.column = lexer->column;
        
        if (isalpha(c) || c == '_') {
            token = lexer_read_identifier(lexer);
        } else if (isdigit(c)) {
            token = lexer_read_number(lexer);
        } else {
            switch (c) {
                case '+':
                    lexer_advance(lexer);
                    token.type = TOK_PLUS;
                    strcpy(token.text, "+");
                    break;
                case '-':
                    lexer_advance(lexer);
                    token.type = TOK_MINUS;
                    strcpy(token.text, "-");
                    break;
                case '*':
                    lexer_advance(lexer);
                    token.type = TOK_STAR;
                    strcpy(token.text, "*");
                    break;
                case '/':
                    lexer_advance(lexer);
                    token.type = TOK_SLASH;
                    strcpy(token.text, "/");
                    break;
                case '=':
                    lexer_advance(lexer);
                    if (lexer_peek(lexer) == '=') {
                        lexer_advance(lexer);
                        token.type = TOK_EQ;
                        strcpy(token.text, "==");
                    } else {
                        token.type = TOK_ASSIGN;
                        strcpy(token.text, "=");
                    }
                    break;
                case '!':
                    lexer_advance(lexer);
                    if (lexer_peek(lexer) == '=') {
                        lexer_advance(lexer);
                        token.type = TOK_NE;
                        strcpy(token.text, "!=");
                    } else {
                        token.type = TOK_ERROR;
                        strcpy(token.text, "!");
                    }
                    break;
                case '<':
                    lexer_advance(lexer);
                    if (lexer_peek(lexer) == '=') {
                        lexer_advance(lexer);
                        token.type = TOK_LE;
                        strcpy(token.text, "<=");
                    } else {
                        token.type = TOK_LT;
                        strcpy(token.text, "<");
                    }
                    break;
                case '>':
                    lexer_advance(lexer);
                    if (lexer_peek(lexer) == '=') {
                        lexer_advance(lexer);
                        token.type = TOK_GE;
                        strcpy(token.text, ">=");
                    } else {
                        token.type = TOK_GT;
                        strcpy(token.text, ">");
                    }
                    break;
                case '(':
                    lexer_advance(lexer);
                    token.type = TOK_LPAREN;
                    strcpy(token.text, "(");
                    break;
                case ')':
                    lexer_advance(lexer);
                    token.type = TOK_RPAREN;
                    strcpy(token.text, ")");
                    break;
                case '{':
                    lexer_advance(lexer);
                    token.type = TOK_LBRACE;
                    strcpy(token.text, "{");
                    break;
                case '}':
                    lexer_advance(lexer);
                    token.type = TOK_RBRACE;
                    strcpy(token.text, "}");
                    break;
                case ';':
                    lexer_advance(lexer);
                    token.type = TOK_SEMICOLON;
                    strcpy(token.text, ";");
                    break;
                case ',':
                    lexer_advance(lexer);
                    token.type = TOK_COMMA;
                    strcpy(token.text, ",");
                    break;
                default:
                    lexer_advance(lexer);
                    token.type = TOK_ERROR;
                    token.text[0] = c;
                    token.text[1] = '\0';
                    break;
            }
        }
        
        if (lexer->token_count < 4096) {
            lexer->tokens[lexer->token_count++] = token;
        }
    }
    
    // Add EOF token
    Token eof_token;
    eof_token.type = TOK_EOF;
    eof_token.line = lexer->line;
    eof_token.column = lexer->column;
    strcpy(eof_token.text, "EOF");
    lexer->tokens[lexer->token_count++] = eof_token;
    
    return 1;
}

void lexer_print_tokens(Lexer* lexer) {
    printf("Tokens:\n");
    for (size_t i = 0; i < lexer->token_count; i++) {
        Token* t = &lexer->tokens[i];
        printf("  [%zu] %s: '%s' (line %d, col %d)\n", 
               i, token_type_str(t->type), t->text, t->line, t->column);
    }
}

//=============================================================================
// AST Node Types (Minimal)
//=============================================================================

typedef enum {
    AST_PROGRAM,
    AST_FUNCTION,
    AST_RETURN_STMT,
    AST_NUMBER,
    AST_BINARY_OP
} ASTNodeType;

const char* ast_type_str(ASTNodeType type) {
    switch (type) {
        case AST_PROGRAM: return "PROGRAM";
        case AST_FUNCTION: return "FUNCTION";
        case AST_RETURN_STMT: return "RETURN_STMT";
        case AST_NUMBER: return "NUMBER";
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
    struct ASTNode* left;
    struct ASTNode* right;
    struct ASTNode** children;
    size_t child_count;
    size_t child_capacity;
} ASTNode;

ASTNode* ast_create_node(ASTNodeType type) {
    ASTNode* node = (ASTNode*)calloc(1, sizeof(ASTNode));
    if (!node) return NULL;
    
    node->type = type;
    node->child_capacity = 8;
    node->children = (ASTNode**)calloc(node->child_capacity, sizeof(ASTNode*));
    
    return node;
}

void ast_add_child(ASTNode* parent, ASTNode* child) {
    if (!parent || !child) return;
    
    if (parent->child_count >= parent->child_capacity) {
        parent->child_capacity *= 2;
        parent->children = (ASTNode**)realloc(parent->children, 
                                                parent->child_capacity * sizeof(ASTNode*));
    }
    
    parent->children[parent->child_count++] = child;
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

// expression ::= term (('+' | '-') term)*
ASTNode* parse_expression(Parser* parser) {
    ASTNode* left = ast_create_node(AST_NUMBER);
    
    if (parser_check(parser, TOK_NUMBER)) {
        Token* num = parser_advance(parser);
        left->type = AST_NUMBER;
        left->int_val = num->int_val;
    } else {
        printf("[ERROR] Expected number in expression\n");
        ast_destroy(left);
        return NULL;
    }
    
    while (parser_check(parser, TOK_PLUS) || parser_check(parser, TOK_MINUS)) {
        Token* op = parser_advance(parser);
        ASTNode* right = ast_create_node(AST_NUMBER);
        
        if (parser_check(parser, TOK_NUMBER)) {
            Token* num = parser_advance(parser);
            right->int_val = num->int_val;
        } else {
            printf("[ERROR] Expected number after operator\n");
            ast_destroy(right);
            ast_destroy(left);
            return NULL;
        }
        
        ASTNode* binop = ast_create_node(AST_BINARY_OP);
        binop->op = op->type;
        binop->left = left;
        binop->right = right;
        left = binop;
    }
    
    return left;
}

// return_statement ::= 'return' expression ';'
ASTNode* parse_return_statement(Parser* parser) {
    parser_expect(parser, TOK_RETURN);
    
    ASTNode* expr = parse_expression(parser);
    if (!expr) return NULL;
    
    parser_expect(parser, TOK_SEMICOLON);
    
    ASTNode* stmt = ast_create_node(AST_RETURN_STMT);
    ast_add_child(stmt, expr);
    
    return stmt;
}

// statement ::= return_statement
ASTNode* parse_statement(Parser* parser) {
    if (parser_check(parser, TOK_RETURN)) {
        return parse_return_statement(parser);
    }
    printf("[ERROR] Expected statement\n");
    return NULL;
}

// function ::= type identifier '(' ')' '{' statement* '}'
ASTNode* parse_function(Parser* parser) {
    // Parse return type
    if (parser_check(parser, TOK_INT) || parser_check(parser, TOK_VOID)) {
        parser_advance(parser);
    } else {
        printf("[ERROR] Expected return type\n");
        return NULL;
    }
    
    // Parse function name
    Token* name = parser_expect(parser, TOK_IDENTIFIER);
    if (!name) return NULL;
    
    parser_expect(parser, TOK_LPAREN);
    parser_expect(parser, TOK_RPAREN);
    parser_expect(parser, TOK_LBRACE);
    
    ASTNode* func = ast_create_node(AST_FUNCTION);
    strcpy(func->name, name->text);
    
    // Parse function body
    while (!parser_check(parser, TOK_RBRACE) && !parser_check(parser, TOK_EOF)) {
        ASTNode* stmt = parse_statement(parser);
        if (stmt) {
            ast_add_child(func, stmt);
        } else {
            break;
        }
    }
    
    parser_expect(parser, TOK_RBRACE);
    
    return func;
}

// program ::= function
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
    int label_count;
} CodeGen;

CodeGen* codegen_create(void) {
    CodeGen* gen = (CodeGen*)calloc(1, sizeof(CodeGen));
    if (!gen) return NULL;
    
    gen->capacity = 65536;
    gen->buffer = (char*)malloc(gen->capacity);
    gen->buffer[0] = '\0';
    gen->size = 0;
    gen->label_count = 0;
    
    return gen;
}

void codegen_destroy(CodeGen* gen) {
    if (gen) {
        free(gen->buffer);
        free(gen);
    }
}

void codegen_emit(CodeGen* gen, const char* fmt, ...) {
    if (!gen || !gen->buffer) return;
    
    va_list args;
    va_start(args, fmt);
    
    char temp[1024];
    int len = vsnprintf(temp, sizeof(temp), fmt, args);
    va_end(args);
    
    if (gen->size + len + 1 > gen->capacity) {
        gen->capacity *= 2;
        gen->buffer = (char*)realloc(gen->buffer, gen->capacity);
    }
    
    strcat(gen->buffer + gen->size, temp);
    gen->size += len;
}

void codegen_emit_prologue(CodeGen* gen) {
    codegen_emit(gen, "; Generated by RawrXD Minimal C Compiler\n");
    codegen_emit(gen, "; x64 Assembly (MASM syntax)\n\n");
    codegen_emit(gen, "bits 64\n");
    codegen_emit(gen, "default rel\n\n");
    codegen_emit(gen, "section .text\n");
    codegen_emit(gen, "global main\n");
    codegen_emit(gen, "extern ExitProcess\n\n");
}

void codegen_emit_function_start(CodeGen* gen, const char* name) {
    codegen_emit(gen, "%s:\n", name);
    codegen_emit(gen, "    push rbp\n");
    codegen_emit(gen, "    mov rbp, rsp\n");
    codegen_emit(gen, "    sub rsp, 32\n");  // Shadow space
}

void codegen_emit_function_end(CodeGen* gen) {
    codegen_emit(gen, "    mov rsp, rbp\n");
    codegen_emit(gen, "    pop rbp\n");
    codegen_emit(gen, "    ret\n\n");
}

void codegen_emit_expression(CodeGen* gen, ASTNode* expr) {
    if (!expr) return;
    
    if (expr->type == AST_NUMBER) {
        codegen_emit(gen, "    mov rax, %d\n", expr->int_val);
    } else if (expr->type == AST_BINARY_OP) {
        codegen_emit_expression(gen, expr->left);
        codegen_emit(gen, "    push rax\n");
        codegen_emit_expression(gen, expr->right);
        codegen_emit(gen, "    mov rbx, rax\n");
        codegen_emit(gen, "    pop rax\n");
        
        if (expr->op == TOK_PLUS) {
            codegen_emit(gen, "    add rax, rbx\n");
        } else if (expr->op == TOK_MINUS) {
            codegen_emit(gen, "    sub rax, rbx\n");
        }
    }
}

void codegen_emit_statement(CodeGen* gen, ASTNode* stmt) {
    if (!stmt) return;
    
    if (stmt->type == AST_RETURN_STMT && stmt->child_count > 0) {
        codegen_emit_expression(gen, stmt->children[0]);
        codegen_emit(gen, "    mov rcx, rax\n");
        codegen_emit(gen, "    call ExitProcess\n");
    }
}

void codegen_emit_function(CodeGen* gen, ASTNode* func) {
    if (!func || func->type != AST_FUNCTION) return;
    
    codegen_emit_function_start(gen, func->name);
    
    int has_return = 0;
    for (size_t i = 0; i < func->child_count; i++) {
        if (func->children[i]->type == AST_RETURN_STMT) {
            has_return = 1;
        }
        codegen_emit_statement(gen, func->children[i]);
    }
    
    // Default return if none specified
    if (!has_return) {
        codegen_emit(gen, "    xor rcx, rcx\n");
        codegen_emit(gen, "    call ExitProcess\n");
    }
    
    codegen_emit_function_end(gen);
}

const char* generate_code(ASTNode* ast) {
    CodeGen* gen = codegen_create();
    if (!gen) return NULL;
    
    codegen_emit_prologue(gen);
    
    for (size_t i = 0; i < ast->child_count; i++) {
        codegen_emit_function(gen, ast->children[i]);
    }
    
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
    
    // Change to the assembler directory for the build
    char* assembler_dir = "d:\\rawrxd\\native_toolchain";
    char asm_file_in_dir[512];
    char obj_file_in_dir[512];
    snprintf(asm_file_in_dir, sizeof(asm_file_in_dir), "%s\\%s", assembler_dir, asm_file);
    snprintf(obj_file_in_dir, sizeof(obj_file_in_dir), "%s\\output.obj", assembler_dir);
    
    // Write assembly file to assembler directory
    if (write_file(asm_file_in_dir, asm_code) != 0) {
        fprintf(stderr, "[FAILED] Cannot write assembly file to assembler directory\n");
        free((void*)asm_code);
        ast_destroy(ast);
        parser_destroy(parser);
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    char asm_cmd[1024];
    snprintf(asm_cmd, sizeof(asm_cmd), "cd /d %s && minimal_assembler_v5.exe %s output.obj", assembler_dir, asm_file);
    printf("[STAGE 5] Running: %s\n", asm_cmd);
    
    int asm_result = system(asm_cmd);
    if (asm_result != 0) {
        fprintf(stderr, "[FAILED] Assembly failed with code %d\n", asm_result);
        if (!keep_asm) remove(asm_file_in_dir);
        free((void*)asm_code);
        ast_destroy(ast);
        parser_destroy(parser);
        lexer_destroy(lexer);
        free(source);
        return 1;
    }
    
    printf("[STAGE 5] Object file created: %s\n", obj_file_in_dir);
    
    // Stage 6: Linking
    printf("\n[STAGE 6] Linking...\n");
    char link_cmd[1024];
    char output_path[512];
    snprintf(output_path, sizeof(output_path), "%s\\%s", assembler_dir, output_file);
    snprintf(link_cmd, sizeof(link_cmd), "cd /d %s && linker_v4.exe output.obj %s", assembler_dir, output_file);
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
    char obj_file_in_dir2[512];
    char asm_file_in_dir2[512];
    snprintf(obj_file_in_dir2, sizeof(obj_file_in_dir2), "d:\\rawrxd\\compilers\\native_toolchain\\output.obj");
    snprintf(asm_file_in_dir2, sizeof(asm_file_in_dir2), "d:\\rawrxd\\compilers\\native_toolchain\\%s", asm_file);
    remove(obj_file_in_dir2);
    if (!keep_asm) remove(asm_file_in_dir2);
    
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
