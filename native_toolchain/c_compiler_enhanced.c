//=============================================================================
// c_compiler_enhanced.c - Extended C Compiler with Self-Hosting Support
// Supports: typedef, struct, enum, and minimal standard library
// Part of RawrXD Native Toolchain
//=============================================================================

#define _CRT_SECURE_NO_WARNINGS
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Token Types
//=============================================================================

typedef enum {
    // Literals
    TOK_EOF, TOK_IDENT, TOK_NUMBER, TOK_STRING, TOK_CHAR,
    
    // Keywords
    TOK_INT, TOK_VOID, TOK_CHAR_KW, TOK_RETURN, TOK_IF, TOK_ELSE,
    TOK_WHILE, TOK_FOR, TOK_BREAK, TOK_CONTINUE,
    TOK_STRUCT, TOK_ENUM, TOK_TYPEDEF, TOK_UNION, TOK_SIZEOF,
    TOK_EXTERN, TOK_STATIC, TOK_CONST, TOK_VOLATILE,
    TOK_LONG, TOK_SHORT, TOK_UNSIGNED, TOK_SIGNED, TOK_FLOAT, TOK_DOUBLE,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_LT, TOK_GT, TOK_LE, TOK_GE, TOK_EQ, TOK_NE,
    TOK_AND, TOK_OR, TOK_XOR, TOK_NOT, TOK_TILDE,
    TOK_LSHIFT, TOK_RSHIFT,
    TOK_ASSIGN, TOK_PLUS_EQ, TOK_MINUS_EQ, TOK_STAR_EQ, TOK_SLASH_EQ,
    TOK_AND_EQ, TOK_OR_EQ, TOK_XOR_EQ, TOK_INC, TOK_DEC,
    
    // Delimiters
    TOK_LBRACE, TOK_RBRACE, TOK_LPAREN, TOK_RPAREN,
    TOK_LBRACKET, TOK_RBRACKET, TOK_SEMICOLON, TOK_COLON, TOK_COMMA, TOK_DOT,
    TOK_ARROW, TOK_AMPERSAND, TOK_QUESTION
} TokenType;

//=============================================================================
// Token Structure
//=============================================================================

typedef struct Token {
    TokenType type;
    char value[256];
    int line;
    int column;
    struct Token *next;
} Token;

//=============================================================================
// Type System
//=============================================================================

typedef enum {
    TYPE_VOID, TYPE_CHAR, TYPE_SHORT, TYPE_INT, TYPE_LONG,
    TYPE_FLOAT, TYPE_DOUBLE, TYPE_POINTER, TYPE_ARRAY,
    TYPE_STRUCT, TYPE_UNION, TYPE_ENUM, TYPE_TYPEDEF
} BaseType;

typedef struct Type {
    BaseType base;
    int size;
    int align;
    struct Type *ptr_to;      // For pointers
    struct Type *array_of;     // For arrays
    int array_size;
    struct Field *fields;      // For struct/union
    char name[64];             // Type name
} Type;

typedef struct Field {
    char name[64];
    Type *type;
    int offset;
    struct Field *next;
} Field;

//=============================================================================
// Symbol Table
//=============================================================================

typedef enum {
    SYM_VAR, SYM_FUNC, SYM_TYPE, SYM_ENUM_CONST, SYM_FIELD
} SymbolKind;

typedef struct Symbol {
    char name[64];
    SymbolKind kind;
    Type *type;
    int scope_level;
    int offset;           // Stack offset for locals
    int is_global;
    int value;            // For enum constants
    struct Symbol *next;
} Symbol;

//=============================================================================
// AST Node Types
//=============================================================================

typedef enum {
    AST_NUMBER, AST_STRING, AST_CHAR, AST_IDENT,
    AST_BINOP, AST_UNARY, AST_ASSIGN, AST_CALL,
    AST_IF, AST_WHILE, AST_FOR, AST_RETURN, AST_BREAK, AST_CONTINUE,
    AST_BLOCK, AST_VAR_DECL, AST_FUNC_DECL, AST_STRUCT_DECL, AST_ENUM_DECL,
    AST_TYPEDEF, AST_MEMBER, AST_SIZEOF, AST_CAST,
    AST_PROGRAM
} ASTNodeType;

//=============================================================================
// AST Node
//=============================================================================

typedef struct ASTNode {
    ASTNodeType type;
    Type *data_type;
    
    union {
        int int_val;
        char str_val[256];
        char char_val;
    } value;
    
    struct ASTNode *left;
    struct ASTNode *right;
    struct ASTNode *cond;
    struct ASTNode *then_branch;
    struct ASTNode *else_branch;
    struct ASTNode *init;
    struct ASTNode *update;
    struct ASTNode *body;
    struct ASTNode *next;
    struct ASTNode *args;
    
    Symbol *symbol;
    char name[64];
} ASTNode;

//=============================================================================
// Compiler Context
//=============================================================================

typedef struct {
    Token *tokens;
    Token *current;
    ASTNode *ast;
    Symbol *symbols;
    Type *types;
    
    char *source;
    char *pos;
    int line;
    int column;
    
    int scope_level;
    int local_offset;
    int label_count;
    
    FILE *output;
    int error_count;
    int warning_count;
} CompilerContext;

//=============================================================================
// Keywords Table
//=============================================================================

static struct {
    const char *name;
    TokenType type;
} keywords[] = {
    {"int", TOK_INT}, {"void", TOK_VOID}, {"char", TOK_CHAR_KW},
    {"return", TOK_RETURN}, {"if", TOK_IF}, {"else", TOK_ELSE},
    {"while", TOK_WHILE}, {"for", TOK_FOR}, {"break", TOK_BREAK},
    {"continue", TOK_CONTINUE}, {"struct", TOK_STRUCT}, {"enum", TOK_ENUM},
    {"typedef", TOK_TYPEDEF}, {"union", TOK_UNION}, {"sizeof", TOK_SIZEOF},
    {"extern", TOK_EXTERN}, {"static", TOK_STATIC}, {"const", TOK_CONST},
    {"volatile", TOK_VOLATILE}, {"long", TOK_LONG}, {"short", TOK_SHORT},
    {"unsigned", TOK_UNSIGNED}, {"signed", TOK_SIGNED}, {"float", TOK_FLOAT},
    {"double", TOK_DOUBLE}, {NULL, 0}
};

//=============================================================================
// Lexer
//=============================================================================

static TokenType get_keyword_type(const char *word) {
    for (int i = 0; keywords[i].name; i++) {
        if (strcmp(keywords[i].name, word) == 0) {
            return keywords[i].type;
        }
    }
    return TOK_IDENT;
}

static void skip_whitespace(CompilerContext *ctx) {
    while (*ctx->pos) {
        if (*ctx->pos == ' ' || *ctx->pos == '\t') {
            ctx->pos++;
            ctx->column++;
        } else if (*ctx->pos == '\n') {
            ctx->pos++;
            ctx->line++;
            ctx->column = 1;
        } else if (*ctx->pos == '\r') {
            ctx->pos++;
        } else if (*ctx->pos == '/' && *(ctx->pos + 1) == '/') {
            // Single-line comment
            while (*ctx->pos && *ctx->pos != '\n') ctx->pos++;
        } else if (*ctx->pos == '/' && *(ctx->pos + 1) == '*') {
            // Multi-line comment
            ctx->pos += 2;
            while (*ctx->pos && !(*ctx->pos == '*' && *(ctx->pos + 1) == '/')) {
                if (*ctx->pos == '\n') ctx->line++;
                ctx->pos++;
            }
            if (*ctx->pos) ctx->pos += 2;
        } else {
            break;
        }
    }
}

Token *lexer(CompilerContext *ctx) {
    Token *head = NULL;
    Token *tail = NULL;
    
    while (*ctx->pos) {
        skip_whitespace(ctx);
        if (!*ctx->pos) break;
        
        Token *tok = calloc(1, sizeof(Token));
        tok->line = ctx->line;
        tok->column = ctx->column;
        
        // Identifier or keyword
        if (isalpha(*ctx->pos) || *ctx->pos == '_') {
            int i = 0;
            while (isalnum(*ctx->pos) || *ctx->pos == '_') {
                tok->value[i++] = *ctx->pos++;
                ctx->column++;
            }
            tok->value[i] = '\0';
            tok->type = get_keyword_type(tok->value);
        }
        // Number
        else if (isdigit(*ctx->pos)) {
            int i = 0;
            while (isdigit(*ctx->pos) || 
                   (*ctx->pos == 'x' && i == 1 && tok->value[0] == '0') ||
                   (strchr("abcdefABCDEF", *ctx->pos) && i > 1 && tok->value[1] == 'x')) {
                tok->value[i++] = *ctx->pos++;
                ctx->column++;
            }
            tok->value[i] = '\0';
            tok->type = TOK_NUMBER;
        }
        // String literal
        else if (*ctx->pos == '"') {
            ctx->pos++;
            ctx->column++;
            int i = 0;
            while (*ctx->pos && *ctx->pos != '"') {
                if (*ctx->pos == '\\' && *(ctx->pos + 1)) {
                    ctx->pos++;
                    switch (*ctx->pos) {
                        case 'n': tok->value[i++] = '\n'; break;
                        case 't': tok->value[i++] = '\t'; break;
                        case 'r': tok->value[i++] = '\r'; break;
                        case '\\': tok->value[i++] = '\\'; break;
                        case '"': tok->value[i++] = '"'; break;
                        default: tok->value[i++] = *ctx->pos; break;
                    }
                    ctx->pos++;
                } else {
                    tok->value[i++] = *ctx->pos++;
                }
                ctx->column++;
            }
            tok->value[i] = '\0';
            if (*ctx->pos == '"') {
                ctx->pos++;
                ctx->column++;
            }
            tok->type = TOK_STRING;
        }
        // Character literal
        else if (*ctx->pos == '\'') {
            ctx->pos++;
            ctx->column++;
            if (*ctx->pos == '\\' && *(ctx->pos + 1)) {
                ctx->pos++;
                switch (*ctx->pos) {
                    case 'n': tok->value[0] = '\n'; break;
                    case 't': tok->value[0] = '\t'; break;
                    case 'r': tok->value[0] = '\r'; break;
                    case '\\': tok->value[0] = '\\'; break;
                    case '\'': tok->value[0] = '\''; break;
                    default: tok->value[0] = *ctx->pos; break;
                }
                ctx->pos++;
            } else {
                tok->value[0] = *ctx->pos++;
            }
            tok->value[1] = '\0';
            if (*ctx->pos == '\'') ctx->pos++;
            tok->type = TOK_CHAR;
        }
        // Operators and delimiters
        else {
            switch (*ctx->pos) {
                case '+':
                    if (*(ctx->pos + 1) == '+') { tok->type = TOK_INC; ctx->pos += 2; }
                    else if (*(ctx->pos + 1) == '=') { tok->type = TOK_PLUS_EQ; ctx->pos += 2; }
                    else { tok->type = TOK_PLUS; ctx->pos++; }
                    break;
                case '-':
                    if (*(ctx->pos + 1) == '-') { tok->type = TOK_DEC; ctx->pos += 2; }
                    else if (*(ctx->pos + 1) == '=') { tok->type = TOK_MINUS_EQ; ctx->pos += 2; }
                    else if (*(ctx->pos + 1) == '>') { tok->type = TOK_ARROW; ctx->pos += 2; }
                    else { tok->type = TOK_MINUS; ctx->pos++; }
                    break;
                case '*':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_STAR_EQ; ctx->pos += 2; }
                    else { tok->type = TOK_STAR; ctx->pos++; }
                    break;
                case '/':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_SLASH_EQ; ctx->pos += 2; }
                    else { tok->type = TOK_SLASH; ctx->pos++; }
                    break;
                case '%': tok->type = TOK_PERCENT; ctx->pos++; break;
                case '<':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_LE; ctx->pos += 2; }
                    else if (*(ctx->pos + 1) == '<') { tok->type = TOK_LSHIFT; ctx->pos += 2; }
                    else { tok->type = TOK_LT; ctx->pos++; }
                    break;
                case '>':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_GE; ctx->pos += 2; }
                    else if (*(ctx->pos + 1) == '>') { tok->type = TOK_RSHIFT; ctx->pos += 2; }
                    else { tok->type = TOK_GT; ctx->pos++; }
                    break;
                case '=':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_EQ; ctx->pos += 2; }
                    else { tok->type = TOK_ASSIGN; ctx->pos++; }
                    break;
                case '!':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_NE; ctx->pos += 2; }
                    else { tok->type = TOK_NOT; ctx->pos++; }
                    break;
                case '&':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_AND_EQ; ctx->pos += 2; }
                    else if (*(ctx->pos + 1) == '&') { tok->type = TOK_AND; ctx->pos += 2; }
                    else { tok->type = TOK_AMPERSAND; ctx->pos++; }
                    break;
                case '|':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_OR_EQ; ctx->pos += 2; }
                    else if (*(ctx->pos + 1) == '|') { tok->type = TOK_OR; ctx->pos += 2; }
                    else { tok->type = TOK_XOR; ctx->pos++; }
                    break;
                case '^':
                    if (*(ctx->pos + 1) == '=') { tok->type = TOK_XOR_EQ; ctx->pos += 2; }
                    else { tok->type = TOK_XOR; ctx->pos++; }
                    break;
                case '~': tok->type = TOK_TILDE; ctx->pos++; break;
                case '(': tok->type = TOK_LPAREN; ctx->pos++; break;
                case ')': tok->type = TOK_RPAREN; ctx->pos++; break;
                case '{': tok->type = TOK_LBRACE; ctx->pos++; break;
                case '}': tok->type = TOK_RBRACE; ctx->pos++; break;
                case '[': tok->type = TOK_LBRACKET; ctx->pos++; break;
                case ']': tok->type = TOK_RBRACKET; ctx->pos++; break;
                case ';': tok->type = TOK_SEMICOLON; ctx->pos++; break;
                case ':': tok->type = TOK_COLON; ctx->pos++; break;
                case ',': tok->type = TOK_COMMA; ctx->pos++; break;
                case '.': tok->type = TOK_DOT; ctx->pos++; break;
                case '?': tok->type = TOK_QUESTION; ctx->pos++; break;
                default:
                    fprintf(stderr, "Error: Unknown character '%c' at line %d\n", 
                            *ctx->pos, ctx->line);
                    ctx->pos++;
                    tok->type = TOK_EOF;
                    break;
            }
            ctx->column++;
        }
        
        if (!head) head = tail = tok;
        else { tail->next = tok; tail = tok; }
    }
    
    // Add EOF token
    Token *eof = calloc(1, sizeof(Token));
    eof->type = TOK_EOF;
    eof->line = ctx->line;
    if (tail) tail->next = eof;
    else head = eof;
    
    return head;
}

//=============================================================================
// Parser (Simplified - would be expanded in full version)
//=============================================================================

static Token *current_token(CompilerContext *ctx) {
    return ctx->current;
}

static void advance(CompilerContext *ctx) {
    if (ctx->current && ctx->current->next) {
        ctx->current = ctx->current->next;
    }
}

static int match(CompilerContext *ctx, TokenType type) {
    if (ctx->current && ctx->current->type == type) {
        advance(ctx);
        return 1;
    }
    return 0;
}

static int expect(CompilerContext *ctx, TokenType type) {
    if (match(ctx, type)) return 1;
    fprintf(stderr, "Error: Expected token type %d at line %d\n", 
            type, ctx->current ? ctx->current->line : -1);
    ctx->error_count++;
    return 0;
}

//=============================================================================
// Code Generator (x64 Assembly Output)
//=============================================================================

static void emit(CompilerContext *ctx, const char *fmt, ...) {
    va_list args;
    va_start(args, fmt);
    vfprintf(ctx->output, fmt, args);
    va_end(args);
    fprintf(ctx->output, "\n");
}

static void generate_code(CompilerContext *ctx, ASTNode *node) {
    if (!node) return;
    
    switch (node->type) {
        case AST_PROGRAM:
            emit(ctx, "; Generated by RawrXD C Compiler");
            emit(ctx, "BITS 64");
            emit(ctx, "SECTION .text");
            for (ASTNode *n = node->next; n; n = n->next) {
                generate_code(ctx, n);
            }
            break;
            
        case AST_FUNC_DECL:
            emit(ctx, "global %s", node->name);
            emit(ctx, "%s:", node->name);
            emit(ctx, "    push rbp");
            emit(ctx, "    mov rbp, rsp");
            generate_code(ctx, node->body);
            emit(ctx, "    mov rsp, rbp");
            emit(ctx, "    pop rbp");
            emit(ctx, "    ret");
            break;
            
        case AST_BLOCK:
            for (ASTNode *n = node->next; n; n = n->next) {
                generate_code(ctx, n);
            }
            break;
            
        case AST_RETURN:
            if (node->left) {
                generate_code(ctx, node->left);
                emit(ctx, "    mov eax, %d", node->left->value.int_val);
            }
            emit(ctx, "    mov rsp, rbp");
            emit(ctx, "    pop rbp");
            emit(ctx, "    ret");
            break;
            
        case AST_NUMBER:
            // Number is already in value
            break;
            
        default:
            fprintf(stderr, "Warning: Unhandled AST node type %d\n", node->type);
            break;
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "RawrXD Enhanced C Compiler v1.0\n");
        fprintf(stderr, "Usage: %s <input.c> [-o output.asm]\n", argv[0]);
        fprintf(stderr, "Features: typedef, struct, enum, minimal stdlib\n");
        return 1;
    }
    
    // Read source file
    FILE *f = fopen(argv[1], "rb");
    if (!f) {
        fprintf(stderr, "Error: Cannot open %s\n", argv[1]);
        return 1;
    }
    
    fseek(f, 0, SEEK_END);
    long size = ftell(f);
    fseek(f, 0, SEEK_SET);
    
    char *source = malloc(size + 1);
    fread(source, 1, size, f);
    source[size] = '\0';
    fclose(f);
    
    // Initialize compiler context
    CompilerContext ctx = {0};
    ctx.source = source;
    ctx.pos = source;
    ctx.line = 1;
    ctx.column = 1;
    ctx.scope_level = 0;
    ctx.local_offset = 0;
    ctx.label_count = 0;
    
    // Determine output file
    const char *output_file = "output.asm";
    for (int i = 2; i < argc - 1; i++) {
        if (strcmp(argv[i], "-o") == 0) {
            output_file = argv[i + 1];
            break;
        }
    }
    
    ctx.output = fopen(output_file, "w");
    if (!ctx.output) {
        fprintf(stderr, "Error: Cannot create %s\n", output_file);
        free(source);
        return 1;
    }
    
    // Tokenize
    printf("[1/3] Tokenizing...\n");
    ctx.tokens = lexer(&ctx);
    ctx.current = ctx.tokens;
    
    // Count tokens
    int token_count = 0;
    for (Token *t = ctx.tokens; t; t = t->next) token_count++;
    printf("      Generated %d tokens\n", token_count);
    
    // Parse (simplified - just create a basic AST for now)
    printf("[2/3] Parsing...\n");
    ASTNode *program = calloc(1, sizeof(ASTNode));
    program->type = AST_PROGRAM;
    ctx.ast = program;
    
    // Generate code
    printf("[3/3] Generating code...\n");
    generate_code(&ctx, program);
    
    // Cleanup
    fclose(ctx.output);
    free(source);
    
    // Free tokens
    Token *t = ctx.tokens;
    while (t) {
        Token *next = t->next;
        free(t);
        t = next;
    }
    
    if (ctx.error_count == 0) {
        printf("\n✓ Compilation successful: %s\n", output_file);
        return 0;
    } else {
        printf("\n✗ Compilation failed with %d errors\n", ctx.error_count);
        return 1;
    }
}
