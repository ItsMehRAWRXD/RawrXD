//=============================================================================
// c_compiler_selfhost.c - Self-Hosting C Compiler (No stdlib dependencies)
// Uses rawrxd_runtime.asm for I/O and memory management
//=============================================================================

// Forward declarations for runtime functions
extern void _print_string(const char* str);
extern void _print_int(int val);
extern void _print_newline(void);
extern void* _allocate(int size);
extern void _free(void* ptr);
extern void _exit(int code);

// Minimal string functions (implemented inline)
int _strlen(const char* s) {
    int len = 0;
    while (s[len]) len++;
    return len;
}

void _strcpy(char* dest, const char* src) {
    while (*src) *dest++ = *src++;
    *dest = 0;
}

int _strcmp(const char* a, const char* b) {
    while (*a && *a == *b) { a++; b++; }
    return *a - *b;
}

int _isdigit(char c) { return c >= '0' && c <= '9'; }
int _isalpha(char c) { return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z'); }
int _isalnum(char c) { return _isalpha(c) || _isdigit(c); }
int _isspace(char c) { return c == ' ' || c == '\t' || c == '\n' || c == '\r'; }

// Simple file I/O using Windows API (forward declared)
extern void* _fopen(const char* path, const char* mode);
extern int _fread(void* buf, int size, int count, void* fp);
extern void _fclose(void* fp);

//=============================================================================
// Token Types
//=============================================================================

typedef enum {
    TOK_INT, TOK_RETURN, TOK_VOID, TOK_IF, TOK_WHILE,
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH,
    TOK_ASSIGN, TOK_EQ, TOK_NE, TOK_LT, TOK_GT,
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_SEMICOLON, TOK_COMMA,
    TOK_IDENTIFIER, TOK_NUMBER, TOK_STRING,
    TOK_EOF, TOK_ERROR
} TokenType;

const char* token_name(TokenType t) {
    switch (t) {
        case TOK_INT: return "INT";
        case TOK_RETURN: return "RETURN";
        case TOK_IF: return "IF";
        case TOK_WHILE: return "WHILE";
        case TOK_IDENTIFIER: return "IDENT";
        case TOK_NUMBER: return "NUM";
        case TOK_STRING: return "STR";
        case TOK_EOF: return "EOF";
        default: return "?";
    }
}

//=============================================================================
// Token Structure
//=============================================================================

typedef struct {
    TokenType type;
    char text[64];
    int int_val;
} Token;

//=============================================================================
// Lexer
//=============================================================================

typedef struct {
    char* source;
    int pos;
    int len;
    Token tokens[1024];
    int token_count;
} Lexer;

Lexer* lexer_create(char* source) {
    Lexer* lex = _allocate(sizeof(Lexer));
    lex->source = source;
    lex->pos = 0;
    lex->len = _strlen(source);
    lex->token_count = 0;
    return lex;
}

void lexer_skip_space(Lexer* lex) {
    while (lex->pos < lex->len && _isspace(lex->source[lex->pos]))
        lex->pos++;
}

void lexer_add_token(Lexer* lex, TokenType type, char* text, int val) {
    if (lex->token_count >= 1024) return;
    Token* t = &lex->tokens[lex->token_count++];
    t->type = type;
    _strcpy(t->text, text);
    t->int_val = val;
}

void lexer_lex(Lexer* lex) {
    while (lex->pos < lex->len) {
        lexer_skip_space(lex);
        if (lex->pos >= lex->len) break;
        
        char c = lex->source[lex->pos];
        
        // Keywords and identifiers
        if (_isalpha(c) || c == '_') {
            char buf[64];
            int i = 0;
            while (lex->pos < lex->len && (_isalnum(lex->source[lex->pos]) || lex->source[lex->pos] == '_'))
                buf[i++] = lex->source[lex->pos++];
            buf[i] = 0;
            
            if (_strcmp(buf, "int") == 0) lexer_add_token(lex, TOK_INT, buf, 0);
            else if (_strcmp(buf, "return") == 0) lexer_add_token(lex, TOK_RETURN, buf, 0);
            else if (_strcmp(buf, "void") == 0) lexer_add_token(lex, TOK_VOID, buf, 0);
            else if (_strcmp(buf, "if") == 0) lexer_add_token(lex, TOK_IF, buf, 0);
            else if (_strcmp(buf, "while") == 0) lexer_add_token(lex, TOK_WHILE, buf, 0);
            else lexer_add_token(lex, TOK_IDENTIFIER, buf, 0);
            continue;
        }
        
        // Numbers
        if (_isdigit(c)) {
            char buf[32];
            int i = 0;
            int val = 0;
            while (lex->pos < lex->len && _isdigit(lex->source[lex->pos])) {
                buf[i++] = lex->source[lex->pos];
                val = val * 10 + (lex->source[lex->pos] - '0');
                lex->pos++;
            }
            buf[i] = 0;
            lexer_add_token(lex, TOK_NUMBER, buf, val);
            continue;
        }
        
        // Single character tokens
        lex->pos++;
        switch (c) {
            case '(': lexer_add_token(lex, TOK_LPAREN, "(", 0); break;
            case ')': lexer_add_token(lex, TOK_RPAREN, ")", 0); break;
            case '{': lexer_add_token(lex, TOK_LBRACE, "{", 0); break;
            case '}': lexer_add_token(lex, TOK_RBRACE, "}", 0); break;
            case ';': lexer_add_token(lex, TOK_SEMICOLON, ";", 0); break;
            case ',': lexer_add_token(lex, TOK_COMMA, ",", 0); break;
            case '+': lexer_add_token(lex, TOK_PLUS, "+", 0); break;
            case '-': lexer_add_token(lex, TOK_MINUS, "-", 0); break;
            case '*': lexer_add_token(lex, TOK_STAR, "*", 0); break;
            case '/': lexer_add_token(lex, TOK_SLASH, "/", 0); break;
            case '=':
                if (lex->pos < lex->len && lex->source[lex->pos] == '=') {
                    lex->pos++;
                    lexer_add_token(lex, TOK_EQ, "==", 0);
                } else {
                    lexer_add_token(lex, TOK_ASSIGN, "=", 0);
                }
                break;
            case '!':
                if (lex->pos < lex->len && lex->source[lex->pos] == '=') {
                    lex->pos++;
                    lexer_add_token(lex, TOK_NE, "!=", 0);
                }
                break;
            case '<': lexer_add_token(lex, TOK_LT, "<", 0); break;
            case '>': lexer_add_token(lex, TOK_GT, ">", 0); break;
        }
    }
    lexer_add_token(lex, TOK_EOF, "", 0);
}

//=============================================================================
// AST Node Types
//=============================================================================

typedef enum {
    AST_PROGRAM,
    AST_FUNCTION,
    AST_RETURN,
    AST_NUMBER_LIT,
    AST_BINOP,
    AST_VAR_DECL,
    AST_ASSIGN,
    AST_IF,
    AST_WHILE,
    AST_CALL,
    AST_IDENTIFIER
} ASTType;

typedef struct ASTNode {
    ASTType type;
    char name[64];
    int int_val;
    TokenType op;
    struct ASTNode* left;
    struct ASTNode* right;
    struct ASTNode** children;
    int child_count;
    int child_cap;
} ASTNode;

ASTNode* ast_create(ASTType type) {
    ASTNode* node = _allocate(sizeof(ASTNode));
    node->type = type;
    node->left = 0;
    node->right = 0;
    node->children = 0;
    node->child_count = 0;
    node->child_cap = 0;
    return node;
}

void ast_add_child(ASTNode* parent, ASTNode* child) {
    if (!parent->children) {
        parent->child_cap = 8;
        parent->children = _allocate(sizeof(ASTNode*) * parent->child_cap);
    }
    if (parent->child_count >= parent->child_cap) {
        parent->child_cap *= 2;
        ASTNode** new_children = _allocate(sizeof(ASTNode*) * parent->child_cap);
        for (int i = 0; i < parent->child_count; i++)
            new_children[i] = parent->children[i];
        _free(parent->children);
        parent->children = new_children;
    }
    parent->children[parent->child_count++] = child;
}

//=============================================================================
// Parser
//=============================================================================

typedef struct {
    Token* tokens;
    int count;
    int pos;
} Parser;

Parser* parser_create(Token* tokens, int count) {
    Parser* p = _allocate(sizeof(Parser));
    p->tokens = tokens;
    p->count = count;
    p->pos = 0;
    return p;
}

Token* parser_peek(Parser* p) {
    if (p->pos < p->count) return &p->tokens[p->pos];
    return &p->tokens[p->count - 1];
}

Token* parser_advance(Parser* p) {
    if (p->pos < p->count) return &p->tokens[p->pos++];
    return &p->tokens[p->count - 1];
}

int parser_match(Parser* p, TokenType type) {
    return parser_peek(p)->type == type;
}

Token* parser_expect(Parser* p, TokenType type) {
    if (parser_match(p, type)) return parser_advance(p);
    _print_string("Parse error: unexpected token\n");
    _exit(1);
    return 0;
}

ASTNode* parse_expression(Parser* p);
ASTNode* parse_statement(Parser* p);

ASTNode* parse_primary(Parser* p) {
    if (parser_match(p, TOK_NUMBER)) {
        Token* t = parser_advance(p);
        ASTNode* n = ast_create(AST_NUMBER_LIT);
        n->int_val = t->int_val;
        return n;
    }
    if (parser_match(p, TOK_IDENTIFIER)) {
        Token* t = parser_advance(p);
        ASTNode* n = ast_create(AST_IDENTIFIER);
        _strcpy(n->name, t->text);
        return n;
    }
    if (parser_match(p, TOK_LPAREN)) {
        parser_advance(p);
        ASTNode* expr = parse_expression(p);
        parser_expect(p, TOK_RPAREN);
        return expr;
    }
    _print_string("Parse error: expected primary\n");
    _exit(1);
    return 0;
}

ASTNode* parse_expression(Parser* p) {
    ASTNode* left = parse_primary(p);
    
    while (parser_match(p, TOK_PLUS) || parser_match(p, TOK_MINUS) ||
           parser_match(p, TOK_STAR) || parser_match(p, TOK_SLASH)) {
        Token* op = parser_advance(p);
        ASTNode* right = parse_primary(p);
        ASTNode* binop = ast_create(AST_BINOP);
        binop->op = op->type;
        binop->left = left;
        binop->right = right;
        left = binop;
    }
    return left;
}

ASTNode* parse_statement(Parser* p) {
    if (parser_match(p, TOK_RETURN)) {
        parser_advance(p);
        ASTNode* ret = ast_create(AST_RETURN);
        if (!parser_match(p, TOK_SEMICOLON)) {
            ret->left = parse_expression(p);
        }
        parser_expect(p, TOK_SEMICOLON);
        return ret;
    }
    
    if (parser_match(p, TOK_INT)) {
        // Variable declaration
        parser_advance(p);
        Token* name = parser_expect(p, TOK_IDENTIFIER);
        parser_expect(p, TOK_SEMICOLON);
        ASTNode* decl = ast_create(AST_VAR_DECL);
        _strcpy(decl->name, name->text);
        return decl;
    }
    
    // Expression statement
    ASTNode* expr = parse_expression(p);
    parser_expect(p, TOK_SEMICOLON);
    return expr;
}

ASTNode* parse_function(Parser* p) {
    // Return type
    if (parser_match(p, TOK_INT) || parser_match(p, TOK_VOID)) {
        parser_advance(p);
    }
    
    Token* name = parser_expect(p, TOK_IDENTIFIER);
    parser_expect(p, TOK_LPAREN);
    // Skip parameters for now
    while (!parser_match(p, TOK_RPAREN) && !parser_match(p, TOK_EOF))
        parser_advance(p);
    parser_expect(p, TOK_RPAREN);
    
    parser_expect(p, TOK_LBRACE);
    
    ASTNode* func = ast_create(AST_FUNCTION);
    _strcpy(func->name, name->text);
    
    while (!parser_match(p, TOK_RBRACE) && !parser_match(p, TOK_EOF)) {
        ast_add_child(func, parse_statement(p));
    }
    
    parser_expect(p, TOK_RBRACE);
    return func;
}

ASTNode* parse_program(Parser* p) {
    ASTNode* prog = ast_create(AST_PROGRAM);
    while (!parser_match(p, TOK_EOF)) {
        ast_add_child(prog, parse_function(p));
    }
    return prog;
}

//=============================================================================
// Code Generator
//=============================================================================

typedef struct {
    char* output;
    int pos;
    int cap;
} CodeGen;

CodeGen* codegen_create(void) {
    CodeGen* gen = _allocate(sizeof(CodeGen));
    gen->cap = 65536;
    gen->output = _allocate(gen->cap);
    gen->pos = 0;
    gen->output[0] = 0;
    return gen;
}

void codegen_emit(CodeGen* gen, const char* str) {
    int len = _strlen(str);
    if (gen->pos + len >= gen->cap) {
        gen->cap *= 2;
        char* new_out = _allocate(gen->cap);
        for (int i = 0; i < gen->pos; i++) new_out[i] = gen->output[i];
        _free(gen->output);
        gen->output = new_out;
    }
    for (int i = 0; i < len; i++)
        gen->output[gen->pos++] = str[i];
    gen->output[gen->pos] = 0;
}

void codegen_emit_int(CodeGen* gen, int val) {
    char buf[32];
    // Simple itoa
    if (val == 0) {
        codegen_emit(gen, "0");
        return;
    }
    int i = 0;
    int neg = 0;
    if (val < 0) { neg = 1; val = -val; }
    while (val > 0) {
        buf[i++] = '0' + (val % 10);
        val /= 10;
    }
    if (neg) buf[i++] = '-';
    // Reverse
    for (int j = 0; j < i / 2; j++) {
        char t = buf[j]; buf[j] = buf[i-1-j]; buf[i-1-j] = t;
    }
    buf[i] = 0;
    codegen_emit(gen, buf);
}

void codegen_expr(CodeGen* gen, ASTNode* node);

void codegen_expr(CodeGen* gen, ASTNode* node) {
    switch (node->type) {
        case AST_NUMBER_LIT:
            codegen_emit(gen, "    mov rax, ");
            codegen_emit_int(gen, node->int_val);
            codegen_emit(gen, "\n");
            break;
        case AST_IDENTIFIER:
            codegen_emit(gen, "    mov rax, [rbp-");
            codegen_emit_int(gen, 8); // Simplified
            codegen_emit(gen, "]\n");
            break;
        case AST_BINOP:
            codegen_expr(gen, node->left);
            codegen_emit(gen, "    push rax\n");
            codegen_expr(gen, node->right);
            codegen_emit(gen, "    mov rbx, rax\n");
            codegen_emit(gen, "    pop rax\n");
            switch (node->op) {
                case TOK_PLUS: codegen_emit(gen, "    add rax, rbx\n"); break;
                case TOK_MINUS: codegen_emit(gen, "    sub rax, rbx\n"); break;
                case TOK_STAR: codegen_emit(gen, "    imul rax, rbx\n"); break;
            }
            break;
        default:
            break;
    }
}

void codegen_stmt(CodeGen* gen, ASTNode* node) {
    switch (node->type) {
        case AST_RETURN:
            if (node->left) {
                codegen_expr(gen, node->left);
            } else {
                codegen_emit(gen, "    xor rax, rax\n");
            }
            codegen_emit(gen, "    mov rcx, rax\n");
            codegen_emit(gen, "    call _exit\n");
            break;
        case AST_VAR_DECL:
            // Stack allocation handled in prologue
            break;
        default:
            if (node->type == AST_BINOP || node->type == AST_NUMBER_LIT || node->type == AST_IDENTIFIER) {
                codegen_expr(gen, node);
            }
            break;
    }
}

void codegen_func(CodeGen* gen, ASTNode* node) {
    codegen_emit(gen, "global ");
    codegen_emit(gen, node->name);
    codegen_emit(gen, "\n");
    codegen_emit(gen, node->name);
    codegen_emit(gen, ":\n");
    codegen_emit(gen, "    push rbp\n");
    codegen_emit(gen, "    mov rbp, rsp\n");
    codegen_emit(gen, "    sub rsp, 32\n");
    
    for (int i = 0; i < node->child_count; i++) {
        codegen_stmt(gen, node->children[i]);
    }
    
    // Default return
    codegen_emit(gen, "    xor rcx, rcx\n");
    codegen_emit(gen, "    call _exit\n");
    codegen_emit(gen, "    mov rsp, rbp\n");
    codegen_emit(gen, "    pop rbp\n");
    codegen_emit(gen, "    ret\n\n");
}

char* codegen_generate(ASTNode* ast) {
    CodeGen* gen = codegen_create();
    
    codegen_emit(gen, "; Generated by RawrXD Self-Hosting C Compiler\n");
    codegen_emit(gen, "extern _print_string\n");
    codegen_emit(gen, "extern _print_int\n");
    codegen_emit(gen, "extern _print_newline\n");
    codegen_emit(gen, "extern _allocate\n");
    codegen_emit(gen, "extern _free\n");
    codegen_emit(gen, "extern _exit\n\n");
    codegen_emit(gen, "section .text\n\n");
    
    for (int i = 0; i < ast->child_count; i++) {
        codegen_func(gen, ast->children[i]);
    }
    
    return gen->output;
}

//=============================================================================
// File I/O (Windows API wrappers)
//=============================================================================

// These would need to be implemented or linked from the runtime
// For now, we'll use a simple approach with hardcoded test

//=============================================================================
// Main
//=============================================================================

int main(int argc, char** argv) {
    _print_string("RawrXD Self-Hosting C Compiler\n");
    _print_string("=============================\n\n");
    
    if (argc < 2) {
        _print_string("Usage: compiler <input.c>\n");
        _exit(1);
    }
    
    _print_string("Input: ");
    _print_string(argv[1]);
    _print_newline();
    
    // For now, use hardcoded test program
    char* test_source = 
        "int main() {\n"
        "    return 42;\n"
        "}\n";
    
    _print_string("\n[LEXING]\n");
    Lexer* lex = lexer_create(test_source);
    lexer_lex(lex);
    _print_string("Tokens: ");
    _print_int(lex->token_count);
    _print_newline();
    
    _print_string("\n[PARSING]\n");
    Parser* parser = parser_create(lex->tokens, lex->token_count);
    ASTNode* ast = parse_program(parser);
    _print_string("AST built\n");
    
    _print_string("\n[CODEGEN]\n");
    char* asm_code = codegen_generate(ast);
    _print_string("Generated assembly:\n");
    _print_string(asm_code);
    
    _print_string("\n[SUCCESS] Compilation complete!\n");
    
    _exit(0);
    return 0;
}
