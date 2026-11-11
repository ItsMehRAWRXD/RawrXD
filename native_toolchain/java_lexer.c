//=============================================================================
// java_lexer.c - Java Language Lexer
// Part of RawrXD Native Toolchain - Batch 3: Additional Language Frontends
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <stdint.h>

#define MAX_TOKEN_TEXT 256
#define MAX_TOKENS 65536
#define MAX_ERRORS 256
#define MAX_STRING_LENGTH 4096

//=============================================================================
// Java Token Types
//=============================================================================
typedef enum {
    // Keywords
    TOK_ABSTRACT, TOK_ASSERT, TOK_BOOLEAN, TOK_BREAK, TOK_BYTE,
    TOK_CASE, TOK_CATCH, TOK_CHAR, TOK_CLASS, TOK_CONST,
    TOK_CONTINUE, TOK_DEFAULT, TOK_DO, TOK_DOUBLE, TOK_ELSE,
    TOK_ENUM, TOK_EXTENDS, TOK_FINAL, TOK_FINALLY, TOK_FLOAT,
    TOK_FOR, TOK_GOTO, TOK_IF, TOK_IMPLEMENTS, TOK_IMPORT,
    TOK_INSTANCEOF, TOK_INT, TOK_INTERFACE, TOK_LONG, TOK_NATIVE,
    TOK_NEW, TOK_PACKAGE, TOK_PRIVATE, TOK_PROTECTED, TOK_PUBLIC,
    TOK_RETURN, TOK_SHORT, TOK_STATIC, TOK_STRICTFP, TOK_SUPER,
    TOK_SWITCH, TOK_SYNCHRONIZED, TOK_THIS, TOK_THROW, TOK_THROWS,
    TOK_TRANSIENT, TOK_TRY, TOK_VOID, TOK_VOLATILE, TOK_WHILE,
    
    // Literals
    TOK_NULL_LITERAL, TOK_TRUE_LITERAL, TOK_FALSE_LITERAL,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_INC, TOK_DEC, TOK_ASSIGN, TOK_PLUS_ASSIGN, TOK_MINUS_ASSIGN,
    TOK_STAR_ASSIGN, TOK_SLASH_ASSIGN, TOK_PERCENT_ASSIGN,
    TOK_AND_ASSIGN, TOK_OR_ASSIGN, TOK_XOR_ASSIGN, TOK_SHL_ASSIGN,
    TOK_SHR_ASSIGN, TOK_USHR_ASSIGN,
    TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_LOGICAL_AND, TOK_LOGICAL_OR, TOK_LOGICAL_NOT,
    TOK_BIT_AND, TOK_BIT_OR, TOK_BIT_XOR, TOK_BIT_NOT,
    TOK_SHL, TOK_SHR, TOK_USHR,
    TOK_TERNARY_QMARK, TOK_COLON, TOK_ARROW,  // -> (lambda)
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET, TOK_SEMICOLON, TOK_COMMA,
    TOK_DOT, TOK_DOUBLE_COLON,  // :: (method reference)
    TOK_ELLIPSIS,  // ... (varargs)
    TOK_AT,  // @ (annotation)
    
    // Literals
    TOK_IDENTIFIER, TOK_INTEGER, TOK_FLOAT_LITERAL, TOK_DOUBLE_LITERAL,
    TOK_STRING, TOK_CHAR_LITERAL, TOK_TEXT_BLOCK,  // Java 15+
    
    // Special
    TOK_EOF, TOK_ERROR, TOK_WHITESPACE, TOK_COMMENT, TOK_DOC_COMMENT,
    TOK_ANNOTATION
} JavaTokenType;

//=============================================================================
// Token Structure
//=============================================================================
typedef struct {
    JavaTokenType type;
    char text[MAX_TOKEN_TEXT];
    int line;
    int column;
    union {
        int64_t int_val;
        double float_val;
        char string_val[MAX_TOKEN_TEXT];
    } value;
} JavaToken;

//=============================================================================
// Lexer State
//=============================================================================
typedef struct {
    const char* source;
    size_t pos;
    size_t length;
    int line;
    int column;
    JavaToken* tokens;
    size_t token_count;
    size_t token_capacity;
    int error_count;
    char errors[MAX_ERRORS][512];
} JavaLexer;

//=============================================================================
// Java Keywords Table
//=============================================================================
typedef struct {
    const char* word;
    JavaTokenType type;
} JavaKeyword;

static const JavaKeyword java_keywords[] = {
    {"abstract", TOK_ABSTRACT}, {"assert", TOK_ASSERT}, {"boolean", TOK_BOOLEAN},
    {"break", TOK_BREAK}, {"byte", TOK_BYTE}, {"case", TOK_CASE},
    {"catch", TOK_CATCH}, {"char", TOK_CHAR}, {"class", TOK_CLASS},
    {"const", TOK_CONST}, {"continue", TOK_CONTINUE}, {"default", TOK_DEFAULT},
    {"do", TOK_DO}, {"double", TOK_DOUBLE}, {"else", TOK_ELSE},
    {"enum", TOK_ENUM}, {"extends", TOK_EXTENDS}, {"final", TOK_FINAL},
    {"finally", TOK_FINALLY}, {"float", TOK_FLOAT}, {"for", TOK_FOR},
    {"goto", TOK_GOTO}, {"if", TOK_IF}, {"implements", TOK_IMPLEMENTS},
    {"import", TOK_IMPORT}, {"instanceof", TOK_INSTANCEOF}, {"int", TOK_INT},
    {"interface", TOK_INTERFACE}, {"long", TOK_LONG}, {"native", TOK_NATIVE},
    {"new", TOK_NEW}, {"package", TOK_PACKAGE}, {"private", TOK_PRIVATE},
    {"protected", TOK_PROTECTED}, {"public", TOK_PUBLIC}, {"return", TOK_RETURN},
    {"short", TOK_SHORT}, {"static", TOK_STATIC}, {"strictfp", TOK_STRICTFP},
    {"super", TOK_SUPER}, {"switch", TOK_SWITCH}, {"synchronized", TOK_SYNCHRONIZED},
    {"this", TOK_THIS}, {"throw", TOK_THROW}, {"throws", TOK_THROWS},
    {"transient", TOK_TRANSIENT}, {"try", TOK_TRY}, {"void", TOK_VOID},
    {"volatile", TOK_VOLATILE}, {"while", TOK_WHILE},
    {NULL, TOK_EOF}
};

//=============================================================================
// Utility Functions
//=============================================================================
static int java_is_ident_start(int c) {
    return isalpha(c) || c == '_' || c == '$';
}

static int java_is_ident_continue(int c) {
    return isalnum(c) || c == '_' || c == '$';
}

static void java_lexer_add_error(JavaLexer* lexer, const char* format, ...) {
    if (lexer->error_count >= MAX_ERRORS) return;
    va_list args;
    va_start(args, format);
    vsnprintf(lexer->errors[lexer->error_count], 512, format, args);
    va_end(args);
    lexer->error_count++;
}

static void java_lexer_add_token(JavaLexer* lexer, JavaTokenType type, const char* text, int line, int col) {
    if (lexer->token_count >= lexer->token_capacity) {
        lexer->token_capacity *= 2;
        lexer->tokens = realloc(lexer->tokens, lexer->token_capacity * sizeof(JavaToken));
    }
    JavaToken* tok = &lexer->tokens[lexer->token_count++];
    tok->type = type;
    strncpy(tok->text, text, MAX_TOKEN_TEXT - 1);
    tok->text[MAX_TOKEN_TEXT - 1] = '\0';
    tok->line = line;
    tok->column = col;
}

static char java_lexer_peek(JavaLexer* lexer) {
    if (lexer->pos >= lexer->length) return '\0';
    return lexer->source[lexer->pos];
}

static char java_lexer_peek_next(JavaLexer* lexer) {
    if (lexer->pos + 1 >= lexer->length) return '\0';
    return lexer->source[lexer->pos + 1];
}

static char java_lexer_advance(JavaLexer* lexer) {
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

static void java_lexer_skip_whitespace(JavaLexer* lexer) {
    while (isspace(java_lexer_peek(lexer))) {
        java_lexer_advance(lexer);
    }
}

//=============================================================================
// Token Recognition Functions
//=============================================================================

static JavaTokenType java_get_keyword_type(const char* word) {
    for (int i = 0; java_keywords[i].word != NULL; i++) {
        if (strcmp(java_keywords[i].word, word) == 0) {
            return java_keywords[i].type;
        }
    }
    return TOK_IDENTIFIER;
}

static void java_lexer_read_identifier(JavaLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    
    while (java_is_ident_continue(java_lexer_peek(lexer)) && i < MAX_TOKEN_TEXT - 1) {
        buffer[i++] = java_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    // Check for boolean literals and null
    if (strcmp(buffer, "true") == 0) {
        java_lexer_add_token(lexer, TOK_TRUE_LITERAL, buffer, start_line, start_col);
    } else if (strcmp(buffer, "false") == 0) {
        java_lexer_add_token(lexer, TOK_FALSE_LITERAL, buffer, start_line, start_col);
    } else if (strcmp(buffer, "null") == 0) {
        java_lexer_add_token(lexer, TOK_NULL_LITERAL, buffer, start_line, start_col);
    } else {
        JavaTokenType type = java_get_keyword_type(buffer);
        java_lexer_add_token(lexer, type, buffer, start_line, start_col);
    }
}

static void java_lexer_read_number(JavaLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_TOKEN_TEXT];
    int i = 0;
    int is_float = 0;
    int is_double = 0;
    int is_long = 0;
    
    // Check for base prefix
    if (java_lexer_peek(lexer) == '0') {
        buffer[i++] = java_lexer_advance(lexer);
        char next = java_lexer_peek(lexer);
        if (next == 'x' || next == 'X') {
            // Hexadecimal
            buffer[i++] = java_lexer_advance(lexer);
            while ((isxdigit(java_lexer_peek(lexer)) || java_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = java_lexer_advance(lexer);
            }
        } else if (next == 'b' || next == 'B') {
            // Binary (Java 7+)
            buffer[i++] = java_lexer_advance(lexer);
            while ((java_lexer_peek(lexer) == '0' || java_lexer_peek(lexer) == '1' ||
                    java_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = java_lexer_advance(lexer);
            }
        } else if (next >= '0' && next <= '7') {
            // Octal
            while (((java_lexer_peek(lexer) >= '0' && java_lexer_peek(lexer) <= '7') ||
                    java_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = java_lexer_advance(lexer);
            }
        }
    } else {
        // Decimal
        while ((isdigit(java_lexer_peek(lexer)) || java_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = java_lexer_advance(lexer);
        }
        
        // Decimal point
        if (java_lexer_peek(lexer) == '.' && isdigit(java_lexer_peek_next(lexer))) {
            is_float = 1;
            buffer[i++] = java_lexer_advance(lexer);
            while ((isdigit(java_lexer_peek(lexer)) || java_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
                buffer[i++] = java_lexer_advance(lexer);
            }
        }
    }
    
    // Exponent
    if (java_lexer_peek(lexer) == 'e' || java_lexer_peek(lexer) == 'E') {
        is_float = 1;
        buffer[i++] = java_lexer_advance(lexer);
        if (java_lexer_peek(lexer) == '+' || java_lexer_peek(lexer) == '-') {
            buffer[i++] = java_lexer_advance(lexer);
        }
        while ((isdigit(java_lexer_peek(lexer)) || java_lexer_peek(lexer) == '_') && i < MAX_TOKEN_TEXT - 1) {
            buffer[i++] = java_lexer_advance(lexer);
        }
    }
    
    // Type suffix
    if (!is_float) {
        if (java_lexer_peek(lexer) == 'l' || java_lexer_peek(lexer) == 'L') {
            is_long = 1;
            buffer[i++] = java_lexer_advance(lexer);
        }
    } else {
        if (java_lexer_peek(lexer) == 'f' || java_lexer_peek(lexer) == 'F') {
            buffer[i++] = java_lexer_advance(lexer);
        } else if (java_lexer_peek(lexer) == 'd' || java_lexer_peek(lexer) == 'D') {
            is_double = 1;
            buffer[i++] = java_lexer_advance(lexer);
        } else {
            is_double = 1;  // Default for floating point
        }
    }
    
    buffer[i] = '\0';
    
    JavaTokenType type;
    if (is_float && !is_double) {
        type = TOK_FLOAT_LITERAL;
    } else if (is_float && is_double) {
        type = TOK_DOUBLE_LITERAL;
    } else {
        type = TOK_INTEGER;
    }
    java_lexer_add_token(lexer, type, buffer, start_line, start_col);
}

static void java_lexer_read_string(JavaLexer* lexer, int is_text_block) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    
    if (is_text_block) {
        // Text block: """...""" (Java 15+)
        java_lexer_advance(lexer); java_lexer_advance(lexer); java_lexer_advance(lexer);  // """
        // Skip optional newline after opening
        if (java_lexer_peek(lexer) == '\r') java_lexer_advance(lexer);
        if (java_lexer_peek(lexer) == '\n') java_lexer_advance(lexer);
        
        while (i < MAX_STRING_LENGTH - 1) {
            if (java_lexer_peek(lexer) == '"' && 
                lexer->pos + 2 < lexer->length &&
                lexer->source[lexer->pos + 1] == '"' &&
                lexer->source[lexer->pos + 2] == '"') {
                java_lexer_advance(lexer); java_lexer_advance(lexer); java_lexer_advance(lexer);
                break;
            }
            if (java_lexer_peek(lexer) == '\0') {
                java_lexer_add_error(lexer, "Unterminated text block at line %d", start_line);
                break;
            }
            buffer[i++] = java_lexer_advance(lexer);
        }
    } else {
        // Regular string
        java_lexer_advance(lexer);  // Opening "
        
        while (java_lexer_peek(lexer) != '"' && java_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
            if (java_lexer_peek(lexer) == '\\') {
                java_lexer_advance(lexer);
                char escape = java_lexer_advance(lexer);
                switch (escape) {
                    case 'n': buffer[i++] = '\n'; break;
                    case 't': buffer[i++] = '\t'; break;
                    case 'r': buffer[i++] = '\r'; break;
                    case 'b': buffer[i++] = '\b'; break;
                    case 'f': buffer[i++] = '\f'; break;
                    case '\\': buffer[i++] = '\\'; break;
                    case '"': buffer[i++] = '"'; break;
                    case '\'': buffer[i++] = '\''; break;
                    case '0': case '1': case '2': case '3':
                    case '4': case '5': case '6': case '7': {
                        // Octal escape
                        int val = escape - '0';
                        if (java_lexer_peek(lexer) >= '0' && java_lexer_peek(lexer) <= '7') {
                            val = val * 8 + (java_lexer_advance(lexer) - '0');
                        }
                        buffer[i++] = (char)val;
                        break;
                    }
                    case 'u': {
                        // Unicode escape \uXXXX
                        char hex[5] = {0};
                        for (int h = 0; h < 4 && isxdigit(java_lexer_peek(lexer)); h++) {
                            hex[h] = java_lexer_advance(lexer);
                        }
                        buffer[i++] = '?';  // Simplified
                        break;
                    }
                    default: buffer[i++] = escape; break;
                }
            } else if (java_lexer_peek(lexer) == '\n') {
                java_lexer_add_error(lexer, "Unterminated string at line %d", start_line);
                break;
            } else {
                buffer[i++] = java_lexer_advance(lexer);
            }
        }
        
        if (java_lexer_peek(lexer) == '"') {
            java_lexer_advance(lexer);
        } else {
            java_lexer_add_error(lexer, "Unterminated string at line %d", start_line);
        }
    }
    
    buffer[i] = '\0';
    java_lexer_add_token(lexer, is_text_block ? TOK_TEXT_BLOCK : TOK_STRING, buffer, start_line, start_col);
}

static void java_lexer_read_char(JavaLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    char buffer[16];
    int i = 0;
    
    java_lexer_advance(lexer);  // '
    
    if (java_lexer_peek(lexer) == '\\') {
        java_lexer_advance(lexer);
        char escape = java_lexer_advance(lexer);
        switch (escape) {
            case 'n': buffer[i++] = '\n'; break;
            case 't': buffer[i++] = '\t'; break;
            case 'r': buffer[i++] = '\r'; break;
            case 'b': buffer[i++] = '\b'; break;
            case 'f': buffer[i++] = '\f'; break;
            case '\\': buffer[i++] = '\\'; break;
            case '\'': buffer[i++] = '\''; break;
            case '"': buffer[i++] = '"'; break;
            case 'u': {
                char hex[5] = {0};
                for (int h = 0; h < 4 && isxdigit(java_lexer_peek(lexer)); h++) {
                    hex[h] = java_lexer_advance(lexer);
                }
                buffer[i++] = '?';
                break;
            }
            default: buffer[i++] = escape; break;
        }
    } else {
        buffer[i++] = java_lexer_advance(lexer);
    }
    
    if (java_lexer_peek(lexer) == '\'') {
        java_lexer_advance(lexer);
    } else {
        java_lexer_add_error(lexer, "Unterminated character literal at line %d", start_line);
    }
    
    buffer[i] = '\0';
    java_lexer_add_token(lexer, TOK_CHAR_LITERAL, buffer, start_line, start_col);
}

static void java_lexer_skip_line_comment(JavaLexer* lexer) {
    java_lexer_advance(lexer);  // /
    java_lexer_advance(lexer);  // /
    
    while (java_lexer_peek(lexer) != '\n' && java_lexer_peek(lexer) != '\0') {
        java_lexer_advance(lexer);
    }
}

static void java_lexer_skip_block_comment(JavaLexer* lexer) {
    int start_line = lexer->line;
    java_lexer_advance(lexer);  // /
    java_lexer_advance(lexer);  // *
    
    while (!(java_lexer_peek(lexer) == '*' && java_lexer_peek_next(lexer) == '/') &&
           java_lexer_peek(lexer) != '\0') {
        java_lexer_advance(lexer);
    }
    
    if (java_lexer_peek(lexer) == '*') {
        java_lexer_advance(lexer);
        java_lexer_advance(lexer);
    } else {
        java_lexer_add_error(lexer, "Unterminated block comment starting at line %d", start_line);
    }
}

static void java_lexer_read_doc_comment(JavaLexer* lexer) {
    int start_line = lexer->line;
    int start_col = lexer->column;
    
    java_lexer_advance(lexer);  // /
    java_lexer_advance(lexer);  // *
    java_lexer_advance(lexer);  // *
    
    char buffer[MAX_STRING_LENGTH];
    int i = 0;
    while (!(java_lexer_peek(lexer) == '*' && java_lexer_peek_next(lexer) == '/') &&
           java_lexer_peek(lexer) != '\0' && i < MAX_STRING_LENGTH - 1) {
        buffer[i++] = java_lexer_advance(lexer);
    }
    buffer[i] = '\0';
    
    if (java_lexer_peek(lexer) == '*') {
        java_lexer_advance(lexer);
        java_lexer_advance(lexer);
    }
    
    java_lexer_add_token(lexer, TOK_DOC_COMMENT, buffer, start_line, start_col);
}

//=============================================================================
// Main Lexer Functions
//=============================================================================

JavaLexer* java_lexer_create(const char* source) {
    JavaLexer* lexer = malloc(sizeof(JavaLexer));
    lexer->source = source;
    lexer->length = strlen(source);
    lexer->pos = 0;
    lexer->line = 1;
    lexer->column = 1;
    lexer->token_capacity = 1024;
    lexer->tokens = malloc(lexer->token_capacity * sizeof(JavaToken));
    lexer->token_count = 0;
    lexer->error_count = 0;
    return lexer;
}

void java_lexer_destroy(JavaLexer* lexer) {
    if (lexer) {
        free(lexer->tokens);
        free(lexer);
    }
}

int java_lexer_tokenize(JavaLexer* lexer) {
    while (lexer->pos < lexer->length) {
        int start_line = lexer->line;
        int start_col = lexer->column;
        char c = java_lexer_peek(lexer);
        
        // Skip whitespace
        if (isspace(c)) {
            java_lexer_advance(lexer);
            continue;
        }
        
        // Comments
        if (c == '/' && java_lexer_peek_next(lexer) == '/') {
            java_lexer_skip_line_comment(lexer);
            continue;
        }
        
        if (c == '/' && java_lexer_peek_next(lexer) == '*') {
            // Check for doc comment
            if (lexer->pos + 2 < lexer->length && lexer->source[lexer->pos + 2] == '*') {
                java_lexer_read_doc_comment(lexer);
            } else {
                java_lexer_skip_block_comment(lexer);
            }
            continue;
        }
        
        // Identifiers and keywords
        if (java_is_ident_start(c)) {
            java_lexer_read_identifier(lexer);
            continue;
        }
        
        // Numbers
        if (isdigit(c)) {
            java_lexer_read_number(lexer);
            continue;
        }
        
        // Strings
        if (c == '"') {
            // Check for text block
            if (lexer->pos + 2 < lexer->length &&
                lexer->source[lexer->pos + 1] == '"' &&
                lexer->source[lexer->pos + 2] == '"') {
                java_lexer_read_string(lexer, 1);
            } else {
                java_lexer_read_string(lexer, 0);
            }
            continue;
        }
        
        // Character literals
        if (c == '\'') {
            java_lexer_read_char(lexer);
            continue;
        }
        
        // Operators and delimiters
        switch (c) {
            case '(': java_lexer_add_token(lexer, TOK_LPAREN, "(", start_line, start_col); java_lexer_advance(lexer); break;
            case ')': java_lexer_add_token(lexer, TOK_RPAREN, ")", start_line, start_col); java_lexer_advance(lexer); break;
            case '{': java_lexer_add_token(lexer, TOK_LBRACE, "{", start_line, start_col); java_lexer_advance(lexer); break;
            case '}': java_lexer_add_token(lexer, TOK_RBRACE, "}", start_line, start_col); java_lexer_advance(lexer); break;
            case '[': java_lexer_add_token(lexer, TOK_LBRACKET, "[", start_line, start_col); java_lexer_advance(lexer); break;
            case ']': java_lexer_add_token(lexer, TOK_RBRACKET, "]", start_line, start_col); java_lexer_advance(lexer); break;
            case ';': java_lexer_add_token(lexer, TOK_SEMICOLON, ";", start_line, start_col); java_lexer_advance(lexer); break;
            case ',': java_lexer_add_token(lexer, TOK_COMMA, ",", start_line, start_col); java_lexer_advance(lexer); break;
            case '@': java_lexer_add_token(lexer, TOK_AT, "@", start_line, start_col); java_lexer_advance(lexer); break;
            case '?': java_lexer_add_token(lexer, TOK_TERNARY_QMARK, "?", start_line, start_col); java_lexer_advance(lexer); break;
            case '~': java_lexer_add_token(lexer, TOK_BIT_NOT, "~", start_line, start_col); java_lexer_advance(lexer); break;
            
            case '+':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '+') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_INC, "++", start_line, start_col);
                } else if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_PLUS_ASSIGN, "+=", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_PLUS, "+", start_line, start_col);
                }
                break;
                
            case '-':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '-') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_DEC, "--", start_line, start_col);
                } else if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_MINUS_ASSIGN, "-=", start_line, start_col);
                } else if (java_lexer_peek(lexer) == '>') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_ARROW, "->", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_MINUS, "-", start_line, start_col);
                }
                break;
                
            case '*':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_STAR_ASSIGN, "*=", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_STAR, "*", start_line, start_col);
                }
                break;
                
            case '/':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_SLASH_ASSIGN, "/=", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_SLASH, "/", start_line, start_col);
                }
                break;
                
            case '%':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_PERCENT_ASSIGN, "%=", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_PERCENT, "%", start_line, start_col);
                }
                break;
                
            case '=':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_EQ, "==", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_ASSIGN, "=", start_line, start_col);
                }
                break;
                
            case '!':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_NE, "!=", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_LOGICAL_NOT, "!", start_line, start_col);
                }
                break;
                
            case '<':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_LE, "<=", start_line, start_col);
                } else if (java_lexer_peek(lexer) == '<') {
                    java_lexer_advance(lexer);
                    if (java_lexer_peek(lexer) == '=') {
                        java_lexer_advance(lexer);
                        java_lexer_add_token(lexer, TOK_SHL_ASSIGN, "<<=", start_line, start_col);
                    } else {
                        java_lexer_add_token(lexer, TOK_SHL, "<<", start_line, start_col);
                    }
                } else {
                    java_lexer_add_token(lexer, TOK_LT, "<", start_line, start_col);
                }
                break;
                
            case '>':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_GE, ">=", start_line, start_col);
                } else if (java_lexer_peek(lexer) == '>') {
                    java_lexer_advance(lexer);
                    if (java_lexer_peek(lexer) == '>') {
                        java_lexer_advance(lexer);
                        if (java_lexer_peek(lexer) == '=') {
                            java_lexer_advance(lexer);
                            java_lexer_add_token(lexer, TOK_USHR_ASSIGN, ">>>=", start_line, start_col);
                        } else {
                            java_lexer_add_token(lexer, TOK_USHR, ">>>", start_line, start_col);
                        }
                    } else if (java_lexer_peek(lexer) == '=') {
                        java_lexer_advance(lexer);
                        java_lexer_add_token(lexer, TOK_SHR_ASSIGN, ">>=", start_line, start_col);
                    } else {
                        java_lexer_add_token(lexer, TOK_SHR, ">>", start_line, start_col);
                    }
                } else {
                    java_lexer_add_token(lexer, TOK_GT, ">", start_line, start_col);
                }
                break;
                
            case '&':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '&') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_LOGICAL_AND, "&&", start_line, start_col);
                } else if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_AND_ASSIGN, "&=", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_BIT_AND, "&", start_line, start_col);
                }
                break;
                
            case '|':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '|') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_LOGICAL_OR, "||", start_line, start_col);
                } else if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_OR_ASSIGN, "|=", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_BIT_OR, "|", start_line, start_col);
                }
                break;
                
            case '^':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '=') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_XOR_ASSIGN, "^=", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_BIT_XOR, "^", start_line, start_col);
                }
                break;
                
            case '.':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == '.' && java_lexer_peek_next(lexer) == '.') {
                    java_lexer_advance(lexer);
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_ELLIPSIS, "...", start_line, start_col);
                } else if (java_lexer_peek(lexer) == '.' && lexer->pos + 1 < lexer->length &&
                           lexer->source[lexer->pos + 1] == '.') {
                    // Method reference ::
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_DOUBLE_COLON, "::", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_DOT, ".", start_line, start_col);
                }
                break;
                
            case ':':
                java_lexer_advance(lexer);
                if (java_lexer_peek(lexer) == ':') {
                    java_lexer_advance(lexer);
                    java_lexer_add_token(lexer, TOK_DOUBLE_COLON, "::", start_line, start_col);
                } else {
                    java_lexer_add_token(lexer, TOK_COLON, ":", start_line, start_col);
                }
                break;
                
            default:
                java_lexer_add_error(lexer, "Unexpected character '%c' at line %d, column %d", c, start_line, start_col);
                java_lexer_advance(lexer);
                break;
        }
    }
    
    java_lexer_add_token(lexer, TOK_EOF, "EOF", lexer->line, lexer->column);
    return lexer->error_count == 0 ? 0 : -1;
}

const char* java_token_type_to_string(JavaTokenType type) {
    switch (type) {
        // Keywords
        case TOK_ABSTRACT: return "ABSTRACT";
        case TOK_ASSERT: return "ASSERT";
        case TOK_BOOLEAN: return "BOOLEAN";
        case TOK_BREAK: return "BREAK";
        case TOK_BYTE: return "BYTE";
        case TOK_CASE: return "CASE";
        case TOK_CATCH: return "CATCH";
        case TOK_CHAR: return "CHAR";
        case TOK_CLASS: return "CLASS";
        case TOK_CONST: return "CONST";
        case TOK_CONTINUE: return "CONTINUE";
        case TOK_DEFAULT: return "DEFAULT";
        case TOK_DO: return "DO";
        case TOK_DOUBLE: return "DOUBLE";
        case TOK_ELSE: return "ELSE";
        case TOK_ENUM: return "ENUM";
        case TOK_EXTENDS: return "EXTENDS";
        case TOK_FINAL: return "FINAL";
        case TOK_FINALLY: return "FINALLY";
        case TOK_FLOAT: return "FLOAT";
        case TOK_FOR: return "FOR";
        case TOK_GOTO: return "GOTO";
        case TOK_IF: return "IF";
        case TOK_IMPLEMENTS: return "IMPLEMENTS";
        case TOK_IMPORT: return "IMPORT";
        case TOK_INSTANCEOF: return "INSTANCEOF";
        case TOK_INT: return "INT";
        case TOK_INTERFACE: return "INTERFACE";
        case TOK_LONG: return "LONG";
        case TOK_NATIVE: return "NATIVE";
        case TOK_NEW: return "NEW";
        case TOK_PACKAGE: return "PACKAGE";
        case TOK_PRIVATE: return "PRIVATE";
        case TOK_PROTECTED: return "PROTECTED";
        case TOK_PUBLIC: return "PUBLIC";
        case TOK_RETURN: return "RETURN";
        case TOK_SHORT: return "SHORT";
        case TOK_STATIC: return "STATIC";
        case TOK_STRICTFP: return "STRICTFP";
        case TOK_SUPER: return "SUPER";
        case TOK_SWITCH: return "SWITCH";
        case TOK_SYNCHRONIZED: return "SYNCHRONIZED";
        case TOK_THIS: return "THIS";
        case TOK_THROW: return "THROW";
        case TOK_THROWS: return "THROWS";
        case TOK_TRANSIENT: return "TRANSIENT";
        case TOK_TRY: return "TRY";
        case TOK_VOID: return "VOID";
        case TOK_VOLATILE: return "VOLATILE";
        case TOK_WHILE: return "WHILE";
        
        // Literals
        case TOK_NULL_LITERAL: return "NULL_LITERAL";
        case TOK_TRUE_LITERAL: return "TRUE_LITERAL";
        case TOK_FALSE_LITERAL: return "FALSE_LITERAL";
        
        // Operators
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_PERCENT: return "PERCENT";
        case TOK_INC: return "INC";
        case TOK_DEC: return "DEC";
        case TOK_ASSIGN: return "ASSIGN";
        case TOK_PLUS_ASSIGN: return "PLUS_ASSIGN";
        case TOK_MINUS_ASSIGN: return "MINUS_ASSIGN";
        case TOK_STAR_ASSIGN: return "STAR_ASSIGN";
        case TOK_SLASH_ASSIGN: return "SLASH_ASSIGN";
        case TOK_PERCENT_ASSIGN: return "PERCENT_ASSIGN";
        case TOK_AND_ASSIGN: return "AND_ASSIGN";
        case TOK_OR_ASSIGN: return "OR_ASSIGN";
        case TOK_XOR_ASSIGN: return "XOR_ASSIGN";
        case TOK_SHL_ASSIGN: return "SHL_ASSIGN";
        case TOK_SHR_ASSIGN: return "SHR_ASSIGN";
        case TOK_USHR_ASSIGN: return "USHR_ASSIGN";
        case TOK_EQ: return "EQ";
        case TOK_NE: return "NE";
        case TOK_LT: return "LT";
        case TOK_GT: return "GT";
        case TOK_LE: return "LE";
        case TOK_GE: return "GE";
        case TOK_LOGICAL_AND: return "LOGICAL_AND";
        case TOK_LOGICAL_OR: return "LOGICAL_OR";
        case TOK_LOGICAL_NOT: return "LOGICAL_NOT";
        case TOK_BIT_AND: return "BIT_AND";
        case TOK_BIT_OR: return "BIT_OR";
        case TOK_BIT_XOR: return "BIT_XOR";
        case TOK_BIT_NOT: return "BIT_NOT";
        case TOK_SHL: return "SHL";
        case TOK_SHR: return "SHR";
        case TOK_USHR: return "USHR";
        case TOK_TERNARY_QMARK: return "TERNARY_QMARK";
        case TOK_COLON: return "COLON";
        case TOK_ARROW: return "ARROW";
        
        // Delimiters
        case TOK_LPAREN: return "LPAREN";
        case TOK_RPAREN: return "RPAREN";
        case TOK_LBRACE: return "LBRACE";
        case TOK_RBRACE: return "RBRACE";
        case TOK_LBRACKET: return "LBRACKET";
        case TOK_RBRACKET: return "RBRACKET";
        case TOK_SEMICOLON: return "SEMICOLON";
        case TOK_COMMA: return "COMMA";
        case TOK_DOT: return "DOT";
        case TOK_DOUBLE_COLON: return "DOUBLE_COLON";
        case TOK_ELLIPSIS: return "ELLIPSIS";
        case TOK_AT: return "AT";
        
        // Literals
        case TOK_IDENTIFIER: return "IDENTIFIER";
        case TOK_INTEGER: return "INTEGER";
        case TOK_FLOAT_LITERAL: return "FLOAT_LITERAL";
        case TOK_DOUBLE_LITERAL: return "DOUBLE_LITERAL";
        case TOK_STRING: return "STRING";
        case TOK_CHAR_LITERAL: return "CHAR_LITERAL";
        case TOK_TEXT_BLOCK: return "TEXT_BLOCK";
        
        // Special
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        case TOK_WHITESPACE: return "WHITESPACE";
        case TOK_COMMENT: return "COMMENT";
        case TOK_DOC_COMMENT: return "DOC_COMMENT";
        case TOK_ANNOTATION: return "ANNOTATION";
        
        default: return "UNKNOWN";
    }
}

void java_lexer_print_tokens(JavaLexer* lexer) {
    printf("\n=== Java Lexer Output ===\n");
    printf("Total tokens: %zu\n\n", lexer->token_count);
    
    for (size_t i = 0; i < lexer->token_count; i++) {
        JavaToken* tok = &lexer->tokens[i];
        printf("[%4zu] %-25s line %3d col %3d  '%s'\n",
               i, java_token_type_to_string(tok->type), tok->line, tok->column, tok->text);
    }
    
    if (lexer->error_count > 0) {
        printf("\n=== Errors ===\n");
        for (int i = 0; i < lexer->error_count; i++) {
            printf("  Error %d: %s\n", i + 1, lexer->errors[i]);
        }
    }
}

//=============================================================================
// Test Main
//=============================================================================
#ifdef JAVA_LEXER_TEST

int main(int argc, char* argv[]) {
    const char* test_code = 
        "package com.example;\n"
        "\n"
        "import java.util.*;\n"
        "\n"
        "/**\n"
        " * A simple Point class.\n"
        " */\n"
        "public class Point {\n"
        "    private final double x;\n"
        "    private final double y;\n"
        "    \n"
        "    public Point(double x, double y) {\n"
        "        this.x = x;\n"
        "        this.y = y;\n"
        "    }\n"
        "    \n"
        "    public double distance() {\n"
        "        return Math.sqrt(x * x + y * y);\n"
        "    }\n"
        "    \n"
        "    @Override\n"
        "    public String toString() {\n"
        "        return \"Point(\" + x + \", \" + y + \")\";\n"
        "    }\n"
        "    \n"
        "    // Lambda example\n"
        "    public static void main(String[] args) {\n"
        "        List<Point> points = Arrays.asList(new Point(3, 4));\n"
        "        points.forEach(p -> System.out.println(p.distance()));\n"
        "        \n"
        "        // Method reference\n"
        "        points.sort(Comparator.comparingDouble(Point::distance));\n"
        "    }\n"
        "}\n";
    
    printf("Java Lexer Test\n");
    printf("===============\n\n");
    printf("Input code:\n%s\n", test_code);
    
    JavaLexer* lexer = java_lexer_create(test_code);
    int result = java_lexer_tokenize(lexer);
    
    java_lexer_print_tokens(lexer);
    
    printf("\n=== Result ===\n");
    if (result == 0) {
        printf("SUCCESS: Tokenized %zu tokens with %d errors\n", 
               lexer->token_count, lexer->error_count);
    } else {
        printf("FAILED: %d errors occurred\n", lexer->error_count);
    }
    
    java_lexer_destroy(lexer);
    return result;
}

#endif