//=============================================================================
// c_lexer.c - C Language Lexer
// Part of RawrXD Native Toolchain - Batch 1: C Frontend Foundation
//=============================================================================

#include "c_frontend.h"

//=============================================================================
// Keyword Table
//=============================================================================
typedef struct {
    const char* word;
    TokenType type;
} Keyword;

static const Keyword keywords[] = {
    {"auto", TOK_AUTO}, {"break", TOK_BREAK}, {"case", TOK_CASE},
    {"char", TOK_CHAR}, {"const", TOK_CONST}, {"continue", TOK_CONTINUE},
    {"default", TOK_DEFAULT}, {"do", TOK_DO}, {"double", TOK_DOUBLE},
    {"else", TOK_ELSE}, {"enum", TOK_ENUM}, {"extern", TOK_EXTERN},
    {"float", TOK_FLOAT}, {"for", TOK_FOR}, {"goto", TOK_GOTO},
    {"if", TOK_IF}, {"inline", TOK_INLINE}, {"int", TOK_INT},
    {"long", TOK_LONG}, {"register", TOK_REGISTER}, {"restrict", TOK_RESTRICT},
    {"return", TOK_RETURN}, {"short", TOK_SHORT}, {"signed", TOK_SIGNED},
    {"sizeof", TOK_SIZEOF}, {"static", TOK_STATIC}, {"struct", TOK_STRUCT},
    {"switch", TOK_SWITCH}, {"typedef", TOK_TYPEDEF}, {"union", TOK_UNION},
    {"unsigned", TOK_UNSIGNED}, {"void", TOK_VOID}, {"volatile", TOK_VOLATILE},
    {"while", TOK_WHILE}, {"_Bool", TOK_BOOL}, {"_Complex", TOK_COMPLEX},
    {"_Imaginary", TOK_IMAGINARY}, {NULL, 0}
};

//=============================================================================
// Lexer Functions
//=============================================================================

Lexer* lexer_create(const char* source) {
    Lexer* lexer = (Lexer*)calloc(1, sizeof(Lexer));
    if (!lexer) return NULL;
    
    lexer->source = source;
    lexer->length = strlen(source);
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

static int lexer_match(Lexer* lexer, char expected) {
    if (lexer_peek(lexer) == expected) {
        lexer_advance(lexer);
        return 1;
    }
    return 0;
}

static void lexer_skip_whitespace(Lexer* lexer) {
    while (isspace(lexer_peek(lexer)) && lexer_peek(lexer) != '\n') {
        lexer_advance(lexer);
    }
}

static void lexer_skip_comment(Lexer* lexer) {
    if (lexer_peek(lexer) == '/' && lexer->source[lexer->pos + 1] == '/') {
        // Single-line comment
        while (lexer_peek(lexer) != '\n' && lexer_peek(lexer) != '\0') {
            lexer_advance(lexer);
        }
    } else if (lexer_peek(lexer) == '/' && lexer->source[lexer->pos + 1] == '*') {
        // Multi-line comment
        lexer_advance(lexer); // /
        lexer_advance(lexer); // *
        while (!(lexer_peek(lexer) == '*' && lexer->source[lexer->pos + 1] == '/') && 
               lexer_peek(lexer) != '\0') {
            lexer_advance(lexer);
        }
        if (lexer_peek(lexer) != '\0') {
            lexer_advance(lexer); // *
            lexer_advance(lexer); // /
        }
    }
}

static TokenType lexer_check_keyword(const char* text) {
    for (int i = 0; keywords[i].word != NULL; i++) {
        if (strcmp(text, keywords[i].word) == 0) {
            return keywords[i].type;
        }
    }
    return TOK_IDENTIFIER;
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
    
    // Check if it's a keyword
    token.type = lexer_check_keyword(token.text);
    
    return token;
}

static Token lexer_read_number(Lexer* lexer) {
    Token token;
    token.type = TOK_INTEGER;
    token.line = lexer->line;
    token.column = lexer->column;
    int i = 0;
    int is_float = 0;
    
    // Handle hex
    if (lexer_peek(lexer) == '0' && (lexer->source[lexer->pos + 1] == 'x' || 
                                      lexer->source[lexer->pos + 1] == 'X')) {
        token.text[i++] = lexer_advance(lexer); // 0
        token.text[i++] = lexer_advance(lexer); // x
        while (isxdigit(lexer_peek(lexer))) {
            if (i < 255) token.text[i++] = lexer_advance(lexer);
            else lexer_advance(lexer);
        }
    } else {
        // Decimal or float
        while (isdigit(lexer_peek(lexer))) {
            if (i < 255) token.text[i++] = lexer_advance(lexer);
            else lexer_advance(lexer);
        }
        
        if (lexer_peek(lexer) == '.' && isdigit(lexer->source[lexer->pos + 1])) {
            is_float = 1;
            token.text[i++] = lexer_advance(lexer); // .
            while (isdigit(lexer_peek(lexer))) {
                if (i < 255) token.text[i++] = lexer_advance(lexer);
                else lexer_advance(lexer);
            }
            
            // Exponent
            if (lexer_peek(lexer) == 'e' || lexer_peek(lexer) == 'E') {
                token.text[i++] = lexer_advance(lexer);
                if (lexer_peek(lexer) == '+' || lexer_peek(lexer) == '-') {
                    token.text[i++] = lexer_advance(lexer);
                }
                while (isdigit(lexer_peek(lexer))) {
                    if (i < 255) token.text[i++] = lexer_advance(lexer);
                    else lexer_advance(lexer);
                }
            }
        }
    }
    
    // Suffix
    while (lexer_peek(lexer) == 'u' || lexer_peek(lexer) == 'U' ||
           lexer_peek(lexer) == 'l' || lexer_peek(lexer) == 'L' ||
           lexer_peek(lexer) == 'f' || lexer_peek(lexer) == 'F') {
        if (i < 255) token.text[i++] = lexer_advance(lexer);
        else lexer_advance(lexer);
    }
    
    token.text[i] = '\0';
    
    if (is_float) {
        token.type = TOK_FLOAT_LITERAL;
        token.value.float_val = strtod(token.text, NULL);
    } else {
        token.value.int_val = strtoll(token.text, NULL, 0);
    }
    
    return token;
}

static Token lexer_read_string(Lexer* lexer) {
    Token token;
    token.type = TOK_STRING;
    token.line = lexer->line;
    token.column = lexer->column;
    int i = 0;
    
    char quote = lexer_advance(lexer); // opening quote
    
    while (lexer_peek(lexer) != quote && lexer_peek(lexer) != '\0') {
        if (lexer_peek(lexer) == '\\') {
            lexer_advance(lexer); // backslash
            char escape = lexer_advance(lexer);
            switch (escape) {
                case 'n': token.value.string_val[i++] = '\n'; break;
                case 't': token.value.string_val[i++] = '\t'; break;
                case 'r': token.value.string_val[i++] = '\r'; break;
                case '\\': token.value.string_val[i++] = '\\'; break;
                case '"': token.value.string_val[i++] = '"'; break;
                case '\'': token.value.string_val[i++] = '\''; break;
                case '0': token.value.string_val[i++] = '\0'; break;
                default: token.value.string_val[i++] = escape; break;
            }
        } else {
            token.value.string_val[i++] = lexer_advance(lexer);
        }
        if (i >= 255) break;
    }
    
    if (lexer_peek(lexer) == quote) {
        lexer_advance(lexer); // closing quote
    }
    
    token.value.string_val[i] = '\0';
    strcpy(token.text, token.value.string_val);
    
    return token;
}

static Token lexer_read_char(Lexer* lexer) {
    Token token;
    token.type = TOK_CHAR_LITERAL;
    token.line = lexer->line;
    token.column = lexer->column;
    
    lexer_advance(lexer); // '
    
    if (lexer_peek(lexer) == '\\') {
        lexer_advance(lexer);
        char escape = lexer_advance(lexer);
        switch (escape) {
            case 'n': token.value.int_val = '\n'; break;
            case 't': token.value.int_val = '\t'; break;
            case 'r': token.value.int_val = '\r'; break;
            case '\\': token.value.int_val = '\\'; break;
            case '\'': token.value.int_val = '\''; break;
            case '"': token.value.int_val = '"'; break;
            case '0': token.value.int_val = '\0'; break;
            default: token.value.int_val = escape; break;
        }
    } else {
        token.value.int_val = lexer_advance(lexer);
    }
    
    if (lexer_peek(lexer) == '\'') {
        lexer_advance(lexer);
    }
    
    sprintf(token.text, "%c", (char)token.value.int_val);
    
    return token;
}

static Token lexer_read_operator(Lexer* lexer) {
    Token token;
    token.line = lexer->line;
    token.column = lexer->column;
    int i = 0;
    
    char c = lexer_peek(lexer);
    
    switch (c) {
        case '+':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '+')) {
                token.text[i++] = '+';
                token.type = TOK_INC;
            } else if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_PLUS_ASSIGN;
            } else {
                token.type = TOK_PLUS;
            }
            break;
            
        case '-':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '-')) {
                token.text[i++] = '-';
                token.type = TOK_DEC;
            } else if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_MINUS_ASSIGN;
            } else if (lexer_match(lexer, '>')) {
                token.text[i++] = '>';
                token.type = TOK_ARROW;
            } else {
                token.type = TOK_MINUS;
            }
            break;
            
        case '*':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_STAR_ASSIGN;
            } else {
                token.type = TOK_STAR;
            }
            break;
            
        case '/':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_SLASH_ASSIGN;
            } else {
                token.type = TOK_SLASH;
            }
            break;
            
        case '%':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_PERCENT_ASSIGN;
            } else {
                token.type = TOK_PERCENT;
            }
            break;
            
        case '=':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_EQ;
            } else {
                token.type = TOK_ASSIGN;
            }
            break;
            
        case '!':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_NE;
            } else {
                token.type = TOK_LOGICAL_NOT;
            }
            break;
            
        case '<':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_LE;
            } else if (lexer_match(lexer, '<')) {
                token.text[i++] = '<';
                if (lexer_match(lexer, '=')) {
                    token.text[i++] = '=';
                    token.type = TOK_SHL_ASSIGN;
                } else {
                    token.type = TOK_SHL;
                }
            } else {
                token.type = TOK_LT;
            }
            break;
            
        case '>':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_GE;
            } else if (lexer_match(lexer, '>')) {
                token.text[i++] = '>';
                if (lexer_match(lexer, '=')) {
                    token.text[i++] = '=';
                    token.type = TOK_SHR_ASSIGN;
                } else {
                    token.type = TOK_SHR;
                }
            } else {
                token.type = TOK_GT;
            }
            break;
            
        case '&':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '&')) {
                token.text[i++] = '&';
                token.type = TOK_LOGICAL_AND;
            } else if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_AND_ASSIGN;
            } else {
                token.type = TOK_BIT_AND;
            }
            break;
            
        case '|':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '|')) {
                token.text[i++] = '|';
                token.type = TOK_LOGICAL_OR;
            } else if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_OR_ASSIGN;
            } else {
                token.type = TOK_BIT_OR;
            }
            break;
            
        case '^':
            token.text[i++] = lexer_advance(lexer);
            if (lexer_match(lexer, '=')) {
                token.text[i++] = '=';
                token.type = TOK_XOR_ASSIGN;
            } else {
                token.type = TOK_BIT_XOR;
            }
            break;
            
        case '~':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_BIT_NOT;
            break;
            
        case '(':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_LPAREN;
            break;
            
        case ')':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_RPAREN;
            break;
            
        case '{':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_LBRACE;
            break;
            
        case '}':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_RBRACE;
            break;
            
        case '[':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_LBRACKET;
            break;
            
        case ']':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_RBRACKET;
            break;
            
        case ';':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_SEMICOLON;
            break;
            
        case ',':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_COMMA;
            break;
            
        case ':':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_COLON;
            break;
            
        case '?':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_QUESTION;
            break;
            
        case '.':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_DOT;
            break;
            
        case '#':
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_HASH;
            break;
            
        default:
            token.text[i++] = lexer_advance(lexer);
            token.type = TOK_ERROR;
            break;
    }
    
    token.text[i] = '\0';
    return token;
}

//=============================================================================
// Main Lexing Function
//=============================================================================

int lexer_tokenize(Lexer* lexer) {
    while (lexer->pos < lexer->length) {
        // Skip whitespace and comments
        lexer_skip_whitespace(lexer);
        
        if (lexer_peek(lexer) == '/' && (lexer->source[lexer->pos + 1] == '/' || 
                                          lexer->source[lexer->pos + 1] == '*')) {
            lexer_skip_comment(lexer);
            continue;
        }
        
        if (lexer->pos >= lexer->length) break;
        
        Token token;
        char c = lexer_peek(lexer);
        
        if (isalpha(c) || c == '_') {
            token = lexer_read_identifier(lexer);
        } else if (isdigit(c)) {
            token = lexer_read_number(lexer);
        } else if (c == '"') {
            token = lexer_read_string(lexer);
        } else if (c == '\'') {
            token = lexer_read_char(lexer);
        } else if (c == '\n') {
            token.type = TOK_NEWLINE;
            token.line = lexer->line;
            token.column = lexer->column;
            token.text[0] = lexer_advance(lexer);
            token.text[1] = '\0';
        } else if (c == '\0') {
            break;
        } else {
            token = lexer_read_operator(lexer);
        }
        
        // Add token to list
        if (lexer->token_count >= lexer->token_capacity) {
            lexer->token_capacity *= 2;
            lexer->tokens = (Token*)realloc(lexer->tokens, 
                                            lexer->token_capacity * sizeof(Token));
            if (!lexer->tokens) return -1;
        }
        
        lexer->tokens[lexer->token_count++] = token;
    }
    
    // Add EOF token
    Token eof_token;
    eof_token.type = TOK_EOF;
    eof_token.line = lexer->line;
    eof_token.column = lexer->column;
    eof_token.text[0] = '\0';
    
    if (lexer->token_count >= lexer->token_capacity) {
        lexer->token_capacity *= 2;
        lexer->tokens = (Token*)realloc(lexer->tokens, 
                                        lexer->token_capacity * sizeof(Token));
    }
    lexer->tokens[lexer->token_count++] = eof_token;
    
    return lexer->token_count;
}

//=============================================================================
// Token String Representation
//=============================================================================

const char* token_type_to_string(TokenType type) {
    switch (type) {
        // Keywords
        case TOK_AUTO: return "AUTO";
        case TOK_BREAK: return "BREAK";
        case TOK_CASE: return "CASE";
        case TOK_CHAR: return "CHAR";
        case TOK_CONST: return "CONST";
        case TOK_CONTINUE: return "CONTINUE";
        case TOK_DEFAULT: return "DEFAULT";
        case TOK_DO: return "DO";
        case TOK_DOUBLE: return "DOUBLE";
        case TOK_ELSE: return "ELSE";
        case TOK_ENUM: return "ENUM";
        case TOK_EXTERN: return "EXTERN";
        case TOK_FLOAT: return "FLOAT";
        case TOK_FOR: return "FOR";
        case TOK_GOTO: return "GOTO";
        case TOK_IF: return "IF";
        case TOK_INLINE: return "INLINE";
        case TOK_INT: return "INT";
        case TOK_LONG: return "LONG";
        case TOK_REGISTER: return "REGISTER";
        case TOK_RESTRICT: return "RESTRICT";
        case TOK_RETURN: return "RETURN";
        case TOK_SHORT: return "SHORT";
        case TOK_SIGNED: return "SIGNED";
        case TOK_SIZEOF: return "SIZEOF";
        case TOK_STATIC: return "STATIC";
        case TOK_STRUCT: return "STRUCT";
        case TOK_SWITCH: return "SWITCH";
        case TOK_TYPEDEF: return "TYPEDEF";
        case TOK_UNION: return "UNION";
        case TOK_UNSIGNED: return "UNSIGNED";
        case TOK_VOID: return "VOID";
        case TOK_VOLATILE: return "VOLATILE";
        case TOK_WHILE: return "WHILE";
        case TOK_BOOL: return "BOOL";
        case TOK_COMPLEX: return "COMPLEX";
        case TOK_IMAGINARY: return "IMAGINARY";
        
        // Operators
        case TOK_PLUS: return "PLUS";
        case TOK_MINUS: return "MINUS";
        case TOK_STAR: return "STAR";
        case TOK_SLASH: return "SLASH";
        case TOK_PERCENT: return "PERCENT";
        case TOK_INC: return "INC";
        case TOK_DEC: return "DEC";
        case TOK_ARROW: return "ARROW";
        case TOK_DOT: return "DOT";
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
        
        // Delimiters
        case TOK_LPAREN: return "LPAREN";
        case TOK_RPAREN: return "RPAREN";
        case TOK_LBRACE: return "LBRACE";
        case TOK_RBRACE: return "RBRACE";
        case TOK_LBRACKET: return "LBRACKET";
        case TOK_RBRACKET: return "RBRACKET";
        case TOK_SEMICOLON: return "SEMICOLON";
        case TOK_COMMA: return "COMMA";
        case TOK_COLON: return "COLON";
        case TOK_QUESTION: return "QUESTION";
        
        // Literals
        case TOK_IDENTIFIER: return "IDENTIFIER";
        case TOK_INTEGER: return "INTEGER";
        case TOK_FLOAT_LITERAL: return "FLOAT_LITERAL";
        case TOK_STRING: return "STRING";
        case TOK_CHAR_LITERAL: return "CHAR_LITERAL";
        
        // Preprocessor
        case TOK_HASH: return "HASH";
        case TOK_HASH_HASH: return "HASH_HASH";
        case TOK_PRAGMA: return "PRAGMA";
        case TOK_INCLUDE: return "INCLUDE";
        case TOK_DEFINE: return "DEFINE";
        
        // Special
        case TOK_EOF: return "EOF";
        case TOK_ERROR: return "ERROR";
        case TOK_NEWLINE: return "NEWLINE";
        case TOK_WHITESPACE: return "WHITESPACE";
        
        default: return "UNKNOWN";
    }
}

//=============================================================================
// Debug Output
//=============================================================================

void lexer_print_tokens(Lexer* lexer) {
    printf("Tokens (%zu total):\n", lexer->token_count);
    printf("%-4s %-20s %-30s %-6s %-6s\n", "#", "Type", "Text", "Line", "Col");
    printf("%-4s %-20s %-30s %-6s %-6s\n", "--", "----", "----", "----", "---");
    
    for (size_t i = 0; i < lexer->token_count; i++) {
        Token* tok = &lexer->tokens[i];
        printf("%-4zu %-20s %-30s %-6d %-6d\n", 
               i, 
               token_type_to_string(tok->type),
               tok->text,
               tok->line,
               tok->column);
    }
}

//=============================================================================
// Main Entry Point (for testing)
//=============================================================================

#ifdef C_LEXER_TEST
int main(int argc, char** argv) {
    const char* test_code = 
        "int main() {\n"
        "    int x = 42;\n"
        "    float y = 3.14;\n"
        "    char* str = \"Hello\";\n"
        "    if (x > 0) {\n"
        "        return x + y;\n"
        "    }\n"
        "    return 0;\n"
        "}\n";
    
    printf("C Lexer Test\n");
    printf("============\n\n");
    printf("Input code:\n%s\n\n", test_code);
    
    Lexer* lexer = lexer_create(test_code);
    if (!lexer) {
        printf("Failed to create lexer\n");
        return 1;
    }
    
    int token_count = lexer_tokenize(lexer);
    if (token_count < 0) {
        printf("Tokenization failed\n");
        lexer_destroy(lexer);
        return 1;
    }
    
    lexer_print_tokens(lexer);
    
    printf("\nTokenization complete: %d tokens\n", token_count);
    
    lexer_destroy(lexer);
    return 0;
}
#endif