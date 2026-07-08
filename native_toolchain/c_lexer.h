//=============================================================================
// c_lexer.h - C Language Lexer (Tokenizer)
// Part of the RawrXD Native Toolchain
// Converts C source code into tokens for the parser
//=============================================================================

#ifndef C_LEXER_H
#define C_LEXER_H

#include <stdint.h>
#include <stdbool.h>

//=============================================================================
// Token Types
//=============================================================================
typedef enum {
    // Literals
    TOKEN_INT_LITERAL,
    TOKEN_FLOAT_LITERAL,
    TOKEN_STRING_LITERAL,
    TOKEN_CHAR_LITERAL,
    
    // Identifiers and Keywords
    TOKEN_IDENTIFIER,
    TOKEN_KEYWORD,
    
    // Operators
    TOKEN_PLUS,          // +
    TOKEN_MINUS,         // -
    TOKEN_STAR,          // *
    TOKEN_SLASH,         // /
    TOKEN_PERCENT,       // %
    TOKEN_AMPERSAND,     // &
    TOKEN_PIPE,          // |
    TOKEN_CARET,         // ^
    TOKEN_TILDE,         // ~
    TOKEN_EXCLAIM,       // !
    TOKEN_QUESTION,      // ?
    TOKEN_COLON,         // :
    
    // Comparison Operators
    TOKEN_EQ,            // ==
    TOKEN_NE,            // !=
    TOKEN_LT,            // <
    TOKEN_GT,            // >
    TOKEN_LE,            // <=
    TOKEN_GE,            // >=
    
    // Assignment Operators
    TOKEN_ASSIGN,        // =
    TOKEN_PLUS_ASSIGN,   // +=
    TOKEN_MINUS_ASSIGN,  // -=
    TOKEN_STAR_ASSIGN,   // *=
    TOKEN_SLASH_ASSIGN,  // /=
    TOKEN_PERCENT_ASSIGN,// %=
    TOKEN_AMP_ASSIGN,    // &=
    TOKEN_PIPE_ASSIGN,   // |=
    TOKEN_CARET_ASSIGN,  // ^=
    TOKEN_LSHIFT_ASSIGN, // <<=
    TOKEN_RSHIFT_ASSIGN, // >>=
    
    // Increment/Decrement
    TOKEN_INCREMENT,     // ++
    TOKEN_DECREMENT,     // --
    
    // Bitwise Shift
    TOKEN_LSHIFT,        // <<
    TOKEN_RSHIFT,        // >>
    
    // Logical Operators
    TOKEN_LOGICAL_AND,   // &&
    TOKEN_LOGICAL_OR,    // ||
    
    // Delimiters
    TOKEN_LPAREN,        // (
    TOKEN_RPAREN,        // )
    TOKEN_LBRACE,        // {
    TOKEN_RBRACE,        // }
    TOKEN_LBRACKET,      // [
    TOKEN_RBRACKET,      // ]
    TOKEN_SEMICOLON,     // ;
    TOKEN_COMMA,         // ,
    TOKEN_DOT,           // .
    TOKEN_ARROW,         // ->
    TOKEN_ELLIPSIS,      // ...
    
    // Preprocessor
    TOKEN_HASH,          // #
    TOKEN_HASH_HASH,     // ##
    
    // Special
    TOKEN_EOF,
    TOKEN_ERROR,
    TOKEN_UNKNOWN
} TokenType;

//=============================================================================
// Keywords
//=============================================================================
typedef enum {
    KEYWORD_AUTO,
    KEYWORD_BREAK,
    KEYWORD_CASE,
    KEYWORD_CHAR,
    KEYWORD_CONST,
    KEYWORD_CONTINUE,
    KEYWORD_DEFAULT,
    KEYWORD_DO,
    KEYWORD_DOUBLE,
    KEYWORD_ELSE,
    KEYWORD_ENUM,
    KEYWORD_EXTERN,
    KEYWORD_FLOAT,
    KEYWORD_FOR,
    KEYWORD_GOTO,
    KEYWORD_IF,
    KEYWORD_INLINE,
    KEYWORD_INT,
    KEYWORD_LONG,
    KEYWORD_REGISTER,
    KEYWORD_RESTRICT,
    KEYWORD_RETURN,
    KEYWORD_SHORT,
    KEYWORD_SIGNED,
    KEYWORD_SIZEOF,
    KEYWORD_STATIC,
    KEYWORD_STRUCT,
    KEYWORD_SWITCH,
    KEYWORD_TYPEDEF,
    KEYWORD_UNION,
    KEYWORD_UNSIGNED,
    KEYWORD_VOID,
    KEYWORD_VOLATILE,
    KEYWORD_WHILE,
    KEYWORD_ALIGNAS,
    KEYWORD_ALIGNOF,
    KEYWORD_ATOMIC,
    KEYWORD_BOOL,
    KEYWORD_COMPLEX,
    KEYWORD_GENERIC,
    KEYWORD_IMAGINARY,
    KEYWORD_NORETURN,
    KEYWORD_STATIC_ASSERT,
    KEYWORD_THREAD_LOCAL,
    KEYWORD_COUNT
} KeywordType;

//=============================================================================
// Token Structure
//=============================================================================
typedef struct {
    TokenType type;
    KeywordType keyword;
    char* value;
    char* string_value;
    int64_t int_value;
    double float_value;
    int line;
    int column;
    int length;
} Token;

//=============================================================================
// Lexer State
//=============================================================================
typedef struct {
    const char* source;
    const char* filename;
    int position;
    int line;
    int column;
    int length;
    Token current_token;
    Token next_token;
    bool has_next_token;
    char error_message[512];
    bool has_error;
} Lexer;

//=============================================================================
// Lexer Functions
//=============================================================================

// Initialize lexer
void lexer_init(Lexer* lexer, const char* source, const char* filename);

// Get next token
Token lexer_next_token(Lexer* lexer);

// Peek next token without consuming
Token lexer_peek_token(Lexer* lexer);

// Check if token is a keyword
bool token_is_keyword(Token* token, KeywordType keyword);

// Check if token is a type keyword
bool token_is_type_keyword(Token* token);

// Get token type name
const char* token_type_name(TokenType type);

// Get keyword name
const char* keyword_name(KeywordType keyword);

// Free token resources
void token_free(Token* token);

// Get current position info
void lexer_get_position(Lexer* lexer, int* line, int* column);

// Skip whitespace and comments
void lexer_skip_whitespace(Lexer* lexer);

// Skip line comment
void lexer_skip_line_comment(Lexer* lexer);

// Skip block comment
void lexer_skip_block_comment(Lexer* lexer);

// Read number literal
Token lexer_read_number(Lexer* lexer);

// Read string literal
Token lexer_read_string(Lexer* lexer);

// Read character literal
Token lexer_read_char(Lexer* lexer);

// Read identifier or keyword
Token lexer_read_identifier(Lexer* lexer);

// Read operator
Token lexer_read_operator(Lexer* lexer);

// Read preprocessor directive
Token lexer_read_preprocessor(Lexer* lexer);

//=============================================================================
// Keyword Table
//=============================================================================
extern const char* keyword_names[];
extern const int keyword_count;

#endif // C_LEXER_H