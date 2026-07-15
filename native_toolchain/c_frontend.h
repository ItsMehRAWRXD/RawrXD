//=============================================================================
// c_frontend.h - C Frontend Header
// Part of RawrXD Native Toolchain - Batch 1: C Frontend Foundation
//=============================================================================

#ifndef C_FRONTEND_H
#define C_FRONTEND_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>

//=============================================================================
// Token Types
//=============================================================================
typedef enum {
    // Keywords
    TOK_AUTO, TOK_BREAK, TOK_CASE, TOK_CHAR, TOK_CONST, TOK_CONTINUE,
    TOK_DEFAULT, TOK_DO, TOK_DOUBLE, TOK_ELSE, TOK_ENUM, TOK_EXTERN,
    TOK_FLOAT, TOK_FOR, TOK_GOTO, TOK_IF, TOK_INLINE, TOK_INT,
    TOK_LONG, TOK_REGISTER, TOK_RESTRICT, TOK_RETURN, TOK_SHORT,
    TOK_SIGNED, TOK_SIZEOF, TOK_STATIC, TOK_STRUCT, TOK_SWITCH,
    TOK_TYPEDEF, TOK_UNION, TOK_UNSIGNED, TOK_VOID, TOK_VOLATILE,
    TOK_WHILE, TOK_BOOL, TOK_COMPLEX, TOK_IMAGINARY,
    
    // Operators
    TOK_PLUS, TOK_MINUS, TOK_STAR, TOK_SLASH, TOK_PERCENT,
    TOK_INC, TOK_DEC, TOK_ARROW, TOK_DOT,
    TOK_ASSIGN, TOK_PLUS_ASSIGN, TOK_MINUS_ASSIGN, TOK_STAR_ASSIGN,
    TOK_SLASH_ASSIGN, TOK_PERCENT_ASSIGN, TOK_AND_ASSIGN, TOK_OR_ASSIGN,
    TOK_XOR_ASSIGN, TOK_SHL_ASSIGN, TOK_SHR_ASSIGN,
    TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_LOGICAL_AND, TOK_LOGICAL_OR, TOK_LOGICAL_NOT,
    TOK_BIT_AND, TOK_BIT_OR, TOK_BIT_XOR, TOK_BIT_NOT,
    TOK_SHL, TOK_SHR,
    
    // Delimiters
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET, TOK_SEMICOLON, TOK_COMMA,
    TOK_COLON, TOK_QUESTION,
    
    // Literals
    TOK_IDENTIFIER, TOK_INTEGER, TOK_FLOAT_LITERAL, TOK_STRING, TOK_CHAR_LITERAL,
    
    // Preprocessor
    TOK_HASH, TOK_HASH_HASH, TOK_PRAGMA, TOK_INCLUDE, TOK_DEFINE,
    
    // Special
    TOK_EOF, TOK_ERROR, TOK_NEWLINE, TOK_WHITESPACE
} TokenType;

//=============================================================================
// Token Structure
//=============================================================================
typedef struct {
    TokenType type;
    char text[256];
    int line;
    int column;
    union {
        int64_t int_val;
        double float_val;
        char string_val[256];
    } value;
} Token;

//=============================================================================
// AST Node Types
//=============================================================================
typedef enum {
    AST_TRANSLATION_UNIT, AST_FUNCTION_DEFINITION, AST_DECLARATION,
    AST_DECLARATOR, AST_INIT_DECLARATOR, AST_PARAMETER_LIST,
    AST_PARAMETER_DECLARATION, AST_ARGUMENT_LIST, AST_TYPE_NAME,
    AST_STRUCT_SPECIFIER, AST_UNION_SPECIFIER, AST_ENUM_SPECIFIER,
    AST_TYPEDEF_NAME, AST_COMPOUND_STATEMENT, AST_EXPRESSION_STATEMENT,
    AST_IF_STATEMENT, AST_SWITCH_STATEMENT, AST_WHILE_STATEMENT,
    AST_DO_WHILE_STATEMENT, AST_FOR_STATEMENT, AST_GOTO_STATEMENT,
    AST_CONTINUE_STATEMENT, AST_BREAK_STATEMENT, AST_RETURN_STATEMENT,
    AST_LABEL_STATEMENT, AST_CASE_STATEMENT, AST_DEFAULT_STATEMENT,
    AST_BINARY_EXPRESSION, AST_UNARY_EXPRESSION, AST_POSTFIX_EXPRESSION,
    AST_PRIMARY_EXPRESSION, AST_ASSIGNMENT_EXPRESSION, AST_CONDITIONAL_EXPRESSION,
    AST_CAST_EXPRESSION, AST_CALL_EXPRESSION, AST_MEMBER_EXPRESSION,
    AST_ARRAY_EXPRESSION, AST_SIZEOF_EXPRESSION, AST_IDENTIFIER, AST_CONSTANT,
    AST_STRING_LITERAL, AST_TYPE_SPECIFIER, AST_POINTER, AST_ARRAY_DECLARATOR,
    AST_FUNCTION_DECLARATOR, AST_DECLARATION_LIST, AST_STATEMENT_LIST,
    AST_EXPRESSION_LIST, AST_INITIALIZER_LIST, AST_EXPRESSION
} ASTNodeType;

//=============================================================================
// Type System
//=============================================================================
typedef enum {
    TYPE_VOID, TYPE_CHAR, TYPE_SHORT, TYPE_INT, TYPE_LONG,
    TYPE_FLOAT, TYPE_DOUBLE, TYPE_SIGNED_CHAR, TYPE_UNSIGNED_CHAR,
    TYPE_UNSIGNED_SHORT, TYPE_UNSIGNED_INT, TYPE_UNSIGNED_LONG,
    TYPE_POINTER, TYPE_ARRAY, TYPE_FUNCTION, TYPE_STRUCT, TYPE_UNION,
    TYPE_ENUM, TYPE_TYPEDEF
} CTypeKind;

typedef struct CType {
    CTypeKind kind;
    int is_const;
    int is_volatile;
    int is_restrict;
    struct CType* base;
    int array_size;
    struct CType* return_type;
    struct CType** param_types;
    int param_count;
    char name[256];
} CType;

//=============================================================================
// AST Node Structure
//=============================================================================
typedef struct ASTNode {
    ASTNodeType type;
    CType* ctype;
    Token token;
    struct ASTNode** children;
    int child_count;
    int child_capacity;
    struct ASTNode* left;
    struct ASTNode* right;
    struct ASTNode* condition;
    struct ASTNode* then_stmt;
    struct ASTNode* else_stmt;
    struct ASTNode* init;
    struct ASTNode* update;
    struct ASTNode* body;
    char name[256];
    struct ASTNode* initializer;
    int line;
    int column;
} ASTNode;

//=============================================================================
// Lexer
//=============================================================================
typedef struct {
    const char* source;
    size_t pos;
    size_t length;
    int line;
    int column;
    Token* tokens;
    size_t token_count;
    size_t token_capacity;
    int error_count;
    char errors[256][512];
} Lexer;

Lexer* lexer_create(const char* source);
void lexer_destroy(Lexer* lexer);
int lexer_tokenize(Lexer* lexer);
void lexer_print_tokens(Lexer* lexer);
const char* token_type_to_string(TokenType type);

//=============================================================================
// Parser
//=============================================================================
typedef struct {
    Token* tokens;
    size_t token_count;
    size_t current;
    struct {
        char name[256];
        CType* type;
        int is_typedef;
    } symbols[1024];
    int symbol_count;
    int error_count;
    char errors[256][512];
    int had_error;
    int panic_mode;
} Parser;

Parser* parser_create(Token* tokens, size_t token_count);
void parser_destroy(Parser* parser);
ASTNode* parse_translation_unit(Parser* parser);
void ast_destroy_node(ASTNode* node);
void ast_print(ASTNode* root);
const char* ast_type_to_string(ASTNodeType type);

//=============================================================================
// Semantic Analyzer
//=============================================================================
typedef struct Symbol {
    char name[256];
    CType* type;
    int is_function;
    int is_global;
    int is_defined;
    int line;
    int column;
    struct Symbol* next;
} Symbol;

typedef struct Scope {
    Symbol* symbols;
    struct Scope* parent;
    int level;
} Scope;

typedef struct {
    Scope* current_scope;
    Scope* global_scope;
    int error_count;
    int warning_count;
    char errors[256][512];
    char warnings[256][512];
    int in_loop;
    int in_switch;
    CType* current_return_type;
    int had_error;
} SemanticAnalyzer;

SemanticAnalyzer* semantic_create(void);
void semantic_destroy(SemanticAnalyzer* sem);
int semantic_analyze(SemanticAnalyzer* sem, ASTNode* ast);
CType* type_create(CTypeKind kind);
CType* type_create_pointer(CType* base);
CType* type_create_array(CType* base, int size);
CType* type_create_function(CType* return_type, int param_count);
void type_destroy(CType* type);
int type_is_arithmetic(CType* type);
int type_is_integer(CType* type);
int type_is_floating(CType* type);
int type_is_scalar(CType* type);
int type_is_compatible(CType* t1, CType* t2);
CType* type_common(CType* t1, CType* t2);
const char* type_to_string(CType* type);

//=============================================================================
// IR Types
//=============================================================================
typedef enum {
    IR_NODE_FUNCTION, IR_NODE_BLOCK, IR_NODE_RETURN, IR_NODE_IF, IR_NODE_ELSE,
    IR_NODE_WHILE, IR_NODE_FOR, IR_NODE_SWITCH, IR_NODE_CASE, IR_NODE_DEFAULT,
    IR_NODE_CALL, IR_NODE_BINARY_OP, IR_NODE_UNARY_OP, IR_NODE_VARIABLE,
    IR_NODE_CONSTANT, IR_NODE_STRING, IR_NODE_ARRAY, IR_NODE_STRUCT,
    IR_NODE_POINTER, IR_NODE_CAST, IR_NODE_ASSIGN, IR_NODE_DEREF,
    IR_NODE_ADDRESS, IR_NODE_MEMBER, IR_NODE_INDEX, IR_NODE_NEW,
    IR_NODE_DELETE, IR_NODE_TRY, IR_NODE_CATCH, IR_NODE_THROW
} IRNodeType;

typedef enum {
    IR_TYPE_VOID, IR_TYPE_BOOL, IR_TYPE_INT8, IR_TYPE_INT16, IR_TYPE_INT32,
    IR_TYPE_INT64, IR_TYPE_UINT8, IR_TYPE_UINT16, IR_TYPE_UINT32, IR_TYPE_UINT64,
    IR_TYPE_FLOAT32, IR_TYPE_FLOAT64, IR_TYPE_POINTER, IR_TYPE_ARRAY,
    IR_TYPE_STRUCT, IR_TYPE_FUNCTION, IR_TYPE_STRING, IR_TYPE_CHAR
} IRDataType;

typedef struct IRNode {
    IRNodeType type;
    IRDataType data_type;
    char name[256];
    char value[256];
    struct IRNode* left;
    struct IRNode* right;
    struct IRNode* next;
    struct IRNode* body;
    struct IRNode* else_body;
    int line_number;
} IRNode;

//=============================================================================
// IR Converter
//=============================================================================
IRNode* c_to_ir_convert(ASTNode* ast);
void ir_destroy_node(IRNode* node);
void ir_print(IRNode* ir);
const char* ir_type_to_string(IRDataType type);

#endif // C_FRONTEND_H