//=============================================================================
// c_parser.h - Complete C Parser for RawrXD Self-Hosting Compiler
// Production-ready recursive descent parser with full C99 support
//=============================================================================

#ifndef RAWRXD_C_PARSER_H
#define RAWRXD_C_PARSER_H

#include <stdint.h>
#include <stdbool.h>

//=============================================================================
// Forward Declarations
//=============================================================================

typedef struct Parser Parser;
typedef struct ASTNode ASTNode;
typedef struct Type Type;
typedef struct Symbol Symbol;
typedef struct Scope Scope;

//=============================================================================
// Token Types (from tokenizer)
//=============================================================================

typedef enum {
    // Literals
    TOK_INTEGER_LITERAL,
    TOK_FLOAT_LITERAL,
    TOK_STRING_LITERAL,
    TOK_CHAR_LITERAL,
    
    // Identifiers
    TOK_IDENTIFIER,
    
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
    TOK_INCREMENT, TOK_DECREMENT,
    TOK_ASSIGN, TOK_PLUS_ASSIGN, TOK_MINUS_ASSIGN, TOK_STAR_ASSIGN,
    TOK_SLASH_ASSIGN, TOK_PERCENT_ASSIGN,
    TOK_AND_ASSIGN, TOK_OR_ASSIGN, TOK_XOR_ASSIGN,
    TOK_SHL_ASSIGN, TOK_SHR_ASSIGN,
    TOK_EQ, TOK_NE, TOK_LT, TOK_GT, TOK_LE, TOK_GE,
    TOK_LOGICAL_AND, TOK_LOGICAL_OR, TOK_LOGICAL_NOT,
    TOK_BIT_AND, TOK_BIT_OR, TOK_BIT_XOR, TOK_BIT_NOT,
    TOK_SHL, TOK_SHR,
    
    // Punctuation
    TOK_LPAREN, TOK_RPAREN, TOK_LBRACE, TOK_RBRACE,
    TOK_LBRACKET, TOK_RBRACKET,
    TOK_SEMICOLON, TOK_COMMA, TOK_DOT, TOK_ARROW,
    TOK_QUESTION, TOK_COLON,
    TOK_ELLIPSIS,
    
    // Preprocessor
    TOK_HASH, TOK_HASH_HASH,
    
    // Special
    TOK_EOF,
    TOK_ERROR,
    TOK_NEWLINE,
    TOK_WHITESPACE,
    TOK_COMMENT,
    
    TOK_COUNT
} TokenType;

//=============================================================================
// Token Structure
//=============================================================================

typedef struct Token {
    TokenType type;
    char* text;
    int line;
    int column;
    union {
        long long int_value;
        double float_value;
        char* string_value;
    } value;
} Token;

//=============================================================================
// AST Node Types
//=============================================================================

typedef enum {
    // Declarations
    AST_TRANSLATION_UNIT,
    AST_FUNCTION_DEFINITION,
    AST_DECLARATION,
    AST_PARAMETER_DECL,
    AST_STRUCT_DECL,
    AST_UNION_DECL,
    AST_ENUM_DECL,
    AST_TYPEDEF_DECL,
    AST_FIELD_DECL,
    AST_ENUM_CONSTANT,
    
    // Statements
    AST_COMPOUND_STMT,
    AST_EXPRESSION_STMT,
    AST_IF_STMT,
    AST_SWITCH_STMT,
    AST_WHILE_STMT,
    AST_DO_WHILE_STMT,
    AST_FOR_STMT,
    AST_GOTO_STMT,
    AST_CONTINUE_STMT,
    AST_BREAK_STMT,
    AST_RETURN_STMT,
    AST_LABEL_STMT,
    AST_CASE_STMT,
    AST_DEFAULT_STMT,
    
    // Expressions
    AST_BINARY_EXPR,
    AST_UNARY_EXPR,
    AST_TERNARY_EXPR,
    AST_CALL_EXPR,
    AST_MEMBER_EXPR,
    AST_ARRAY_SUBSCRIPT_EXPR,
    AST_CAST_EXPR,
    AST_SIZEOF_EXPR,
    AST_IDENTIFIER_EXPR,
    AST_INTEGER_LITERAL,
    AST_FLOAT_LITERAL,
    AST_STRING_LITERAL,
    AST_CHAR_LITERAL,
    AST_INITIALIZER_LIST,
    AST_DESIGNATED_INITIALIZER,
    AST_COMMA_EXPR,
    AST_ASSIGNMENT_EXPR,
    AST_CONDITIONAL_EXPR,
    
    // Types
    AST_TYPE_NAME,
    AST_POINTER_TYPE,
    AST_ARRAY_TYPE,
    AST_FUNCTION_TYPE,
    AST_STRUCT_TYPE,
    AST_UNION_TYPE,
    AST_ENUM_TYPE,
    
    AST_COUNT
} ASTNodeType;

//=============================================================================
// Type System
//=============================================================================

typedef enum {
    TYPE_VOID,
    TYPE_CHAR,
    TYPE_SHORT,
    TYPE_INT,
    TYPE_LONG,
    TYPE_LONG_LONG,
    TYPE_FLOAT,
    TYPE_DOUBLE,
    TYPE_LONG_DOUBLE,
    TYPE_BOOL,
    TYPE_POINTER,
    TYPE_ARRAY,
    TYPE_FUNCTION,
    TYPE_STRUCT,
    TYPE_UNION,
    TYPE_ENUM,
    TYPE_TYPEDEF,
    TYPE_QUALIFIED,
    TYPE_COUNT
} TypeKind;

typedef struct Type {
    TypeKind kind;
    int is_const;
    int is_volatile;
    int is_restrict;
    int is_signed;
    int is_unsigned;
    int is_inline;
    int is_static;
    int is_extern;
    int is_register;
    
    union {
        struct {
            Type* pointee;
        } pointer;
        struct {
            Type* element_type;
            int size;
        } array;
        struct {
            Type* return_type;
            Type** param_types;
            int param_count;
            int is_variadic;
        } function;
        struct {
            char* name;
            Symbol** fields;
            int field_count;
            int size;
            int alignment;
        } aggregate;
        struct {
            char* name;
            Symbol** constants;
            int constant_count;
        } enum_type;
        struct {
            Type* base;
        } qualified;
    } data;
} Type;

//=============================================================================
// Symbol Table
//=============================================================================

typedef enum {
    SYM_VARIABLE,
    SYM_FUNCTION,
    SYM_TYPE,
    SYM_FIELD,
    SYM_ENUM_CONST,
    SYM_LABEL,
    SYM_TYPEDEF,
    SYM_COUNT
} SymbolKind;

struct Symbol {
    char* name;
    SymbolKind kind;
    Type* type;
    ASTNode* decl;
    int scope_level;
    int is_defined;
    int is_initialized;
    union {
        long long int_value;
        double float_value;
        void* data;
    } value;
    Symbol* next;
};

struct Scope {
    Symbol** symbols;
    int symbol_count;
    int symbol_capacity;
    Scope* parent;
    int level;
};

//=============================================================================
// AST Node Structure
//=============================================================================

struct ASTNode {
    ASTNodeType type;
    Token* token;
    Type* expr_type;
    int line;
    int column;
    
    union {
        // Translation unit
        struct {
            ASTNode** declarations;
            int decl_count;
        } translation_unit;
        
        // Function definition
        struct {
            ASTNode* decl_specifiers;
            ASTNode* declarator;
            ASTNode* body;
            Symbol* symbol;
        } function_def;
        
        // Declaration
        struct {
            ASTNode* specifiers;
            ASTNode** init_declarators;
            int init_count;
        } declaration;
        
        // Binary expression
        struct {
            TokenType op;
            ASTNode* left;
            ASTNode* right;
        } binary;
        
        // Unary expression
        struct {
            TokenType op;
            ASTNode* operand;
        } unary;
        
        // Ternary expression
        struct {
            ASTNode* cond;
            ASTNode* true_expr;
            ASTNode* false_expr;
        } ternary;
        
        // Call expression
        struct {
            ASTNode* callee;
            ASTNode** args;
            int arg_count;
        } call;
        
        // Member expression
        struct {
            ASTNode* object;
            char* member_name;
            int is_arrow;
        } member;
        
        // Array subscript
        struct {
            ASTNode* array;
            ASTNode* index;
        } subscript;
        
        // Cast expression
        struct {
            ASTNode* type_name;
            ASTNode* expr;
        } cast;
        
        // sizeof expression
        struct {
            ASTNode* operand;
            int is_type;
        } sizeof_expr;
        
        // Identifier
        struct {
            char* name;
            Symbol* symbol;
        } identifier;
        
        // Literal
        struct {
            long long int_value;
            double float_value;
            char* string_value;
            char char_value;
        } literal;
        
        // Compound statement
        struct {
            ASTNode** items;
            int item_count;
            Scope* scope;
        } compound;
        
        // If statement
        struct {
            ASTNode* cond;
            ASTNode* then_stmt;
            ASTNode* else_stmt;
        } if_stmt;
        
        // Switch statement
        struct {
            ASTNode* cond;
            ASTNode* body;
        } switch_stmt;
        
        // While statement
        struct {
            ASTNode* cond;
            ASTNode* body;
        } while_stmt;
        
        // For statement
        struct {
            ASTNode* init;
            ASTNode* cond;
            ASTNode* iter;
            ASTNode* body;
        } for_stmt;
        
        // Return statement
        struct {
            ASTNode* expr;
        } return_stmt;
        
        // Goto statement
        struct {
            char* label;
        } goto_stmt;
        
        // Label statement
        struct {
            char* name;
            ASTNode* stmt;
        } label;
        
        // Case statement
        struct {
            ASTNode* expr;
            ASTNode* stmt;
        } case_stmt;
        
        // Type name
        struct {
            ASTNode* specifiers;
            ASTNode* abstract_decl;
        } type_name;
        
        // Initializer list
        struct {
            ASTNode** elements;
            int element_count;
        } init_list;
        
    } data;
    
    ASTNode* next;
};

//=============================================================================
// Parser Structure
//=============================================================================

struct Parser {
    Token* tokens;
    int token_count;
    int current;
    
    Scope* current_scope;
    Scope* global_scope;
    int scope_level;
    
    char* source;
    char* filename;
    
    int error_count;
    int warning_count;
    int max_errors;
    
    ASTNode* ast_root;
};

//=============================================================================
// Parser API
//=============================================================================

// Lifecycle
Parser* parser_create(const char* source, const char* filename);
void parser_destroy(Parser* parser);

// Parsing
int parser_parse(Parser* parser);
ASTNode* parser_get_ast(Parser* parser);

// Error handling
void parser_error(Parser* parser, const char* format, ...);
void parser_warning(Parser* parser, const char* format, ...);
int parser_has_errors(Parser* parser);

// Scope management
void parser_push_scope(Parser* parser);
void parser_pop_scope(Parser* parser);
Scope* parser_current_scope(Parser* parser);

// Symbol management
Symbol* parser_add_symbol(Parser* parser, const char* name, SymbolKind kind, Type* type);
Symbol* parser_lookup_symbol(Parser* parser, const char* name);
Symbol* parser_lookup_symbol_current(Parser* parser, const char* name);

// Type system
Type* type_create(TypeKind kind);
Type* type_pointer(Type* pointee);
Type* type_array(Type* element, int size);
Type* type_function(Type* ret, Type** params, int count, int variadic);
Type* type_copy(Type* type);
void type_destroy(Type* type);
int type_equal(Type* a, Type* b);
int type_size(Type* type);
int type_alignment(Type* type);

// AST utilities
ASTNode* ast_create(ASTNodeType type, Token* token);
void ast_destroy(ASTNode* node);
void ast_print(ASTNode* node, int indent);
const char* ast_type_name(ASTNodeType type);

// Debug
void parser_print_tokens(Parser* parser);
void parser_print_ast(Parser* parser);
void parser_print_symbols(Parser* parser);

#endif // RAWRXD_C_PARSER_H
