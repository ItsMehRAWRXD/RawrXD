//=============================================================================
// c_semantic.c - C Language Semantic Analyzer
// Part of RawrXD Native Toolchain - Batch 1: C Frontend Foundation
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdarg.h>

// Forward declarations from c_parser.c
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
    AST_EXPRESSION_LIST, AST_INITIALIZER_LIST
} ASTNodeType;

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

typedef struct ASTNode {
    ASTNodeType type;
    CType* ctype;
    struct Token { int type; char text[256]; int line; int column; } token;
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
// Semantic Analysis Structures
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

//=============================================================================
// Type System Functions
//=============================================================================

CType* type_create(CTypeKind kind) {
    CType* type = (CType*)calloc(1, sizeof(CType));
    type->kind = kind;
    return type;
}

CType* type_create_pointer(CType* base) {
    CType* type = type_create(TYPE_POINTER);
    type->base = base;
    return type;
}

CType* type_create_array(CType* base, int size) {
    CType* type = type_create(TYPE_ARRAY);
    type->base = base;
    type->array_size = size;
    return type;
}

CType* type_create_function(CType* return_type, int param_count) {
    CType* type = type_create(TYPE_FUNCTION);
    type->return_type = return_type;
    type->param_count = param_count;
    type->param_types = (CType**)calloc(param_count, sizeof(CType*));
    return type;
}

int type_is_arithmetic(CType* type) {
    if (!type) return 0;
    switch (type->kind) {
        case TYPE_CHAR:
        case TYPE_SHORT:
        case TYPE_INT:
        case TYPE_LONG:
        case TYPE_FLOAT:
        case TYPE_DOUBLE:
        case TYPE_SIGNED_CHAR:
        case TYPE_UNSIGNED_CHAR:
        case TYPE_UNSIGNED_SHORT:
        case TYPE_UNSIGNED_INT:
        case TYPE_UNSIGNED_LONG:
            return 1;
        default:
            return 0;
    }
}

int type_is_integer(CType* type) {
    if (!type) return 0;
    switch (type->kind) {
        case TYPE_CHAR:
        case TYPE_SHORT:
        case TYPE_INT:
        case TYPE_LONG:
        case TYPE_SIGNED_CHAR:
        case TYPE_UNSIGNED_CHAR:
        case TYPE_UNSIGNED_SHORT:
        case TYPE_UNSIGNED_INT:
        case TYPE_UNSIGNED_LONG:
            return 1;
        default:
            return 0;
    }
}

int type_is_floating(CType* type) {
    if (!type) return 0;
    return type->kind == TYPE_FLOAT || type->kind == TYPE_DOUBLE;
}

int type_is_scalar(CType* type) {
    return type_is_arithmetic(type) || type->kind == TYPE_POINTER;
}

int type_is_complete(CType* type) {
    if (!type) return 0;
    if (type->kind == TYPE_ARRAY) {
        return type->array_size > 0;
    }
    if (type->kind == TYPE_VOID) return 0;
    return 1;
}

int type_is_compatible(CType* t1, CType* t2) {
    if (!t1 || !t2) return 0;
    if (t1->kind != t2->kind) return 0;
    
    if (t1->kind == TYPE_POINTER) {
        return type_is_compatible(t1->base, t2->base);
    }
    
    if (t1->kind == TYPE_ARRAY) {
        if (t1->array_size != t2->array_size) return 0;
        return type_is_compatible(t1->base, t2->base);
    }
    
    if (t1->kind == TYPE_FUNCTION) {
        if (t1->param_count != t2->param_count) return 0;
        if (!type_is_compatible(t1->return_type, t2->return_type)) return 0;
        for (int i = 0; i < t1->param_count; i++) {
            if (!type_is_compatible(t1->param_types[i], t2->param_types[i])) return 0;
        }
        return 1;
    }
    
    return 1;
}

CType* type_common(CType* t1, CType* t2) {
    // Usual arithmetic conversions
    if (type_is_floating(t1) || type_is_floating(t2)) {
        if (t1->kind == TYPE_DOUBLE || t2->kind == TYPE_DOUBLE) {
            return type_create(TYPE_DOUBLE);
        }
        return type_create(TYPE_FLOAT);
    }
    
    // Integer promotions
    if (t1->kind == TYPE_LONG || t2->kind == TYPE_LONG) {
        return type_create(TYPE_LONG);
    }
    if (t1->kind == TYPE_UNSIGNED_LONG || t2->kind == TYPE_UNSIGNED_LONG) {
        return type_create(TYPE_UNSIGNED_LONG);
    }
    if (t1->kind == TYPE_INT || t2->kind == TYPE_INT) {
        return type_create(TYPE_INT);
    }
    if (t1->kind == TYPE_UNSIGNED_INT || t2->kind == TYPE_UNSIGNED_INT) {
        return type_create(TYPE_UNSIGNED_INT);
    }
    
    return type_create(TYPE_INT);
}

const char* type_to_string(CType* type) {
    static char buffer[256];
    if (!type) return "void";
    
    switch (type->kind) {
        case TYPE_VOID: return "void";
        case TYPE_CHAR: return "char";
        case TYPE_SHORT: return "short";
        case TYPE_INT: return "int";
        case TYPE_LONG: return "long";
        case TYPE_FLOAT: return "float";
        case TYPE_DOUBLE: return "double";
        case TYPE_SIGNED_CHAR: return "signed char";
        case TYPE_UNSIGNED_CHAR: return "unsigned char";
        case TYPE_UNSIGNED_SHORT: return "unsigned short";
        case TYPE_UNSIGNED_INT: return "unsigned int";
        case TYPE_UNSIGNED_LONG: return "unsigned long";
        case TYPE_POINTER:
            snprintf(buffer, sizeof(buffer), "%s*", type_to_string(type->base));
            return buffer;
        case TYPE_ARRAY:
            snprintf(buffer, sizeof(buffer), "%s[%d]", type_to_string(type->base), type->array_size);
            return buffer;
        case TYPE_FUNCTION:
            snprintf(buffer, sizeof(buffer), "%s()", type_to_string(type->return_type));
            return buffer;
        case TYPE_STRUCT: return type->name[0] ? type->name : "struct";
        case TYPE_UNION: return type->name[0] ? type->name : "union";
        case TYPE_ENUM: return type->name[0] ? type->name : "enum";
        case TYPE_TYPEDEF: return type->name;
        default: return "unknown";
    }
}

//=============================================================================
// Semantic Analyzer Functions
//=============================================================================

SemanticAnalyzer* semantic_create(void) {
    SemanticAnalyzer* sem = (SemanticAnalyzer*)calloc(1, sizeof(SemanticAnalyzer));
    if (!sem) return NULL;
    
    // Create global scope
    sem->global_scope = (Scope*)calloc(1, sizeof(Scope));
    sem->global_scope->level = 0;
    sem->current_scope = sem->global_scope;
    
    return sem;
}

void semantic_destroy(SemanticAnalyzer* sem) {
    if (!sem) return;
    
    // Free scopes
    Scope* scope = sem->global_scope;
    while (scope) {
        Scope* next = scope->parent;
        
        // Free symbols
        Symbol* sym = scope->symbols;
        while (sym) {
            Symbol* next_sym = sym->next;
            free(sym);
            sym = next_sym;
        }
        
        free(scope);
        scope = next;
    }
    
    free(sem);
}

void semantic_error(SemanticAnalyzer* sem, int line, const char* format, ...) {
    if (sem->error_count >= 256) return;
    
    va_list args;
    va_start(args, format);
    vsnprintf(sem->errors[sem->error_count], 512, format, args);
    va_end(args);
    
    fprintf(stderr, "[Semantic Error] Line %d: %s\n", line, sem->errors[sem->error_count]);
    sem->error_count++;
    sem->had_error = 1;
}

void semantic_warning(SemanticAnalyzer* sem, int line, const char* format, ...) {
    if (sem->warning_count >= 256) return;
    
    va_list args;
    va_start(args, format);
    vsnprintf(sem->warnings[sem->warning_count], 512, format, args);
    va_end(args);
    
    fprintf(stderr, "[Warning] Line %d: %s\n", line, sem->warnings[sem->warning_count]);
    sem->warning_count++;
}

//=============================================================================
// Scope Management
//=============================================================================

void semantic_enter_scope(SemanticAnalyzer* sem) {
    Scope* new_scope = (Scope*)calloc(1, sizeof(Scope));
    new_scope->parent = sem->current_scope;
    new_scope->level = sem->current_scope->level + 1;
    sem->current_scope = new_scope;
}

void semantic_exit_scope(SemanticAnalyzer* sem) {
    if (sem->current_scope->parent) {
        Scope* old_scope = sem->current_scope;
        sem->current_scope = sem->current_scope->parent;
        
        // Free symbols in old scope
        Symbol* sym = old_scope->symbols;
        while (sym) {
            Symbol* next = sym->next;
            free(sym);
            sym = next;
        }
        
        free(old_scope);
    }
}

Symbol* semantic_lookup_symbol(SemanticAnalyzer* sem, const char* name) {
    Scope* scope = sem->current_scope;
    while (scope) {
        Symbol* sym = scope->symbols;
        while (sym) {
            if (strcmp(sym->name, name) == 0) {
                return sym;
            }
            sym = sym->next;
        }
        scope = scope->parent;
    }
    return NULL;
}

Symbol* semantic_lookup_current_scope(SemanticAnalyzer* sem, const char* name) {
    Symbol* sym = sem->current_scope->symbols;
    while (sym) {
        if (strcmp(sym->name, name) == 0) {
            return sym;
        }
        sym = sym->next;
    }
    return NULL;
}

void semantic_add_symbol(SemanticAnalyzer* sem, const char* name, CType* type, 
                       int is_function, int is_global, int line) {
    // Check for redeclaration in current scope
    Symbol* existing = semantic_lookup_current_scope(sem, name);
    if (existing) {
        semantic_error(sem, line, "Redeclaration of '%s'", name);
        return;
    }
    
    Symbol* sym = (Symbol*)calloc(1, sizeof(Symbol));
    strncpy(sym->name, name, 255);
    sym->type = type;
    sym->is_function = is_function;
    sym->is_global = is_global;
    sym->line = line;
    
    // Add to scope
    sym->next = sem->current_scope->symbols;
    sem->current_scope->symbols = sym;
}

//=============================================================================
// Type Inference from AST
//=============================================================================

CType* semantic_infer_type_specifier(ASTNode* node);

CType* semantic_infer_type(SemanticAnalyzer* sem, ASTNode* node) {
    if (!node) return type_create(TYPE_VOID);
    
    if (node->ctype) return node->ctype;
    
    switch (node->type) {
        case AST_CONSTANT:
            // Infer from token
            if (node->token.type == 0) { // TOK_INTEGER
                return type_create(TYPE_INT);
            } else if (node->token.type == 1) { // TOK_FLOAT_LITERAL
                return type_create(TYPE_DOUBLE);
            } else if (node->token.type == 2) { // TOK_CHAR_LITERAL
                return type_create(TYPE_CHAR);
            }
            return type_create(TYPE_INT);
            
        case AST_STRING_LITERAL:
            return type_create_pointer(type_create(TYPE_CHAR));
            
        case AST_IDENTIFIER: {
            Symbol* sym = semantic_lookup_symbol(sem, node->name);
            if (sym) {
                return sym->type;
            }
            semantic_error(sem, node->line, "Undefined identifier '%s'", node->name);
            return type_create(TYPE_INT);
        }
        
        case AST_BINARY_EXPRESSION: {
            CType* left = semantic_infer_type(sem, node->left);
            CType* right = semantic_infer_type(sem, node->right);
            
            // Check operator
            int op = node->token.type;
            
            // Logical operators return int
            if (op == 100 || op == 101) { // TOK_LOGICAL_AND, TOK_LOGICAL_OR
                return type_create(TYPE_INT);
            }
            
            // Comparison operators return int
            if (op >= 90 && op <= 95) { // Comparison ops
                return type_create(TYPE_INT);
            }
            
            // Arithmetic operators
            return type_common(left, right);
        }
        
        case AST_UNARY_EXPRESSION: {
            CType* operand = semantic_infer_type(sem, node->left);
            int op = node->token.type;
            
            if (op == 60) { // TOK_STAR (dereference)
                if (operand->kind == TYPE_POINTER) {
                    return operand->base;
                }
                semantic_error(sem, node->line, "Cannot dereference non-pointer type");
                return type_create(TYPE_INT);
            }
            
            if (op == 61) { // TOK_BIT_AND (address-of)
                return type_create_pointer(operand);
            }
            
            if (op == 98) { // TOK_LOGICAL_NOT
                return type_create(TYPE_INT);
            }
            
            if (op == 99) { // TOK_BIT_NOT
                return operand;
            }
            
            return operand;
        }
        
        case AST_CALL_EXPRESSION: {
            CType* func_type = semantic_infer_type(sem, node->left);
            if (func_type->kind == TYPE_FUNCTION) {
                return func_type->return_type;
            }
            semantic_error(sem, node->line, "Cannot call non-function type");
            return type_create(TYPE_INT);
        }
        
        case AST_ARRAY_EXPRESSION: {
            CType* array_type = semantic_infer_type(sem, node->left);
            if (array_type->kind == TYPE_ARRAY) {
                return array_type->base;
            }
            if (array_type->kind == TYPE_POINTER) {
                return array_type->base;
            }
            semantic_error(sem, node->line, "Cannot index non-array type");
            return type_create(TYPE_INT);
        }
        
        case AST_MEMBER_EXPRESSION: {
            // Simplified - would need struct member lookup
            return type_create(TYPE_INT);
        }
        
        case AST_ASSIGNMENT_EXPRESSION: {
            return semantic_infer_type(sem, node->left);
        }
        
        case AST_CONDITIONAL_EXPRESSION: {
            CType* then_type = semantic_infer_type(sem, node->then_stmt);
            CType* else_type = semantic_infer_type(sem, node->else_stmt);
            return type_common(then_type, else_type);
        }
        
        case AST_SIZEOF_EXPRESSION: {
            return type_create(TYPE_UNSIGNED_LONG);
        }
        
        case AST_CAST_EXPRESSION: {
            // Would need to parse type name
            return type_create(TYPE_INT);
        }
        
        default:
            return type_create(TYPE_INT);
    }
}

//=============================================================================
// Semantic Analysis Functions
//=============================================================================

void semantic_analyze_translation_unit(SemanticAnalyzer* sem, ASTNode* node);
void semantic_analyze_external_declaration(SemanticAnalyzer* sem, ASTNode* node);
void semantic_analyze_function_definition(SemanticAnalyzer* sem, ASTNode* node);
void semantic_analyze_declaration(SemanticAnalyzer* sem, ASTNode* node);
void semantic_analyze_statement(SemanticAnalyzer* sem, ASTNode* node);
void semantic_analyze_expression(SemanticAnalyzer* sem, ASTNode* node);

void semantic_analyze_translation_unit(SemanticAnalyzer* sem, ASTNode* node) {
    if (!node) return;
    
    for (int i = 0; i < node->child_count; i++) {
        semantic_analyze_external_declaration(sem, node->children[i]);
    }
}

void semantic_analyze_external_declaration(SemanticAnalyzer* sem, ASTNode* node) {
    if (!node) return;
    
    switch (node->type) {
        case AST_FUNCTION_DEFINITION:
            semantic_analyze_function_definition(sem, node);
            break;
        case AST_DECLARATION:
            semantic_analyze_declaration(sem, node);
            break;
        default:
            break;
    }
}

void semantic_analyze_function_definition(SemanticAnalyzer* sem, ASTNode* node) {
    if (!node || node->child_count < 2) return;
    
    ASTNode* specifiers = node->children[0];
    ASTNode* declarator = node->children[1];
    
    // Get function name from declarator
    const char* func_name = declarator->name;
    if (!func_name[0] && declarator->left) {
        func_name = declarator->left->name;
    }
    
    // Infer return type
    CType* return_type = type_create(TYPE_INT); // Simplified
    
    // Create function type
    CType* func_type = type_create_function(return_type, 0);
    
    // Add to symbol table
    semantic_add_symbol(sem, func_name, func_type, 1, 1, node->line);
    
    // Enter function scope
    semantic_enter_scope(sem);
    
    // Set current return type
    sem->current_return_type = return_type;
    
    // Analyze parameters
    if (declarator->right && declarator->right->type == AST_PARAMETER_LIST) {
        ASTNode* params = declarator->right;
        for (int i = 0; i < params->child_count; i++) {
            ASTNode* param = params->children[i];
            if (param->child_count >= 2) {
                ASTNode* param_decl = param->children[1];
                if (param_decl) {
                    CType* param_type = type_create(TYPE_INT); // Simplified
                    semantic_add_symbol(sem, param_decl->name, param_type, 0, 0, param->line);
                }
            }
        }
    }
    
    // Analyze body
    if (node->body) {
        semantic_analyze_statement(sem, node->body);
    }
    
    // Exit function scope
    semantic_exit_scope(sem);
    sem->current_return_type = NULL;
}

void semantic_analyze_declaration(SemanticAnalyzer* sem, ASTNode* node) {
    if (!node || node->child_count < 1) return;
    
    ASTNode* specifiers = node->children[0];
    
    // Analyze each declarator
    for (int i = 1; i < node->child_count; i++) {
        ASTNode* declarator = node->children[i];
        if (!declarator) continue;
        
        const char* name = declarator->name;
        if (!name[0] && declarator->left) {
            name = declarator->left->name;
        }
        
        CType* var_type = type_create(TYPE_INT); // Simplified
        
        // Handle array declarators
        if (declarator->type == AST_ARRAY_DECLARATOR) {
            int size = 0;
            if (declarator->right) {
                // Would evaluate constant expression
                size = 10; // Placeholder
            }
            var_type = type_create_array(var_type, size);
        }
        
        // Handle pointer declarators
        if (declarator->left && declarator->left->type == AST_POINTER) {
            var_type = type_create_pointer(var_type);
        }
        
        semantic_add_symbol(sem, name, var_type, 0, 
                          sem->current_scope == sem->global_scope, 
                          declarator->line);
        
        // Check initializer
        if (declarator->initializer) {
            CType* init_type = semantic_infer_type(sem, declarator->initializer);
            if (!type_is_compatible(var_type, init_type)) {
                semantic_warning(sem, declarator->line, 
                    "Initialization from incompatible type");
            }
        }
    }
}

void semantic_analyze_statement(SemanticAnalyzer* sem, ASTNode* node) {
    if (!node) return;
    
    switch (node->type) {
        case AST_COMPOUND_STATEMENT:
            semantic_enter_scope(sem);
            for (int i = 0; i < node->child_count; i++) {
                semantic_analyze_statement(sem, node->children[i]);
            }
            semantic_exit_scope(sem);
            break;
            
        case AST_DECLARATION:
            semantic_analyze_declaration(sem, node);
            break;
            
        case AST_EXPRESSION_STATEMENT:
            if (node->left) {
                semantic_analyze_expression(sem, node->left);
            }
            break;
            
        case AST_IF_STATEMENT:
            if (node->condition) {
                CType* cond_type = semantic_infer_type(sem, node->condition);
                if (!type_is_scalar(cond_type)) {
                    semantic_error(sem, node->line, "If condition must be scalar");
                }
            }
            semantic_analyze_statement(sem, node->then_stmt);
            if (node->else_stmt) {
                semantic_analyze_statement(sem, node->else_stmt);
            }
            break;
            
        case AST_WHILE_STATEMENT:
            sem->in_loop++;
            if (node->condition) {
                CType* cond_type = semantic_infer_type(sem, node->condition);
                if (!type_is_scalar(cond_type)) {
                    semantic_error(sem, node->line, "While condition must be scalar");
                }
            }
            semantic_analyze_statement(sem, node->body);
            sem->in_loop--;
            break;
            
        case AST_FOR_STATEMENT:
            sem->in_loop++;
            semantic_enter_scope(sem);
            if (node->init) {
                semantic_analyze_expression(sem, node->init);
            }
            if (node->condition) {
                CType* cond_type = semantic_infer_type(sem, node->condition);
                if (!type_is_scalar(cond_type)) {
                    semantic_error(sem, node->line, "For condition must be scalar");
                }
            }
            if (node->update) {
                semantic_analyze_expression(sem, node->update);
            }
            semantic_analyze_statement(sem, node->body);
            semantic_exit_scope(sem);
            sem->in_loop--;
            break;
            
        case AST_RETURN_STATEMENT:
            if (node->left) {
                CType* ret_type = semantic_infer_type(sem, node->left);
                if (sem->current_return_type && 
                    !type_is_compatible(sem->current_return_type, ret_type)) {
                    semantic_warning(sem, node->line, 
                        "Return type mismatch");
                }
            } else if (sem->current_return_type && 
                       sem->current_return_type->kind != TYPE_VOID) {
                semantic_error(sem, node->line, 
                    "Non-void function must return a value");
            }
            break;
            
        case AST_BREAK_STATEMENT:
            if (!sem->in_loop && !sem->in_switch) {
                semantic_error(sem, node->line, "Break outside loop or switch");
            }
            break;
            
        case AST_CONTINUE_STATEMENT:
            if (!sem->in_loop) {
                semantic_error(sem, node->line, "Continue outside loop");
            }
            break;
            
        default:
            break;
    }
}

void semantic_analyze_expression(SemanticAnalyzer* sem, ASTNode* node) {
    if (!node) return;
    
    // Infer type to trigger semantic checks
    CType* type = semantic_infer_type(sem, node);
    
    // Store inferred type in node
    node->ctype = type;
    
    // Recursively analyze children
    semantic_analyze_expression(sem, node->left);
    semantic_analyze_expression(sem, node->right);
    
    for (int i = 0; i < node->child_count; i++) {
        semantic_analyze_expression(sem, node->children[i]);
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

int semantic_analyze(SemanticAnalyzer* sem, ASTNode* ast) {
    semantic_analyze_translation_unit(sem, ast);
    
    printf("\nSemantic Analysis Complete:\n");
    printf("  Errors: %d\n", sem->error_count);
    printf("  Warnings: %d\n", sem->warning_count);
    
    return sem->had_error ? 1 : 0;
}

#ifdef C_SEMANTIC_TEST
// Include parser and lexer for testing
#include "c_parser.c"
#include "c_lexer.c"

int main(int argc, char** argv) {
    const char* test_code = 
        "int x;\n"
        "\n"
        "int factorial(int n) {\n"
        "    if (n \u003c= 1) {\n"
        "        return 1;\n"
        "    }\n"
        "    return n * factorial(n - 1);\n"
        "}\n"
        "\n"
        "int main() {\n"
        "    int result = factorial(5);\n"
        "    int y = x;\n"
        "    return result;\n"
        "}\n";
    
    printf("C Semantic Analyzer Test\n");
    printf("========================\n\n");
    
    // Tokenize
    Lexer* lexer = lexer_create(test_code);
    lexer_tokenize(lexer);
    
    // Parse
    Parser* parser = parser_create(lexer->tokens, lexer->token_count);
    ASTNode* ast = parse_translation_unit(parser);
    
    if (parser->had_error) {
        printf("Parsing failed\n");
        return 1;
    }
    
    // Analyze
    SemanticAnalyzer* sem = semantic_create();
    int result = semantic_analyze(sem, ast);
    
    // Cleanup
    semantic_destroy(sem);
    ast_destroy_node(ast);
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    return result;
}
#endif