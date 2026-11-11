//=============================================================================
// c_to_ir.c - C AST to Intermediate Representation Converter
// Part of RawrXD Native Toolchain - Batch 1: C Frontend Foundation
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// Forward declarations
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

typedef struct ASTNode {
    ASTNodeType type;
    struct Token { int type; char text[256]; int line; int column; } token;
    struct ASTNode** children;
    int child_count;
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
} ASTNode;

//=============================================================================
// IR Node Types (matching language_backend_generator.c)
//=============================================================================
typedef enum {
    IR_NODE_FUNCTION,
    IR_NODE_BLOCK,
    IR_NODE_RETURN,
    IR_NODE_IF,
    IR_NODE_ELSE,
    IR_NODE_WHILE,
    IR_NODE_FOR,
    IR_NODE_SWITCH,
    IR_NODE_CASE,
    IR_NODE_DEFAULT,
    IR_NODE_CALL,
    IR_NODE_BINARY_OP,
    IR_NODE_UNARY_OP,
    IR_NODE_VARIABLE,
    IR_NODE_CONSTANT,
    IR_NODE_STRING,
    IR_NODE_ARRAY,
    IR_NODE_STRUCT,
    IR_NODE_POINTER,
    IR_NODE_CAST,
    IR_NODE_ASSIGN,
    IR_NODE_DEREF,
    IR_NODE_ADDRESS,
    IR_NODE_MEMBER,
    IR_NODE_INDEX,
    IR_NODE_NEW,
    IR_NODE_DELETE,
    IR_NODE_TRY,
    IR_NODE_CATCH,
    IR_NODE_THROW
} IRNodeType;

typedef enum {
    TYPE_VOID, TYPE_BOOL, TYPE_INT8, TYPE_INT16, TYPE_INT32, TYPE_INT64,
    TYPE_UINT8, TYPE_UINT16, TYPE_UINT32, TYPE_UINT64, TYPE_FLOAT32, TYPE_FLOAT64,
    TYPE_POINTER, TYPE_ARRAY, TYPE_STRUCT, TYPE_FUNCTION, TYPE_STRING, TYPE_CHAR
} DataType;

//=============================================================================
// IR Node Structure
//=============================================================================
typedef struct IRNode {
    IRNodeType type;
    DataType data_type;
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
// IR Builder
//=============================================================================
typedef struct {
    IRNode* functions[256];
    int function_count;
    IRNode* globals[256];
    int global_count;
    int label_counter;
    int temp_counter;
    FILE* output;
} IRBuilder;

IRBuilder* ir_builder_create(FILE* output) {
    IRBuilder* builder = (IRBuilder*)calloc(1, sizeof(IRBuilder));
    builder->output = output;
    return builder;
}

void ir_builder_destroy(IRBuilder* builder) {
    free(builder);
}

IRNode* ir_create_node(IRNodeType type) {
    IRNode* node = (IRNode*)calloc(1, sizeof(IRNode));
    node->type = type;
    return node;
}

void ir_destroy_node(IRNode* node) {
    if (!node) return;
    ir_destroy_node(node->left);
    ir_destroy_node(node->right);
    ir_destroy_node(node->next);
    ir_destroy_node(node->body);
    ir_destroy_node(node->else_body);
    free(node);
}

//=============================================================================
// Type Conversion
//=============================================================================

DataType c_type_to_ir_type(ASTNode* type_node) {
    // Simplified type conversion
    if (!type_node) return TYPE_INT32;
    
    // Check for pointer
    if (type_node->type == AST_POINTER) {
        return TYPE_POINTER;
    }
    
    // Check for array
    if (type_node->type == AST_ARRAY_DECLARATOR) {
        return TYPE_ARRAY;
    }
    
    // Check token type
    if (type_node->token.type == 0) { // void
        return TYPE_VOID;
    } else if (type_node->token.type == 1) { // char
        return TYPE_INT8;
    } else if (type_node->token.type == 2) { // short
        return TYPE_INT16;
    } else if (type_node->token.type == 3) { // int
        return TYPE_INT32;
    } else if (type_node->token.type == 4) { // long
        return TYPE_INT64;
    } else if (type_node->token.type == 5) { // float
        return TYPE_FLOAT32;
    } else if (type_node->token.type == 6) { // double
        return TYPE_FLOAT64;
    }
    
    return TYPE_INT32;
}

//=============================================================================
// AST to IR Conversion
//=============================================================================

IRNode* convert_expression(IRBuilder* builder, ASTNode* node);
IRNode* convert_statement(IRBuilder* builder, ASTNode* node);

IRNode* convert_identifier(ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_VARIABLE);
    strcpy(ir->name, node->name);
    return ir;
}

IRNode* convert_constant(ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_CONSTANT);
    strcpy(ir->value, node->token.text);
    
    // Determine type
    if (node->token.type == 0) { // Integer
        ir->data_type = TYPE_INT32;
    } else if (node->token.type == 1) { // Float
        ir->data_type = TYPE_FLOAT64;
    } else if (node->token.type == 2) { // Char
        ir->data_type = TYPE_INT8;
    }
    
    return ir;
}

IRNode* convert_string(ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_STRING);
    strcpy(ir->value, node->token.text);
    ir->data_type = TYPE_POINTER;
    return ir;
}

IRNode* convert_binary_expression(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_BINARY_OP);
    
    // Map C operators to IR operators
    int op = node->token.type;
    if (op == 10) strcpy(ir->value, "+");
    else if (op == 11) strcpy(ir->value, "-");
    else if (op == 12) strcpy(ir->value, "*");
    else if (op == 13) strcpy(ir->value, "/");
    else if (op == 14) strcpy(ir->value, "%");
    else if (op == 90) strcpy(ir->value, "==");
    else if (op == 91) strcpy(ir->value, "!=");
    else if (op == 92) strcpy(ir->value, "<");
    else if (op == 93) strcpy(ir->value, ">");
    else if (op == 94) strcpy(ir->value, "<=");
    else if (op == 95) strcpy(ir->value, ">=");
    else if (op == 100) strcpy(ir->value, "&&");
    else if (op == 101) strcpy(ir->value, "||");
    else if (op == 110) strcpy(ir->value, "&");
    else if (op == 111) strcpy(ir->value, "|");
    else if (op == 112) strcpy(ir->value, "^");
    else if (op == 120) strcpy(ir->value, "<<");
    else if (op == 121) strcpy(ir->value, ">>");
    else strcpy(ir->value, "?");
    
    ir->left = convert_expression(builder, node->left);
    ir->right = convert_expression(builder, node->right);
    
    return ir;
}

IRNode* convert_unary_expression(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_UNARY_OP);
    
    int op = node->token.type;
    if (op == 20) strcpy(ir->value, "++"); // pre-inc
    else if (op == 21) strcpy(ir->value, "--"); // pre-dec
    else if (op == 22) strcpy(ir->value, "+");
    else if (op == 23) strcpy(ir->value, "-");
    else if (op == 98) strcpy(ir->value, "!");
    else if (op == 99) strcpy(ir->value, "~");
    else if (op == 60) strcpy(ir->value, "*"); // deref
    else if (op == 61) strcpy(ir->value, "&"); // address
    else strcpy(ir->value, "?");
    
    ir->left = convert_expression(builder, node->left);
    
    return ir;
}

IRNode* convert_call_expression(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_CALL);
    
    // Function name
    if (node->left->type == AST_IDENTIFIER) {
        strcpy(ir->name, node->left->name);
    }
    
    // Arguments
    if (node->right) {
        IRNode* prev = NULL;
        for (int i = 0; i < node->right->child_count; i++) {
            IRNode* arg = convert_expression(builder, node->right->children[i]);
            if (prev) {
                prev->next = arg;
            } else {
                ir->left = arg;
            }
            prev = arg;
        }
    }
    
    return ir;
}

IRNode* convert_assignment_expression(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_ASSIGN);
    
    ir->left = convert_expression(builder, node->left);
    ir->right = convert_expression(builder, node->right);
    
    return ir;
}

IRNode* convert_expression(IRBuilder* builder, ASTNode* node) {
    if (!node) return NULL;
    
    switch (node->type) {
        case AST_IDENTIFIER:
            return convert_identifier(node);
        case AST_CONSTANT:
            return convert_constant(node);
        case AST_STRING_LITERAL:
            return convert_string(node);
        case AST_BINARY_EXPRESSION:
            return convert_binary_expression(builder, node);
        case AST_UNARY_EXPRESSION:
            return convert_unary_expression(builder, node);
        case AST_CALL_EXPRESSION:
            return convert_call_expression(builder, node);
        case AST_ASSIGNMENT_EXPRESSION:
            return convert_assignment_expression(builder, node);
        case AST_CONDITIONAL_EXPRESSION: {
            IRNode* ir = ir_create_node(IR_NODE_IF);
            ir->condition = convert_expression(builder, node->condition);
            ir->body = convert_expression(builder, node->then_stmt);
            ir->else_body = convert_expression(builder, node->else_stmt);
            return ir;
        }
        case AST_ARRAY_EXPRESSION: {
            IRNode* ir = ir_create_node(IR_NODE_INDEX);
            ir->left = convert_expression(builder, node->left);
            ir->right = convert_expression(builder, node->right);
            return ir;
        }
        case AST_MEMBER_EXPRESSION: {
            IRNode* ir = ir_create_node(IR_NODE_MEMBER);
            ir->left = convert_expression(builder, node->left);
            if (node->right) {
                strcpy(ir->name, node->right->name);
            }
            return ir;
        }
        case AST_SIZEOF_EXPRESSION: {
            IRNode* ir = ir_create_node(IR_NODE_CONSTANT);
            strcpy(ir->value, "8"); // Simplified
            ir->data_type = TYPE_UINT64;
            return ir;
        }
        default:
            return ir_create_node(IR_NODE_CONSTANT);
    }
}

IRNode* convert_compound_statement(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_BLOCK);
    
    IRNode* prev = NULL;
    for (int i = 0; i < node->child_count; i++) {
        IRNode* stmt = convert_statement(builder, node->children[i]);
        if (stmt) {
            if (prev) {
                prev->next = stmt;
            } else {
                ir->body = stmt;
            }
            prev = stmt;
        }
    }
    
    return ir;
}

IRNode* convert_if_statement(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_IF);
    
    ir->condition = convert_expression(builder, node->condition);
    ir->body = convert_statement(builder, node->then_stmt);
    if (node->else_stmt) {
        ir->else_body = convert_statement(builder, node->else_stmt);
    }
    
    return ir;
}

IRNode* convert_while_statement(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_WHILE);
    
    ir->condition = convert_expression(builder, node->condition);
    ir->body = convert_statement(builder, node->body);
    
    return ir;
}

IRNode* convert_for_statement(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_FOR);
    
    // For loop is converted to while with init and update
    IRNode* init = NULL;
    if (node->init) {
        init = convert_expression(builder, node->init);
    }
    
    ir->condition = convert_expression(builder, node->condition);
    ir->body = convert_statement(builder, node->body);
    
    // Attach update to end of body
    if (node->update) {
        IRNode* update = convert_expression(builder, node->update);
        // Find end of body
        IRNode* end = ir->body;
        while (end && end->next) {
            end = end->next;
        }
        if (end) {
            end->next = update;
        }
    }
    
    return ir;
}

IRNode* convert_return_statement(IRBuilder* builder, ASTNode* node) {
    IRNode* ir = ir_create_node(IR_NODE_RETURN);
    
    if (node->left) {
        ir->left = convert_expression(builder, node->left);
    }
    
    return ir;
}

IRNode* convert_declaration(IRBuilder* builder, ASTNode* node) {
    // Convert to variable declarations
    IRNode* first = NULL;
    IRNode* prev = NULL;
    
    DataType type = TYPE_INT32; // Simplified
    if (node->child_count > 0) {
        type = c_type_to_ir_type(node->children[0]);
    }
    
    for (int i = 1; i < node->child_count; i++) {
        ASTNode* decl = node->children[i];
        if (!decl) continue;
        
        IRNode* var = ir_create_node(IR_NODE_VARIABLE);
        var->data_type = type;
        
        // Get name
        if (decl->type == AST_IDENTIFIER) {
            strcpy(var->name, decl->name);
        } else if (strlen(decl->name) > 0) {
            strcpy(var->name, decl->name);
        } else if (decl->left) {
            strcpy(var->name, decl->left->name);
        }
        
        // Handle initializer
        if (decl->initializer) {
            IRNode* init = ir_create_node(IR_NODE_ASSIGN);
            init->left = var;
            init->right = convert_expression(builder, decl->initializer);
            var = init;
        }
        
        if (prev) {
            prev->next = var;
        } else {
            first = var;
        }
        prev = var;
    }
    
    return first;
}

IRNode* convert_statement(IRBuilder* builder, ASTNode* node) {
    if (!node) return NULL;
    
    switch (node->type) {
        case AST_COMPOUND_STATEMENT:
            return convert_compound_statement(builder, node);
        case AST_EXPRESSION_STATEMENT:
            return convert_expression(builder, node->left);
        case AST_IF_STATEMENT:
            return convert_if_statement(builder, node);
        case AST_WHILE_STATEMENT:
            return convert_while_statement(builder, node);
        case AST_FOR_STATEMENT:
            return convert_for_statement(builder, node);
        case AST_RETURN_STATEMENT:
            return convert_return_statement(builder, node);
        case AST_DECLARATION:
            return convert_declaration(builder, node);
        case AST_BREAK_STATEMENT:
            return ir_create_node(IR_NODE_BREAK); // Simplified
        case AST_CONTINUE_STATEMENT:
            return ir_create_node(IR_NODE_CONTINUE); // Simplified
        default:
            return NULL;
    }
}

IRNode* convert_function_definition(IRBuilder* builder, ASTNode* node) {
    IRNode* func = ir_create_node(IR_NODE_FUNCTION);
    
    // Get function name
    if (node->child_count >= 2) {
        ASTNode* declarator = node->children[1];
        if (strlen(declarator->name) > 0) {
            strcpy(func->name, declarator->name);
        } else if (declarator->left) {
            strcpy(func->name, declarator->left->name);
        }
        
        // Get return type
        if (node->child_count > 0) {
            func->data_type = c_type_to_ir_type(node->children[0]);
        }
    }
    
    // Convert body
    if (node->body) {
        func->body = convert_statement(builder, node->body);
    }
    
    return func;
}

//=============================================================================
// IR Output
//=============================================================================

void ir_print_expression(IRNode* node, int indent);

void ir_print_indent(int indent) {
    for (int i = 0; i < indent; i++) {
        printf("  ");
    }
}

const char* ir_type_to_string(DataType type) {
    switch (type) {
        case TYPE_VOID: return "void";
        case TYPE_BOOL: return "bool";
        case TYPE_INT8: return "int8";
        case TYPE_INT16: return "int16";
        case TYPE_INT32: return "int32";
        case TYPE_INT64: return "int64";
        case TYPE_UINT8: return "uint8";
        case TYPE_UINT16: return "uint16";
        case TYPE_UINT32: return "uint32";
        case TYPE_UINT64: return "uint64";
        case TYPE_FLOAT32: return "float32";
        case TYPE_FLOAT64: return "float64";
        case TYPE_POINTER: return "pointer";
        case TYPE_ARRAY: return "array";
        case TYPE_STRUCT: return "struct";
        case TYPE_FUNCTION: return "function";
        case TYPE_STRING: return "string";
        case TYPE_CHAR: return "char";
        default: return "unknown";
    }
}

void ir_print_node(IRNode* node, int indent) {
    if (!node) return;
    
    ir_print_indent(indent);
    
    switch (node->type) {
        case IR_NODE_FUNCTION:
            printf("FUNCTION %s : %s\n", node->name, ir_type_to_string(node->data_type));
            ir_print_node(node->body, indent + 1);
            break;
            
        case IR_NODE_BLOCK:
            printf("BLOCK\n");
            ir_print_node(node->body, indent + 1);
            break;
            
        case IR_NODE_RETURN:
            printf("RETURN\n");
            if (node->left) {
                ir_print_expression(node->left, indent + 1);
            }
            break;
            
        case IR_NODE_IF:
            printf("IF\n");
            ir_print_indent(indent + 1);
            printf("condition:\n");
            ir_print_expression(node->condition, indent + 2);
            ir_print_indent(indent + 1);
            printf("then:\n");
            ir_print_node(node->body, indent + 2);
            if (node->else_body) {
                ir_print_indent(indent + 1);
                printf("else:\n");
                ir_print_node(node->else_body, indent + 2);
            }
            break;
            
        case IR_NODE_WHILE:
            printf("WHILE\n");
            ir_print_indent(indent + 1);
            printf("condition:\n");
            ir_print_expression(node->condition, indent + 2);
            ir_print_indent(indent + 1);
            printf("body:\n");
            ir_print_node(node->body, indent + 2);
            break;
            
        case IR_NODE_FOR:
            printf("FOR\n");
            ir_print_indent(indent + 1);
            printf("condition:\n");
            ir_print_expression(node->condition, indent + 2);
            ir_print_indent(indent + 1);
            printf("body:\n");
            ir_print_node(node->body, indent + 2);
            break;
            
        case IR_NODE_CALL:
            printf("CALL %s\n", node->name);
            if (node->left) {
                ir_print_indent(indent + 1);
                printf("args:\n");
                ir_print_expression(node->left, indent + 2);
            }
            break;
            
        case IR_NODE_ASSIGN:
            printf("ASSIGN\n");
            ir_print_indent(indent + 1);
            printf("lhs:\n");
            ir_print_expression(node->left, indent + 2);
            ir_print_indent(indent + 1);
            printf("rhs:\n");
            ir_print_expression(node->right, indent + 2);
            break;
            
        default:
            printf("UNKNOWN\n");
            break;
    }
    
    if (node->next) {
        ir_print_node(node->next, indent);
    }
}

void ir_print_expression(IRNode* node, int indent) {
    if (!node) return;
    
    ir_print_indent(indent);
    
    switch (node->type) {
        case IR_NODE_VARIABLE:
            printf("VAR %s : %s\n", node->name, ir_type_to_string(node->data_type));
            break;
            
        case IR_NODE_CONSTANT:
            printf("CONST %s : %s\n", node->value, ir_type_to_string(node->data_type));
            break;
            
        case IR_NODE_STRING:
            printf("STRING \"%s\"\n", node->value);
            break;
            
        case IR_NODE_BINARY_OP:
            printf("BINARY %s\n", node->value);
            ir_print_expression(node->left, indent + 1);
            ir_print_expression(node->right, indent + 1);
            break;
            
        case IR_NODE_UNARY_OP:
            printf("UNARY %s\n", node->value);
            ir_print_expression(node->left, indent + 1);
            break;
            
        case IR_NODE_CALL:
            printf("CALL %s\n", node->name);
            if (node->left) {
                ir_print_expression(node->left, indent + 1);
            }
            break;
            
        case IR_NODE_INDEX:
            printf("INDEX\n");
            ir_print_expression(node->left, indent + 1);
            ir_print_expression(node->right, indent + 1);
            break;
            
        case IR_NODE_MEMBER:
            printf("MEMBER %s\n", node->name);
            ir_print_expression(node->left, indent + 1);
            break;
            
        default:
            printf("EXPR\n");
            break;
    }
    
    if (node->next) {
        ir_print_expression(node->next, indent);
    }
}

void ir_print(IRNode* ir) {
    printf("IR:\n");
    ir_print_node(ir, 0);
}

//=============================================================================
// Main Entry Point
//=============================================================================

IRNode* c_to_ir_convert(ASTNode* ast) {
    if (!ast) return NULL;
    
    IRBuilder* builder = ir_builder_create(NULL);
    
    // Convert translation unit
    IRNode* first_func = NULL;
    IRNode* prev_func = NULL;
    
    for (int i = 0; i < ast->child_count; i++) {
        ASTNode* decl = ast->children[i];
        if (decl->type == AST_FUNCTION_DEFINITION) {
            IRNode* func = convert_function_definition(builder, decl);
            if (func) {
                if (prev_func) {
                    prev_func->next = func;
                } else {
                    first_func = func;
                }
                prev_func = func;
            }
        }
    }
    
    ir_builder_destroy(builder);
    
    return first_func;
}

#ifdef C_TO_IR_TEST
// Include parser and lexer for testing
#include "c_parser.c"
#include "c_lexer.c"

int main(int argc, char** argv) {
    const char* test_code = 
        "int factorial(int n) {\n"
        "    if (n \u003c= 1) {\n"
        "        return 1;\n"
        "    }\n"
        "    return n * factorial(n - 1);\n"
        "}\n"
        "\n"
        "int main() {\n"
        "    int result = factorial(5);\n"
        "    return result;\n"
        "}\n";
    
    printf("C to IR Converter Test\n");
    printf("======================\n\n");
    
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
    
    // Convert to IR
    IRNode* ir = c_to_ir_convert(ast);
    
    // Print IR
    ir_print(ir);
    
    // Cleanup
    ir_destroy_node(ir);
    ast_destroy_node(ast);
    parser_destroy(parser);
    lexer_destroy(lexer);
    
    return 0;
}
#endif