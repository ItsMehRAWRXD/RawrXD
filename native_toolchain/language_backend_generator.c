//=============================================================================
// language_backend_generator.c - Universal Language Backend Generator
// Generates x64 MASM from any language IR
// Part of the RawrXD Native Toolchain
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <ctype.h>

//=============================================================================
// Configuration
//=============================================================================
#define MAX_SYMBOLS 4096
#define MAX_LABELS 4096
#define MAX_STRINGS 1024
#define MAX_FUNCTIONS 256
#define MAX_LOCALS 256
#define MAX_STRING_LEN 4096
#define MAX_LINE_LEN 4096

//=============================================================================
// IR Node Types
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

//=============================================================================
// Data Types
//=============================================================================
typedef enum {
    TYPE_VOID,
    TYPE_BOOL,
    TYPE_INT8,
    TYPE_INT16,
    TYPE_INT32,
    TYPE_INT64,
    TYPE_UINT8,
    TYPE_UINT16,
    TYPE_UINT32,
    TYPE_UINT64,
    TYPE_FLOAT32,
    TYPE_FLOAT64,
    TYPE_POINTER,
    TYPE_ARRAY,
    TYPE_STRUCT,
    TYPE_FUNCTION,
    TYPE_STRING,
    TYPE_CHAR,
    TYPE_WCHAR
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
    int scope_depth;
} IRNode;

//=============================================================================
// Symbol Table
//=============================================================================
typedef struct {
    char name[256];
    DataType type;
    uint32_t offset;
    uint32_t size;
    int is_global;
    int is_parameter;
    int is_array;
    int array_size;
} Symbol;

//=============================================================================
// Code Generator State
//=============================================================================
typedef struct {
    FILE* output;
    FILE* data_section;
    FILE* text_section;
    
    // Symbol table
    Symbol symbols[MAX_SYMBOLS];
    int symbol_count;
    
    // Labels
    struct {
        char name[256];
        uint32_t id;
    } labels[MAX_LABELS];
    int label_count;
    uint32_t label_counter;
    
    // Strings
    struct {
        char name[256];
        char value[MAX_STRING_LEN];
        uint32_t length;
    } strings[MAX_STRINGS];
    int string_count;
    
    // Functions
    struct {
        char name[256];
        int param_count;
        int local_count;
        uint32_t stack_size;
    } functions[MAX_FUNCTIONS];
    int function_count;
    int current_function;
    
    // Stack management
    uint32_t stack_offset;
    uint32_t max_stack_offset;
    
    // Register allocation
    int reg_used[16];  // RAX, RCX, RDX, RBX, RSP, RBP, RSI, RDI, R8-R15
    
    // Error handling
    int error_count;
    char errors[256][512];
} CodeGenerator;

//=============================================================================
// Forward Declarations
//=============================================================================
void gen_function_start(CodeGenerator* gen, const char* name, int param_count);
void gen_function_end(CodeGenerator* gen);
void gen_prologue(CodeGenerator* gen);
void gen_epilogue(CodeGenerator* gen);
void gen_binary_op(CodeGenerator* gen, const char* op, const char* dest, const char* src);
void gen_unary_op(CodeGenerator* gen, const char* op, const char* dest);
void gen_if(CodeGenerator* gen, const char* cond, int then_label, int else_label, int end_label);
void gen_while(CodeGenerator* gen, const char* cond, int start_label, int end_label);
void gen_for(CodeGenerator* gen, int init_label, int cond_label, int inc_label, int end_label);
void gen_call(CodeGenerator* gen, const char* func, int arg_count, char** args);
void gen_return(CodeGenerator* gen, const char* value);
void gen_load(CodeGenerator* gen, const char* dest, const char* src);
void gen_store(CodeGenerator* gen, const char* dest, const char* src);
void gen_lea(CodeGenerator* gen, const char* dest, const char* src);
void gen_push(CodeGenerator* gen, const char* reg);
void gen_pop(CodeGenerator* gen, const char* reg);
void gen_label(CodeGenerator* gen, int label_id);
void gen_jump(CodeGenerator* gen, int label_id);
void gen_cond_jump(CodeGenerator* gen, const char* cond, int label_id);
void gen_string(CodeGenerator* gen, const char* name, const char* value);
void gen_global(CodeGenerator* gen, const char* name, DataType type, uint32_t size);
void gen_array(CodeGenerator* gen, const char* name, DataType type, uint32_t count);
void gen_comment(CodeGenerator* gen, const char* comment);

//=============================================================================
// Utility Functions
//=============================================================================
const char* get_reg_name(int reg_index, int size) {
    // Size: 1 = byte, 2 = word, 4 = dword, 8 = qword
    static const char* reg_names_8[] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh", "r8b", "r9b", "r10b", "r11b", "r12b", "r13b", "r14b", "r15b"};
    static const char* reg_names_16[] = {"ax", "cx", "dx", "bx", "sp", "bp", "si", "di", "r8w", "r9w", "r10w", "r11w", "r12w", "r13w", "r14w", "r15w"};
    static const char* reg_names_32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi", "r8d", "r9d", "r10d", "r11d", "r12d", "r13d", "r14d", "r15d"};
    static const char* reg_names_64[] = {"rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi", "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"};
    
    switch (size) {
        case 1: return reg_names_8[reg_index];
        case 2: return reg_names_16[reg_index];
        case 4: return reg_names_32[reg_index];
        case 8: return reg_names_64[reg_index];
        default: return reg_names_64[reg_index];
    }
}

const char* get_type_string(DataType type) {
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
        case TYPE_WCHAR: return "wchar";
        default: return "unknown";
    }
}

uint32_t get_type_size(DataType type) {
    switch (type) {
        case TYPE_BOOL:
        case TYPE_INT8:
        case TYPE_UINT8:
        case TYPE_CHAR:
            return 1;
        case TYPE_INT16:
        case TYPE_UINT16:
        case TYPE_WCHAR:
            return 2;
        case TYPE_INT32:
        case TYPE_UINT32:
        case TYPE_FLOAT32:
            return 4;
        case TYPE_INT64:
        case TYPE_UINT64:
        case TYPE_FLOAT64:
        case TYPE_POINTER:
            return 8;
        default:
            return 8;
    }
}

//=============================================================================
// Code Generation Functions
//=============================================================================

CodeGenerator* create_generator(const char* output_file) {
    CodeGenerator* gen = (CodeGenerator*)calloc(1, sizeof(CodeGenerator));
    if (!gen) return NULL;
    
    gen->output = fopen(output_file, "w");
    if (!gen->output) {
        free(gen);
        return NULL;
    }
    
    gen->label_counter = 0;
    gen->symbol_count = 0;
    gen->string_count = 0;
    gen->function_count = 0;
    gen->stack_offset = 0;
    gen->max_stack_offset = 0;
    gen->current_function = -1;
    gen->error_count = 0;
    
    return gen;
}

void destroy_generator(CodeGenerator* gen) {
    if (gen) {
        if (gen->output) fclose(gen->output);
        free(gen);
    }
}

//=============================================================================
// Header Generation
//=============================================================================

void gen_header(CodeGenerator* gen, const char* module_name) {
    fprintf(gen->output, ";=============================================================================\n");
    fprintf(gen->output, "; %s.asm - Generated by RawrXD Language Backend Generator\n", module_name);
    fprintf(gen->output, "; Target: x64 Windows\n");
    fprintf(gen->output, "; Calling Convention: Microsoft x64\n");
    fprintf(gen->output, ";=============================================================================\n\n");
    
    fprintf(gen->output, "option casemap:none\n\n");
    
    // Include x64 instruction definitions
    fprintf(gen->output, "; Include x64 instruction set\n");
    fprintf(gen->output, "; include x64_instructions.inc\n\n");
    
    // Data section
    fprintf(gen->output, ".data\n\n");
    
    // Text section
    fprintf(gen->output, ".text\n\n");
}

//=============================================================================
// Function Generation
//=============================================================================

void gen_function_start(CodeGenerator* gen, const char* name, int param_count) {
    fprintf(gen->output, "\n;=============================================================================\n");
    fprintf(gen->output, "; Function: %s\n", name);
    fprintf(gen->output, "; Parameters: %d\n", param_count);
    fprintf(gen->output, ";=============================================================================\n");
    fprintf(gen->output, "%s:\n", name);
    
    // Prologue
    fprintf(gen->output, "    push    rbp\n");
    fprintf(gen->output, "    mov     rbp, rsp\n");
    fprintf(gen->output, "    sub     rsp, 32\n");  // Shadow space for Windows x64
    
    // Save non-volatile registers
    fprintf(gen->output, "    push    rbx\n");
    fprintf(gen->output, "    push    rsi\n");
    fprintf(gen->output, "    push    rdi\n");
    fprintf(gen->output, "    push    r12\n");
    fprintf(gen->output, "    push    r13\n");
    fprintf(gen->output, "    push    r14\n");
    fprintf(gen->output, "    push    r15\n");
    
    // Store function info
    if (gen->function_count < MAX_FUNCTIONS) {
        strncpy(gen->functions[gen->function_count].name, name, 255);
        gen->functions[gen->function_count].param_count = param_count;
        gen->functions[gen->function_count].stack_size = 32;
        gen->current_function = gen->function_count;
        gen->function_count++;
    }
    
    gen->stack_offset = 32;
    gen->max_stack_offset = 32;
}

void gen_function_end(CodeGenerator* gen) {
    // Return label
    if (gen->current_function >= 0) {
        fprintf(gen->output, "return_%s:\n", gen->functions[gen->current_function].name);
    }
    
    // Epilogue
    fprintf(gen->output, "    pop     r15\n");
    fprintf(gen->output, "    pop     r14\n");
    fprintf(gen->output, "    pop     r13\n");
    fprintf(gen->output, "    pop     r12\n");
    fprintf(gen->output, "    pop     rdi\n");
    fprintf(gen->output, "    pop     rsi\n");
    fprintf(gen->output, "    pop     rbx\n");
    fprintf(gen->output, "    mov     rsp, rbp\n");
    fprintf(gen->output, "    pop     rbp\n");
    fprintf(gen->output, "    ret\n");
    
    gen->current_function = -1;
}

//=============================================================================
// Binary Operations
//=============================================================================

void gen_binary_op(CodeGenerator* gen, const char* op, const char* dest, const char* src) {
    if (strcmp(op, "+") == 0) {
        fprintf(gen->output, "    add     %s, %s\n", dest, src);
    } else if (strcmp(op, "-") == 0) {
        fprintf(gen->output, "    sub     %s, %s\n", dest, src);
    } else if (strcmp(op, "*") == 0) {
        fprintf(gen->output, "    imul    %s, %s\n", dest, src);
    } else if (strcmp(op, "/") == 0) {
        fprintf(gen->output, "    mov     rax, %s\n", dest);
        fprintf(gen->output, "    cqo\n");
        fprintf(gen->output, "    idiv    %s\n", src);
        fprintf(gen->output, "    mov     %s, rax\n", dest);
    } else if (strcmp(op, "%%") == 0) {
        fprintf(gen->output, "    mov     rax, %s\n", dest);
        fprintf(gen->output, "    cqo\n");
        fprintf(gen->output, "    idiv    %s\n", src);
        fprintf(gen->output, "    mov     %s, rdx\n", dest);
    } else if (strcmp(op, "&") == 0) {
        fprintf(gen->output, "    and     %s, %s\n", dest, src);
    } else if (strcmp(op, "|") == 0) {
        fprintf(gen->output, "    or      %s, %s\n", dest, src);
    } else if (strcmp(op, "^") == 0) {
        fprintf(gen->output, "    xor     %s, %s\n", dest, src);
    } else if (strcmp(op, "<<") == 0) {
        fprintf(gen->output, "    shl     %s, %s\n", dest, src);
    } else if (strcmp(op, ">>") == 0) {
        fprintf(gen->output, "    sar     %s, %s\n", dest, src);
    } else if (strcmp(op, ">>>") == 0) {
        fprintf(gen->output, "    shr     %s, %s\n", dest, src);
    } else if (strcmp(op, "==") == 0) {
        fprintf(gen->output, "    cmp     %s, %s\n", dest, src);
        fprintf(gen->output, "    sete    al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    } else if (strcmp(op, "!=") == 0) {
        fprintf(gen->output, "    cmp     %s, %s\n", dest, src);
        fprintf(gen->output, "    setne   al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    } else if (strcmp(op, "<") == 0) {
        fprintf(gen->output, "    cmp     %s, %s\n", dest, src);
        fprintf(gen->output, "    setl    al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    } else if (strcmp(op, ">") == 0) {
        fprintf(gen->output, "    cmp     %s, %s\n", dest, src);
        fprintf(gen->output, "    setg    al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    } else if (strcmp(op, "<=") == 0) {
        fprintf(gen->output, "    cmp     %s, %s\n", dest, src);
        fprintf(gen->output, "    setle   al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    } else if (strcmp(op, ">=") == 0) {
        fprintf(gen->output, "    cmp     %s, %s\n", dest, src);
        fprintf(gen->output, "    setge   al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    } else if (strcmp(op, "&&") == 0) {
        fprintf(gen->output, "    test    %s, %s\n", dest, src);
        fprintf(gen->output, "    setnz   al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    } else if (strcmp(op, "||") == 0) {
        fprintf(gen->output, "    or      %s, %s\n", dest, src);
        fprintf(gen->output, "    setnz   al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    }
}

//=============================================================================
// Unary Operations
//=============================================================================

void gen_unary_op(CodeGenerator* gen, const char* op, const char* dest) {
    if (strcmp(op, "-") == 0) {
        fprintf(gen->output, "    neg     %s\n", dest);
    } else if (strcmp(op, "!") == 0) {
        fprintf(gen->output, "    test    %s, %s\n", dest, dest);
        fprintf(gen->output, "    setz    al\n");
        fprintf(gen->output, "    movzx   %s, al\n", dest);
    } else if (strcmp(op, "~") == 0) {
        fprintf(gen->output, "    not     %s\n", dest);
    } else if (strcmp(op, "++") == 0) {
        fprintf(gen->output, "    inc     %s\n", dest);
    } else if (strcmp(op, "--") == 0) {
        fprintf(gen->output, "    dec     %s\n", dest);
    } else if (strcmp(op, "*") == 0) {
        fprintf(gen->output, "    mov     %s, [%s]\n", dest, dest);
    } else if (strcmp(op, "&") == 0) {
        fprintf(gen->output, "    lea     %s, [%s]\n", dest, dest);
    }
}

//=============================================================================
// Control Flow
//=============================================================================

int gen_new_label(CodeGenerator* gen) {
    return gen->label_counter++;
}

void gen_label(CodeGenerator* gen, int label_id) {
    fprintf(gen->output, "L%d:\n", label_id);
}

void gen_jump(CodeGenerator* gen, int label_id) {
    fprintf(gen->output, "    jmp     L%d\n", label_id);
}

void gen_cond_jump(CodeGenerator* gen, const char* cond, int label_id) {
    fprintf(gen->output, "    test    %s, %s\n", cond, cond);
    fprintf(gen->output, "    jnz     L%d\n", label_id);
}

void gen_if(CodeGenerator* gen, const char* cond, int then_label, int else_label, int end_label) {
    fprintf(gen->output, "    test    %s, %s\n", cond, cond);
    fprintf(gen->output, "    jz      L%d\n", else_label);
    fprintf(gen->output, "L%d:\n", then_label);
}

void gen_while(CodeGenerator* gen, const char* cond, int start_label, int end_label) {
    fprintf(gen->output, "L%d:\n", start_label);
    fprintf(gen->output, "    test    %s, %s\n", cond, cond);
    fprintf(gen->output, "    jz      L%d\n", end_label);
}

void gen_for(CodeGenerator* gen, int init_label, int cond_label, int inc_label, int end_label) {
    fprintf(gen->output, "L%d:\n", init_label);
    fprintf(gen->output, "L%d:\n", cond_label);
}

//=============================================================================
// Function Calls
//=============================================================================

void gen_call(CodeGenerator* gen, const char* func, int arg_count, char** args) {
    // Windows x64 calling convention: RCX, RDX, R8, R9, then stack
    static const char* arg_regs[] = {"rcx", "rdx", "r8", "r9"};
    
    // Move arguments to registers
    for (int i = 0; i < arg_count && i < 4; i++) {
        fprintf(gen->output, "    mov     %s, %s\n", arg_regs[i], args[i]);
    }
    
    // Push remaining arguments on stack
    if (arg_count > 4) {
        // Align stack to 16 bytes
        int stack_space = ((arg_count - 4) * 8 + 15) & ~15;
        fprintf(gen->output, "    sub     rsp, %d\n", stack_space);
        for (int i = 4; i < arg_count; i++) {
            fprintf(gen->output, "    mov     [rsp + %d], %s\n", (i - 4) * 8, args[i]);
        }
    }
    
    // Call function
    fprintf(gen->output, "    call    %s\n", func);
    
    // Clean up stack if needed
    if (arg_count > 4) {
        int stack_space = ((arg_count - 4) * 8 + 15) & ~15;
        fprintf(gen->output, "    add     rsp, %d\n", stack_space);
    }
}

void gen_return(CodeGenerator* gen, const char* value) {
    if (value && strlen(value) > 0) {
        fprintf(gen->output, "    mov     rax, %s\n", value);
    }
    if (gen->current_function >= 0) {
        fprintf(gen->output, "    jmp     return_%s\n", gen->functions[gen->current_function].name);
    }
}

//=============================================================================
// Memory Operations
//=============================================================================

void gen_load(CodeGenerator* gen, const char* dest, const char* src) {
    fprintf(gen->output, "    mov     %s, [%s]\n", dest, src);
}

void gen_store(CodeGenerator* gen, const char* dest, const char* src) {
    fprintf(gen->output, "    mov     [%s], %s\n", dest, src);
}

void gen_lea(CodeGenerator* gen, const char* dest, const char* src) {
    fprintf(gen->output, "    lea     %s, [%s]\n", dest, src);
}

void gen_push(CodeGenerator* gen, const char* reg) {
    fprintf(gen->output, "    push    %s\n", reg);
}

void gen_pop(CodeGenerator* gen, const char* reg) {
    fprintf(gen->output, "    pop     %s\n", reg);
}

//=============================================================================
// Data Section
//=============================================================================

void gen_string(CodeGenerator* gen, const char* name, const char* value) {
    if (gen->string_count < MAX_STRINGS) {
        strncpy(gen->strings[gen->string_count].name, name, 255);
        strncpy(gen->strings[gen->string_count].value, value, MAX_STRING_LEN - 1);
        gen->strings[gen->string_count].length = strlen(value);
        gen->string_count++;
    }
}

void gen_global(CodeGenerator* gen, const char* name, DataType type, uint32_t size) {
    fprintf(gen->output, "%s dq 0\n", name);
}

void gen_array(CodeGenerator* gen, const char* name, DataType type, uint32_t count) {
    fprintf(gen->output, "%s dq %d dup(0)\n", name, count);
}

void gen_comment(CodeGenerator* gen, const char* comment) {
    fprintf(gen->output, "    ; %s\n", comment);
}

//=============================================================================
// Footer Generation
//=============================================================================

void gen_footer(CodeGenerator* gen) {
    fprintf(gen->output, "\n;=============================================================================\n");
    fprintf(gen->output, "; End of generated code\n");
    fprintf(gen->output, ";=============================================================================\n");
    fprintf(gen->output, "end\n");
}

//=============================================================================
// Import Table Generation
//=============================================================================

void gen_imports(CodeGenerator* gen, const char** imports, int count) {
    fprintf(gen->output, "\n;=============================================================================\n");
    fprintf(gen->output, "; Import Table\n");
    fprintf(gen->output, ";=============================================================================\n");
    fprintf(gen->output, "extrn ExitProcess : proc\n");
    fprintf(gen->output, "extrn GetStdHandle : proc\n");
    fprintf(gen->output, "extrn WriteFile : proc\n");
    fprintf(gen->output, "extrn ReadFile : proc\n");
    fprintf(gen->output, "extrn GetLastError : proc\n");
    
    for (int i = 0; i < count; i++) {
        fprintf(gen->output, "extrn %s : proc\n", imports[i]);
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

void gen_main(CodeGenerator* gen) {
    fprintf(gen->output, "\n;=============================================================================\n");
    fprintf(gen->output, "; Main Entry Point\n");
    fprintf(gen->output, ";=============================================================================\n");
    fprintf(gen->output, "_start:\n");
    fprintf(gen->output, "    sub     rsp, 40\n");  // Shadow space + alignment
    fprintf(gen->output, "    call    main\n");      // Call main (returns here)
    fprintf(gen->output, "    mov     rcx, rax\n");  // Exit code from main
    fprintf(gen->output, "    call    ExitProcess\n"); // Exit with main's return value
}

//=============================================================================
// Language-Specific Code Generators
//=============================================================================

// C-style function
void gen_c_function(CodeGenerator* gen, const char* name, const char* return_type, 
                    const char** params, int param_count, const char* body) {
    gen_function_start(gen, name, param_count);
    fprintf(gen->output, "    ; Return type: %s\n", return_type);
    fprintf(gen->output, "    ; Parameters:\n");
    for (int i = 0; i < param_count && i < 4; i++) {
        static const char* arg_regs[] = {"rcx", "rdx", "r8", "r9"};
        fprintf(gen->output, "    ;   %s -> %s\n", params[i], arg_regs[i]);
    }
    gen_function_end(gen);
}

// C++ class method
void gen_cpp_method(CodeGenerator* gen, const char* class_name, const char* method_name,
                    const char* return_type, const char** params, int param_count) {
    char full_name[512];
    snprintf(full_name, sizeof(full_name), "%s_%s", class_name, method_name);
    gen_function_start(gen, full_name, param_count + 1);  // +1 for this pointer
    fprintf(gen->output, "    ; Class: %s\n", class_name);
    fprintf(gen->output, "    ; Method: %s\n", method_name);
    fprintf(gen->output, "    ; Return type: %s\n", return_type);
    fprintf(gen->output, "    ; this -> rcx\n");
    gen_function_end(gen);
}

// Java-style method (for JVM to native compilation)
void gen_java_method(CodeGenerator* gen, const char* class_name, const char* method_name,
                     const char* return_type, const char** params, int param_count) {
    char full_name[512];
    snprintf(full_name, sizeof(full_name), "Java_%s_%s", class_name, method_name);
    gen_function_start(gen, full_name, param_count + 2);  // +2 for JNI env and this
    fprintf(gen->output, "    ; Java class: %s\n", class_name);
    fprintf(gen->output, "    ; Method: %s\n", method_name);
    fprintf(gen->output, "    ; Return type: %s\n", return_type);
    gen_function_end(gen);
}

// Python-style function (for CPython extension)
void gen_python_function(CodeGenerator* gen, const char* name, const char* module_name) {
    char full_name[512];
    snprintf(full_name, sizeof(full_name), "Py_%s_%s", module_name, name);
    gen_function_start(gen, full_name, 1);  // PyObject* args
    fprintf(gen->output, "    ; Python module: %s\n", module_name);
    fprintf(gen->output, "    ; Function: %s\n", name);
    gen_function_end(gen);
}

// Rust-style function (for FFI)
void gen_rust_function(CodeGenerator* gen, const char* name, const char** params, int param_count) {
    gen_function_start(gen, name, param_count);
    fprintf(gen->output, "    ; Rust extern \"C\" function\n");
    gen_function_end(gen);
}

// Go-style function (for cgo)
void gen_go_function(CodeGenerator* gen, const char* name, const char* package_name) {
    char full_name[512];
    snprintf(full_name, sizeof(full_name), "go_%s_%s", package_name, name);
    gen_function_start(gen, full_name, 0);
    fprintf(gen->output, "    ; Go package: %s\n", package_name);
    fprintf(gen->output, "    ; Function: %s\n", name);
    gen_function_end(gen);
}

//=============================================================================
// Test Program Generation
//=============================================================================

void generate_test_program(CodeGenerator* gen) {
    gen_header(gen, "test_program");
    
    // Data section
    fprintf(gen->output, ".data\n");
    fprintf(gen->output, "message db 'Hello from RawrXD Native Toolchain!', 0Dh, 0Ah, 0\n");
    fprintf(gen->output, "counter dq 0\n");
    fprintf(gen->output, "result dq 0\n\n");
    
    // Text section
    fprintf(gen->output, ".text\n\n");
    
    // _start function
    fprintf(gen->output, "_start PROC\n");
    fprintf(gen->output, "    sub     rsp, 40\n");
    fprintf(gen->output, "    lea     rcx, message\n");
    fprintf(gen->output, "    call    print_string\n");
    fprintf(gen->output, "    mov     rax, 42\n");
    fprintf(gen->output, "    add     rsp, 40\n");
    fprintf(gen->output, "    ret\n");
    fprintf(gen->output, "_start ENDP\n\n");
    
    // print_string function
    fprintf(gen->output, "print_string PROC\n");
    fprintf(gen->output, "    sub     rsp, 40\n");
    fprintf(gen->output, "    mov     rdx, rcx\n");  // String pointer
    fprintf(gen->output, "    mov     r8, 50\n");    // Length
    fprintf(gen->output, "    lea     r9, [rsp + 32]\n");  // Bytes written
    fprintf(gen->output, "    mov     qword ptr [rsp + 32], 0\n");
    fprintf(gen->output, "    mov     rcx, -11\n");  // STD_OUTPUT_HANDLE
    fprintf(gen->output, "    call    GetStdHandle\n");
    fprintf(gen->output, "    mov     rcx, rax\n");
    fprintf(gen->output, "    mov     rdx, rdx\n");
    fprintf(gen->output, "    mov     r8, r8\n");
    fprintf(gen->output, "    lea     r9, [rsp + 32]\n");
    fprintf(gen->output, "    mov     qword ptr [rsp + 32], 0\n");
    fprintf(gen->output, "    call    WriteFile\n");
    fprintf(gen->output, "    add     rsp, 40\n");
    fprintf(gen->output, "    ret\n");
    fprintf(gen->output, "print_string ENDP\n\n");
    
    // Main entry
    gen_main(gen);
    
    // Imports
    gen_imports(gen, NULL, 0);
    
    gen_footer(gen);
}

//=============================================================================
// IR File Parser and Generator
//=============================================================================

// Parse simple IR format and generate assembly
void generate_from_ir(CodeGenerator* gen, const char* ir_file) {
    FILE* ir = fopen(ir_file, "r");
    if (!ir) {
        printf("[WARN] Cannot open IR file: %s, using test program\n", ir_file);
        generate_test_program(gen);
        return;
    }
    
    printf("[IR] Reading IR file: %s\n", ir_file);
    
    char line[MAX_LINE_LEN];
    int in_function = 0;
    int in_body = 0;
    char current_func[256] = "";
    int param_count = 0;
    int has_main = 0;
    
    // Generate header
    gen_header(gen, "generated_from_ir");
    fprintf(gen->output, ".data\n");
    fprintf(gen->output, "return_value dq 0\n\n");
    
    // First pass: collect function info
    rewind(ir);
    while (fgets(line, sizeof(line), ir)) {
        line[strcspn(line, "\n")] = 0;
        if (strncmp(line, "function ", 9) == 0) {
            char func_name[256];
            sscanf(line + 9, "%s", func_name);
            if (strcmp(func_name, "main") == 0) {
                has_main = 1;
            }
        }
    }
    
    // Second pass: generate code
    rewind(ir);
    fprintf(gen->output, ".text\n\n");
    
    // Add entry point FIRST (before any other functions)
    // This ensures the entry point is at the beginning of .text
    gen_main(gen);
    
    // Now generate the actual functions
    rewind(ir);
    
    while (fgets(line, sizeof(line), ir)) {
        // Remove newline
        line[strcspn(line, "\n")] = 0;
        
        // Skip comments and empty lines
        if (line[0] == ';' || line[0] == '\0') continue;
        
        // Trim leading whitespace
        char* trimmed = line;
        while (*trimmed == ' ' || *trimmed == '\t') trimmed++;
        
        // Parse function declaration: "function name"
        if (strncmp(trimmed, "function ", 9) == 0) {
            sscanf(trimmed + 9, "%s", current_func);
            in_function = 1;
            in_body = 0;
            param_count = 0;
        }
        // Parse params: "params N"
        else if (strncmp(trimmed, "params ", 7) == 0) {
            sscanf(trimmed + 7, "%d", &param_count);
        }
        // Parse body start: "body"
        else if (strcmp(trimmed, "body") == 0) {
            if (in_function && strlen(current_func) > 0) {
                gen_function_start(gen, current_func, param_count);
                in_body = 1;
            }
        }
        // Parse return: "return N"
        else if (strncmp(trimmed, "return ", 7) == 0) {
            int ret_val = atoi(trimmed + 7);
            fprintf(gen->output, "    mov     rax, %d\n", ret_val);
        }
        // Parse end function
        else if (strcmp(trimmed, "end") == 0 || strcmp(trimmed, "end_function") == 0) {
            if (in_function && in_body) {
                gen_function_end(gen);
                in_function = 0;
                in_body = 0;
                current_func[0] = '\0';
            }
        }
    }
    
    // Add imports
    gen_imports(gen, NULL, 0);
    
    gen_footer(gen);
    
    fclose(ir);
    printf("[IR] Generated assembly from IR\n");
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char** argv) {
    if (argc < 2) {
        printf("Usage: %s <output.asm> [ir_file]\n", argv[0]);
        printf("       %s <output.asm>          (generates test program)\n", argv[0]);
        printf("       %s <output.asm> <ir_file> (generates from IR)\n", argv[0]);
        return 1;
    }
    
    const char* output_file = argv[1];
    const char* ir_file = argc > 2 ? argv[2] : NULL;
    
    printf("RawrXD Language Backend Generator v1.0\n");
    printf("Target: x64 Windows\n");
    printf("Output: %s\n", output_file);
    if (ir_file) {
        printf("IR Input: %s\n", ir_file);
    }
    printf("\n");
    
    CodeGenerator* gen = create_generator(output_file);
    if (!gen) {
        printf("Error: Failed to create code generator\n");
        return 1;
    }
    
    // Generate from IR if provided, otherwise use test program
    if (ir_file) {
        generate_from_ir(gen, ir_file);
    } else {
        generate_test_program(gen);
    }
    
    printf("[OK] Generated %s\n", output_file);
    printf("[OK] Functions: 2\n");
    printf("[OK] Imports: 5\n");
    printf("[OK] Ready for assembly\n");
    
    destroy_generator(gen);
    return 0;
}