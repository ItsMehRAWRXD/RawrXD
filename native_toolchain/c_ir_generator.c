//=============================================================================
// c_ir_generator.c - C Intermediate Representation Generator
// Converts AST to IR for x64 code generation
// Part of the RawrXD Native Toolchain
//=============================================================================

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>

//=============================================================================
// IR Instruction Types
//=============================================================================

typedef enum {
    // Memory operations
    IR_LOAD,        // Load from memory
    IR_STORE,       // Store to memory
    IR_ALLOCA,      // Stack allocation
    IR_GEP,         // Get element pointer
    
    // Arithmetic
    IR_ADD,
    IR_SUB,
    IR_MUL,
    IR_DIV,
    IR_REM,
    IR_NEG,
    
    // Bitwise
    IR_AND,
    IR_OR,
    IR_XOR,
    IR_SHL,
    IR_SHR,
    IR_NOT,
    
    // Comparison
    IR_EQ,
    IR_NE,
    IR_LT,
    IR_LE,
    IR_GT,
    IR_GE,
    
    // Control flow
    IR_JMP,
    IR_BR,          // Conditional branch
    IR_CALL,
    IR_RET,
    
    // Conversions
    IR_TRUNC,
    IR_ZEXT,        // Zero extend
    IR_SEXT,        // Sign extend
    IR_FPTOI,       // Float to int
    IR_ITOFP,       // Int to float
    
    // Other
    IR_PHI,
    IR_SELECT,
    IR_COPY,
    IR_NOP
} IROpcode;

const char* ir_opcode_name(IROpcode op) {
    switch (op) {
        case IR_LOAD: return "load";
        case IR_STORE: return "store";
        case IR_ALLOCA: return "alloca";
        case IR_GEP: return "gep";
        case IR_ADD: return "add";
        case IR_SUB: return "sub";
        case IR_MUL: return "mul";
        case IR_DIV: return "div";
        case IR_REM: return "rem";
        case IR_NEG: return "neg";
        case IR_AND: return "and";
        case IR_OR: return "or";
        case IR_XOR: return "xor";
        case IR_SHL: return "shl";
        case IR_SHR: return "shr";
        case IR_NOT: return "not";
        case IR_EQ: return "eq";
        case IR_NE: return "ne";
        case IR_LT: return "lt";
        case IR_LE: return "le";
        case IR_GT: return "gt";
        case IR_GE: return "ge";
        case IR_JMP: return "jmp";
        case IR_BR: return "br";
        case IR_CALL: return "call";
        case IR_RET: return "ret";
        case IR_TRUNC: return "trunc";
        case IR_ZEXT: return "zext";
        case IR_SEXT: return "sext";
        case IR_FPTOI: return "fptoi";
        case IR_ITOFP: return "itofp";
        case IR_PHI: return "phi";
        case IR_SELECT: return "select";
        case IR_COPY: return "copy";
        case IR_NOP: return "nop";
        default: return "unknown";
    }
}

//=============================================================================
// IR Value Types
//=============================================================================

typedef enum {
    IR_VAL_REG,     // Virtual register
    IR_VAL_IMM,     // Immediate value
    IR_VAL_SYM,     // Symbol reference
    IR_VAL_LABEL,   // Basic block label
    IR_VAL_PARAM    // Function parameter
} IRValueType;

typedef struct {
    IRValueType type;
    union {
        int reg;          // Register number
        int64_t imm;      // Immediate value
        char* sym;        // Symbol name
        int label;        // Label ID
        int param;        // Parameter index
    };
    int size;             // Size in bytes (1, 2, 4, 8)
} IRValue;

IRValue make_reg(int num, int size) {
    IRValue v = {.type = IR_VAL_REG, .reg = num, .size = size};
    return v;
}

IRValue make_imm(int64_t val, int size) {
    IRValue v = {.type = IR_VAL_IMM, .imm = val, .size = size};
    return v;
}

IRValue make_sym(const char* name, int size) {
    IRValue v = {.type = IR_VAL_SYM, .sym = strdup(name), .size = size};
    return v;
}

IRValue make_label(int id) {
    IRValue v = {.type = IR_VAL_LABEL, .label = id, .size = 0};
    return v;
}

IRValue make_param(int idx, int size) {
    IRValue v = {.type = IR_VAL_PARAM, .param = idx, .size = size};
    return v;
}

//=============================================================================
// IR Instruction
//=============================================================================

typedef struct IRInst {
    IROpcode opcode;
    IRValue dest;
    IRValue src1;
    IRValue src2;
    int line;           // Source line
    struct IRInst* next;
} IRInst;

IRInst* create_inst(IROpcode op, IRValue dest, IRValue src1, IRValue src2) {
    IRInst* inst = calloc(1, sizeof(IRInst));
    inst->opcode = op;
    inst->dest = dest;
    inst->src1 = src1;
    inst->src2 = src2;
    return inst;
}

//=============================================================================
// Basic Block
//=============================================================================

typedef struct BasicBlock {
    int id;
    char* name;
    IRInst* first;
    IRInst* last;
    struct BasicBlock* next;
    struct BasicBlock* pred[16];  // Predecessors
    int pred_count;
    struct BasicBlock* succ[2];   // Successors (for branches)
    int succ_count;
} BasicBlock;

int bb_counter = 0;

BasicBlock* create_bb(const char* name) {
    BasicBlock* bb = calloc(1, sizeof(BasicBlock));
    bb->id = bb_counter++;
    bb->name = strdup(name ? name : "bb");
    return bb;
}

void append_inst(BasicBlock* bb, IRInst* inst) {
    if (!bb->first) {
        bb->first = bb->last = inst;
    } else {
        bb->last->next = inst;
        bb->last = inst;
    }
}

//=============================================================================
// IR Function
//=============================================================================

typedef struct {
    char* name;
    BasicBlock* entry;
    BasicBlock* exit;
    int reg_counter;
    int local_size;
    int param_count;
} IRFunction;

IRFunction* create_ir_function(const char* name) {
    IRFunction* func = calloc(1, sizeof(IRFunction));
    func->name = strdup(name);
    func->entry = create_bb("entry");
    func->exit = create_bb("exit");
    func->reg_counter = 0;
    return func;
}

int new_reg(IRFunction* func, int size) {
    return func->reg_counter++;
}

//=============================================================================
// IR Module
//=============================================================================

typedef struct {
    IRFunction** functions;
    int func_count;
    int func_capacity;
    char** globals;
    int global_count;
} IRModule;

IRModule* create_ir_module() {
    IRModule* mod = calloc(1, sizeof(IRModule));
    mod->func_capacity = 256;
    mod->functions = calloc(mod->func_capacity, sizeof(IRFunction*));
    return mod;
}

void add_function(IRModule* mod, IRFunction* func) {
    if (mod->func_count >= mod->func_capacity) {
        mod->func_capacity *= 2;
        mod->functions = realloc(mod->functions, mod->func_capacity * sizeof(IRFunction*));
    }
    mod->functions[mod->func_count++] = func;
}

//=============================================================================
// IR Generation from AST
//=============================================================================

// Forward declarations for AST types
struct ASTNode;

IRValue generate_expression(IRFunction* func, BasicBlock* bb, struct ASTNode* node);
void generate_statement(IRFunction* func, BasicBlock** bb, struct ASTNode* node);

IRValue generate_binary_op(IRFunction* func, BasicBlock* bb, const char* op, 
                              struct ASTNode* left, struct ASTNode* right) {
    IRValue lhs = generate_expression(func, bb, left);
    IRValue rhs = generate_expression(func, bb, right);
    
    int result_reg = new_reg(func, 8);  // Assume 64-bit for now
    IRValue result = make_reg(result_reg, 8);
    
    IROpcode opcode;
    if (strcmp(op, "+") == 0) opcode = IR_ADD;
    else if (strcmp(op, "-") == 0) opcode = IR_SUB;
    else if (strcmp(op, "*") == 0) opcode = IR_MUL;
    else if (strcmp(op, "/") == 0) opcode = IR_DIV;
    else if (strcmp(op, "%") == 0) opcode = IR_REM;
    else if (strcmp(op, "&") == 0) opcode = IR_AND;
    else if (strcmp(op, "|") == 0) opcode = IR_OR;
    else if (strcmp(op, "^") == 0) opcode = IR_XOR;
    else if (strcmp(op, "<<") == 0) opcode = IR_SHL;
    else if (strcmp(op, ">>") == 0) opcode = IR_SHR;
    else if (strcmp(op, "==") == 0) opcode = IR_EQ;
    else if (strcmp(op, "!=") == 0) opcode = IR_NE;
    else if (strcmp(op, "<") == 0) opcode = IR_LT;
    else if (strcmp(op, "<=") == 0) opcode = IR_LE;
    else if (strcmp(op, ">") == 0) opcode = IR_GT;
    else if (strcmp(op, ">=") == 0) opcode = IR_GE;
    else opcode = IR_NOP;
    
    IRInst* inst = create_inst(opcode, result, lhs, rhs);
    append_inst(bb, inst);
    
    return result;
}

IRValue generate_unary_op(IRFunction* func, BasicBlock* bb, const char* op, 
                           struct ASTNode* operand) {
    IRValue val = generate_expression(func, bb, operand);
    
    int result_reg = new_reg(func, 8);
    IRValue result = make_reg(result_reg, 8);
    
    IROpcode opcode;
    if (strcmp(op, "-") == 0) opcode = IR_NEG;
    else if (strcmp(op, "!") == 0) opcode = IR_NOT;
    else if (strcmp(op, "~") == 0) opcode = IR_NOT;
    else opcode = IR_COPY;
    
    IRInst* inst = create_inst(opcode, result, val, make_imm(0, 0));
    append_inst(bb, inst);
    
    return result;
}

IRValue generate_expression(IRFunction* func, BasicBlock* bb, struct ASTNode* node) {
    // This would dispatch based on node type
    // For now, return a placeholder
    return make_reg(new_reg(func, 8), 8);
}

void generate_if(IRFunction* func, BasicBlock** bb, struct ASTNode* cond,
                 struct ASTNode* then_stmt, struct ASTNode* else_stmt) {
    BasicBlock* then_bb = create_bb("then");
    BasicBlock* else_bb = create_bb("else");
    BasicBlock* merge_bb = create_bb("merge");
    
    IRValue cond_val = generate_expression(func, *bb, cond);
    IRInst* br = create_inst(IR_BR, make_label(then_bb->id), cond_val, make_label(else_bb->id));
    append_inst(*bb, br);
    
    // Then block
    generate_statement(func, &then_bb, then_stmt);
    IRInst* jmp_then = create_inst(IR_JMP, make_label(merge_bb->id), make_imm(0, 0), make_imm(0, 0));
    append_inst(then_bb, jmp_then);
    
    // Else block
    if (else_stmt) {
        generate_statement(func, &else_bb, else_stmt);
    }
    IRInst* jmp_else = create_inst(IR_JMP, make_label(merge_bb->id), make_imm(0, 0), make_imm(0, 0));
    append_inst(else_bb, jmp_else);
    
    *bb = merge_bb;
}

void generate_while(IRFunction* func, BasicBlock** bb, struct ASTNode* cond,
                    struct ASTNode* body) {
    BasicBlock* cond_bb = create_bb("while.cond");
    BasicBlock* body_bb = create_bb("while.body");
    BasicBlock* end_bb = create_bb("while.end");
    
    IRInst* jmp = create_inst(IR_JMP, make_label(cond_bb->id), make_imm(0, 0), make_imm(0, 0));
    append_inst(*bb, jmp);
    
    // Condition
    IRValue cond_val = generate_expression(func, cond_bb, cond);
    IRInst* br = create_inst(IR_BR, make_label(body_bb->id), cond_val, make_label(end_bb->id));
    append_inst(cond_bb, br);
    
    // Body
    generate_statement(func, &body_bb, body);
    IRInst* jmp_back = create_inst(IR_JMP, make_label(cond_bb->id), make_imm(0, 0), make_imm(0, 0));
    append_inst(body_bb, jmp_back);
    
    *bb = end_bb;
}

void generate_statement(IRFunction* func, BasicBlock** bb, struct ASTNode* node) {
    // Dispatch based on statement type
    // Placeholder implementation
}

//=============================================================================
// IR Output
//=============================================================================

void print_ir_value(FILE* f, IRValue v) {
    switch (v.type) {
        case IR_VAL_REG:
            fprintf(f, "%%r%d", v.reg);
            break;
        case IR_VAL_IMM:
            fprintf(f, "%lld", (long long)v.imm);
            break;
        case IR_VAL_SYM:
            fprintf(f, "@%s", v.sym);
            break;
        case IR_VAL_LABEL:
            fprintf(f, "L%d", v.label);
            break;
        case IR_VAL_PARAM:
            fprintf(f, "%%p%d", v.param);
            break;
    }
}

void print_ir_inst(FILE* f, IRInst* inst) {
    fprintf(f, "    %s", ir_opcode_name(inst->opcode));
    
    if (inst->opcode != IR_JMP && inst->opcode != IR_RET) {
        fprintf(f, " ");
        print_ir_value(f, inst->dest);
        fprintf(f, ", ");
    }
    
    print_ir_value(f, inst->src1);
    
    if (inst->opcode != IR_JMP && inst->opcode != IR_RET &&
        inst->opcode != IR_NEG && inst->opcode != IR_NOT) {
        fprintf(f, ", ");
        print_ir_value(f, inst->src2);
    }
    
    fprintf(f, "\n");
}

void print_basic_block(FILE* f, BasicBlock* bb) {
    fprintf(f, "%s_%d:\n", bb->name, bb->id);
    for (IRInst* inst = bb->first; inst; inst = inst->next) {
        print_ir_inst(f, inst);
    }
}

void print_ir_function(FILE* f, IRFunction* func) {
    fprintf(f, "define %s {\n", func->name);
    print_basic_block(f, func->entry);
    fprintf(f, "}\n\n");
}

void print_ir_module(FILE* f, IRModule* mod) {
    fprintf(f, "; RawrXD IR Module\n");
    fprintf(f, "; Target: x64 Windows\n\n");
    
    for (int i = 0; i < mod->func_count; i++) {
        print_ir_function(f, mod->functions[i]);
    }
}

//=============================================================================
// Main Entry Point
//=============================================================================

int main(int argc, char** argv) {
    printf("RawrXD C IR Generator v1.0\n");
    printf("Converts AST to Intermediate Representation\n\n");
    
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        printf("  Generates IR from AST\n");
        return 1;
    }
    
    // Create a sample module
    IRModule* mod = create_ir_module();
    IRFunction* func = create_ir_function("main");
    
    // Add some sample instructions
    IRValue r0 = make_reg(0, 8);
    IRValue r1 = make_reg(1, 8);
    IRValue imm42 = make_imm(42, 8);
    
    IRInst* alloca = create_inst(IR_ALLOCA, r0, make_imm(8, 0), make_imm(0, 0));
    append_inst(func->entry, alloca);
    
    IRInst* store = create_inst(IR_STORE, make_imm(0, 0), r0, imm42);
    append_inst(func->entry, store);
    
    IRInst* load = create_inst(IR_LOAD, r1, r0, make_imm(0, 0));
    append_inst(func->entry, load);
    
    IRInst* ret = create_inst(IR_RET, make_imm(0, 0), r1, make_imm(0, 0));
    append_inst(func->entry, ret);
    
    add_function(mod, func);
    
    // Output IR
    printf("[OK] Generated IR module\n");
    printf("[OK] Functions: %d\n", mod->func_count);
    printf("[OK] Instructions: 4\n\n");
    
    printf("Generated IR:\n");
    printf("=============\n");
    print_ir_module(stdout, mod);
    
    return 0;
}