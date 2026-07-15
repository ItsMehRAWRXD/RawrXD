// RawrXD-Script Bytecode Compiler
// AST → Bytecode translation for high-performance execution

#pragma once

#include "../ast/ast_simple.hpp"
#include <vector>
#include <memory>
#include <unordered_map>
#include <string>
#include <cstdint>

namespace RawrXD {
namespace Script {

// Forward declarations
struct CompilerContext;

// Simple bytecode module for compiler output (standalone, not from bytecode.hpp)
struct BytecodeModule {
    std::vector<uint8_t> code;           // Bytecode instructions
    std::vector<double> constants;       // Number constants
    std::vector<std::string> strings;    // String constants
    
    void clear() {
        code.clear();
        constants.clear();
        strings.clear();
    }
};

// Compilation result
struct CompileResult {
    BytecodeModule module;
    bool success;
    std::string errorMessage;
    uint32_t errorLine;
    uint32_t errorColumn;
    
    CompileResult() : success(false), errorLine(0), errorColumn(0) {}
    
    static CompileResult Success(BytecodeModule&& mod) {
        CompileResult r;
        r.success = true;
        r.module = std::move(mod);
        return r;
    }
    
    static CompileResult Error(const std::string& msg, uint32_t line = 0, uint32_t col = 0) {
        CompileResult r;
        r.success = false;
        r.errorMessage = msg;
        r.errorLine = line;
        r.errorColumn = col;
        return r;
    }
};

// Register allocation (simple stack-based for now)
class RegisterAllocator {
public:
    RegisterAllocator();
    
    // Allocate a register (returns register index 0-15)
    uint8_t Allocate();
    
    // Free a register
    void Free(uint8_t reg);
    
    // Check if register is available
    bool IsAvailable(uint8_t reg) const;
    
    // Reset all registers
    void Reset();
    
private:
    uint16_t used_mask_;  // Bitmask of used registers
};

// Variable scope tracking
struct Scope {
    std::unordered_map<std::string, uint8_t> variables;  // name -> register
    uint8_t parent_scope_id;
};

// Loop info for break/continue
struct LoopInfo {
    size_t start_pos;   // Bytecode position of loop start
    size_t exit_pos;    // Bytecode position to jump on break
};

// Compiler context for AST traversal
struct CompilerContext {
    BytecodeModule* module;
    RegisterAllocator* registers;
    std::vector<Scope> scopes;
    uint8_t current_scope_id;
    
    // Constant pool management
    std::unordered_map<double, uint16_t> number_constants;
    std::unordered_map<std::string, uint16_t> string_constants;
    
    // Loop stack for break/continue
    std::vector<LoopInfo> loop_stack;
    
    CompilerContext(BytecodeModule* mod, RegisterAllocator* regs)
        : module(mod), registers(regs), current_scope_id(0) {
        scopes.push_back(Scope{});  // Global scope
    }
    
    // Enter new scope
    void EnterScope();
    
    // Exit current scope
    void ExitScope();
    
    // Declare variable in current scope
    void DeclareVariable(const std::string& name, uint8_t reg);
    
    // Lookup variable (returns register or 0xFF if not found)
    uint8_t LookupVariable(const std::string& name);
    
    // Add constant to pool
    uint16_t AddNumberConstant(double value);
    uint16_t AddStringConstant(const std::string& value);
};

// Main Compiler class
class Compiler {
public:
    Compiler();
    
    // Compile AST to bytecode module
    CompileResult Compile(Program* ast);
    
    // Compile expression (returns register holding result)
    uint8_t CompileExpression(CompilerContext& ctx, Expression* expr);
    
    // Compile statement
    void CompileStatement(CompilerContext& ctx, Statement* stmt);
    
    // Compile declaration
    void CompileDeclaration(CompilerContext& ctx, Declaration* decl);
    
private:
    RegisterAllocator registers_;
    
    // Expression compilers
    uint8_t CompileNumberLiteral(CompilerContext& ctx, NumberLiteralExpr* expr);
    uint8_t CompileStringLiteral(CompilerContext& ctx, StringLiteralExpr* expr);
    uint8_t CompileBooleanLiteral(CompilerContext& ctx, BooleanLiteralExpr* expr);
    uint8_t CompileNullLiteral(CompilerContext& ctx, NullLiteralExpr* expr);
    uint8_t CompileUndefinedLiteral(CompilerContext& ctx, UndefinedLiteralExpr* expr);
    uint8_t CompileIdentifier(CompilerContext& ctx, IdentifierExpr* expr);
    uint8_t CompileBinaryExpr(CompilerContext& ctx, BinaryExpr* expr);
    uint8_t CompileUnaryExpr(CompilerContext& ctx, UnaryExpr* expr);
    uint8_t CompileAssignmentExpr(CompilerContext& ctx, AssignmentExpr* expr);
    uint8_t CompileCallExpr(CompilerContext& ctx, CallExpr* expr);
    uint8_t CompileMemberExpr(CompilerContext& ctx, MemberExpr* expr);
    uint8_t CompileConditionalExpr(CompilerContext& ctx, ConditionalExpr* expr);
    uint8_t CompileArrayExpr(CompilerContext& ctx, ArrayExpr* expr);
    uint8_t CompileObjectExpr(CompilerContext& ctx, ObjectExpr* expr);
    uint8_t CompileFunctionExpr(CompilerContext& ctx, FunctionExpr* expr);
    
    // Statement compilers
    void CompileExpressionStmt(CompilerContext& ctx, ExpressionStmt* stmt);
    void CompileBlockStmt(CompilerContext& ctx, BlockStmt* stmt);
    void CompileVariableStmt(CompilerContext& ctx, VariableDecl* stmt);
    void CompileIfStmt(CompilerContext& ctx, IfStmt* stmt);
    void CompileWhileStmt(CompilerContext& ctx, WhileStmt* stmt);
    void CompileForStmt(CompilerContext& ctx, ForStmt* stmt);
    void CompileReturnStmt(CompilerContext& ctx, ReturnStmt* stmt);
    void CompileBreakStmt(CompilerContext& ctx, BreakStmt* stmt);
    void CompileContinueStmt(CompilerContext& ctx, ContinueStmt* stmt);
    
    // Instruction emission helpers (using uint8_t for opcode)
    void EmitOp(CompilerContext& ctx, uint8_t op);
    void EmitOpReg(CompilerContext& ctx, uint8_t op, uint8_t reg);
    void EmitOpRegConst(CompilerContext& ctx, uint8_t op, uint8_t reg, uint16_t const_idx);
    void EmitOpRegReg(CompilerContext& ctx, uint8_t op, uint8_t dst, uint8_t src);
    void EmitOpRegRegReg(CompilerContext& ctx, uint8_t op, uint8_t dst, uint8_t src_a, uint8_t src_b);
    void EmitOpRegImm(CompilerContext& ctx, uint8_t op, uint8_t reg, int32_t imm);
    void EmitOpImm(CompilerContext& ctx, uint8_t op, int32_t imm);
    void PatchImm32(CompilerContext& ctx, size_t pos, int32_t imm);
    
    // Get opcode for binary operator
    uint8_t GetBinaryOpcode(const std::string& op);
    
    // Get opcode for unary operator
    uint8_t GetUnaryOpcode(const std::string& op);
};

// Utility functions
std::string OpcodeToString(uint8_t op);
void DumpBytecode(const BytecodeModule& module, FILE* out = stdout);

} // namespace Script
} // namespace RawrXD
