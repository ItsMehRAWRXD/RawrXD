// RawrXD-Script Bytecode Compiler Implementation
// AST → Bytecode translation

#include "compiler.hpp"
#include "../bytecode/bytecode.hpp"
#include <cstring>
#include <cstdio>
#include <cmath>

namespace RawrXD {
namespace Script {

// Opcode constants for convenience
using Opcode = Bytecode::Opcode;

// ============================================================================
// Register Allocator
// ============================================================================

RegisterAllocator::RegisterAllocator() : used_mask_(0) {}

uint8_t RegisterAllocator::Allocate() {
    // Find first free register (0-15)
    for (int i = 0; i < 16; i++) {
        if (!(used_mask_ & (1 << i))) {
            used_mask_ |= (1 << i);
            return static_cast<uint8_t>(i);
        }
    }
    // No registers available - return 0 and let caller handle spill
    return 0;
}

void RegisterAllocator::Free(uint8_t reg) {
    if (reg < 16) {
        used_mask_ &= ~(1 << reg);
    }
}

bool RegisterAllocator::IsAvailable(uint8_t reg) const {
    return reg < 16 && !(used_mask_ & (1 << reg));
}

void RegisterAllocator::Reset() {
    used_mask_ = 0;
}

// ============================================================================
// Compiler Context
// ============================================================================

void CompilerContext::EnterScope() {
    scopes.push_back(Scope{});
    current_scope_id = static_cast<uint8_t>(scopes.size() - 1);
}

void CompilerContext::ExitScope() {
    if (scopes.size() > 1) {
        scopes.pop_back();
        current_scope_id = static_cast<uint8_t>(scopes.size() - 1);
    }
}

void CompilerContext::DeclareVariable(const std::string& name, uint8_t reg) {
    if (!scopes.empty()) {
        scopes.back().variables[name] = reg;
    }
}

uint8_t CompilerContext::LookupVariable(const std::string& name) {
    // Search from innermost to outermost scope
    for (auto it = scopes.rbegin(); it != scopes.rend(); ++it) {
        auto var_it = it->variables.find(name);
        if (var_it != it->variables.end()) {
            return var_it->second;
        }
    }
    return 0xFF;  // Not found
}

uint16_t CompilerContext::AddNumberConstant(double value) {
    auto it = number_constants.find(value);
    if (it != number_constants.end()) {
        return it->second;
    }
    
    uint16_t idx = static_cast<uint16_t>(module->constants.size());
    module->constants.push_back(value);
    number_constants[value] = idx;
    return idx;
}

uint16_t CompilerContext::AddStringConstant(const std::string& value) {
    auto it = string_constants.find(value);
    if (it != string_constants.end()) {
        return it->second;
    }
    
    uint16_t idx = static_cast<uint16_t>(module->strings.size());
    module->strings.push_back(value);
    string_constants[value] = idx;
    return idx;
}

// ============================================================================
// Compiler
// ============================================================================

Compiler::Compiler() {}

CompileResult Compiler::Compile(Program* ast) {
    if (!ast) {
        return CompileResult::Error("Null AST");
    }
    
    BytecodeModule module;
    registers_.Reset();
    
    CompilerContext ctx(&module, &registers_);
    
    // Compile each statement in the program
    for (auto& stmt : ast->body) {
        CompileStatement(ctx, stmt.get());
    }
    
    // Always end with RETURN (if not already present)
    if (module.code.empty() || module.code.back() != static_cast<uint8_t>(Opcode::OP_RETURN)) {
        // Return undefined from r0
        EmitOpReg(ctx, static_cast<uint8_t>(Opcode::OP_RETURN), 0);
    }
    
    return CompileResult::Success(std::move(module));
}

uint8_t Compiler::CompileExpression(CompilerContext& ctx, Expression* expr) {
    if (!expr) return 0;
    
    // Dispatch based on expression type
    switch (expr->type) {
        case ASTNodeType::NumberLiteral:
            return CompileNumberLiteral(ctx, static_cast<NumberLiteralExpr*>(expr));
        case ASTNodeType::StringLiteral:
            return CompileStringLiteral(ctx, static_cast<StringLiteralExpr*>(expr));
        case ASTNodeType::BooleanLiteral:
            return CompileBooleanLiteral(ctx, static_cast<BooleanLiteralExpr*>(expr));
        case ASTNodeType::NullLiteral:
            return CompileNullLiteral(ctx, static_cast<NullLiteralExpr*>(expr));
        case ASTNodeType::UndefinedLiteral:
            return CompileUndefinedLiteral(ctx, static_cast<UndefinedLiteralExpr*>(expr));
        case ASTNodeType::Identifier:
            return CompileIdentifier(ctx, static_cast<IdentifierExpr*>(expr));
        case ASTNodeType::BinaryExpression:
            return CompileBinaryExpr(ctx, static_cast<BinaryExpr*>(expr));
        case ASTNodeType::UnaryExpression:
            return CompileUnaryExpr(ctx, static_cast<UnaryExpr*>(expr));
        case ASTNodeType::AssignmentExpression:
            return CompileAssignmentExpr(ctx, static_cast<AssignmentExpr*>(expr));
        case ASTNodeType::CallExpression:
            return CompileCallExpr(ctx, static_cast<CallExpr*>(expr));
        case ASTNodeType::MemberExpression:
            return CompileMemberExpr(ctx, static_cast<MemberExpr*>(expr));
        case ASTNodeType::ConditionalExpression:
            return CompileConditionalExpr(ctx, static_cast<ConditionalExpr*>(expr));
        case ASTNodeType::ArrayExpression:
            return CompileArrayExpr(ctx, static_cast<ArrayExpr*>(expr));
        case ASTNodeType::ObjectExpression:
            return CompileObjectExpr(ctx, static_cast<ObjectExpr*>(expr));
        case ASTNodeType::FunctionExpression:
            return CompileFunctionExpr(ctx, static_cast<FunctionExpr*>(expr));
        default:
            return 0;
    }
}

void Compiler::CompileStatement(CompilerContext& ctx, Statement* stmt) {
    if (!stmt) return;
    
    switch (stmt->type) {
        case ASTNodeType::ExpressionStatement:
            CompileExpressionStmt(ctx, static_cast<ExpressionStmt*>(stmt));
            break;
        case ASTNodeType::BlockStatement:
            CompileBlockStmt(ctx, static_cast<BlockStmt*>(stmt));
            break;
        case ASTNodeType::VariableDeclaration:
            CompileVariableStmt(ctx, static_cast<VariableDecl*>(stmt));
            break;
        case ASTNodeType::IfStatement:
            CompileIfStmt(ctx, static_cast<IfStmt*>(stmt));
            break;
        case ASTNodeType::WhileStatement:
            CompileWhileStmt(ctx, static_cast<WhileStmt*>(stmt));
            break;
        case ASTNodeType::ForStatement:
            CompileForStmt(ctx, static_cast<ForStmt*>(stmt));
            break;
        case ASTNodeType::ReturnStatement:
            CompileReturnStmt(ctx, static_cast<ReturnStmt*>(stmt));
            break;
        case ASTNodeType::BreakStatement:
            CompileBreakStmt(ctx, static_cast<BreakStmt*>(stmt));
            break;
        case ASTNodeType::ContinueStatement:
            CompileContinueStmt(ctx, static_cast<ContinueStmt*>(stmt));
            break;
        default:
            break;
    }
}

// ============================================================================
// Expression Compilers
// ============================================================================

uint8_t Compiler::CompileNumberLiteral(CompilerContext& ctx, NumberLiteralExpr* expr) {
    uint8_t reg = ctx.registers->Allocate();
    uint16_t const_idx = ctx.AddNumberConstant(expr->value);
    EmitOpRegConst(ctx, static_cast<uint8_t>(Opcode::OP_LOAD_CONST), reg, const_idx);
    return reg;
}

uint8_t Compiler::CompileStringLiteral(CompilerContext& ctx, StringLiteralExpr* expr) {
    uint8_t reg = ctx.registers->Allocate();
    uint16_t str_idx = ctx.AddStringConstant(expr->value);
    EmitOpRegConst(ctx, static_cast<uint8_t>(Opcode::OP_LOAD_STRING), reg, str_idx);
    return reg;
}

uint8_t Compiler::CompileBooleanLiteral(CompilerContext& ctx, BooleanLiteralExpr* expr) {
    uint8_t reg = ctx.registers->Allocate();
    EmitOpReg(ctx, expr->value ? static_cast<uint8_t>(Opcode::OP_LOAD_TRUE) : static_cast<uint8_t>(Opcode::OP_LOAD_FALSE), reg);
    return reg;
}

uint8_t Compiler::CompileNullLiteral(CompilerContext& ctx, NullLiteralExpr* expr) {
    uint8_t reg = ctx.registers->Allocate();
    EmitOpReg(ctx, static_cast<uint8_t>(Opcode::OP_LOAD_NULL), reg);
    return reg;
}

uint8_t Compiler::CompileUndefinedLiteral(CompilerContext& ctx, UndefinedLiteralExpr* expr) {
    uint8_t reg = ctx.registers->Allocate();
    EmitOpReg(ctx, static_cast<uint8_t>(Opcode::OP_LOAD_UNDEFINED), reg);
    return reg;
}

uint8_t Compiler::CompileIdentifier(CompilerContext& ctx, IdentifierExpr* expr) {
    // Look up variable in scope
    uint8_t var_reg = ctx.LookupVariable(expr->name);
    if (var_reg != 0xFF) {
        return var_reg;  // Return the register holding this variable
    }
    // Variable not found - return undefined in new register
    uint8_t reg = ctx.registers->Allocate();
    EmitOpReg(ctx, static_cast<uint8_t>(Opcode::OP_LOAD_UNDEFINED), reg);
    return reg;
}

uint8_t Compiler::CompileBinaryExpr(CompilerContext& ctx, BinaryExpr* expr) {
    // Compile left and right operands
    uint8_t left_reg = CompileExpression(ctx, expr->left.get());
    uint8_t right_reg = CompileExpression(ctx, expr->right.get());
    
    // Allocate result register
    uint8_t result_reg = ctx.registers->Allocate();
    
    // Get opcode for operator
    uint8_t op = GetBinaryOpcode(expr->op);
    
    // Emit: result = left op right
    EmitOpRegRegReg(ctx, op, result_reg, left_reg, right_reg);
    
    // Free operand registers (they're consumed)
    ctx.registers->Free(left_reg);
    ctx.registers->Free(right_reg);
    
    return result_reg;
}

uint8_t Compiler::CompileUnaryExpr(CompilerContext& ctx, UnaryExpr* expr) {
    uint8_t arg_reg = CompileExpression(ctx, expr->argument.get());
    uint8_t result_reg = ctx.registers->Allocate();
    
    uint8_t op = GetUnaryOpcode(expr->op);
    
    // For negation, we need to emit NEG
    if (expr->op == "-") {
        EmitOpRegReg(ctx, static_cast<uint8_t>(Opcode::OP_NEG), result_reg, arg_reg);
    } else if (expr->op == "!") {
        // Logical not - compare with false and return result
        EmitOpRegRegReg(ctx, static_cast<uint8_t>(Opcode::OP_EQ), result_reg, arg_reg, 0); // r0 = false
    } else {
        // Default: just move
        EmitOpRegReg(ctx, static_cast<uint8_t>(Opcode::OP_MOVE), result_reg, arg_reg);
    }
    
    ctx.registers->Free(arg_reg);
    return result_reg;
}

uint8_t Compiler::CompileAssignmentExpr(CompilerContext& ctx, AssignmentExpr* expr) {
    // For now, simple assignment: left = right
    // Left must be an identifier
    if (auto* ident = dynamic_cast<IdentifierExpr*>(expr->left.get())) {
        uint8_t right_reg = CompileExpression(ctx, expr->right.get());
        uint8_t var_reg = ctx.LookupVariable(ident->name);
        
        if (var_reg != 0xFF) {
            // Variable exists - move value to its register
            EmitOpRegReg(ctx, static_cast<uint8_t>(Opcode::OP_MOVE), var_reg, right_reg);
            ctx.registers->Free(right_reg);
            return var_reg;
        } else {
            // New variable - declare it
            ctx.DeclareVariable(ident->name, right_reg);
            return right_reg;
        }
    }
    
    // Complex assignment - just evaluate right side
    return CompileExpression(ctx, expr->right.get());
}

uint8_t Compiler::CompileCallExpr(CompilerContext& ctx, CallExpr* expr) {
    // Compile callee
    uint8_t callee_reg = CompileExpression(ctx, expr->callee.get());
    
    // Compile arguments
    std::vector<uint8_t> arg_regs;
    for (auto& arg : expr->arguments) {
        uint8_t arg_reg = CompileExpression(ctx, arg.get());
        arg_regs.push_back(arg_reg);
    }
    
    // Allocate result register
    uint8_t result_reg = ctx.registers->Allocate();
    
    // Emit OP_CALL: result = callee(arg1, arg2, ...)
    // Format: [OP][DST][CALLEE][ARG_COUNT][ARG1][ARG2]...
    ctx.module->code.push_back(static_cast<uint8_t>(Opcode::OP_CALL));
    ctx.module->code.push_back(result_reg);
    ctx.module->code.push_back(callee_reg);
    ctx.module->code.push_back(static_cast<uint8_t>(arg_regs.size()));
    for (uint8_t ar : arg_regs) {
        ctx.module->code.push_back(ar);
    }
    
    // Free argument registers
    for (uint8_t ar : arg_regs) {
        ctx.registers->Free(ar);
    }
    ctx.registers->Free(callee_reg);
    
    return result_reg;
}

uint8_t Compiler::CompileMemberExpr(CompilerContext& ctx, MemberExpr* expr) {
    // Compile object
    uint8_t obj_reg = CompileExpression(ctx, expr->object.get());
    
    // Get property name
    std::string prop_name;
    if (expr->computed) {
        // Computed: obj[prop]
        uint8_t prop_reg = CompileExpression(ctx, expr->property.get());
        // For computed, we'd need runtime property lookup
        ctx.registers->Free(prop_reg);
        // Simplified: return undefined
        uint8_t result_reg = ctx.registers->Allocate();
        EmitOpReg(ctx, static_cast<uint8_t>(Opcode::OP_LOAD_UNDEFINED), result_reg);
        ctx.registers->Free(obj_reg);
        return result_reg;
    } else {
        // Static: obj.prop
        if (auto* ident = dynamic_cast<IdentifierExpr*>(expr->property.get())) {
            prop_name = ident->name;
        }
    }
    
    // Add property name to string pool
    uint16_t name_idx = ctx.AddStringConstant(prop_name);
    
    // Allocate result register
    uint8_t result_reg = ctx.registers->Allocate();
    
    // Emit OP_GET_PROP: result = obj.prop
    ctx.module->code.push_back(static_cast<uint8_t>(Opcode::OP_GET_PROP));
    ctx.module->code.push_back(result_reg);  // Destination
    ctx.module->code.push_back(obj_reg);     // Object
    ctx.module->code.push_back(static_cast<uint8_t>(name_idx & 0xFF));
    ctx.module->code.push_back(static_cast<uint8_t>((name_idx >> 8) & 0xFF));
    ctx.module->code.push_back(0);           // IC slot (0 for now)
    ctx.module->code.push_back(0);
    ctx.module->code.push_back(0);
    ctx.module->code.push_back(0);
    
    ctx.registers->Free(obj_reg);
    return result_reg;
}

uint8_t Compiler::CompileConditionalExpr(CompilerContext& ctx, ConditionalExpr* expr) {
    // Placeholder: just evaluate consequent
    return CompileExpression(ctx, expr->consequent.get());
}

uint8_t Compiler::CompileArrayExpr(CompilerContext& ctx, ArrayExpr* expr) {
    // Allocate result register
    uint8_t result_reg = ctx.registers->Allocate();
    
    // Emit OP_CREATE_ARRAY with size hint
    uint8_t size_hint = static_cast<uint8_t>(std::min(expr->elements.size(), size_t(255)));
    ctx.module->code.push_back(static_cast<uint8_t>(Opcode::OP_CREATE_ARRAY));
    ctx.module->code.push_back(result_reg);
    ctx.module->code.push_back(size_hint);
    
    // Compile and add each element
    for (size_t i = 0; i < expr->elements.size(); i++) {
        uint8_t elem_reg = CompileExpression(ctx, expr->elements[i].get());
        
        // Emit OP_ARRAY_PUSH: result.push(elem)
        ctx.module->code.push_back(static_cast<uint8_t>(Opcode::OP_ARRAY_PUSH));
        ctx.module->code.push_back(result_reg);  // Array
        ctx.module->code.push_back(elem_reg);   // Element
        
        ctx.registers->Free(elem_reg);
    }
    
    return result_reg;
}

uint8_t Compiler::CompileObjectExpr(CompilerContext& ctx, ObjectExpr* expr) {
    // Allocate result register
    uint8_t result_reg = ctx.registers->Allocate();
    
    // Emit OP_CREATE_OBJECT
    EmitOpReg(ctx, static_cast<uint8_t>(Opcode::OP_CREATE_OBJECT), result_reg);
    
    // Compile and add each property
    for (const auto& prop : expr->properties) {
        // Get property name
        std::string prop_name;
        if (auto* ident = dynamic_cast<IdentifierExpr*>(prop.key.get())) {
            prop_name = ident->name;
        } else if (auto* str = dynamic_cast<StringLiteralExpr*>(prop.key.get())) {
            prop_name = str->value;
        } else {
            // Computed property key - evaluate and convert to string
            prop_name = ""; // Simplified
        }
        
        // Add property name to string pool
        uint16_t name_idx = ctx.AddStringConstant(prop_name);
        
        // Compile value
        uint8_t value_reg = CompileExpression(ctx, prop.value.get());
        
        // Emit OP_OBJECT_SET: result[name] = value
        ctx.module->code.push_back(static_cast<uint8_t>(Opcode::OP_OBJECT_SET));
        ctx.module->code.push_back(result_reg);  // Object
        ctx.module->code.push_back(static_cast<uint8_t>(name_idx & 0xFF));
        ctx.module->code.push_back(static_cast<uint8_t>((name_idx >> 8) & 0xFF));
        ctx.module->code.push_back(value_reg);   // Value
        
        ctx.registers->Free(value_reg);
    }
    
    return result_reg;
}

uint8_t Compiler::CompileFunctionExpr(CompilerContext& ctx, FunctionExpr* expr) {
    // Create function object with bytecode
    uint8_t result_reg = ctx.registers->Allocate();
    
    // Compile function body to separate bytecode
    BytecodeModule func_module;
    RegisterAllocator func_regs;
    CompilerContext func_ctx(&func_module, &func_regs);
    
    // Enter function scope
    func_ctx.EnterScope();
    
    // Declare parameters as local variables
    for (const auto& param : expr->params) {
        uint8_t param_reg = func_ctx.registers->Allocate();
        func_ctx.DeclareVariable(param, param_reg);
    }
    
    // Compile function body
    if (expr->body) {
        CompileStatement(func_ctx, expr->body.get());
    }
    
    // Ensure function ends with return
    if (func_module.code.empty() || func_module.code.back() != static_cast<uint8_t>(Opcode::OP_RETURN)) {
        EmitOpReg(func_ctx, static_cast<uint8_t>(Opcode::OP_LOAD_UNDEFINED), 0);
        EmitOpReg(func_ctx, static_cast<uint8_t>(Opcode::OP_RETURN), 0);
    }
    
    func_ctx.ExitScope();
    
    // Emit OP_CREATE_FUNC with function bytecode reference
    // For now, store function index in constant pool
    uint16_t func_idx = static_cast<uint16_t>(ctx.module->constants.size());
    ctx.module->constants.push_back(static_cast<double>(func_idx)); // Hack: store index as double
    
    EmitOpRegConst(ctx, static_cast<uint8_t>(Opcode::OP_CREATE_FUNC), result_reg, func_idx);
    
    return result_reg;
}

// ============================================================================
// Statement Compilers
// ============================================================================

void Compiler::CompileExpressionStmt(CompilerContext& ctx, ExpressionStmt* stmt) {
    // Compile expression and discard result
    uint8_t reg = CompileExpression(ctx, stmt->expression.get());
    ctx.registers->Free(reg);
}

void Compiler::CompileBlockStmt(CompilerContext& ctx, BlockStmt* stmt) {
    ctx.EnterScope();
    for (auto& s : stmt->body) {
        CompileStatement(ctx, s.get());
    }
    ctx.ExitScope();
}

void Compiler::CompileVariableStmt(CompilerContext& ctx, VariableDecl* stmt) {
    for (auto& declarator : stmt->declarations) {
        if (declarator.init.has_value() && declarator.init.value()) {
            uint8_t init_reg = CompileExpression(ctx, declarator.init.value().get());
            
            // Get variable name from identifier
            if (auto* ident = dynamic_cast<IdentifierExpr*>(declarator.id.get())) {
                ctx.DeclareVariable(ident->name, init_reg);
            }
        }
    }
}

void Compiler::CompileIfStmt(CompilerContext& ctx, IfStmt* stmt) {
    // Compile condition
    uint8_t cond_reg = CompileExpression(ctx, stmt->test.get());
    
    // Emit conditional jump to else (or end if no else)
    // OP_JMP_NOT_COND: if (!cond) pc += offset
    size_t jmp_else_pos = ctx.module->code.size();
    EmitOpRegImm(ctx, static_cast<uint8_t>(Opcode::OP_JMP_NOT_COND), cond_reg, 0); // Placeholder offset
    ctx.registers->Free(cond_reg);
    
    // Compile consequent (then branch)
    CompileStatement(ctx, stmt->consequent.get());
    
    if (stmt->alternate) {
        // Emit jump over else block
        size_t jmp_end_pos = ctx.module->code.size();
        EmitOpImm(ctx, static_cast<uint8_t>(Opcode::OP_JMP), 0); // Placeholder
        
        // Patch jump to else
        size_t else_start = ctx.module->code.size();
        int32_t else_offset = static_cast<int32_t>(else_start - jmp_else_pos - 6); // 6 bytes for OP_JMP_NOT_COND
        PatchImm32(ctx, jmp_else_pos + 2, else_offset);
        
        // Compile alternate (else branch)
        CompileStatement(ctx, stmt->alternate.get());
        
        // Patch jump over else
        size_t end_pos = ctx.module->code.size();
        int32_t end_offset = static_cast<int32_t>(end_pos - jmp_end_pos - 5); // 5 bytes for OP_JMP
        PatchImm32(ctx, jmp_end_pos + 1, end_offset);
    } else {
        // Patch jump to end (no else)
        size_t end_pos = ctx.module->code.size();
        int32_t end_offset = static_cast<int32_t>(end_pos - jmp_else_pos - 6);
        PatchImm32(ctx, jmp_else_pos + 2, end_offset);
    }
}

void Compiler::CompileWhileStmt(CompilerContext& ctx, WhileStmt* stmt) {
    // Label for loop start
    size_t loop_start = ctx.module->code.size();
    
    // Compile condition
    uint8_t cond_reg = CompileExpression(ctx, stmt->test.get());
    
    // Emit conditional exit jump
    size_t jmp_exit_pos = ctx.module->code.size();
    EmitOpRegImm(ctx, static_cast<uint8_t>(Opcode::OP_JMP_NOT_COND), cond_reg, 0);
    ctx.registers->Free(cond_reg);
    
    // Track break/continue positions for this loop
    ctx.loop_stack.push_back({loop_start, jmp_exit_pos});
    
    // Compile body
    CompileStatement(ctx, stmt->body.get());
    
    ctx.loop_stack.pop_back();
    
    // Emit jump back to loop start
    int32_t back_offset = static_cast<int32_t>(loop_start - ctx.module->code.size() - 5);
    EmitOpImm(ctx, static_cast<uint8_t>(Opcode::OP_JMP), back_offset);
    
    // Patch exit jump
    size_t loop_end = ctx.module->code.size();
    int32_t exit_offset = static_cast<int32_t>(loop_end - jmp_exit_pos - 6);
    PatchImm32(ctx, jmp_exit_pos + 2, exit_offset);
}

void Compiler::CompileForStmt(CompilerContext& ctx, ForStmt* stmt) {
    // Enter scope for loop variables
    ctx.EnterScope();
    
    // Compile init (if present)
    if (stmt->init) {
        if (auto* var_decl = dynamic_cast<VariableDecl*>(stmt->init.value().get())) {
            CompileVariableStmt(ctx, var_decl);
        } else {
            // Expression init
            uint8_t init_reg = CompileExpression(ctx, stmt->init.value().get());
            ctx.registers->Free(init_reg);
        }
    }
    
    // Label for loop start
    size_t loop_start = ctx.module->code.size();
    
    // Compile test (if present)
    size_t jmp_exit_pos = 0;
    if (stmt->test) {
        uint8_t cond_reg = CompileExpression(ctx, stmt->test.value().get());
        jmp_exit_pos = ctx.module->code.size();
        EmitOpRegImm(ctx, static_cast<uint8_t>(Opcode::OP_JMP_NOT_COND), cond_reg, 0);
        ctx.registers->Free(cond_reg);
    }
    
    // Track break/continue for this loop
    ctx.loop_stack.push_back({loop_start, jmp_exit_pos});
    
    // Compile body
    CompileStatement(ctx, stmt->body.get());
    
    // Label for continue (update section)
    size_t update_pos = ctx.module->code.size();
    
    // Compile update (if present)
    if (stmt->update) {
        uint8_t update_reg = CompileExpression(ctx, stmt->update.value().get());
        ctx.registers->Free(update_reg);
    }
    
    ctx.loop_stack.pop_back();
    
    // Jump back to loop start
    int32_t back_offset = static_cast<int32_t>(loop_start - ctx.module->code.size() - 5);
    EmitOpImm(ctx, static_cast<uint8_t>(Opcode::OP_JMP), back_offset);
    
    // Patch exit jump
    if (stmt->test && jmp_exit_pos > 0) {
        size_t loop_end = ctx.module->code.size();
        int32_t exit_offset = static_cast<int32_t>(loop_end - jmp_exit_pos - 6);
        PatchImm32(ctx, jmp_exit_pos + 2, exit_offset);
    }
    
    ctx.ExitScope();
}

void Compiler::CompileReturnStmt(CompilerContext& ctx, ReturnStmt* stmt) {
    uint8_t reg = 0;  // Default: return undefined from r0
    if (stmt->argument && stmt->argument.value()) {
        reg = CompileExpression(ctx, stmt->argument.value().get());
    } else {
        EmitOpReg(ctx, static_cast<uint8_t>(Opcode::OP_LOAD_UNDEFINED), 0);
    }
    EmitOpReg(ctx, static_cast<uint8_t>(Opcode::OP_RETURN), reg);
}

void Compiler::CompileBreakStmt(CompilerContext& ctx, BreakStmt* stmt) {
    if (ctx.loop_stack.empty()) {
        // Error: break outside loop - emit NOP for now
        EmitOp(ctx, static_cast<uint8_t>(Opcode::OP_NOP));
        return;
    }
    
    // Jump to loop exit (will be patched)
    auto& loop_info = ctx.loop_stack.back();
    size_t break_pos = ctx.module->code.size();
    EmitOpImm(ctx, static_cast<uint8_t>(Opcode::OP_JMP), 0); // Placeholder
    
    // Store position to patch later (simplified - would need proper break list)
    // For now, just jump to the recorded exit position
    int32_t offset = static_cast<int32_t>(loop_info.exit_pos - break_pos - 5);
    PatchImm32(ctx, break_pos + 1, offset);
}

void Compiler::CompileContinueStmt(CompilerContext& ctx, ContinueStmt* stmt) {
    if (ctx.loop_stack.empty()) {
        // Error: continue outside loop
        EmitOp(ctx, static_cast<uint8_t>(Opcode::OP_NOP));
        return;
    }
    
    // Jump to loop start
    auto& loop_info = ctx.loop_stack.back();
    int32_t offset = static_cast<int32_t>(loop_info.start_pos - ctx.module->code.size() - 5);
    EmitOpImm(ctx, static_cast<uint8_t>(Opcode::OP_JMP), offset);
}

// ============================================================================
// Instruction Emission
// ============================================================================

void Compiler::EmitOp(CompilerContext& ctx, uint8_t op) {
    ctx.module->code.push_back(op);
}

void Compiler::EmitOpReg(CompilerContext& ctx, uint8_t op, uint8_t reg) {
    ctx.module->code.push_back(op);
    ctx.module->code.push_back(reg);
}

void Compiler::EmitOpRegConst(CompilerContext& ctx, uint8_t op, uint8_t reg, uint16_t const_idx) {
    ctx.module->code.push_back(op);
    ctx.module->code.push_back(reg);
    ctx.module->code.push_back(const_idx & 0xFF);
    ctx.module->code.push_back((const_idx >> 8) & 0xFF);
}

void Compiler::EmitOpRegReg(CompilerContext& ctx, uint8_t op, uint8_t dst, uint8_t src) {
    ctx.module->code.push_back(op);
    ctx.module->code.push_back(dst);
    ctx.module->code.push_back(src);
}

void Compiler::EmitOpRegRegReg(CompilerContext& ctx, uint8_t op, uint8_t dst, uint8_t src_a, uint8_t src_b) {
    // Format: [OP:1][DST:1][SRC_A:1][SRC_B:1] - matches interpreter expectation
    ctx.module->code.push_back(op);
    ctx.module->code.push_back(dst);
    ctx.module->code.push_back(src_a);
    ctx.module->code.push_back(src_b);
}

void Compiler::EmitOpRegImm(CompilerContext& ctx, uint8_t op, uint8_t reg, int32_t imm) {
    ctx.module->code.push_back(op);
    ctx.module->code.push_back(reg);
    ctx.module->code.push_back(imm & 0xFF);
    ctx.module->code.push_back((imm >> 8) & 0xFF);
    ctx.module->code.push_back((imm >> 16) & 0xFF);
    ctx.module->code.push_back((imm >> 24) & 0xFF);
}

void Compiler::EmitOpImm(CompilerContext& ctx, uint8_t op, int32_t imm) {
    ctx.module->code.push_back(op);
    ctx.module->code.push_back(imm & 0xFF);
    ctx.module->code.push_back((imm >> 8) & 0xFF);
    ctx.module->code.push_back((imm >> 16) & 0xFF);
    ctx.module->code.push_back((imm >> 24) & 0xFF);
}

void Compiler::PatchImm32(CompilerContext& ctx, size_t pos, int32_t imm) {
    if (pos + 4 <= ctx.module->code.size()) {
        ctx.module->code[pos] = imm & 0xFF;
        ctx.module->code[pos + 1] = (imm >> 8) & 0xFF;
        ctx.module->code[pos + 2] = (imm >> 16) & 0xFF;
        ctx.module->code[pos + 3] = (imm >> 24) & 0xFF;
    }
}

// ============================================================================
// Opcode Mapping
// ============================================================================

uint8_t Compiler::GetBinaryOpcode(const std::string& op) {
    if (op == "+") return static_cast<uint8_t>(Opcode::OP_ADD);
    if (op == "-") return static_cast<uint8_t>(Opcode::OP_SUB);
    if (op == "*") return static_cast<uint8_t>(Opcode::OP_MUL);
    if (op == "/") return static_cast<uint8_t>(Opcode::OP_DIV);
    if (op == "%") return static_cast<uint8_t>(Opcode::OP_MOD);
    if (op == "==") return static_cast<uint8_t>(Opcode::OP_EQ);
    if (op == "!=") return static_cast<uint8_t>(Opcode::OP_NEQ);
    if (op == "===") return static_cast<uint8_t>(Opcode::OP_STRICT_EQ);
    if (op == "!==") return static_cast<uint8_t>(Opcode::OP_STRICT_NEQ);
    if (op == "<") return static_cast<uint8_t>(Opcode::OP_LT);
    if (op == "<=") return static_cast<uint8_t>(Opcode::OP_LTE);
    if (op == ">") return static_cast<uint8_t>(Opcode::OP_GT);
    if (op == ">=") return static_cast<uint8_t>(Opcode::OP_GTE);
    if (op == "&") return static_cast<uint8_t>(Opcode::OP_BIT_AND);
    if (op == "|") return static_cast<uint8_t>(Opcode::OP_BIT_OR);
    if (op == "^") return static_cast<uint8_t>(Opcode::OP_BIT_XOR);
    if (op == "<<") return static_cast<uint8_t>(Opcode::OP_SHL);
    if (op == ">>") return static_cast<uint8_t>(Opcode::OP_SHR);
    if (op == ">>>") return static_cast<uint8_t>(Opcode::OP_SHR_U);
    return static_cast<uint8_t>(Opcode::OP_ADD);  // Default
}

uint8_t Compiler::GetUnaryOpcode(const std::string& op) {
    if (op == "-") return static_cast<uint8_t>(Opcode::OP_NEG);
    if (op == "!") return static_cast<uint8_t>(Opcode::OP_EQ);  // Will be used for logical not
    if (op == "~") return static_cast<uint8_t>(Opcode::OP_BIT_NOT);
    return static_cast<uint8_t>(Opcode::OP_MOVE);
}

// ============================================================================
// Utility Functions
// ============================================================================

std::string OpcodeToString(uint8_t op) {
    switch (static_cast<Opcode>(op)) {
        case Opcode::OP_LOAD_CONST: return "LOAD_CONST";
        case Opcode::OP_LOAD_INT: return "LOAD_INT";
        case Opcode::OP_LOAD_TRUE: return "LOAD_TRUE";
        case Opcode::OP_LOAD_FALSE: return "LOAD_FALSE";
        case Opcode::OP_LOAD_NULL: return "LOAD_NULL";
        case Opcode::OP_LOAD_UNDEFINED: return "LOAD_UNDEFINED";
        case Opcode::OP_ADD: return "ADD";
        case Opcode::OP_SUB: return "SUB";
        case Opcode::OP_MUL: return "MUL";
        case Opcode::OP_DIV: return "DIV";
        case Opcode::OP_MOD: return "MOD";
        case Opcode::OP_NEG: return "NEG";
        case Opcode::OP_MOVE: return "MOVE";
        case Opcode::OP_RETURN: return "RETURN";
        default: return "UNKNOWN";
    }
}

void DumpBytecode(const BytecodeModule& module, FILE* out) {
    fprintf(out, "Bytecode Module Dump:\n");
    fprintf(out, "  Constants: %zu\n", module.constants.size());
    for (size_t i = 0; i < module.constants.size(); i++) {
        fprintf(out, "    [%zu] = %f\n", i, module.constants[i]);
    }
    fprintf(out, "  Code (%zu bytes):\n", module.code.size());
    for (size_t i = 0; i < module.code.size(); i++) {
        fprintf(out, "    [%zu] = 0x%02X\n", i, module.code[i]);
    }
}

} // namespace Script
} // namespace RawrXD
