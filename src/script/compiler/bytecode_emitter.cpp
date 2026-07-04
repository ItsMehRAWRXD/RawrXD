// RawrXD-Script Bytecode Emitter Implementation
// Converts AST to RAWR bytecode

#include "bytecode_emitter.hpp"
#include <stdexcept>

namespace RawrXD {
namespace Script {

BytecodeEmitter::BytecodeEmitter() : resultRegister_(0) {}

bool BytecodeEmitter::Emit(Program* program, Bytecode::BytecodeModule* module) {
    ctx_.module = module;
    ctx_.scopes.clear();
    ctx_.labels.clear();
    ctx_.pendingJumps.clear();
    ctx_.nextRegister = 0;
    errors_.clear();
    
    try {
        // Enter global scope
        EnterScope();
        
        // Compile all statements
        for (const auto& stmt : program->body) {
            CompileStatement(stmt.get());
        }
        
        // Add implicit return undefined
        EmitInstruction(Bytecode::Opcode::OP_LOAD_UNDEFINED, 0);
        EmitInstruction(Bytecode::Opcode::OP_RETURN, 0);
        
        // Patch pending jumps
        for (const auto& [offset, label] : ctx_.pendingJumps) {
            auto it = ctx_.labels.find(label);
            if (it != ctx_.labels.end()) {
                PatchJump(offset, it->second);
            } else {
                errors_.push_back("Undefined label: " + label);
            }
        }
        
        ExitScope();
        return errors_.empty();
        
    } catch (const std::exception& e) {
        errors_.push_back(e.what());
        return false;
    }
}

// Helper methods
void BytecodeEmitter::EmitInstruction(Bytecode::Opcode op, uint8_t dst, uint8_t srcA, uint8_t srcB) {
    Bytecode::Instruction inst(op, dst, srcA, srcB);
    ctx_.module->AppendInstruction(inst);
}

void BytecodeEmitter::EmitLoadConst(uint8_t reg, uint32_t constIdx) {
    // Extended instruction for large constants
    if (constIdx < 256) {
        EmitInstruction(Bytecode::Opcode::OP_LOAD_CONST, reg, 
                       static_cast<uint8_t>(constIdx & 0xFF), 
                       static_cast<uint8_t>((constIdx >> 8) & 0xFF));
    } else {
        // Use extended format
        EmitInstruction(Bytecode::Opcode::OP_LOAD_CONST, reg);
        // TODO: Emit extended instruction data
    }
}

void BytecodeEmitter::EmitLoadInt(uint8_t reg, int32_t value) {
    if (value == 0) {
        EmitInstruction(Bytecode::Opcode::OP_LOAD_ZERO, reg);
    } else if (value == 1) {
        EmitInstruction(Bytecode::Opcode::OP_LOAD_ONE, reg);
    } else if (value >= -32768 && value <= 32767) {
        // Fits in 16-bit immediate
        EmitInstruction(Bytecode::Opcode::OP_LOAD_INT, reg,
                       static_cast<uint8_t>(value & 0xFF),
                       static_cast<uint8_t>((value >> 8) & 0xFF));
    } else {
        // Use constant pool
        uint32_t idx = AddConstantInt(value);
        EmitLoadConst(reg, idx);
    }
}

void BytecodeEmitter::EmitLoadString(uint8_t reg, const std::string& str) {
    uint32_t idx = AddConstantString(str);
    EmitInstruction(Bytecode::Opcode::OP_LOAD_STRING, reg,
                   static_cast<uint8_t>(idx & 0xFF),
                   static_cast<uint8_t>((idx >> 8) & 0xFF));
}

void BytecodeEmitter::EmitJump(Bytecode::Opcode op, uint8_t condReg, int32_t offset) {
    // Emit jump with placeholder offset
    EmitInstruction(op, condReg,
                   static_cast<uint8_t>(offset & 0xFF),
                   static_cast<uint8>((offset >> 8) & 0xFF));
}

void BytecodeEmitter::PatchJump(uint32_t jumpOffset, uint32_t targetOffset) {
    // Calculate relative offset
    int32_t relOffset = static_cast<int32_t>(targetOffset) - static_cast<int32_t>(jumpOffset);
    
    // Patch the instruction at jumpOffset
    // This would require access to the instruction array
    // For now, just record the patch needed
}

// Register allocation
uint8_t BytecodeEmitter::AllocateRegister() {
    if (ctx_.nextRegister >= 16) {
        throw std::runtime_error("Out of registers");
    }
    return ctx_.nextRegister++;
}

void BytecodeEmitter::FreeRegister(uint8_t reg) {
    // Simple stack-based allocation - just decrement
    if (reg == ctx_.nextRegister - 1) {
        ctx_.nextRegister--;
    }
}

// Variable scope management
void BytecodeEmitter::EnterScope() {
    ctx_.scopes.emplace_back();
}

void BytecodeEmitter::ExitScope() {
    if (!ctx_.scopes.empty()) {
        ctx_.scopes.pop_back();
    }
}

uint8_t BytecodeEmitter::LookupVariable(const std::string& name) {
    // Search from innermost to outermost scope
    for (auto it = ctx_.scopes.rbegin(); it != ctx_.scopes.rend(); ++it) {
        auto varIt = it->find(name);
        if (varIt != it->end()) {
            return varIt->second;
        }
    }
    // Not found - allocate new global
    uint8_t reg = AllocateRegister();
    DeclareVariable(name, reg);
    return reg;
}

void BytecodeEmitter::DeclareVariable(const std::string& name, uint8_t reg) {
    if (!ctx_.scopes.empty()) {
        ctx_.scopes.back()[name] = reg;
    }
}

// Constant pool helpers
uint32_t BytecodeEmitter::AddConstantInt(int32_t value) {
    Bytecode::Constant c;
    c.type = Bytecode::ConstantType::Int32;
    c.int32_value = value;
    return ctx_.module->AddConstant(c);
}

uint32_t BytecodeEmitter::AddConstantDouble(double value) {
    Bytecode::Constant c;
    c.type = Bytecode::ConstantType::Float64;
    c.float64_value = value;
    return ctx_.module->AddConstant(c);
}

uint32_t BytecodeEmitter::AddConstantString(const std::string& value) {
    return ctx_.module->AddString(value);
}

// Expression compilation
uint8_t BytecodeEmitter::CompileExpression(Expression* expr) {
    // Use visitor pattern
    std::visit([this](auto&& node) {
        this->Visit(node);
    }, *expr);
    return resultRegister_;
}

uint8_t BytecodeEmitter::CompileBinaryExpression(BinaryExpr* expr) {
    uint8_t leftReg = CompileExpression(expr->left.get());
    uint8_t rightReg = CompileExpression(expr->right.get());
    uint8_t resultReg = AllocateRegister();
    
    Bytecode::Opcode op;
    if (expr->op == "+") op = Bytecode::Opcode::OP_ADD;
    else if (expr->op == "-") op = Bytecode::Opcode::OP_SUB;
    else if (expr->op == "*") op = Bytecode::Opcode::OP_MUL;
    else if (expr->op == "/") op = Bytecode::Opcode::OP_DIV;
    else if (expr->op == "%") op = Bytecode::Opcode::OP_MOD;
    else if (expr->op == "==") op = Bytecode::Opcode::OP_EQ;
    else if (expr->op == "!=") op = Bytecode::Opcode::OP_NEQ;
    else if (expr->op == "===") op = Bytecode::Opcode::OP_STRICT_EQ;
    else if (expr->op == "!==") op = Bytecode::Opcode::OP_STRICT_NEQ;
    else if (expr->op == "<") op = Bytecode::Opcode::OP_LT;
    else if (expr->op == ">") op = Bytecode::Opcode::OP_GT;
    else if (expr->op == "<=") op = Bytecode::Opcode::OP_LTE;
    else if (expr->op == ">=") op = Bytecode::Opcode::OP_GTE;
    else if (expr->op == "&&") op = Bytecode::Opcode::OP_LOGICAL_AND;
    else if (expr->op == "||") op = Bytecode::Opcode::OP_LOGICAL_OR;
    else if (expr->op == "&") op = Bytecode::Opcode::OP_BIT_AND;
    else if (expr->op == "|") op = Bytecode::Opcode::OP_BIT_OR;
    else if (expr->op == "^") op = Bytecode::Opcode::OP_BIT_XOR;
    else if (expr->op == "<<") op = Bytecode::Opcode::OP_SHL;
    else if (expr->op == ">>") op = Bytecode::Opcode::OP_SHR;
    else if (expr->op == ">>>") op = Bytecode::Opcode::OP_SHR_U;
    else {
        throw std::runtime_error("Unknown binary operator: " + expr->op);
    }
    
    EmitInstruction(op, resultReg, leftReg, rightReg);
    
    FreeRegister(leftReg);
    FreeRegister(rightReg);
    
    resultRegister_ = resultReg;
    return resultReg;
}

uint8_t BytecodeEmitter::CompileUnaryExpression(UnaryExpr* expr) {
    uint8_t argReg = CompileExpression(expr->argument.get());
    uint8_t resultReg = AllocateRegister();
    
    Bytecode::Opcode op;
    if (expr->op == "-") op = Bytecode::Opcode::OP_NEG;
    else if (expr->op == "!") op = Bytecode::Opcode::OP_LOGICAL_NOT;
    else if (expr->op == "~") op = Bytecode::Opcode::OP_BIT_NOT;
    else if (expr->op == "typeof") op = Bytecode::Opcode::OP_TYPEOF;
    else {
        throw std::runtime_error("Unknown unary operator: " + expr->op);
    }
    
    EmitInstruction(op, resultReg, argReg);
    FreeRegister(argReg);
    
    resultRegister_ = resultReg;
    return resultReg;
}

uint8_t BytecodeEmitter::CompileAssignmentExpression(AssignmentExpr* expr) {
    // Get value first
    uint8_t valueReg = CompileExpression(expr->right.get());
    
    // Handle different assignment targets
    if (auto* ident = dynamic_cast<IdentifierExpr*>(expr->left.get())) {
        uint8_t targetReg = LookupVariable(ident->name);
        
        if (expr->op == "=") {
            EmitInstruction(Bytecode::Opcode::OP_MOVE, targetReg, valueReg);
        } else {
            // Compound assignment: +=, -=, etc.
            Bytecode::Opcode op;
            if (expr->op == "+=") op = Bytecode::Opcode::OP_ADD;
            else if (expr->op == "-=") op = Bytecode::Opcode::OP_SUB;
            else if (expr->op == "*=") op = Bytecode::Opcode::OP_MUL;
            else if (expr->op == "/=") op = Bytecode::Opcode::OP_DIV;
            else if (expr->op == "%=") op = Bytecode::Opcode::OP_MOD;
            else {
                throw std::runtime_error("Unknown assignment operator: " + expr->op);
            }
            EmitInstruction(op, targetReg, targetReg, valueReg);
        }
        
        resultRegister_ = targetReg;
        return targetReg;
        
    } else if (auto* member = dynamic_cast<MemberExpr*>(expr->left.get())) {
        // Member assignment: obj.prop = value
        uint8_t objReg = CompileExpression(member->object.get());
        
        if (member->computed) {
            uint8_t propReg = CompileExpression(member->property.get());
            EmitInstruction(Bytecode::Opcode::OP_SET_ELEM, objReg, propReg, valueReg);
            FreeRegister(propReg);
        } else {
            // Static property
            auto* ident = dynamic_cast<IdentifierExpr*>(member->property.get());
            if (ident) {
                uint32_t strIdx = AddConstantString(ident->name);
                uint8_t strReg = AllocateRegister();
                EmitLoadString(strReg, ident->name);
                EmitInstruction(Bytecode::Opcode::OP_SET_PROP, objReg, strReg, valueReg);
                FreeRegister(strReg);
            }
        }
        
        FreeRegister(objReg);
        resultRegister_ = valueReg;
        return valueReg;
    }
    
    throw std::runtime_error("Invalid assignment target");
}

uint8_t BytecodeEmitter::CompileCallExpression(CallExpr* expr) {
    // Compile callee
    uint8_t calleeReg = CompileExpression(expr->callee.get());
    
    // Compile arguments
    std::vector<uint8_t> argRegs;
    for (const auto& arg : expr->arguments) {
        argRegs.push_back(CompileExpression(arg.get()));
    }
    
    // Move arguments to consecutive registers
    uint8_t firstArgReg = AllocateRegister();
    for (size_t i = 0; i < argRegs.size(); i++) {
        EmitInstruction(Bytecode::Opcode::OP_MOVE, firstArgReg + i, argRegs[i]);
        FreeRegister(argRegs[i]);
    }
    
    // Call
    uint8_t resultReg = AllocateRegister();
    EmitInstruction(Bytecode::Opcode::OP_CALL, resultReg, calleeReg, firstArgReg);
    
    FreeRegister(calleeReg);
    
    resultRegister_ = resultReg;
    return resultReg;
}

uint8_t BytecodeEmitter::CompileMemberExpression(MemberExpr* expr) {
    uint8_t objReg = CompileExpression(expr->object.get());
    uint8_t resultReg = AllocateRegister();
    
    if (expr->computed) {
        uint8_t propReg = CompileExpression(expr->property.get());
        EmitInstruction(Bytecode::Opcode::OP_GET_ELEM, resultReg, objReg, propReg);
        FreeRegister(propReg);
    } else {
        // Static property access
        auto* ident = dynamic_cast<IdentifierExpr*>(expr->property.get());
        if (ident) {
            uint8_t strReg = AllocateRegister();
            EmitLoadString(strReg, ident->name);
            EmitInstruction(Bytecode::Opcode::OP_GET_PROP, resultReg, objReg, strReg);
            FreeRegister(strReg);
        }
    }
    
    FreeRegister(objReg);
    resultRegister_ = resultReg;
    return resultReg;
}

uint8_t BytecodeEmitter::CompileLiteralExpression(ASTNode* expr) {
    uint8_t resultReg = AllocateRegister();
    
    if (auto* num = dynamic_cast<NumberLiteralExpr*>(expr)) {
        if (num->value == static_cast<int32_t>(num->value)) {
            EmitLoadInt(resultReg, static_cast<int32_t>(num->value));
        } else {
            uint32_t idx = AddConstantDouble(num->value);
            EmitLoadConst(resultReg, idx);
        }
    } else if (auto* str = dynamic_cast<StringLiteralExpr*>(expr)) {
        EmitLoadString(resultReg, str->value);
    } else if (auto* boolLit = dynamic_cast<BooleanLiteralExpr*>(expr)) {
        EmitInstruction(boolLit->value ? Bytecode::Opcode::OP_LOAD_TRUE : Bytecode::Opcode::OP_LOAD_FALSE, 
                       resultReg);
    } else if (dynamic_cast<NullLiteralExpr*>(expr)) {
        EmitInstruction(Bytecode::Opcode::OP_LOAD_NULL, resultReg);
    } else if (dynamic_cast<UndefinedLiteralExpr*>(expr)) {
        EmitInstruction(Bytecode::Opcode::OP_LOAD_UNDEFINED, resultReg);
    }
    
    resultRegister_ = resultReg;
    return resultReg;
}

uint8_t BytecodeEmitter::CompileIdentifierExpression(IdentifierExpr* expr) {
    uint8_t reg = LookupVariable(expr->name);
    resultRegister_ = reg;
    return reg;
}

uint8_t BytecodeEmitter::CompileArrayExpression(ArrayExpr* expr) {
    uint8_t resultReg = AllocateRegister();
    
    // Create array
    EmitInstruction(Bytecode::Opcode::OP_CREATE_ARRAY, resultReg);
    
    // Add elements
    for (size_t i = 0; i < expr->elements.size(); i++) {
        if (expr->elements[i]) {
            uint8_t elemReg = CompileExpression(expr->elements[i].get());
            EmitInstruction(Bytecode::Opcode::OP_ARRAY_PUSH, resultReg, elemReg);
            FreeRegister(elemReg);
        }
    }
    
    resultRegister_ = resultReg;
    return resultReg;
}

uint8_t BytecodeEmitter::CompileObjectExpression(ObjectExpr* expr) {
    uint8_t resultReg = AllocateRegister();
    
    // Create object
    EmitInstruction(Bytecode::Opcode::OP_CREATE_OBJECT, resultReg);
    
    // Add properties
    for (const auto& prop : expr->properties) {
        uint8_t valueReg = CompileExpression(prop.value.get());
        
        if (std::holds_alternative<std::string>(prop.key)) {
            const std::string& keyName = std::get<std::string>(prop.key);
            uint8_t keyReg = AllocateRegister();
            EmitLoadString(keyReg, keyName);
            EmitInstruction(Bytecode::Opcode::OP_OBJECT_SET, resultReg, keyReg, valueReg);
            FreeRegister(keyReg);
        }
        
        FreeRegister(valueReg);
    }
    
    resultRegister_ = resultReg;
    return resultReg;
}

uint8_t BytecodeEmitter::CompileConditionalExpression(ConditionalExpr* expr) {
    uint8_t condReg = CompileExpression(expr->condition.get());
    uint8_t resultReg = AllocateRegister();
    
    // Jump to else if condition is false
    uint32_t elseJump = ctx_.module->GetCode().size();
    EmitJump(Bytecode::Opcode::OP_JMP_NOT_COND, condReg, 0);  // Placeholder
    
    // Consequent
    uint8_t consReg = CompileExpression(expr->consequent.get());
    EmitInstruction(Bytecode::Opcode::OP_MOVE, resultReg, consReg);
    FreeRegister(consReg);
    
    // Jump over else
    uint32_t endJump = ctx_.module->GetCode().size();
    EmitJump(Bytecode::Opcode::OP_JMP, 0, 0);  // Placeholder
    
    // Else
    uint32_t elseOffset = ctx_.module->GetCode().size();
    PatchJump(elseJump, elseOffset);
    
    uint8_t altReg = CompileExpression(expr->alternate.get());
    EmitInstruction(Bytecode::Opcode::OP_MOVE, resultReg, altReg);
    FreeRegister(altReg);
    
    // End
    uint32_t endOffset = ctx_.module->GetCode().size();
    PatchJump(endJump, endOffset);
    
    FreeRegister(condReg);
    resultRegister_ = resultReg;
    return resultReg;
}

// Statement compilation
void BytecodeEmitter::CompileStatement(Statement* stmt) {
    std::visit([this](auto&& node) {
        this->Visit(node);
    }, *stmt);
}

void BytecodeEmitter::CompileBlockStatement(BlockStmt* stmt) {
    EnterScope();
    for (const auto& s : stmt->body) {
        CompileStatement(s.get());
    }
    ExitScope();
}

void BytecodeEmitter::CompileExpressionStatement(ExpressionStmt* stmt) {
    uint8_t reg = CompileExpression(stmt->expression.get());
    FreeRegister(reg);
}

void BytecodeEmitter::CompileIfStatement(IfStmt* stmt) {
    uint8_t condReg = CompileExpression(stmt->condition.get());
    
    // Jump to else if condition is false
    uint32_t elseJump = ctx_.module->GetCode().size();
    EmitJump(Bytecode::Opcode::OP_JMP_NOT_COND, condReg, 0);
    
    // Consequent
    CompileStatement(stmt->consequent.get());
    
    // Jump over else
    uint32_t endJump = 0;
    if (stmt->alternate) {
        endJump = ctx_.module->GetCode().size();
        EmitJump(Bytecode::Opcode::OP_JMP, 0, 0);
    }
    
    // Else
    uint32_t elseOffset = ctx_.module->GetCode().size();
    PatchJump(elseJump, elseOffset);
    
    if (stmt->alternate) {
        CompileStatement(stmt->alternate->get());
        uint32_t endOffset = ctx_.module->GetCode().size();
        PatchJump(endJump, endOffset);
    }
    
    FreeRegister(condReg);
}

void BytecodeEmitter::CompileWhileStatement(WhileStmt* stmt) {
    CompileContext::LoopContext loopCtx;
    loopCtx.startOffset = ctx_.module->GetCode().size();
    ctx_.loopStack.push(loopCtx);
    
    uint8_t condReg = CompileExpression(stmt->condition.get());
    
    // Jump out if condition is false
    uint32_t exitJump = ctx_.module->GetCode().size();
    EmitJump(Bytecode::Opcode::OP_JMP_NOT_COND, condReg, 0);
    
    // Body
    CompileStatement(stmt->body.get());
    
    // Jump back to condition
    EmitJump(Bytecode::Opcode::OP_JMP, 0, 
             static_cast<int32_t>(loopCtx.startOffset) - static_cast<int32_t>(ctx_.module->GetCode().size()) - 1);
    
    // Exit
    uint32_t exitOffset = ctx_.module->GetCode().size();
    PatchJump(exitJump, exitOffset);
    
    // Patch break jumps
    for (uint32_t breakOffset : ctx_.loopStack.top().breakJumps) {
        PatchJump(breakOffset, exitOffset);
    }
    
    ctx_.loopStack.pop();
    FreeRegister(condReg);
}

void BytecodeEmitter::CompileForStatement(ForStmt* stmt) {
    EnterScope();
    
    // Initialization
    if (stmt->init) {
        if (auto* varDecl = dynamic_cast<VariableDeclaration*>(stmt->init->get())) {
            // Variable declaration in for loop
            for (auto& decl : varDecl->declarations) {
                uint8_t reg = CompileExpression(decl.initializer.get());
                DeclareVariable(decl.name, reg);
            }
        } else {
            // Expression statement
            uint8_t initReg = CompileExpression(stmt->init->get());
            FreeRegister(initReg);
        }
    }
    
    CompileContext::LoopContext loopCtx;
    loopCtx.startOffset = ctx_.module->GetCode().size();
    ctx_.loopStack.push(loopCtx);
    
    // Condition
    if (stmt->condition) {
        uint8_t condReg = CompileExpression(stmt->condition->get());
        uint32_t exitJump = ctx_.module->GetCode().size();
        EmitJump(Bytecode::Opcode::OP_JMP_NOT_COND, condReg, 0);
        FreeRegister(condReg);
    }
    
    // Body
    CompileStatement(stmt->body.get());
    
    // Update
    if (stmt->update) {
        uint8_t updateReg = CompileExpression(stmt->update->get());
        FreeRegister(updateReg);
    }
    
    // Jump back
    EmitJump(Bytecode::Opcode::OP_JMP, 0,
             static_cast<int32_t>(loopCtx.startOffset) - static_cast<int32_t>(ctx_.module->GetCode().size()) - 1);
    
    // Exit
    uint32_t exitOffset = ctx_.module->GetCode().size();
    
    // Patch jumps
    for (uint32_t breakOffset : ctx_.loopStack.top().breakJumps) {
        PatchJump(breakOffset, exitOffset);
    }
    
    ctx_.loopStack.pop();
    ExitScope();
}

void BytecodeEmitter::CompileReturnStatement(ReturnStmt* stmt) {
    if (stmt->argument) {
        uint8_t reg = CompileExpression(stmt->argument->get());
        EmitInstruction(Bytecode::Opcode::OP_RETURN, reg);
        FreeRegister(reg);
    } else {
        EmitInstruction(Bytecode::Opcode::OP_LOAD_UNDEFINED, 0);
        EmitInstruction(Bytecode::Opcode::OP_RETURN, 0);
    }
}

void BytecodeEmitter::CompileBreakStatement(BreakStmt* stmt) {
    if (!ctx_.loopStack.empty()) {
        uint32_t jumpOffset = ctx_.module->GetCode().size();
        EmitJump(Bytecode::Opcode::OP_JMP, 0, 0);
        ctx_.loopStack.top().breakJumps.push_back(jumpOffset);
    }
}

void BytecodeEmitter::CompileContinueStatement(ContinueStmt* stmt) {
    if (!ctx_.loopStack.empty()) {
        uint32_t jumpOffset = ctx_.module->GetCode().size();
        EmitJump(Bytecode::Opcode::OP_JMP, 0, 0);
        ctx_.loopStack.top().continueJumps.push_back(jumpOffset);
    }
}

void BytecodeEmitter::CompileVariableDeclaration(VariableDecl* decl) {
    for (const auto& d : decl->declarations) {
        uint8_t reg = AllocateRegister();
        
        if (d.init) {
            uint8_t initReg = CompileExpression(d.init->get());
            EmitInstruction(Bytecode::Opcode::OP_MOVE, reg, initReg);
            FreeRegister(initReg);
        } else {
            EmitInstruction(Bytecode::Opcode::OP_LOAD_UNDEFINED, reg);
        }
        
        // Get variable name
        if (auto* ident = dynamic_cast<IdentifierExpr*>(d.id.get())) {
            DeclareVariable(ident->name, reg);
        }
    }
}

void BytecodeEmitter::CompileFunctionDeclaration(FunctionDecl* decl) {
    // Save current context
    bool wasInFunction = ctx_.inFunction;
    uint16_t prevLocalCount = ctx_.localCount;
    
    // Create function object
    uint8_t funcReg = AllocateRegister();
    EmitInstruction(Bytecode::Opcode::OP_CREATE_FUNC, funcReg);
    
    // Store in variable
    DeclareVariable(decl->name, funcReg);
    
    // Compile function body separately
    ctx_.inFunction = true;
    ctx_.localCount = 0;
    
    // Enter new scope for function
    EnterScope();
    
    // Add parameters as local variables
    for (const auto& param : decl->parameters) {
        uint8_t paramReg = AllocateRegister();
        DeclareVariable(param, paramReg);
        ctx_.localCount++;
    }
    
    // Compile function body
    if (decl->body) {
        CompileStatement(decl->body.get());
    }
    
    // Ensure function returns undefined if no explicit return
    EmitInstruction(Bytecode::Opcode::OP_LOAD_UNDEFINED, funcReg);
    EmitInstruction(Bytecode::Opcode::OP_RETURN, funcReg);
    
    // Exit function scope
    ExitScope();
    
    // Restore context
    ctx_.inFunction = wasInFunction;
    ctx_.localCount = prevLocalCount;
}

// ASTVisitor implementations
void BytecodeEmitter::Visit(const NumberLiteralExpr& node) {
    CompileLiteralExpression(const_cast<NumberLiteralExpr*>(&node));
}

void BytecodeEmitter::Visit(const StringLiteralExpr& node) {
    CompileLiteralExpression(const_cast<StringLiteralExpr*>(&node));
}

void BytecodeEmitter::Visit(const BooleanLiteralExpr& node) {
    CompileLiteralExpression(const_cast<BooleanLiteralExpr*>(&node));
}

void BytecodeEmitter::Visit(const NullLiteralExpr& node) {
    CompileLiteralExpression(const_cast<NullLiteralExpr*>(&node));
}

void BytecodeEmitter::Visit(const UndefinedLiteralExpr& node) {
    CompileLiteralExpression(const_cast<UndefinedLiteralExpr*>(&node));
}

void BytecodeEmitter::Visit(const IdentifierExpr& node) {
    CompileIdentifierExpression(const_cast<IdentifierExpr*>(&node));
}

void BytecodeEmitter::Visit(const BinaryExpr& node) {
    CompileBinaryExpression(const_cast<BinaryExpr*>(&node));
}

void BytecodeEmitter::Visit(const UnaryExpr& node) {
    CompileUnaryExpression(const_cast<UnaryExpr*>(&node));
}

void BytecodeEmitter::Visit(const AssignmentExpr& node) {
    CompileAssignmentExpression(const_cast<AssignmentExpr*>(&node));
}

void BytecodeEmitter::Visit(const CallExpr& node) {
    CompileCallExpression(const_cast<CallExpr*>(&node));
}

void BytecodeEmitter::Visit(const MemberExpr& node) {
    CompileMemberExpression(const_cast<MemberExpr*>(&node));
}

void BytecodeEmitter::Visit(const ArrayExpr& node) {
    CompileArrayExpression(const_cast<ArrayExpr*>(&node));
}

void BytecodeEmitter::Visit(const ObjectExpr& node) {
    CompileObjectExpression(const_cast<ObjectExpr*>(&node));
}

void BytecodeEmitter::Visit(const FunctionExpr& node) {
    // Anonymous function expression
    // Similar to function declaration but without name binding
    uint8_t funcReg = AllocateRegister();
    EmitInstruction(Bytecode::Opcode::OP_CREATE_FUNC, funcReg);
    resultRegister_ = funcReg;
}

void BytecodeEmitter::Visit(const ConditionalExpr& node) {
    CompileConditionalExpression(const_cast<ConditionalExpr*>(&node));
}

void BytecodeEmitter::Visit(const UpdateExpr& node) {
    // ++ or -- operators
    uint8_t operandReg = CompileExpression(node.operand.get());
    
    // Load 1
    uint8_t oneReg = AllocateRegister();
    EmitLoadInt(oneReg, 1);
    
    if (node.isPrefix) {
        // ++x or --x: modify then return
        if (node.isIncrement) {
            EmitInstruction(Bytecode::Opcode::OP_ADD, operandReg, operandReg, oneReg);
        } else {
            EmitInstruction(Bytecode::Opcode::OP_SUB, operandReg, operandReg, oneReg);
        }
        resultRegister_ = operandReg;
    } else {
        // x++ or x--: return original, then modify
        uint8_t resultReg = AllocateRegister();
        EmitInstruction(Bytecode::Opcode::OP_MOVE, resultReg, operandReg, 0);
        
        if (node.isIncrement) {
            EmitInstruction(Bytecode::Opcode::OP_ADD, operandReg, operandReg, oneReg);
        } else {
            EmitInstruction(Bytecode::Opcode::OP_SUB, operandReg, operandReg, oneReg);
        }
        
        FreeRegister(operandReg);
        resultRegister_ = resultReg;
    }
    
    FreeRegister(oneReg);
}

void BytecodeEmitter::Visit(const NewExpr& node) {
    // new Constructor(args...)
    // Create new object
    uint8_t objReg = AllocateRegister();
    EmitInstruction(Bytecode::Opcode::OP_CREATE_OBJECT, objReg);
    
    // Evaluate constructor
    uint8_t ctorReg = CompileExpression(node.callee.get());
    
    // Evaluate arguments
    std::vector<uint8_t> argRegs;
    for (const auto& arg : node.arguments) {
        argRegs.push_back(CompileExpression(arg.get()));
    }
    
    // Call constructor with 'this' bound to new object
    // Note: In real implementation, need to handle constructor binding
    EmitInstruction(Bytecode::Opcode::OP_CALL, ctorReg, objReg, static_cast<uint8_t>(argRegs.size()));
    
    // Clean up
    for (auto reg : argRegs) {
        FreeRegister(reg);
    }
    FreeRegister(ctorReg);
    
    resultRegister_ = objReg;
}

void BytecodeEmitter::Visit(const ThisExpr& node) {
    // 'this' keyword - load from special register or global
    // In function context, 'this' is passed as implicit parameter
    // For now, load undefined (will be fixed when proper 'this' binding is implemented)
    uint8_t thisReg = AllocateRegister();
    EmitInstruction(Bytecode::Opcode::OP_LOAD_UNDEFINED, thisReg);
    resultRegister_ = thisReg;
}

void BytecodeEmitter::Visit(const ExpressionStmt& node) {
    CompileExpressionStatement(const_cast<ExpressionStmt*>(&node));
}

void BytecodeEmitter::Visit(const BlockStmt& node) {
    CompileBlockStatement(const_cast<BlockStmt*>(&node));
}

void BytecodeEmitter::Visit(const IfStmt& node) {
    CompileIfStatement(const_cast<IfStmt*>(&node));
}

void BytecodeEmitter::Visit(const WhileStmt& node) {
    CompileWhileStatement(const_cast<WhileStmt*>(&node));
}

void BytecodeEmitter::Visit(const ForStmt& node) {
    CompileForStatement(const_cast<ForStmt*>(&node));
}

void BytecodeEmitter::Visit(const ReturnStmt& node) {
    CompileReturnStatement(const_cast<ReturnStmt*>(&node));
}

void BytecodeEmitter::Visit(const BreakStmt& node) {
    CompileBreakStatement(const_cast<BreakStmt*>(&node));
}

void BytecodeEmitter::Visit(const ContinueStmt& node) {
    CompileContinueStatement(const_cast<ContinueStmt*>(&node));
}

void BytecodeEmitter::Visit(const SwitchStmt& node) {
    // TODO: Implement
}

void BytecodeEmitter::Visit(const TryStmt& node) {
    // TODO: Implement
}

void BytecodeEmitter::Visit(const ThrowStmt& node) {
    // TODO: Implement
}

void BytecodeEmitter::Visit(const VariableDecl& node) {
    CompileVariableDeclaration(const_cast<VariableDecl*>(&node));
}

void BytecodeEmitter::Visit(const FunctionDecl& node) {
    CompileFunctionDeclaration(const_cast<FunctionDecl*>(&node));
}

void BytecodeEmitter::Visit(const Program& node) {
    for (const auto& stmt : node.body) {
        CompileStatement(stmt.get());
    }
}

} // namespace Script
} // namespace RawrXD
