// RawrXD-Script Bytecode Emitter
// Converts AST to RAWR bytecode

#pragma once

#include "../ast/ast.hpp"
#include "../bytecode/bytecode.hpp"
#include <vector>
#include <map>
#include <string>
#include <stack>

namespace RawrXD {
namespace Script {

// Compilation context
struct CompileContext {
    Bytecode::BytecodeModule* module;
    
    // Variable scope tracking
    std::vector<std::map<std::string, uint8_t>> scopes;  // name -> register
    uint8_t nextRegister;
    
    // Label resolution for jumps
    std::map<std::string, uint32_t> labels;           // label name -> bytecode offset
    std::vector<std::pair<uint32_t, std::string>> pendingJumps; // offset -> label
    
    // Loop context for break/continue
    struct LoopContext {
        uint32_t startOffset;
        std::vector<uint32_t> breakJumps;    // offsets needing patch
        std::vector<uint32_t> continueJumps; // offsets needing patch
    };
    std::stack<LoopContext> loopStack;
    
    // Function context
    bool inFunction;
    uint16_t localCount;
    
    CompileContext() : nextRegister(0), inFunction(false), localCount(0) {}
};

// Bytecode emitter class
class BytecodeEmitter : public ASTVisitor {
public:
    BytecodeEmitter();
    
    // Main entry point
    bool Emit(Program* program, Bytecode::BytecodeModule* module);
    
    // Get compilation errors
    const std::vector<std::string>& GetErrors() const { return errors_; }
    
private:
    CompileContext ctx_;
    std::vector<std::string> errors_;
    
    // Current register for expression results
    uint8_t resultRegister_;
    
    // Helper methods
    void EmitInstruction(Bytecode::Opcode op, uint8_t dst = 0, uint8_t srcA = 0, uint8_t srcB = 0);
    void EmitLoadConst(uint8_t reg, uint32_t constIdx);
    void EmitLoadInt(uint8_t reg, int32_t value);
    void EmitLoadString(uint8_t reg, const std::string& str);
    void EmitJump(Bytecode::Opcode op, uint8_t condReg, int32_t offset);
    void PatchJump(uint32_t jumpOffset, uint32_t targetOffset);
    
    // Register allocation
    uint8_t AllocateRegister();
    void FreeRegister(uint8_t reg);
    
    // Variable scope management
    void EnterScope();
    void ExitScope();
    uint8_t LookupVariable(const std::string& name);
    void DeclareVariable(const std::string& name, uint8_t reg);
    
    // Constant pool helpers
    uint32_t AddConstantInt(int32_t value);
    uint32_t AddConstantDouble(double value);
    uint32_t AddConstantString(const std::string& value);
    
    // Expression compilation (returns register with result)
    uint8_t CompileExpression(Expression* expr);
    uint8_t CompileBinaryExpression(BinaryExpr* expr);
    uint8_t CompileUnaryExpression(UnaryExpr* expr);
    uint8_t CompileAssignmentExpression(AssignmentExpr* expr);
    uint8_t CompileCallExpression(CallExpr* expr);
    uint8_t CompileMemberExpression(MemberExpr* expr);
    uint8_t CompileLiteralExpression(ASTNode* expr);
    uint8_t CompileIdentifierExpression(IdentifierExpr* expr);
    uint8_t CompileArrayExpression(ArrayExpr* expr);
    uint8_t CompileObjectExpression(ObjectExpr* expr);
    uint8_t CompileConditionalExpression(ConditionalExpr* expr);
    
    // Statement compilation
    void CompileStatement(Statement* stmt);
    void CompileBlockStatement(BlockStmt* stmt);
    void CompileExpressionStatement(ExpressionStmt* stmt);
    void CompileIfStatement(IfStmt* stmt);
    void CompileWhileStatement(WhileStmt* stmt);
    void CompileForStatement(ForStmt* stmt);
    void CompileReturnStatement(ReturnStmt* stmt);
    void CompileBreakStatement(BreakStmt* stmt);
    void CompileContinueStatement(ContinueStmt* stmt);
    void CompileVariableDeclaration(VariableDecl* decl);
    void CompileFunctionDeclaration(FunctionDecl* decl);
    
    // ASTVisitor interface
    void Visit(const NumberLiteralExpr& node) override;
    void Visit(const StringLiteralExpr& node) override;
    void Visit(const BooleanLiteralExpr& node) override;
    void Visit(const NullLiteralExpr& node) override;
    void Visit(const UndefinedLiteralExpr& node) override;
    void Visit(const IdentifierExpr& node) override;
    void Visit(const BinaryExpr& node) override;
    void Visit(const UnaryExpr& node) override;
    void Visit(const AssignmentExpr& node) override;
    void Visit(const CallExpr& node) override;
    void Visit(const MemberExpr& node) override;
    void Visit(const ArrayExpr& node) override;
    void Visit(const ObjectExpr& node) override;
    void Visit(const FunctionExpr& node) override;
    void Visit(const ConditionalExpr& node) override;
    void Visit(const UpdateExpr& node) override;
    void Visit(const NewExpr& node) override;
    void Visit(const ThisExpr& node) override;
    void Visit(const ExpressionStmt& node) override;
    void Visit(const BlockStmt& node) override;
    void Visit(const IfStmt& node) override;
    void Visit(const WhileStmt& node) override;
    void Visit(const ForStmt& node) override;
    void Visit(const ReturnStmt& node) override;
    void Visit(const BreakStmt& node) override;
    void Visit(const ContinueStmt& node) override;
    void Visit(const SwitchStmt& node) override;
    void Visit(const TryStmt& node) override;
    void Visit(const ThrowStmt& node) override;
    void Visit(const VariableDecl& node) override;
    void Visit(const FunctionDecl& node) override;
    void Visit(const Program& node) override;
};

} // namespace Script
} // namespace RawrXD
