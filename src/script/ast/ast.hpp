// RawrXD-Script AST Node Definitions
// Phase 1: Bytecode Spec + C++ Parser

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <variant>
#include <optional>

namespace RawrXD {
namespace Script {

// Forward declarations - all AST node types
struct ASTNode;
struct NumberLiteralExpr;
struct StringLiteralExpr;
struct BooleanLiteralExpr;
struct NullLiteralExpr;
struct UndefinedLiteralExpr;
struct IdentifierExpr;
struct BinaryExpr;
struct UnaryExpr;
struct AssignmentExpr;
struct CallExpr;
struct MemberExpr;
struct ArrayExpr;
struct ObjectExpr;
struct FunctionExpr;
struct ConditionalExpr;
struct UpdateExpr;
struct NewExpr;
struct ThisExpr;

struct ExpressionStmt;
struct BlockStmt;
struct IfStmt;
struct WhileStmt;
struct ForStmt;
struct ReturnStmt;
struct BreakStmt;
struct ContinueStmt;
struct SwitchStmt;
struct TryStmt;
struct ThrowStmt;

struct VariableDecl;
struct FunctionDecl;

// AST node types
enum class ASTNodeType {
    // Expressions
    NumberLiteral,
    StringLiteral,
    BooleanLiteral,
    NullLiteral,
    UndefinedLiteral,
    Identifier,
    BinaryExpression,
    UnaryExpression,
    AssignmentExpression,
    CallExpression,
    MemberExpression,
    ArrayExpression,
    ObjectExpression,
    FunctionExpression,
    ConditionalExpression,
    UpdateExpression,
    NewExpression,
    ThisExpression,
    
    // Statements
    ExpressionStatement,
    BlockStatement,
    IfStatement,
    WhileStatement,
    ForStatement,
    ReturnStatement,
    BreakStatement,
    ContinueStatement,
    SwitchStatement,
    TryStatement,
    ThrowStatement,
    
    // Declarations
    VariableDeclaration,
    FunctionDeclaration,
    
    // Program
    Program,
};

// Base AST node
struct ASTNode {
    ASTNodeType type;
    uint32_t line;
    uint32_t column;
    
    ASTNode(ASTNodeType t, uint32_t ln, uint32_t col) 
        : type(t), line(ln), column(col) {}
    virtual ~ASTNode() = default;
};

// ============================================================================
// Expressions
// ============================================================================

struct NumberLiteralExpr : ASTNode {
    double value;
    
    NumberLiteralExpr(double val, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::NumberLiteral, ln, col), value(val) {}
};

struct StringLiteralExpr : ASTNode {
    std::string value;
    
    StringLiteralExpr(std::string val, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::StringLiteral, ln, col), value(std::move(val)) {}
};

struct BooleanLiteralExpr : ASTNode {
    bool value;
    
    BooleanLiteralExpr(bool val, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::BooleanLiteral, ln, col), value(val) {}
};

struct NullLiteralExpr : ASTNode {
    NullLiteralExpr(uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::NullLiteral, ln, col) {}
};

struct UndefinedLiteralExpr : ASTNode {
    UndefinedLiteralExpr(uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::UndefinedLiteral, ln, col) {}
};

struct IdentifierExpr : ASTNode {
    std::string name;
    
    IdentifierExpr(std::string n, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::Identifier, ln, col), name(std::move(n)) {}
};

// Forward declare Expression variant for use in expression structs
using Expression = std::variant<
    NumberLiteralExpr,
    StringLiteralExpr,
    BooleanLiteralExpr,
    NullLiteralExpr,
    UndefinedLiteralExpr,
    IdentifierExpr,
    BinaryExpr,
    UnaryExpr,
    AssignmentExpr,
    CallExpr,
    MemberExpr,
    ArrayExpr,
    ObjectExpr,
    FunctionExpr,
    ConditionalExpr,
    UpdateExpr,
    NewExpr,
    ThisExpr
>;

// Binary operations: +, -, *, /, %, ==, !=, ===, !==, <, >, <=, >=, &&, ||, &, |, ^, <<, >>, >>>
struct BinaryExpr : ASTNode {
    std::unique_ptr<Expression> left;
    std::unique_ptr<Expression> right;
    std::string op;  // Operator as string
    
    BinaryExpr(std::unique_ptr<Expression> l, std::unique_ptr<Expression> r, 
               std::string oper, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::BinaryExpression, ln, col), 
          left(std::move(l)), right(std::move(r)), op(std::move(oper)) {}
};

// Unary operations: +, -, !, ~, typeof, void, delete
struct UnaryExpr : ASTNode {
    std::string op;
    std::unique_ptr<Expression> argument;
    bool prefix;  // true for prefix, false for postfix
    
    UnaryExpr(std::string oper, std::unique_ptr<Expression> arg, 
              bool pre, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::UnaryExpression, ln, col), 
          op(std::move(oper)), argument(std::move(arg)), prefix(pre) {}
};

// Assignment: =, +=, -=, *=, /=, %=
struct AssignmentExpr : ASTNode {
    std::unique_ptr<Expression> left;   // Must be valid assignment target
    std::unique_ptr<Expression> right;
    std::string op;
    
    AssignmentExpr(std::unique_ptr<Expression> l, std::unique_ptr<Expression> r,
                   std::string oper, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::AssignmentExpression, ln, col),
          left(std::move(l)), right(std::move(r)), op(std::move(oper)) {}
};

// Function call: fn(arg1, arg2, ...)
struct CallExpr : ASTNode {
    std::unique_ptr<Expression> callee;
    std::vector<std::unique_ptr<Expression>> arguments;
    
    CallExpr(std::unique_ptr<Expression> c, std::vector<std::unique_ptr<Expression>> args,
             uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::CallExpression, ln, col),
          callee(std::move(c)), arguments(std::move(args)) {}
};

// Member access: obj.property or obj[index]
struct MemberExpr : ASTNode {
    std::unique_ptr<Expression> object;
    std::unique_ptr<Expression> property;
    bool computed;  // true for obj[index], false for obj.property
    
    MemberExpr(std::unique_ptr<Expression> obj, std::unique_ptr<Expression> prop,
               bool comp, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::MemberExpression, ln, col),
          object(std::move(obj)), property(std::move(prop)), computed(comp) {}
};

// Array literal: [1, 2, 3]
struct ArrayExpr : ASTNode {
    std::vector<std::unique_ptr<Expression>> elements;
    
    ArrayExpr(std::vector<std::unique_ptr<Expression>> elems, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ArrayExpression, ln, col), elements(std::move(elems)) {}
};

// Object literal: { key: value, "key": value }
struct ObjectProperty {
    std::variant<std::string, std::unique_ptr<Expression>> key;  // Identifier or computed
    std::unique_ptr<Expression> value;
    bool computed;
};

struct ObjectExpr : ASTNode {
    std::vector<ObjectProperty> properties;
    
    ObjectExpr(std::vector<ObjectProperty> props, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ObjectExpression, ln, col), properties(std::move(props)) {}
};

// Forward declare Statement variant for use in expression structs
using Statement = std::variant<
    ExpressionStmt,
    BlockStmt,
    IfStmt,
    WhileStmt,
    ForStmt,
    ReturnStmt,
    BreakStmt,
    ContinueStmt,
    SwitchStmt,
    TryStmt,
    ThrowStmt
>;

// Function expression: function name?(params) { body }
struct FunctionExpr : ASTNode {
    std::optional<std::string> name;
    std::vector<std::string> params;
    std::unique_ptr<Statement> body;  // BlockStatement
    
    FunctionExpr(std::optional<std::string> n, std::vector<std::string> p,
                 std::unique_ptr<Statement> b, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::FunctionExpression, ln, col),
          name(std::move(n)), params(std::move(p)), body(std::move(b)) {}
};

// Conditional: condition ? consequent : alternate
struct ConditionalExpr : ASTNode {
    std::unique_ptr<Expression> condition;
    std::unique_ptr<Expression> consequent;
    std::unique_ptr<Expression> alternate;
    
    ConditionalExpr(std::unique_ptr<Expression> cond, std::unique_ptr<Expression> cons,
                    std::unique_ptr<Expression> alt, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ConditionalExpression, ln, col),
          condition(std::move(cond)), consequent(std::move(cons)), alternate(std::move(alt)) {}
};

// Update expression: ++expr, --expr, expr++, expr--
struct UpdateExpr : ASTNode {
    std::string op;  // ++ or --
    std::unique_ptr<Expression> argument;
    bool prefix;
    
    UpdateExpr(std::string oper, std::unique_ptr<Expression> arg, bool pre,
                 uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::UpdateExpression, ln, col),
          op(std::move(oper)), argument(std::move(arg)), prefix(pre) {}
};

// New expression: new Constructor(args)
struct NewExpr : ASTNode {
    std::unique_ptr<Expression> callee;
    std::vector<std::unique_ptr<Expression>> arguments;
    
    NewExpr(std::unique_ptr<Expression> c, std::vector<std::unique_ptr<Expression>> args,
            uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::NewExpression, ln, col),
          callee(std::move(c)), arguments(std::move(args)) {}
};

// This expression
struct ThisExpr : ASTNode {
    ThisExpr(uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ThisExpression, ln, col) {}
};

// ============================================================================
// Statements
// ============================================================================

struct ExpressionStmt : ASTNode {
    std::unique_ptr<Expression> expression;
    
    ExpressionStmt(std::unique_ptr<Expression> expr, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ExpressionStatement, ln, col), expression(std::move(expr)) {}
};

struct BlockStmt : ASTNode {
    std::vector<std::unique_ptr<Statement>> body;
    
    BlockStmt(std::vector<std::unique_ptr<Statement>> b, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::BlockStatement, ln, col), body(std::move(b)) {}
};

struct IfStmt : ASTNode {
    std::unique_ptr<Expression> condition;
    std::unique_ptr<Statement> consequent;
    std::optional<std::unique_ptr<Statement>> alternate;
    
    IfStmt(std::unique_ptr<Expression> cond, std::unique_ptr<Statement> cons,
           std::optional<std::unique_ptr<Statement>> alt, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::IfStatement, ln, col),
          condition(std::move(cond)), consequent(std::move(cons)), alternate(std::move(alt)) {}
};

struct WhileStmt : ASTNode {
    std::unique_ptr<Expression> condition;
    std::unique_ptr<Statement> body;
    
    WhileStmt(std::unique_ptr<Expression> cond, std::unique_ptr<Statement> b,
              uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::WhileStatement, ln, col),
          condition(std::move(cond)), body(std::move(b)) {}
};

// Forward declare Declaration variant for use in ForStmt
using Declaration = std::variant<
    VariableDecl,
    FunctionDecl
>;

struct ForStmt : ASTNode {
    std::optional<std::unique_ptr<Declaration>> init;  // VariableDeclaration or expression
    std::optional<std::unique_ptr<Expression>> condition;
    std::optional<std::unique_ptr<Expression>> update;
    std::unique_ptr<Statement> body;
    
    ForStmt(std::optional<std::unique_ptr<Declaration>> i,
            std::optional<std::unique_ptr<Expression>> cond,
            std::optional<std::unique_ptr<Expression>> upd,
            std::unique_ptr<Statement> b, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ForStatement, ln, col),
          init(std::move(i)), condition(std::move(cond)), 
          update(std::move(upd)), body(std::move(b)) {}
};

struct ReturnStmt : ASTNode {
    std::optional<std::unique_ptr<Expression>> argument;
    
    ReturnStmt(std::optional<std::unique_ptr<Expression>> arg, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ReturnStatement, ln, col), argument(std::move(arg)) {}
};

struct BreakStmt : ASTNode {
    BreakStmt(uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::BreakStatement, ln, col) {}
};

struct ContinueStmt : ASTNode {
    ContinueStmt(uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ContinueStatement, ln, col) {}
};

struct SwitchCase {
    std::optional<std::unique_ptr<Expression>> test;  // null for default
    std::vector<std::unique_ptr<Statement>> consequent;
};

struct SwitchStmt : ASTNode {
    std::unique_ptr<Expression> discriminant;
    std::vector<SwitchCase> cases;
    
    SwitchStmt(std::unique_ptr<Expression> disc, std::vector<SwitchCase> c,
               uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::SwitchStatement, ln, col),
          discriminant(std::move(disc)), cases(std::move(c)) {}
};

struct CatchClause {
    std::optional<std::string> param;  // catch(e)
    std::unique_ptr<Statement> body;
};

struct TryStmt : ASTNode {
    std::unique_ptr<Statement> block;
    std::optional<CatchClause> handler;
    std::optional<std::unique_ptr<Statement>> finalizer;
    
    TryStmt(std::unique_ptr<Statement> blk, std::optional<CatchClause> hnd,
            std::optional<std::unique_ptr<Statement>> fin, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::TryStatement, ln, col),
          block(std::move(blk)), handler(std::move(hnd)), finalizer(std::move(fin)) {}
};

struct ThrowStmt : ASTNode {
    std::unique_ptr<Expression> argument;
    
    ThrowStmt(std::unique_ptr<Expression> arg, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::ThrowStatement, ln, col), argument(std::move(arg)) {}
};

// ============================================================================
// Declarations
// ============================================================================

struct VariableDeclarator {
    std::unique_ptr<Expression> id;  // Identifier
    std::optional<std::unique_ptr<Expression>> init;
};

struct VariableDecl : ASTNode {
    std::string kind;  // "var", "let", or "const"
    std::vector<VariableDeclarator> declarations;
    
    VariableDecl(std::string k, std::vector<VariableDeclarator> decls, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::VariableDeclaration, ln, col),
          kind(std::move(k)), declarations(std::move(decls)) {}
};

struct FunctionDecl : ASTNode {
    std::string name;
    std::vector<std::string> params;
    std::unique_ptr<Statement> body;  // BlockStatement
    
    FunctionDecl(std::string n, std::vector<std::string> p,
                 std::unique_ptr<Statement> b, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::FunctionDeclaration, ln, col),
          name(std::move(n)), params(std::move(p)), body(std::move(b)) {}
};

// ============================================================================
// Program
// ============================================================================

struct Program : ASTNode {
    std::vector<std::unique_ptr<Statement>> body;
    
    Program(std::vector<std::unique_ptr<Statement>> b, uint32_t ln, uint32_t col)
        : ASTNode(ASTNodeType::Program, ln, col), body(std::move(b)) {}
};

// AST visitor pattern
class ASTVisitor {
public:
    virtual ~ASTVisitor() = default;
    
    // Expressions
    virtual void Visit(const NumberLiteralExpr& node) = 0;
    virtual void Visit(const StringLiteralExpr& node) = 0;
    virtual void Visit(const BooleanLiteralExpr& node) = 0;
    virtual void Visit(const NullLiteralExpr& node) = 0;
    virtual void Visit(const UndefinedLiteralExpr& node) = 0;
    virtual void Visit(const IdentifierExpr& node) = 0;
    virtual void Visit(const BinaryExpr& node) = 0;
    virtual void Visit(const UnaryExpr& node) = 0;
    virtual void Visit(const AssignmentExpr& node) = 0;
    virtual void Visit(const CallExpr& node) = 0;
    virtual void Visit(const MemberExpr& node) = 0;
    virtual void Visit(const ArrayExpr& node) = 0;
    virtual void Visit(const ObjectExpr& node) = 0;
    virtual void Visit(const FunctionExpr& node) = 0;
    virtual void Visit(const ConditionalExpr& node) = 0;
    virtual void Visit(const UpdateExpr& node) = 0;
    virtual void Visit(const NewExpr& node) = 0;
    virtual void Visit(const ThisExpr& node) = 0;
    
    // Statements
    virtual void Visit(const ExpressionStmt& node) = 0;
    virtual void Visit(const BlockStmt& node) = 0;
    virtual void Visit(const IfStmt& node) = 0;
    virtual void Visit(const WhileStmt& node) = 0;
    virtual void Visit(const ForStmt& node) = 0;
    virtual void Visit(const ReturnStmt& node) = 0;
    virtual void Visit(const BreakStmt& node) = 0;
    virtual void Visit(const ContinueStmt& node) = 0;
    virtual void Visit(const SwitchStmt& node) = 0;
    virtual void Visit(const TryStmt& node) = 0;
    virtual void Visit(const ThrowStmt& node) = 0;
    
    // Declarations
    virtual void Visit(const VariableDecl& node) = 0;
    virtual void Visit(const FunctionDecl& node) = 0;
    
    // Program
    virtual void Visit(const Program& node) = 0;
};

} // namespace Script
} // namespace RawrXD
