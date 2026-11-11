// RawrXD-Script AST Node Definitions
// Simplified polymorphic version for parser compatibility

#pragma once

#include <memory>
#include <vector>
#include <string>
#include <optional>
#include <variant>
namespace RawrXD {
namespace Script {

// Forward declarations
struct ASTNode;
struct Expression;
struct Statement;
struct Declaration;

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

// Base Expression
struct Expression : ASTNode {
    Expression(ASTNodeType t, uint32_t ln, uint32_t col) : ASTNode(t, ln, col) {}
};

// Base Statement  
struct Statement : ASTNode {
    Statement(ASTNodeType t, uint32_t ln, uint32_t col) : ASTNode(t, ln, col) {}
};

// Base Declaration - also a Statement (declarations can appear where statements can)
struct Declaration : Statement {
    Declaration(ASTNodeType t, uint32_t ln, uint32_t col) : Statement(t, ln, col) {}
};

// ============================================================================
// Expressions
// ============================================================================

struct NumberLiteralExpr : Expression {
    double value;
    
    NumberLiteralExpr(double val, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::NumberLiteral, ln, col), value(val) {}
};

struct StringLiteralExpr : Expression {
    std::string value;
    
    StringLiteralExpr(std::string val, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::StringLiteral, ln, col), value(std::move(val)) {}
};

struct BooleanLiteralExpr : Expression {
    bool value;
    
    BooleanLiteralExpr(bool val, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::BooleanLiteral, ln, col), value(val) {}
};

struct NullLiteralExpr : Expression {
    NullLiteralExpr(uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::NullLiteral, ln, col) {}
};

struct UndefinedLiteralExpr : Expression {
    UndefinedLiteralExpr(uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::UndefinedLiteral, ln, col) {}
};

struct IdentifierExpr : Expression {
    std::string name;
    
    IdentifierExpr(std::string n, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::Identifier, ln, col), name(std::move(n)) {}
};

// Binary operations
struct BinaryExpr : Expression {
    std::unique_ptr<Expression> left;
    std::unique_ptr<Expression> right;
    std::string op;
    
    BinaryExpr(std::unique_ptr<Expression> l, std::unique_ptr<Expression> r, 
               std::string oper, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::BinaryExpression, ln, col), 
          left(std::move(l)), right(std::move(r)), op(std::move(oper)) {}
};

// Unary operations
struct UnaryExpr : Expression {
    std::string op;
    std::unique_ptr<Expression> argument;
    bool prefix;
    
    UnaryExpr(std::string oper, std::unique_ptr<Expression> arg, 
              bool pre, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::UnaryExpression, ln, col), 
          op(std::move(oper)), argument(std::move(arg)), prefix(pre) {}
};

// Assignment
struct AssignmentExpr : Expression {
    std::unique_ptr<Expression> left;
    std::unique_ptr<Expression> right;
    std::string op;
    
    AssignmentExpr(std::unique_ptr<Expression> l, std::unique_ptr<Expression> r,
                   std::string oper, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::AssignmentExpression, ln, col),
          left(std::move(l)), right(std::move(r)), op(std::move(oper)) {}
};

// Function call
struct CallExpr : Expression {
    std::unique_ptr<Expression> callee;
    std::vector<std::unique_ptr<Expression>> arguments;
    
    CallExpr(std::unique_ptr<Expression> c, std::vector<std::unique_ptr<Expression>> args,
             uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::CallExpression, ln, col),
          callee(std::move(c)), arguments(std::move(args)) {}
};

// Member access
struct MemberExpr : Expression {
    std::unique_ptr<Expression> object;
    std::unique_ptr<Expression> property;
    bool computed;
    
    MemberExpr(std::unique_ptr<Expression> obj, std::unique_ptr<Expression> prop,
               bool comp, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::MemberExpression, ln, col),
          object(std::move(obj)), property(std::move(prop)), computed(comp) {}
};

// Array literal
struct ArrayExpr : Expression {
    std::vector<std::unique_ptr<Expression>> elements;
    
    ArrayExpr(std::vector<std::unique_ptr<Expression>> elems, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::ArrayExpression, ln, col), elements(std::move(elems)) {}
};

// Object literal
struct ObjectProperty {
    std::variant<std::string, std::unique_ptr<Expression>> key;
    std::unique_ptr<Expression> value;
    bool computed;
};

struct ObjectExpr : Expression {
    std::vector<ObjectProperty> properties;
    
    ObjectExpr(std::vector<ObjectProperty> props, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::ObjectExpression, ln, col), properties(std::move(props)) {}
};

// Function expression
struct FunctionExpr : Expression {
    std::optional<std::string> name;
    std::vector<std::string> params;
    std::unique_ptr<Statement> body;
    
    FunctionExpr(std::optional<std::string> n, std::vector<std::string> p,
                 std::unique_ptr<Statement> b, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::FunctionExpression, ln, col),
          name(std::move(n)), params(std::move(p)), body(std::move(b)) {}
};

// Conditional
struct ConditionalExpr : Expression {
    std::unique_ptr<Expression> condition;
    std::unique_ptr<Expression> consequent;
    std::unique_ptr<Expression> alternate;
    
    ConditionalExpr(std::unique_ptr<Expression> cond, std::unique_ptr<Expression> cons,
                    std::unique_ptr<Expression> alt, uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::ConditionalExpression, ln, col),
          condition(std::move(cond)), consequent(std::move(cons)), alternate(std::move(alt)) {}
};

// Update expression
struct UpdateExpr : Expression {
    std::string op;
    std::unique_ptr<Expression> argument;
    bool prefix;
    
    UpdateExpr(std::string oper, std::unique_ptr<Expression> arg, bool pre,
                 uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::UpdateExpression, ln, col),
          op(std::move(oper)), argument(std::move(arg)), prefix(pre) {}
};

// New expression
struct NewExpr : Expression {
    std::unique_ptr<Expression> callee;
    std::vector<std::unique_ptr<Expression>> arguments;
    
    NewExpr(std::unique_ptr<Expression> c, std::vector<std::unique_ptr<Expression>> args,
            uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::NewExpression, ln, col),
          callee(std::move(c)), arguments(std::move(args)) {}
};

// This expression
struct ThisExpr : Expression {
    ThisExpr(uint32_t ln, uint32_t col)
        : Expression(ASTNodeType::ThisExpression, ln, col) {}
};

// ============================================================================
// Statements
// ============================================================================

struct ExpressionStmt : Statement {
    std::unique_ptr<Expression> expression;
    
    ExpressionStmt(std::unique_ptr<Expression> expr, uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::ExpressionStatement, ln, col), expression(std::move(expr)) {}
};

struct BlockStmt : Statement {
    std::vector<std::unique_ptr<Statement>> body;
    
    BlockStmt(std::vector<std::unique_ptr<Statement>> b, uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::BlockStatement, ln, col), body(std::move(b)) {}
};

struct IfStmt : Statement {
    std::unique_ptr<Expression> condition;
    std::unique_ptr<Statement> consequent;
    std::optional<std::unique_ptr<Statement>> alternate;
    
    IfStmt(std::unique_ptr<Expression> cond, std::unique_ptr<Statement> cons,
           std::optional<std::unique_ptr<Statement>> alt, uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::IfStatement, ln, col),
          condition(std::move(cond)), consequent(std::move(cons)), alternate(std::move(alt)) {}
};

struct WhileStmt : Statement {
    std::unique_ptr<Expression> condition;
    std::unique_ptr<Statement> body;
    
    WhileStmt(std::unique_ptr<Expression> cond, std::unique_ptr<Statement> b,
              uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::WhileStatement, ln, col),
          condition(std::move(cond)), body(std::move(b)) {}
};

struct ForStmt : Statement {
    std::optional<std::unique_ptr<Declaration>> init;
    std::optional<std::unique_ptr<Expression>> condition;
    std::optional<std::unique_ptr<Expression>> update;
    std::unique_ptr<Statement> body;
    
    ForStmt(std::optional<std::unique_ptr<Declaration>> i,
            std::optional<std::unique_ptr<Expression>> cond,
            std::optional<std::unique_ptr<Expression>> upd,
            std::unique_ptr<Statement> b, uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::ForStatement, ln, col),
          init(std::move(i)), condition(std::move(cond)), 
          update(std::move(upd)), body(std::move(b)) {}
};

struct ReturnStmt : Statement {
    std::optional<std::unique_ptr<Expression>> argument;
    
    ReturnStmt(std::optional<std::unique_ptr<Expression>> arg, uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::ReturnStatement, ln, col), argument(std::move(arg)) {}
};

struct BreakStmt : Statement {
    BreakStmt(uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::BreakStatement, ln, col) {}
};

struct ContinueStmt : Statement {
    ContinueStmt(uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::ContinueStatement, ln, col) {}
};

struct SwitchCase {
    std::optional<std::unique_ptr<Expression>> test;
    std::vector<std::unique_ptr<Statement>> consequent;
};

struct SwitchStmt : Statement {
    std::unique_ptr<Expression> discriminant;
    std::vector<SwitchCase> cases;
    
    SwitchStmt(std::unique_ptr<Expression> disc, std::vector<SwitchCase> c,
               uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::SwitchStatement, ln, col),
          discriminant(std::move(disc)), cases(std::move(c)) {}
};

struct CatchClause {
    std::optional<std::string> param;
    std::unique_ptr<Statement> body;
};

struct TryStmt : Statement {
    std::unique_ptr<Statement> block;
    std::optional<CatchClause> handler;
    std::optional<std::unique_ptr<Statement>> finalizer;
    
    TryStmt(std::unique_ptr<Statement> blk, std::optional<CatchClause> hnd,
            std::optional<std::unique_ptr<Statement>> fin, uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::TryStatement, ln, col),
          block(std::move(blk)), handler(std::move(hnd)), finalizer(std::move(fin)) {}
};

struct ThrowStmt : Statement {
    std::unique_ptr<Expression> argument;
    
    ThrowStmt(std::unique_ptr<Expression> arg, uint32_t ln, uint32_t col)
        : Statement(ASTNodeType::ThrowStatement, ln, col), argument(std::move(arg)) {}
};

// ============================================================================
// Declarations
// ============================================================================

struct VariableDeclarator {
    std::unique_ptr<Expression> id;
    std::optional<std::unique_ptr<Expression>> init;
};

struct VariableDecl : Declaration {
    std::string kind;
    std::vector<VariableDeclarator> declarations;
    
    VariableDecl(std::string k, std::vector<VariableDeclarator> decls, uint32_t ln, uint32_t col)
        : Declaration(ASTNodeType::VariableDeclaration, ln, col),
          kind(std::move(k)), declarations(std::move(decls)) {}
};

struct FunctionDecl : Declaration {
    std::string name;
    std::vector<std::string> params;
    std::unique_ptr<Statement> body;
    
    FunctionDecl(std::string n, std::vector<std::string> p,
                 std::unique_ptr<Statement> b, uint32_t ln, uint32_t col)
        : Declaration(ASTNodeType::FunctionDeclaration, ln, col),
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

} // namespace Script
} // namespace RawrXD
