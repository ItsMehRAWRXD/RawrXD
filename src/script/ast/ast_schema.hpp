// RawrXD-Script AST JSON Schema Definition
// Formalizes AST node structure for LSP integration and serialization

#ifndef AST_SCHEMA_HPP
#define AST_SCHEMA_HPP

#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <optional>

namespace RawrXD {
namespace Script {
namespace AST {

// ============================================================================
// AST Node Types (ESTree-compatible)
// ============================================================================

enum class NodeType {
    // Program
    Program,
    
    // Statements
    VariableDeclaration,
    FunctionDeclaration,
    ExpressionStatement,
    IfStatement,
    WhileStatement,
    ForStatement,
    ReturnStatement,
    BlockStatement,
    EmptyStatement,
    
    // Expressions
    BinaryExpression,
    UnaryExpression,
    AssignmentExpression,
    CallExpression,
    MemberExpression,
    UpdateExpression,
    ConditionalExpression,
    
    // Literals
    Literal,
    Identifier,
    ArrayExpression,
    ObjectExpression,
    
    // Declarations
    VariableDeclarator,
    
    // Patterns
    ArrayPattern,
    ObjectPattern,
    
    // Other
    FunctionExpression,
    ArrowFunctionExpression,
    TemplateLiteral,
    TaggedTemplateExpression,
    
    // RawrXD-specific
    NativeCallExpression,
    TracePointExpression
};

// Convert NodeType to string
const char* NodeTypeToString(NodeType type);

// ============================================================================
// Source Location (for LSP)
// ============================================================================

struct SourceLocation {
    uint32_t line;      // 1-based line number
    uint32_t column;    // 0-based column number
    uint32_t offset;    // Byte offset from start of file
    
    SourceLocation() : line(1), column(0), offset(0) {}
    SourceLocation(uint32_t l, uint32_t c, uint32_t o) : line(l), column(c), offset(o) {}
};

struct SourceRange {
    SourceLocation start;
    SourceLocation end;
    std::string sourceFile;
    
    SourceRange() = default;
    SourceRange(const SourceLocation& s, const SourceLocation& e, const std::string& file = "")
        : start(s), end(e), sourceFile(file) {}
};

// ============================================================================
// Base AST Node
// ============================================================================

struct ASTNode {
    NodeType type;
    SourceRange loc;
    std::vector<std::shared_ptr<ASTNode>> children;
    
    // Parent pointer for traversal (optional, set during tree building)
    ASTNode* parent = nullptr;
    
    ASTNode(NodeType t) : type(t) {}
    virtual ~ASTNode() = default;
    
    // JSON serialization
    virtual std::string ToJSON() const;
    
    // Get child nodes for LSP traversal
    virtual std::vector<std::shared_ptr<ASTNode>> GetChildren() const { return children; }
};

// ============================================================================
// Program Node (Root)
// ============================================================================

struct ProgramNode : public ASTNode {
    std::vector<std::shared_ptr<ASTNode>> body;
    std::string sourceType = "script"; // "script" or "module"
    
    ProgramNode() : ASTNode(NodeType::Program) {}
    
    std::string ToJSON() const override;
};

// ============================================================================
// Statement Nodes
// ============================================================================

struct VariableDeclarationNode : public ASTNode {
    std::string kind; // "var", "let", or "const"
    std::vector<std::shared_ptr<ASTNode>> declarations;
    
    VariableDeclarationNode() : ASTNode(NodeType::VariableDeclaration) {}
    
    std::string ToJSON() const override;
};

struct VariableDeclaratorNode : public ASTNode {
    std::shared_ptr<ASTNode> id;        // Identifier or Pattern
    std::shared_ptr<ASTNode> init;      // Initializer expression (optional)
    
    VariableDeclaratorNode() : ASTNode(NodeType::VariableDeclarator) {}
    
    std::string ToJSON() const override;
};

struct FunctionDeclarationNode : public ASTNode {
    std::shared_ptr<ASTNode> id;                    // Function name
    std::vector<std::shared_ptr<ASTNode>> params;   // Parameters
    std::shared_ptr<ASTNode> body;                  // Function body (BlockStatement)
    bool async = false;
    bool generator = false;
    
    FunctionDeclarationNode() : ASTNode(NodeType::FunctionDeclaration) {}
    
    std::string ToJSON() const override;
};

struct ExpressionStatementNode : public ASTNode {
    std::shared_ptr<ASTNode> expression;
    
    ExpressionStatementNode() : ASTNode(NodeType::ExpressionStatement) {}
    
    std::string ToJSON() const override;
};

struct BlockStatementNode : public ASTNode {
    std::vector<std::shared_ptr<ASTNode>> body;
    
    BlockStatementNode() : ASTNode(NodeType::BlockStatement) {}
    
    std::string ToJSON() const override;
};

struct IfStatementNode : public ASTNode {
    std::shared_ptr<ASTNode> test;       // Condition
    std::shared_ptr<ASTNode> consequent; // Then branch
    std::shared_ptr<ASTNode> alternate;  // Else branch (optional)
    
    IfStatementNode() : ASTNode(NodeType::IfStatement) {}
    
    std::string ToJSON() const override;
};

struct WhileStatementNode : public ASTNode {
    std::shared_ptr<ASTNode> test;  // Condition
    std::shared_ptr<ASTNode> body;  // Loop body
    
    WhileStatementNode() : ASTNode(NodeType::WhileStatement) {}
    
    std::string ToJSON() const override;
};

struct ForStatementNode : public ASTNode {
    std::shared_ptr<ASTNode> init;      // Initialization (optional)
    std::shared_ptr<ASTNode> test;      // Condition (optional)
    std::shared_ptr<ASTNode> update;    // Update expression (optional)
    std::shared_ptr<ASTNode> body;        // Loop body
    
    ForStatementNode() : ASTNode(NodeType::ForStatement) {}
    
    std::string ToJSON() const override;
};

struct ReturnStatementNode : public ASTNode {
    std::shared_ptr<ASTNode> argument; // Return value (optional)
    
    ReturnStatementNode() : ASTNode(NodeType::ReturnStatement) {}
    
    std::string ToJSON() const override;
};

// ============================================================================
// Expression Nodes
// ============================================================================

struct BinaryExpressionNode : public ASTNode {
    std::string operator_; // "+", "-", "*", "/", "%", "==", "!=", "<", ">", etc.
    std::shared_ptr<ASTNode> left;
    std::shared_ptr<ASTNode> right;
    
    BinaryExpressionNode() : ASTNode(NodeType::BinaryExpression) {}
    
    std::string ToJSON() const override;
};

struct UnaryExpressionNode : public ASTNode {
    std::string operator_; // "+", "-", "!", "~", "typeof", "void", "delete"
    std::shared_ptr<ASTNode> argument;
    bool prefix = true;
    
    UnaryExpressionNode() : ASTNode(NodeType::UnaryExpression) {}
    
    std::string ToJSON() const override;
};

struct AssignmentExpressionNode : public ASTNode {
    std::string operator_; // "=", "+=", "-=", "*=", "/=", etc.
    std::shared_ptr<ASTNode> left;   // Target (Identifier or MemberExpression)
    std::shared_ptr<ASTNode> right;  // Value
    
    AssignmentExpressionNode() : ASTNode(NodeType::AssignmentExpression) {}
    
    std::string ToJSON() const override;
};

struct CallExpressionNode : public ASTNode {
    std::shared_ptr<ASTNode> callee;                  // Function being called
    std::vector<std::shared_ptr<ASTNode>> arguments; // Arguments
    bool optional = false;                            // Optional chaining
    
    CallExpressionNode() : ASTNode(NodeType::CallExpression) {}
    
    std::string ToJSON() const override;
};

struct MemberExpressionNode : public ASTNode {
    std::shared_ptr<ASTNode> object;   // Object being accessed
    std::shared_ptr<ASTNode> property; // Property name
    bool computed = false;               // true if obj[prop], false if obj.prop
    bool optional = false;             // Optional chaining
    
    MemberExpressionNode() : ASTNode(NodeType::MemberExpression) {}
    
    std::string ToJSON() const override;
};

struct UpdateExpressionNode : public ASTNode {
    std::string operator_; // "++" or "--"
    std::shared_ptr<ASTNode> argument;
    bool prefix = false;
    
    UpdateExpressionNode() : ASTNode(NodeType::UpdateExpression) {}
    
    std::string ToJSON() const override;
};

struct ConditionalExpressionNode : public ASTNode {
    std::shared_ptr<ASTNode> test;       // Condition
    std::shared_ptr<ASTNode> consequent; // True branch
    std::shared_ptr<ASTNode> alternate;  // False branch
    
    ConditionalExpressionNode() : ASTNode(NodeType::ConditionalExpression) {}
    
    std::string ToJSON() const override;
};

// ============================================================================
// Literal Nodes
// ============================================================================

struct LiteralNode : public ASTNode {
    enum class LiteralType {
        Number,
        String,
        Boolean,
        Null,
        Undefined,
        RegExp
    };
    
    LiteralType literalType;
    std::string raw;      // Raw source text
    std::string value;      // String representation of value
    double numericValue = 0; // For numbers
    
    LiteralNode() : ASTNode(NodeType::Literal), literalType(LiteralType::Null) {}
    
    std::string ToJSON() const override;
};

struct IdentifierNode : public ASTNode {
    std::string name;
    
    IdentifierNode() : ASTNode(NodeType::Identifier) {}
    explicit IdentifierNode(const std::string& n) : ASTNode(NodeType::Identifier), name(n) {}
    
    std::string ToJSON() const override;
};

struct ArrayExpressionNode : public ASTNode {
    std::vector<std::shared_ptr<ASTNode>> elements; // null for sparse arrays
    
    ArrayExpressionNode() : ASTNode(NodeType::ArrayExpression) {}
    
    std::string ToJSON() const override;
};

struct ObjectExpressionNode : public ASTNode {
    struct Property {
        std::shared_ptr<ASTNode> key;       // Identifier or Literal
        std::shared_ptr<ASTNode> value;     // Expression
        std::string kind;                   // "init", "get", or "set"
        bool computed = false;
        bool shorthand = false;
    };
    
    std::vector<Property> properties;
    
    ObjectExpressionNode() : ASTNode(NodeType::ObjectExpression) {}
    
    std::string ToJSON() const override;
};

// ============================================================================
// Function Expression Nodes
// ============================================================================

struct FunctionExpressionNode : public ASTNode {
    std::shared_ptr<ASTNode> id;                    // Function name (optional)
    std::vector<std::shared_ptr<ASTNode>> params;   // Parameters
    std::shared_ptr<ASTNode> body;                  // Function body
    bool async = false;
    bool generator = false;
    
    FunctionExpressionNode() : ASTNode(NodeType::FunctionExpression) {}
    
    std::string ToJSON() const override;
};

struct ArrowFunctionExpressionNode : public ASTNode {
    std::vector<std::shared_ptr<ASTNode>> params;
    std::shared_ptr<ASTNode> body; // BlockStatement or expression
    bool async = false;
    bool expression = false; // true if body is expression, false if block
    
    ArrowFunctionExpressionNode() : ASTNode(NodeType::ArrowFunctionExpression) {}
    
    std::string ToJSON() const override;
};

// ============================================================================
// RawrXD-Specific Nodes
// ============================================================================

struct NativeCallExpressionNode : public ASTNode {
    std::string nativeFunction; // Name of native function
    std::vector<std::shared_ptr<ASTNode>> arguments;
    
    NativeCallExpressionNode() : ASTNode(NodeType::NativeCallExpression) {}
    
    std::string ToJSON() const override;
};

struct TracePointExpressionNode : public ASTNode {
    std::string label;      // Trace point label
    std::shared_ptr<ASTNode> expression; // Expression to trace
    
    TracePointExpressionNode() : ASTNode(NodeType::TracePointExpression) {}
    
    std::string ToJSON() const override;
};

// ============================================================================
// AST Traversal Helpers (for LSP)
// ============================================================================

// Find node at specific position
std::shared_ptr<ASTNode> FindNodeAtPosition(
    const std::shared_ptr<ASTNode>& root,
    uint32_t line,
    uint32_t column
);

// Find all nodes of specific type
std::vector<std::shared_ptr<ASTNode>> FindNodesByType(
    const std::shared_ptr<ASTNode>& root,
    NodeType type
);

// Find definition of identifier
std::shared_ptr<ASTNode> FindDefinition(
    const std::shared_ptr<ASTNode>& root,
    const std::string& name,
    const SourceLocation& from
);

// Get scope chain at position
std::vector<std::shared_ptr<ASTNode>> GetScopeChain(
    const std::shared_ptr<ASTNode>& root,
    const SourceLocation& pos
);

// ============================================================================
// JSON Serialization
// ============================================================================

// Serialize entire AST to JSON string
std::string SerializeAST(const std::shared_ptr<ASTNode>& root, bool pretty = true);

// Deserialize JSON to AST
std::shared_ptr<ASTNode> DeserializeAST(const std::string& json);

// Write AST to file
bool WriteASTToFile(const std::shared_ptr<ASTNode>& root, const std::string& path);

// Read AST from file
std::shared_ptr<ASTNode> ReadASTFromFile(const std::string& path);

} // namespace AST
} // namespace Script
} // namespace RawrXD

#endif // AST_SCHEMA_HPP
