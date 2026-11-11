// RawrXD-Script AST JSON Schema Implementation
// JSON serialization and traversal for LSP integration

#include "ast_schema.hpp"
#include <sstream>
#include <iomanip>
#include <fstream>

namespace RawrXD {
namespace Script {
namespace AST {

// ============================================================================
// NodeType to String
// ============================================================================

const char* NodeTypeToString(NodeType type) {
    switch (type) {
        case NodeType::Program: return "Program";
        case NodeType::VariableDeclaration: return "VariableDeclaration";
        case NodeType::FunctionDeclaration: return "FunctionDeclaration";
        case NodeType::ExpressionStatement: return "ExpressionStatement";
        case NodeType::IfStatement: return "IfStatement";
        case NodeType::WhileStatement: return "WhileStatement";
        case NodeType::ForStatement: return "ForStatement";
        case NodeType::ReturnStatement: return "ReturnStatement";
        case NodeType::BlockStatement: return "BlockStatement";
        case NodeType::EmptyStatement: return "EmptyStatement";
        case NodeType::BinaryExpression: return "BinaryExpression";
        case NodeType::UnaryExpression: return "UnaryExpression";
        case NodeType::AssignmentExpression: return "AssignmentExpression";
        case NodeType::CallExpression: return "CallExpression";
        case NodeType::MemberExpression: return "MemberExpression";
        case NodeType::UpdateExpression: return "UpdateExpression";
        case NodeType::ConditionalExpression: return "ConditionalExpression";
        case NodeType::Literal: return "Literal";
        case NodeType::Identifier: return "Identifier";
        case NodeType::ArrayExpression: return "ArrayExpression";
        case NodeType::ObjectExpression: return "ObjectExpression";
        case NodeType::VariableDeclarator: return "VariableDeclarator";
        case NodeType::ArrayPattern: return "ArrayPattern";
        case NodeType::ObjectPattern: return "ObjectPattern";
        case NodeType::FunctionExpression: return "FunctionExpression";
        case NodeType::ArrowFunctionExpression: return "ArrowFunctionExpression";
        case NodeType::TemplateLiteral: return "TemplateLiteral";
        case NodeType::TaggedTemplateExpression: return "TaggedTemplateExpression";
        case NodeType::NativeCallExpression: return "NativeCallExpression";
        case NodeType::TracePointExpression: return "TracePointExpression";
        default: return "Unknown";
    }
}

// ============================================================================
// JSON Escape Helper
// ============================================================================

static std::string EscapeJSON(const std::string& str) {
    std::ostringstream oss;
    for (char c : str) {
        switch (c) {
            case '"': oss << "\\\""; break;
            case '\\': oss << "\\\\"; break;
            case '\b': oss << "\\b"; break;
            case '\f': oss << "\\f"; break;
            case '\n': oss << "\\n"; break;
            case '\r': oss << "\\r"; break;
            case '\t': oss << "\\t"; break;
            default:
                if (c >= 0x20 && c <= 0x7E) {
                    oss << c;
                } else {
                    oss << "\\u" << std::hex << std::setw(4) << std::setfill('0') << (int)(unsigned char)c;
                }
        }
    }
    return oss.str();
}

// ============================================================================
// Base AST Node
// ============================================================================

std::string ASTNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"" << NodeTypeToString(type) << "\"";
    oss << ",\"loc\":{";
    oss << "\"start\":{"line\":" << loc.start.line << ",\"column\":" << loc.start.column << "},";
    oss << "\"end\":{"line\":" << loc.end.line << ",\"column\":" << loc.end.column << "}";
    if (!loc.sourceFile.empty()) {
        oss << ",\"sourceFile\":\"" << EscapeJSON(loc.sourceFile) << "\"";
    }
    oss << "}";
    return oss.str();
}

// ============================================================================
// Program Node
// ============================================================================

std::string ProgramNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"Program\"";
    oss << ",\"sourceType\":\"" << sourceType << "\"";
    oss << ",\"body\":[";
    for (size_t i = 0; i < body.size(); ++i) {
        if (i > 0) oss << ",";
        oss << body[i]->ToJSON();
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

// ============================================================================
// Statement Nodes
// ============================================================================

std::string VariableDeclarationNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"VariableDeclaration\"";
    oss << ",\"kind\":\"" << kind << "\"";
    oss << ",\"declarations\":[";
    for (size_t i = 0; i < declarations.size(); ++i) {
        if (i > 0) oss << ",";
        oss << declarations[i]->ToJSON();
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

std::string VariableDeclaratorNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"VariableDeclarator\"";
    oss << ",\"id\":" << (id ? id->ToJSON() : "null");
    if (init) {
        oss << ",\"init\":" << init->ToJSON();
    } else {
        oss << ",\"init\":null";
    }
    oss << "}";
    return oss.str();
}

std::string FunctionDeclarationNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"FunctionDeclaration\"";
    oss << ",\"id\":" << (id ? id->ToJSON() : "null");
    oss << ",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i > 0) oss << ",";
        oss << params[i]->ToJSON();
    }
    oss << "]";
    oss << ",\"body\":" << body->ToJSON();
    oss << ",\"async\":" << (async ? "true" : "false");
    oss << ",\"generator\":" << (generator ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string ExpressionStatementNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"ExpressionStatement\"";
    oss << ",\"expression\":" << expression->ToJSON();
    oss << "}";
    return oss.str();
}

std::string BlockStatementNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"BlockStatement\"";
    oss << ",\"body\":[";
    for (size_t i = 0; i < body.size(); ++i) {
        if (i > 0) oss << ",";
        oss << body[i]->ToJSON();
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

std::string IfStatementNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"IfStatement\"";
    oss << ",\"test\":" << test->ToJSON();
    oss << ",\"consequent\":" << consequent->ToJSON();
    if (alternate) {
        oss << ",\"alternate\":" << alternate->ToJSON();
    } else {
        oss << ",\"alternate\":null";
    }
    oss << "}";
    return oss.str();
}

std::string WhileStatementNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"WhileStatement\"";
    oss << ",\"test\":" << test->ToJSON();
    oss << ",\"body\":" << body->ToJSON();
    oss << "}";
    return oss.str();
}

std::string ForStatementNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"ForStatement\"";
    oss << ",\"init\":" << (init ? init->ToJSON() : "null");
    oss << ",\"test\":" << (test ? test->ToJSON() : "null");
    oss << ",\"update\":" << (update ? update->ToJSON() : "null");
    oss << ",\"body\":" << body->ToJSON();
    oss << "}";
    return oss.str();
}

std::string ReturnStatementNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"ReturnStatement\"";
    oss << ",\"argument\":" << (argument ? argument->ToJSON() : "null");
    oss << "}";
    return oss.str();
}

// ============================================================================
// Expression Nodes
// ============================================================================

std::string BinaryExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"BinaryExpression\"";
    oss << ",\"operator\":\"" << EscapeJSON(operator_) << "\"";
    oss << ",\"left\":" << left->ToJSON();
    oss << ",\"right\":" << right->ToJSON();
    oss << "}";
    return oss.str();
}

std::string UnaryExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"UnaryExpression\"";
    oss << ",\"operator\":\"" << EscapeJSON(operator_) << "\"";
    oss << ",\"prefix\":" << (prefix ? "true" : "false");
    oss << ",\"argument\":" << argument->ToJSON();
    oss << "}";
    return oss.str();
}

std::string AssignmentExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"AssignmentExpression\"";
    oss << ",\"operator\":\"" << EscapeJSON(operator_) << "\"";
    oss << ",\"left\":" << left->ToJSON();
    oss << ",\"right\":" << right->ToJSON();
    oss << "}";
    return oss.str();
}

std::string CallExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"CallExpression\"";
    oss << ",\"callee\":" << callee->ToJSON();
    oss << ",\"arguments\":[";
    for (size_t i = 0; i < arguments.size(); ++i) {
        if (i > 0) oss << ",";
        oss << arguments[i]->ToJSON();
    }
    oss << "]";
    oss << ",\"optional\":" << (optional ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string MemberExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"MemberExpression\"";
    oss << ",\"object\":" << object->ToJSON();
    oss << ",\"property\":" << property->ToJSON();
    oss << ",\"computed\":" << (computed ? "true" : "false");
    oss << ",\"optional\":" << (optional ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string UpdateExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"UpdateExpression\"";
    oss << ",\"operator\":\"" << EscapeJSON(operator_) << "\"";
    oss << ",\"argument\":" << argument->ToJSON();
    oss << ",\"prefix\":" << (prefix ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string ConditionalExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"ConditionalExpression\"";
    oss << ",\"test\":" << test->ToJSON();
    oss << ",\"consequent\":" << consequent->ToJSON();
    oss << ",\"alternate\":" << alternate->ToJSON();
    oss << "}";
    return oss.str();
}

// ============================================================================
// Literal Nodes
// ============================================================================

std::string LiteralNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"Literal\"";
    
    switch (literalType) {
        case LiteralType::Number:
            oss << ",\"value\":" << numericValue;
            break;
        case LiteralType::String:
            oss << ",\"value\":\"" << EscapeJSON(value) << "\"";
            break;
        case LiteralType::Boolean:
            oss << ",\"value\":" << (value == "true" ? "true" : "false");
            break;
        case LiteralType::Null:
            oss << ",\"value\":null";
            break;
        case LiteralType::Undefined:
            oss << ",\"value\":null";
            break;
        default:
            oss << ",\"value\":null";
    }
    
    oss << ",\"raw\":\"" << EscapeJSON(raw) << "\"";
    oss << "}";
    return oss.str();
}

std::string IdentifierNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"Identifier\"";
    oss << ",\"name\":\"" << EscapeJSON(name) << "\"";
    oss << "}";
    return oss.str();
}

std::string ArrayExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"ArrayExpression\"";
    oss << ",\"elements\":[";
    for (size_t i = 0; i < elements.size(); ++i) {
        if (i > 0) oss << ",";
        if (elements[i]) {
            oss << elements[i]->ToJSON();
        } else {
            oss << "null";
        }
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

std::string ObjectExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"ObjectExpression\"";
    oss << ",\"properties\":[";
    for (size_t i = 0; i < properties.size(); ++i) {
        if (i > 0) oss << ",";
        const auto& prop = properties[i];
        oss << "{";
        oss << "\"key\":" << prop.key->ToJSON() << ",";
        oss << "\"value\":" << prop.value->ToJSON() << ",";
        oss << "\"kind\":\"" << prop.kind << "\",";
        oss << "\"computed\":" << (prop.computed ? "true" : "false") << ",";
        oss << "\"shorthand\":" << (prop.shorthand ? "true" : "false");
        oss << "}";
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

// ============================================================================
// Function Expression Nodes
// ============================================================================

std::string FunctionExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"FunctionExpression\"";
    oss << ",\"id\":" << (id ? id->ToJSON() : "null");
    oss << ",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i > 0) oss << ",";
        oss << params[i]->ToJSON();
    }
    oss << "]";
    oss << ",\"body\":" << body->ToJSON();
    oss << ",\"async\":" << (async ? "true" : "false");
    oss << ",\"generator\":" << (generator ? "true" : "false");
    oss << "}";
    return oss.str();
}

std::string ArrowFunctionExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"ArrowFunctionExpression\"";
    oss << ",\"params\":[";
    for (size_t i = 0; i < params.size(); ++i) {
        if (i > 0) oss << ",";
        oss << params[i]->ToJSON();
    }
    oss << "]";
    oss << ",\"body\":" << body->ToJSON();
    oss << ",\"async\":" << (async ? "true" : "false");
    oss << ",\"expression\":" << (expression ? "true" : "false");
    oss << "}";
    return oss.str();
}

// ============================================================================
// RawrXD-Specific Nodes
// ============================================================================

std::string NativeCallExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"NativeCallExpression\"";
    oss << ",\"nativeFunction\":\"" << EscapeJSON(nativeFunction) << "\"";
    oss << ",\"arguments\":[";
    for (size_t i = 0; i < arguments.size(); ++i) {
        if (i > 0) oss << ",";
        oss << arguments[i]->ToJSON();
    }
    oss << "]";
    oss << "}";
    return oss.str();
}

std::string TracePointExpressionNode::ToJSON() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"type\":\"TracePointExpression\"";
    oss << ",\"label\":\"" << EscapeJSON(label) << "\"";
    oss << ",\"expression\":" << expression->ToJSON();
    oss << "}";
    return oss.str();
}

// ============================================================================
// AST Traversal Helpers
// ============================================================================

std::shared_ptr<ASTNode> FindNodeAtPosition(
    const std::shared_ptr<ASTNode>& root,
    uint32_t line,
    uint32_t column
) {
    if (!root) return nullptr;
    
    // Check if this node contains the position
    const auto& loc = root->loc;
    if (line < loc.start.line || line > loc.end.line) {
        return nullptr;
    }
    if (line == loc.start.line && column < loc.start.column) {
        return nullptr;
    }
    if (line == loc.end.line && column > loc.end.column) {
        return nullptr;
    }
    
    // Check children first (more specific match)
    for (const auto& child : root->GetChildren()) {
        auto found = FindNodeAtPosition(child, line, column);
        if (found) return found;
    }
    
    return root;
}

std::vector<std::shared_ptr<ASTNode>> FindNodesByType(
    const std::shared_ptr<ASTNode>& root,
    NodeType type
) {
    std::vector<std::shared_ptr<ASTNode>> results;
    if (!root) return results;
    
    if (root->type == type) {
        results.push_back(root);
    }
    
    for (const auto& child : root->GetChildren()) {
        auto childResults = FindNodesByType(child, type);
        results.insert(results.end(), childResults.begin(), childResults.end());
    }
    
    return results;
}

std::shared_ptr<ASTNode> FindDefinition(
    const std::shared_ptr<ASTNode>& root,
    const std::string& name,
    const SourceLocation& from
) {
    // TODO: Implement scope-aware definition lookup
    // This requires walking up the scope chain from 'from' position
    return nullptr;
}

std::vector<std::shared_ptr<ASTNode>> GetScopeChain(
    const std::shared_ptr<ASTNode>& root,
    const SourceLocation& pos
) {
    std::vector<std::shared_ptr<ASTNode>> chain;
    // TODO: Implement scope chain extraction
    return chain;
}

// ============================================================================
// JSON Serialization
// ============================================================================

std::string SerializeAST(const std::shared_ptr<ASTNode>& root, bool pretty) {
    if (!root) return "null";
    return root->ToJSON();
}

std::shared_ptr<ASTNode> DeserializeAST(const std::string& json) {
    // TODO: Implement JSON deserialization
    // This would require a JSON parser library
    return nullptr;
}

bool WriteASTToFile(const std::shared_ptr<ASTNode>& root, const std::string& path) {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << SerializeAST(root, true);
    return file.good();
}

std::shared_ptr<ASTNode> ReadASTFromFile(const std::string& path) {
    std::ifstream file(path);
    if (!file.is_open()) return nullptr;
    
    std::string json((std::istreambuf_iterator<char>(file)),
                      std::istreambuf_iterator<char>());
    
    return DeserializeAST(json);
}

} // namespace AST
} // namespace Script
} // namespace RawrXD
