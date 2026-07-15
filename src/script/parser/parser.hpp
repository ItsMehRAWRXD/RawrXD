// RawrXD-Script Parser
// Phase 1: Bytecode Spec + C++ Parser
// Recursive descent parser for ES5 subset

#pragma once

#include "../lexer/lexer.hpp"
#include "../ast/ast_simple.hpp"
#include <memory>
#include <vector>
#include <optional>
#include <functional>

namespace RawrXD {
namespace Script {

// Parser error codes
enum class ParserError {
    None,
    UnexpectedToken,
    ExpectedToken,
    InvalidAssignmentTarget,
    DuplicateParameter,
    StrictModeViolation,
    InvalidBreak,
    InvalidContinue,
    InvalidReturn,
    MalformedTemplate,
};

struct ParserResult {
    std::unique_ptr<Program> ast;
    bool success;
    ParserError error;
    uint32_t errorLine;
    uint32_t errorColumn;
    std::string errorMessage;
    std::vector<std::string> warnings;
    
    ParserResult() : success(false), error(ParserError::None), errorLine(0), errorColumn(0) {}
    
    static ParserResult Error(ParserError err, const std::string& msg, uint32_t line, uint32_t col) {
        ParserResult result;
        result.success = false;
        result.error = err;
        result.errorMessage = msg;
        result.errorLine = line;
        result.errorColumn = col;
        return result;
    }
    
    static ParserResult Success(std::unique_ptr<Program> program) {
        ParserResult result;
        result.success = true;
        result.ast = std::move(program);
        return result;
    }
};

// Parser context for tracking state
struct ParserContext {
    bool strict_mode = false;
    bool in_function = false;
    bool in_loop = false;
    bool in_switch = false;
    int function_depth = 0;
    int loop_depth = 0;
    std::vector<std::string> labels;
};

class Parser {
public:
    Parser();
    
    // Parse source code into AST
    ParserResult Parse(std::string_view source);
    
    // Parse from tokens (for testing)
    ParserResult ParseTokens(std::vector<Token> tokens);
    
    // Reset parser state
    void Reset();
    
private:
    std::vector<Token> tokens_;
    size_t current_;
    ParserContext context_;
    std::vector<std::string> warnings_;
    
    // Token access
    Token& Current();
    Token& Peek(size_t offset = 0);
    Token& Previous();
    bool IsAtEnd();
    
    // Token consumption
    Token Advance();
    bool Check(TokenType type);
    bool Match(TokenType type);
    bool Match(std::initializer_list<TokenType> types);
    Token Consume(TokenType type, const std::string& message);
    
    // Error handling
    ParserResult Error(const std::string& message);
    ParserResult ErrorAt(const Token& token, const std::string& message);
    void Warn(const std::string& message);
    
    // Synchronization for error recovery
    void Synchronize();
    
    // ============================================================================
    // Grammar Rules (Recursive Descent)
    // ============================================================================
    
    // Program
    std::unique_ptr<Program> ParseProgram();
    
    // Statements
    std::unique_ptr<Statement> ParseStatement();
    std::unique_ptr<Statement> ParseBlockStatement();
    std::unique_ptr<Statement> ParseVariableStatement();
    std::unique_ptr<Statement> ParseEmptyStatement();
    std::unique_ptr<Statement> ParseExpressionStatement();
    std::unique_ptr<Statement> ParseIfStatement();
    std::unique_ptr<Statement> ParseWhileStatement();
    std::unique_ptr<Statement> ParseForStatement();
    std::unique_ptr<Statement> ParseContinueStatement();
    std::unique_ptr<Statement> ParseBreakStatement();
    std::unique_ptr<Statement> ParseReturnStatement();
    std::unique_ptr<Statement> ParseWithStatement();  // Not in strict mode
    std::unique_ptr<Statement> ParseSwitchStatement();
    std::unique_ptr<Statement> ParseThrowStatement();
    std::unique_ptr<Statement> ParseTryStatement();
    std::unique_ptr<Statement> ParseDebuggerStatement();
    std::unique_ptr<Statement> ParseLabelledStatement();
    
    // Declarations
    std::unique_ptr<Declaration> ParseDeclaration();
    std::unique_ptr<Declaration> ParseFunctionDeclaration();
    std::unique_ptr<Declaration> ParseVariableDeclaration();
    std::unique_ptr<Declaration> ParseVariableDeclaration(const std::string& kind);
    
    // Expressions
    std::unique_ptr<Expression> ParseExpression();
    std::unique_ptr<Expression> ParseAssignmentExpression();
    std::unique_ptr<Expression> ParseConditionalExpression();
    std::unique_ptr<Expression> ParseBinaryExpression();
    std::unique_ptr<Expression> ParseUnaryExpression();
    std::unique_ptr<Expression> ParsePostfixExpression();
    std::unique_ptr<Expression> ParseLeftHandSideExpression();
    std::unique_ptr<Expression> ParseCallExpression(std::unique_ptr<Expression> callee);
    std::unique_ptr<Expression> ParseMemberExpression();
    std::unique_ptr<Expression> ParsePrimaryExpression();
    std::unique_ptr<Expression> ParseArrayLiteral();
    std::unique_ptr<Expression> ParseObjectLiteral();
    std::unique_ptr<Expression> ParseFunctionExpression();
    std::unique_ptr<Expression> ParseArguments();
    
    // Helper methods
    bool IsValidAssignmentTarget(const Expression& expr);
    bool IsValidSimpleAssignmentTarget(const Expression& expr);
    std::vector<std::string> ParseParameters();
    std::vector<std::unique_ptr<Expression>> ParseArgumentsList();
    
    // Context management
    void EnterFunction();
    void ExitFunction();
    void EnterLoop();
    void ExitLoop();
    void EnterSwitch();
    void ExitSwitch();
    void PushLabel(const std::string& label);
    void PopLabel();
    bool HasLabel(const std::string& label);
    
    // Precedence levels for binary expressions
    enum class Precedence {
        None = 0,
        Assignment,      // = += -= etc
        Conditional,     // ?:
        LogicalOr,       // ||
        LogicalAnd,      // &&
        BitwiseOr,         // |
        BitwiseXor,      // ^
        BitwiseAnd,      // &
        Equality,        // == != === !==
        Relational,      // < > <= >= instanceof in
        BitwiseShift,    // << >> >>>
        Additive,        // + -
        Multiplicative,  // * / %
        Unary,             // + - ! ~ typeof void delete
        Postfix,           // ++ --
        Call,             // () . []
        Primary            // literals, identifiers, etc
    };
    
    Precedence GetTokenPrecedence(TokenType type);
    std::unique_ptr<Expression> ParseBinaryExpression(std::unique_ptr<Expression> left, Precedence minPrec);
};

} // namespace Script
} // namespace RawrXD
