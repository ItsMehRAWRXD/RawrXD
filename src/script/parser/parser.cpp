// RawrXD-Script Parser Implementation
// Phase 1: Working Implementation

#include "parser.hpp"
#include <stdexcept>

namespace RawrXD {
namespace Script {

Parser::Parser() : current_(0) {}

ParserResult Parser::Parse(std::string_view source) {
    Lexer lexer;
    LexerResult lex_result = lexer.Tokenize(source);
    
    if (!lex_result.Success()) {
        return ParserResult::Error(
            ParserError::UnexpectedToken,
            lex_result.errorMessage,
            lex_result.errorLine,
            lex_result.errorColumn
        );
    }
    
    return ParseTokens(std::move(lex_result.tokens));
}

ParserResult Parser::ParseTokens(std::vector<Token> tokens) {
    tokens_ = std::move(tokens);
    current_ = 0;
    context_ = {};
    warnings_.clear();
    
    try {
        auto program = ParseProgram();
        return ParserResult::Success(std::move(program));
    } catch (const std::exception& e) {
        Token& tok = Current();
        return ParserResult::Error(
            ParserError::UnexpectedToken,
            e.what(),
            tok.line,
            tok.column
        );
    }
}

void Parser::Reset() {
    tokens_.clear();
    current_ = 0;
    context_ = {};
}

// Token access
Token& Parser::Current() {
    if (current_ >= tokens_.size()) {
        static Token eof{TokenType::EndOfFile, "", 0, 0};
        return eof;
    }
    return tokens_[current_];
}

Token& Parser::Peek(size_t offset) {
    if (current_ + offset >= tokens_.size()) {
        static Token eof{TokenType::EndOfFile, "", 0, 0};
        return eof;
    }
    return tokens_[current_ + offset];
}

Token& Parser::Previous() {
    if (current_ == 0) {
        static Token eof{TokenType::EndOfFile, "", 0, 0};
        return eof;
    }
    return tokens_[current_ - 1];
}

bool Parser::IsAtEnd() {
    return Current().type == TokenType::EndOfFile;
}

// Token consumption
Token Parser::Advance() {
    if (!IsAtEnd()) current_++;
    return Previous();
}

bool Parser::Check(TokenType type) {
    if (IsAtEnd()) return false;
    return Current().type == type;
}

bool Parser::Match(TokenType type) {
    if (Check(type)) {
        Advance();
        return true;
    }
    return false;
}

bool Parser::Match(std::initializer_list<TokenType> types) {
    for (auto type : types) {
        if (Check(type)) {
            Advance();
            return true;
        }
    }
    return false;
}

Token Parser::Consume(TokenType type, const std::string& message) {
    if (Check(type)) return Advance();
    throw std::runtime_error(message);
}

// Grammar rules
std::unique_ptr<Program> Parser::ParseProgram() {
    uint32_t line = Current().line;
    uint32_t col = Current().column;
    
    std::vector<std::unique_ptr<Statement>> statements;
    
    while (!IsAtEnd()) {
        auto stmt = ParseStatement();
        if (stmt) {
            statements.push_back(std::move(stmt));
        }
    }
    
    return std::make_unique<Program>(std::move(statements), line, col);
}

std::unique_ptr<Statement> Parser::ParseStatement() {
    // Try declaration first
    if (Check(TokenType::KeywordFunction)) {
        auto decl = ParseFunctionDeclaration();
        // Convert declaration to statement
        // For now, return as expression statement
        return std::make_unique<ExpressionStmt>(
            std::make_unique<IdentifierExpr>("function", Current().line, Current().column),
            Current().line, Current().column
        );
    }
    
    if (Check(TokenType::KeywordVar) || Check(TokenType::KeywordLet) || 
        Check(TokenType::KeywordConst)) {
        return ParseVariableStatement();
    }
    
    // Block
    if (Match(TokenType::LeftBrace)) {
        return ParseBlockStatement();
    }
    
    // Control flow
    if (Match(TokenType::KeywordIf)) return ParseIfStatement();
    if (Match(TokenType::KeywordWhile)) return ParseWhileStatement();
    if (Match(TokenType::KeywordFor)) return ParseForStatement();
    if (Match(TokenType::KeywordReturn)) return ParseReturnStatement();
    if (Match(TokenType::KeywordBreak)) return ParseBreakStatement();
    if (Match(TokenType::KeywordContinue)) return ParseContinueStatement();
    
    // Expression statement
    return ParseExpressionStatement();
}

std::unique_ptr<Statement> Parser::ParseBlockStatement() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    std::vector<std::unique_ptr<Statement>> statements;
    
    while (!Check(TokenType::RightBrace) && !IsAtEnd()) {
        statements.push_back(ParseStatement());
    }
    
    Consume(TokenType::RightBrace, "Expected '}' after block");
    
    return std::make_unique<BlockStmt>(std::move(statements), line, col);
}

std::unique_ptr<Statement> Parser::ParseVariableStatement() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    std::string kind;
    if (Previous().type == TokenType::KeywordVar) kind = "var";
    else if (Previous().type == TokenType::KeywordLet) kind = "let";
    else if (Previous().type == TokenType::KeywordConst) kind = "const";
    
    std::vector<VariableDeclarator> declarators;
    
    do {
        Token name = Consume(TokenType::Identifier, "Expected variable name");
        
        std::unique_ptr<Expression> init = nullptr;
        if (Match(TokenType::Assign)) {
            init = ParseExpression();
        }
        
        VariableDeclarator declarator;
        declarator.id = std::make_unique<IdentifierExpr>(
            std::string(name.text), name.line, name.column
        );
        if (init) {
            declarator.init = std::move(init);
        }
        
        declarators.push_back(std::move(declarator));
    } while (Match(TokenType::Comma));
    
    Consume(TokenType::Semicolon, "Expected ';' after variable declaration");
    
    // Create a proper VariableDecl statement
    auto decl = std::make_unique<VariableDecl>(kind, std::move(declarators), line, col);
    // VariableDecl inherits from Declaration which inherits from Statement
    // Use static_cast to convert unique_ptr<VariableDecl> to unique_ptr<Statement>
    return std::unique_ptr<Statement>(static_cast<Statement*>(decl.release()));
}

std::unique_ptr<Statement> Parser::ParseExpressionStatement() {
    uint32_t line = Current().line;
    uint32_t col = Current().column;
    
    auto expr = ParseExpression();
    
    // Optional semicolon (ASI)
    if (!Match(TokenType::Semicolon)) {
        // Check if next token starts a new statement
        if (!IsAtEnd() && !Check(TokenType::RightBrace)) {
            // Automatic semicolon insertion
        }
    }
    
    return std::make_unique<ExpressionStmt>(std::move(expr), line, col);
}

std::unique_ptr<Statement> Parser::ParseIfStatement() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    Consume(TokenType::LeftParen, "Expected '(' after 'if'");
    auto condition = ParseExpression();
    Consume(TokenType::RightParen, "Expected ')' after condition");
    
    auto consequent = ParseStatement();
    
    std::optional<std::unique_ptr<Statement>> alternate = std::nullopt;
    if (Match(TokenType::KeywordElse)) {
        alternate = ParseStatement();
    }
    
    return std::make_unique<IfStmt>(
        std::move(condition), std::move(consequent), std::move(alternate), line, col
    );
}

std::unique_ptr<Statement> Parser::ParseWhileStatement() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    EnterLoop();
    
    Consume(TokenType::LeftParen, "Expected '(' after 'while'");
    auto condition = ParseExpression();
    Consume(TokenType::RightParen, "Expected ')' after condition");
    
    auto body = ParseStatement();
    
    ExitLoop();
    
    return std::make_unique<WhileStmt>(
        std::move(condition), std::move(body), line, col
    );
}

std::unique_ptr<Statement> Parser::ParseForStatement() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    EnterLoop();
    
    Consume(TokenType::LeftParen, "Expected '(' after 'for'");
    
    std::optional<std::unique_ptr<Declaration>> init = std::nullopt;
    std::optional<std::unique_ptr<Expression>> condition = std::nullopt;
    std::optional<std::unique_ptr<Expression>> update = std::nullopt;
    
    // Initialization
    if (Match(TokenType::Semicolon)) {
        // No initialization
    } else if (Check(TokenType::KeywordVar) || Check(TokenType::KeywordLet) || 
               Check(TokenType::KeywordConst)) {
        Advance();
        // init = ParseVariableDeclaration(); // TODO
        Consume(TokenType::Semicolon, "Expected ';' after for-init");
    } else {
        auto expr = ParseExpression();
        Consume(TokenType::Semicolon, "Expected ';' after for-init");
    }
    
    // Condition
    if (!Check(TokenType::Semicolon)) {
        condition = ParseExpression();
    }
    Consume(TokenType::Semicolon, "Expected ';' after for-condition");
    
    // Update
    if (!Check(TokenType::RightParen)) {
        update = ParseExpression();
    }
    Consume(TokenType::RightParen, "Expected ')' after for-clause");
    
    auto body = ParseStatement();
    
    ExitLoop();
    
    return std::make_unique<ForStmt>(
        std::move(init), std::move(condition), std::move(update), std::move(body), line, col
    );
}

std::unique_ptr<Statement> Parser::ParseReturnStatement() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    if (!context_.in_function) {
        throw std::runtime_error("Return statement outside of function");
    }
    
    std::optional<std::unique_ptr<Expression>> argument = std::nullopt;
    if (!Check(TokenType::Semicolon)) {
        argument = ParseExpression();
    }
    
    Consume(TokenType::Semicolon, "Expected ';' after return");
    
    return std::make_unique<ReturnStmt>(std::move(argument), line, col);
}

std::unique_ptr<Statement> Parser::ParseBreakStatement() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    if (!context_.in_loop && !context_.in_switch) {
        throw std::runtime_error("Break statement outside of loop or switch");
    }
    
    Consume(TokenType::Semicolon, "Expected ';' after break");
    
    return std::make_unique<BreakStmt>(line, col);
}

std::unique_ptr<Statement> Parser::ParseContinueStatement() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    if (!context_.in_loop) {
        throw std::runtime_error("Continue statement outside of loop");
    }
    
    Consume(TokenType::Semicolon, "Expected ';' after continue");
    
    return std::make_unique<ContinueStmt>(line, col);
}

std::unique_ptr<Declaration> Parser::ParseFunctionDeclaration() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    Token name = Consume(TokenType::Identifier, "Expected function name");
    
    Consume(TokenType::LeftParen, "Expected '(' after function name");
    std::vector<std::string> params;
    
    if (!Check(TokenType::RightParen)) {
        do {
            Token param = Consume(TokenType::Identifier, "Expected parameter name");
            params.push_back(std::string(param.text));
        } while (Match(TokenType::Comma));
    }
    
    Consume(TokenType::RightParen, "Expected ')' after parameters");
    
    EnterFunction();
    auto body = ParseBlockStatement();
    ExitFunction();
    
    return std::make_unique<FunctionDecl>(
        std::string(name.text), std::move(params), std::move(body), line, col
    );
}

// Expressions
std::unique_ptr<Expression> Parser::ParseExpression() {
    return ParseAssignmentExpression();
}

std::unique_ptr<Expression> Parser::ParseAssignmentExpression() {
    auto left = ParseConditionalExpression();
    
    if (Match(TokenType::Assign) || Match(TokenType::PlusAssign) || 
        Match(TokenType::MinusAssign) || Match(TokenType::MultiplyAssign) ||
        Match(TokenType::DivideAssign) || Match(TokenType::ModuloAssign)) {
        
        Token op = Previous();
        auto right = ParseAssignmentExpression();
        
        return std::make_unique<AssignmentExpr>(
            std::move(left), std::move(right), std::string(op.text), op.line, op.column
        );
    }
    
    return left;
}

std::unique_ptr<Expression> Parser::ParseConditionalExpression() {
    auto condition = ParseBinaryExpression();
    
    if (Match(TokenType::QuestionMark)) {
        auto consequent = ParseExpression();
        Consume(TokenType::Colon, "Expected ':' in conditional");
        auto alternate = ParseConditionalExpression();
        
        return std::make_unique<ConditionalExpr>(
            std::move(condition), std::move(consequent), std::move(alternate),
            condition->line, condition->column
        );
    }
    
    return condition;
}

std::unique_ptr<Expression> Parser::ParseBinaryExpression() {
    return ParseBinaryExpression(ParseUnaryExpression(), Precedence::Assignment);
}

std::unique_ptr<Expression> Parser::ParseBinaryExpression(
    std::unique_ptr<Expression> left, Precedence minPrec) {
    
    while (true) {
        TokenType opType = Current().type;
        Precedence prec = GetTokenPrecedence(opType);
        
        if (prec < minPrec) break;
        
        Token op = Advance();
        auto right = ParseUnaryExpression();
        
        TokenType nextOp = Current().type;
        Precedence nextPrec = GetTokenPrecedence(nextOp);
        
        if (prec < nextPrec) {
            right = ParseBinaryExpression(std::move(right), static_cast<Precedence>(
                static_cast<int>(prec) + 1));
        }
        
        left = std::make_unique<BinaryExpr>(
            std::move(left), std::move(right), std::string(op.text), op.line, op.column
        );
    }
    
    return left;
}

std::unique_ptr<Expression> Parser::ParseUnaryExpression() {
    if (Match(TokenType::Minus) || Match(TokenType::Plus) || 
        Match(TokenType::LogicalNot) || Match(TokenType::BitwiseNot) ||
        Match(TokenType::KeywordTypeof) || Match(TokenType::KeywordDelete) ||
        Match(TokenType::KeywordVoid)) {
        
        Token op = Previous();
        auto argument = ParseUnaryExpression();
        
        return std::make_unique<UnaryExpr>(
            std::string(op.text), std::move(argument), true, op.line, op.column
        );
    }
    
    return ParsePostfixExpression();
}

std::unique_ptr<Expression> Parser::ParsePostfixExpression() {
    auto expr = ParseLeftHandSideExpression();
    
    if (!Check(TokenType::Semicolon) && (Check(TokenType::Increment) || Check(TokenType::Decrement))) {
        // Postfix ++ or -- (no line terminator before)
        Token op = Advance();
        return std::make_unique<UpdateExpr>(
            std::string(op.text), std::move(expr), false, op.line, op.column
        );
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::ParseLeftHandSideExpression() {
    auto expr = ParsePrimaryExpression();
    
    while (true) {
        if (Match(TokenType::LeftParen)) {
            // Function call
            expr = ParseCallExpression(std::move(expr));
        } else if (Match(TokenType::LeftBracket)) {
            // Computed member access
            auto property = ParseExpression();
            Consume(TokenType::RightBracket, "Expected ']'");
            expr = std::make_unique<MemberExpr>(
                std::move(expr), std::move(property), true, expr->line, expr->column
            );
        } else if (Match(TokenType::Dot)) {
            // Static member access
            Token name = Consume(TokenType::Identifier, "Expected property name");
            auto property = std::make_unique<IdentifierExpr>(
                std::string(name.text), name.line, name.column
            );
            expr = std::make_unique<MemberExpr>(
                std::move(expr), std::move(property), false, expr->line, expr->column
            );
        } else {
            break;
        }
    }
    
    return expr;
}

std::unique_ptr<Expression> Parser::ParseCallExpression(std::unique_ptr<Expression> callee) {
    uint32_t line = callee->line;
    uint32_t col = callee->column;
    
    std::vector<std::unique_ptr<Expression>> args;
    
    if (!Check(TokenType::RightParen)) {
        do {
            args.push_back(ParseExpression());
        } while (Match(TokenType::Comma));
    }
    
    Consume(TokenType::RightParen, "Expected ')' after arguments");
    
    return std::make_unique<CallExpr>(std::move(callee), std::move(args), line, col);
}

std::unique_ptr<Expression> Parser::ParsePrimaryExpression() {
    if (Match(TokenType::KeywordThis)) {
        return std::make_unique<ThisExpr>(Previous().line, Previous().column);
    }
    
    if (Match(TokenType::KeywordFunction)) {
        return ParseFunctionExpression();
    }
    
    if (Match(TokenType::LeftBracket)) {
        return ParseArrayLiteral();
    }
    
    if (Match(TokenType::LeftBrace)) {
        return ParseObjectLiteral();
    }
    
    if (Match(TokenType::NumberLiteral)) {
        Token num = Previous();
        return std::make_unique<NumberLiteralExpr>(num.numberValue, num.line, num.column);
    }
    
    if (Match(TokenType::StringLiteral)) {
        Token str = Previous();
        return std::make_unique<StringLiteralExpr>(
            str.stringValue, str.line, str.column
        );
    }
    
    if (Match(TokenType::BooleanLiteral)) {
        Token boolean = Previous();
        return std::make_unique<BooleanLiteralExpr>(
            boolean.text == "true", boolean.line, boolean.column
        );
    }
    
    if (Match(TokenType::NullLiteral)) {
        return std::make_unique<NullLiteralExpr>(Previous().line, Previous().column);
    }
    
    if (Match(TokenType::UndefinedLiteral)) {
        return std::make_unique<UndefinedLiteralExpr>(Previous().line, Previous().column);
    }
    
    if (Match(TokenType::Identifier)) {
        Token ident = Previous();
        return std::make_unique<IdentifierExpr>(
            std::string(ident.text), ident.line, ident.column
        );
    }
    
    if (Match(TokenType::LeftParen)) {
        auto expr = ParseExpression();
        Consume(TokenType::RightParen, "Expected ')' after expression");
        return expr;
    }
    
    throw std::runtime_error("Unexpected token");
}

std::unique_ptr<Expression> Parser::ParseArrayLiteral() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    std::vector<std::unique_ptr<Expression>> elements;
    
    if (!Check(TokenType::RightBracket)) {
        do {
            if (Check(TokenType::Comma)) {
                // Elision (hole in array)
                elements.push_back(nullptr);
            } else {
                elements.push_back(ParseExpression());
            }
        } while (Match(TokenType::Comma));
    }
    
    Consume(TokenType::RightBracket, "Expected ']' after array elements");
    
    return std::make_unique<ArrayExpr>(std::move(elements), line, col);
}

std::unique_ptr<Expression> Parser::ParseObjectLiteral() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    std::vector<ObjectProperty> properties;
    
    if (!Check(TokenType::RightBrace)) {
        do {
            // Property key
            std::variant<std::string, std::unique_ptr<Expression>> key;
            bool computed = false;
            
            if (Check(TokenType::Identifier) || Check(TokenType::StringLiteral)) {
                Token keyToken = Advance();
                key = std::string(keyToken.text);
            } else if (Match(TokenType::LeftBracket)) {
                key = ParseExpression();
                computed = true;
                Consume(TokenType::RightBracket, "Expected ']'");
            } else {
                throw std::runtime_error("Expected property key");
            }
            
            Consume(TokenType::Colon, "Expected ':' after property key");
            auto value = ParseExpression();
            
            ObjectProperty prop;
            prop.key = std::move(key);
            prop.value = std::move(value);
            prop.computed = computed;
            
            properties.push_back(std::move(prop));
        } while (Match(TokenType::Comma));
    }
    
    Consume(TokenType::RightBrace, "Expected '}' after object properties");
    
    return std::make_unique<ObjectExpr>(std::move(properties), line, col);
}

std::unique_ptr<Expression> Parser::ParseFunctionExpression() {
    uint32_t line = Previous().line;
    uint32_t col = Previous().column;
    
    std::optional<std::string> name = std::nullopt;
    if (Check(TokenType::Identifier)) {
        name = std::string(Advance().text);
    }
    
    Consume(TokenType::LeftParen, "Expected '('");
    std::vector<std::string> params;
    
    if (!Check(TokenType::RightParen)) {
        do {
            Token param = Consume(TokenType::Identifier, "Expected parameter name");
            params.push_back(std::string(param.text));
        } while (Match(TokenType::Comma));
    }
    
    Consume(TokenType::RightParen, "Expected ')'");
    
    EnterFunction();
    auto body = ParseBlockStatement();
    ExitFunction();
    
    return std::make_unique<FunctionExpr>(
        std::move(name), std::move(params), std::move(body), line, col
    );
}

// Context management
void Parser::EnterFunction() {
    context_.in_function = true;
    context_.function_depth++;
}

void Parser::ExitFunction() {
    context_.function_depth--;
    context_.in_function = context_.function_depth > 0;
}

void Parser::EnterLoop() {
    context_.in_loop = true;
    context_.loop_depth++;
}

void Parser::ExitLoop() {
    context_.loop_depth--;
    context_.in_loop = context_.loop_depth > 0;
}

void Parser::EnterSwitch() {
    context_.in_switch = true;
}

void Parser::ExitSwitch() {
    context_.in_switch = false;
}

// Precedence
Parser::Precedence Parser::GetTokenPrecedence(TokenType type) {
    switch (type) {
        case TokenType::Assign:
        case TokenType::PlusAssign:
        case TokenType::MinusAssign:
        case TokenType::MultiplyAssign:
        case TokenType::DivideAssign:
        case TokenType::ModuloAssign:
            return Precedence::Assignment;
        case TokenType::QuestionMark:
            return Precedence::Conditional;
        case TokenType::LogicalOr:
            return Precedence::LogicalOr;
        case TokenType::LogicalAnd:
            return Precedence::LogicalAnd;
        case TokenType::BitwiseOr:
            return Precedence::BitwiseOr;
        case TokenType::BitwiseXor:
            return Precedence::BitwiseXor;
        case TokenType::BitwiseAnd:
            return Precedence::BitwiseAnd;
        case TokenType::Equal:
        case TokenType::NotEqual:
        case TokenType::StrictEqual:
        case TokenType::StrictNotEqual:
            return Precedence::Equality;
        case TokenType::LessThan:
        case TokenType::GreaterThan:
        case TokenType::LessThanOrEqual:
        case TokenType::GreaterThanOrEqual:
        case TokenType::KeywordInstanceof:
        case TokenType::KeywordIn:
            return Precedence::Relational;
        case TokenType::LeftShift:
        case TokenType::RightShift:
        case TokenType::UnsignedRightShift:
            return Precedence::BitwiseShift;
        case TokenType::Plus:
        case TokenType::Minus:
            return Precedence::Additive;
        case TokenType::Multiply:
        case TokenType::Divide:
        case TokenType::Modulo:
            return Precedence::Multiplicative;
        default:
            return Precedence::None;
    }
}

} // namespace Script
} // namespace RawrXD
