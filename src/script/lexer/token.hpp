// RawrXD-Script Lexer - Token Definitions
// Phase 1: Bytecode Spec + C++ Parser

#pragma once

#include <cstdint>
#include <string>
#include <string_view>

namespace RawrXD {
namespace Script {

// Token types for ES5 subset
enum class TokenType : uint8_t {
    // End of file
    EndOfFile = 0,
    
    // Literals
    NumberLiteral,      // 123, 3.14
    StringLiteral,      // "hello", 'world'
    BooleanLiteral,     // true, false
    NullLiteral,        // null
    UndefinedLiteral,   // undefined
    
    // Identifiers
    Identifier,
    
    // Keywords
    KeywordFunction,    // function
    KeywordVar,         // var
    KeywordLet,         // let
    KeywordConst,       // const
    KeywordIf,          // if
    KeywordElse,        // else
    KeywordWhile,       // while
    KeywordFor,         // for
    KeywordReturn,      // return
    KeywordBreak,       // break
    KeywordContinue,    // continue
    KeywordNew,         // new
    KeywordThis,        // this
    KeywordTypeof,      // typeof
    KeywordInstanceof,  // instanceof
    KeywordIn,          // in
    KeywordDelete,      // delete
    KeywordVoid,        // void
    KeywordSwitch,      // switch
    KeywordCase,        // case
    KeywordDefault,     // default
    KeywordTry,         // try
    KeywordCatch,       // catch
    KeywordFinally,     // finally
    KeywordThrow,       // throw
    
    // Operators
    Plus,               // +
    Minus,              // -
    Multiply,           // *
    Divide,             // /
    Modulo,             // %
    Increment,          // ++
    Decrement,          // --
    
    Assign,             // =
    PlusAssign,         // +=
    MinusAssign,        // -=
    MultiplyAssign,     // *=
    DivideAssign,       // /=
    ModuloAssign,       // %=
    
    Equal,              // ==
    NotEqual,           // !=
    StrictEqual,        // ===
    StrictNotEqual,     // !==
    LessThan,           // <
    GreaterThan,        // >
    LessThanOrEqual,    // <=
    GreaterThanOrEqual, // >=
    
    BitwiseAnd,         // &
    BitwiseOr,          // |
    BitwiseXor,         // ^
    BitwiseNot,         // ~
    LeftShift,          // <<
    RightShift,         // >>
    UnsignedRightShift, // >>>
    
    // Compound assignment operators
    LeftShiftAssign,        // <<=
    RightShiftAssign,       // >>=
    UnsignedRightShiftAssign, // >>>=
    BitwiseAndAssign,       // &=
    BitwiseOrAssign,        // |=
    BitwiseXorAssign,       // ^=
    
    LogicalAnd,         // &&
    LogicalOr,          // ||
    LogicalNot,         // !
    
    // Punctuation
    Semicolon,          // ;
    Comma,              // ,
    Dot,                // .
    Colon,              // :
    QuestionMark,       // ?
    
    // Brackets
    LeftParen,          // (
    RightParen,         // )
    LeftBrace,          // {
    RightBrace,         // }
    LeftBracket,        // [
    RightBracket,       // ]
    
    // Arrow (for future async functions)
    Arrow,              // =>
};

// Token structure
struct Token {
    TokenType type;
    std::string_view text;
    uint32_t line;
    uint32_t column;
    
    // For numeric literals
    double numberValue;
    
    // For string literals (owned storage)
    std::string stringValue;
    
    Token() : type(TokenType::EndOfFile), line(0), column(0), numberValue(0.0) {}
    
    Token(TokenType t, std::string_view txt, uint32_t ln, uint32_t col)
        : type(t), text(txt), line(ln), column(col), numberValue(0.0) {}
    
    bool IsKeyword() const;
    bool IsOperator() const;
    bool IsLiteral() const;
    
    std::string ToString() const;
};

// Get token type name for debugging
const char* TokenTypeToString(TokenType type);

} // namespace Script
} // namespace RawrXD
