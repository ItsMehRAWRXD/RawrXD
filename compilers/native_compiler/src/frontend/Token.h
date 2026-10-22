// C++20 token model for the RawrXD native compiler.

#ifndef RAWR_COMPILER_TOKEN_H
#define RAWR_COMPILER_TOKEN_H

#include "common/SourceManager.h"
#include "rawrstd/string.h"
#include "common/Types.h"

namespace rawr {

enum class TokenKind : uint16 {
    // --- end markers ---
    EndOfFile,
    Unknown,

    // --- literals ---
    Identifier,
    Keyword,            // `text` holds the keyword spelling
    IntegerLiteral,
    FloatingLiteral,
    CharacterLiteral,
    StringLiteral,
    UserDefinedLiteral, // text = "12_km", suffix = "_km"
    WideStringLiteral,
    Char8StringLiteral,
    Char16StringLiteral,
    Char32StringLiteral,
    WideCharacterLiteral,
    Char8CharacterLiteral,
    Char16CharacterLiteral,
    Char32CharacterLiteral,

    // --- punctuation ---
    LParen, RParen,
    LBracket, RBracket,
    LBrace, RBrace,
    Period, Ellipsis,
    Arrow, ArrowStar,
    Scope,                              // ::
    Plus, Minus, Star, Slash, Percent,
    PlusPlus, MinusMinus,
    Less, Greater, LessEqual, GreaterEqual, Spaceship,
    EqualEqual, NotEqual,
    Equal, PlusEqual, MinusEqual, StarEqual, SlashEqual, PercentEqual,
    AmpEqual, PipeEqual, CaretEqual, ShiftLeftEqual, ShiftRightEqual,
    Amp, Pipe, Caret, Tilde,
    AmpAmp, PipePipe,
    Shl, Shr,
    Exclaim, Question, Colon, Semicolon, Comma,
    Assign,
    Hash, HashHash,

    // --- keywords (stored in `text`) ---
    // The lexer classifies keywords separately so the parser can switch on a
    // compact enum without string comparisons. See keyword_id() below.

    KwAlignas, KwAlignof, KwAnd, KwAndEq, KwAsm, KwAuto,
    KwBool, KwBreak, KwCase, KwCatch, KwChar, KwChar8_t, KwChar16_t, KwChar32_t,
    KwClass, KwConcept, KwConst, KwConsteval, KwConstexpr, KwConstinit, KwConst_cast,
    KwContinue, KwCo_await, KwCo_return, KwCo_yield,
    KwDecltype, KwDefault, KwDelete, KwDo, KwDouble, KwDynamic_cast,
    KwElse, KwEnum, KwExplicit, KwExport, KwExtern, KwFalse,
    KwFloat, KwFor, KwFriend, KwGoto, KwIf, KwInline, KwInt, KwLong,
    KwMutable, KwNamespace, KwNew, KwNoexcept, KwNullptr,
    KwOperator, KwPrivate, KwProtected, KwPublic, KwRegister,
    KwReinterpret_cast, KwRequires, KwReturn, KwShort, KwSigned,
    KwSizeof, KwStatic, KwStatic_assert, KwStatic_cast, KwStruct,
    KwSwitch, KwTemplate, KwThis, KwThread_local, KwThrow, KwTrue, KwTry,
    KwTypedef, KwTypeid, KwTypename, KwUnion, KwUnsigned, KwUsing, KwVirtual,
    KwVoid, KwVolatile, KwWchar_t, KwWhile,

    // --- preprocessing (only produced by the preprocessor layer) ---
    DirectiveHash,   // '#' at the start of a logical line
};

// Returns true when the token is a punctuator.
bool is_punctuator(TokenKind k);

// Returns true when the token can begin an expression.
bool is_primary_expression_start(TokenKind k);

// Maps a keyword spelling to its TokenKind, or TokenKind::Identifier.
TokenKind keyword_id(const char* text, size_type length);

// Returns the canonical spelling of a keyword token.
const char* keyword_spelling(TokenKind k);

struct Token {
    TokenKind kind = TokenKind::Unknown;
    SourceLoc loc;              // start of the token
    uint32 length = 0;          // byte length of the token text

    // For literals: the decoded value / text.
    rawrstd::String text;       // identifier, keyword, or literal spelling
    rawrstd::String suffix;     // user-defined literal suffix

    // Numeric literal details.
    bool is_unsigned = false;
    bool is_long = false;
    bool is_long_long = false;
    bool is_float = false;      // 'f' suffix on a floating literal
    bool is_long_double = false;

    // Character/string literal encoding.
    bool is_wide = false;
    bool is_utf8 = false;
    bool is_utf16 = false;
    bool is_utf32 = false;

    // Set when the token was produced by macro expansion.
    bool from_macro = false;

    const char* begin() const { return text.data(); }
    size_type size() const { return text.size(); }
    bool is(TokenKind k) const { return kind == k; }
    bool is_keyword(TokenKind k) const { return kind == k; }
    bool is_identifier(const char* s) const {
        return kind == TokenKind::Identifier && text == s;
    }
    bool is_eof() const { return kind == TokenKind::EndOfFile; }
};

} // namespace rawr

#endif // RAWR_COMPILER_TOKEN_H
