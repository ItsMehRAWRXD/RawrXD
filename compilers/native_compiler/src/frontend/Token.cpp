#include "frontend/Token.h"

#include "rawrstd/sys.h"

namespace rawr {

using rawrstd::String;

// ---------------------------------------------------------------------------
// Keyword table
// ---------------------------------------------------------------------------

struct KeywordEntry {
    const char* spelling;
    TokenKind kind;
};

// Sorted by spelling so lookup can binary-search.
static const KeywordEntry kKeywords[] = {
    { "alignas",         TokenKind::KwAlignas },
    { "alignof",         TokenKind::KwAlignof },
    { "and",             TokenKind::KwAnd },
    { "and_eq",          TokenKind::KwAndEq },
    { "asm",             TokenKind::KwAsm },
    { "auto",            TokenKind::KwAuto },
    { "bool",            TokenKind::KwBool },
    { "break",           TokenKind::KwBreak },
    { "case",            TokenKind::KwCase },
    { "catch",           TokenKind::KwCatch },
    { "char",            TokenKind::KwChar },
    { "char16_t",        TokenKind::KwChar16_t },
    { "char32_t",        TokenKind::KwChar32_t },
    { "char8_t",         TokenKind::KwChar8_t },
    { "class",           TokenKind::KwClass },
    { "co_await",        TokenKind::KwCo_await },
    { "co_return",       TokenKind::KwCo_return },
    { "co_yield",        TokenKind::KwCo_yield },
    { "concept",         TokenKind::KwConcept },
    { "const",           TokenKind::KwConst },
    { "const_cast",      TokenKind::KwConst_cast },
    { "consteval",       TokenKind::KwConsteval },
    { "constexpr",       TokenKind::KwConstexpr },
    { "constinit",       TokenKind::KwConstinit },
    { "continue",        TokenKind::KwContinue },
    { "decltype",        TokenKind::KwDecltype },
    { "default",         TokenKind::KwDefault },
    { "delete",          TokenKind::KwDelete },
    { "do",              TokenKind::KwDo },
    { "double",          TokenKind::KwDouble },
    { "dynamic_cast",    TokenKind::KwDynamic_cast },
    { "else",            TokenKind::KwElse },
    { "enum",            TokenKind::KwEnum },
    { "explicit",        TokenKind::KwExplicit },
    { "export",          TokenKind::KwExport },
    { "extern",          TokenKind::KwExtern },
    { "false",           TokenKind::KwFalse },
    { "float",           TokenKind::KwFloat },
    { "for",             TokenKind::KwFor },
    { "friend",          TokenKind::KwFriend },
    { "goto",            TokenKind::KwGoto },
    { "if",              TokenKind::KwIf },
    { "inline",          TokenKind::KwInline },
    { "int",             TokenKind::KwInt },
    { "long",            TokenKind::KwLong },
    { "mutable",         TokenKind::KwMutable },
    { "namespace",       TokenKind::KwNamespace },
    { "new",             TokenKind::KwNew },
    { "noexcept",        TokenKind::KwNoexcept },
    { "nullptr",         TokenKind::KwNullptr },
    { "operator",        TokenKind::KwOperator },
    { "private",         TokenKind::KwPrivate },
    { "protected",       TokenKind::KwProtected },
    { "public",          TokenKind::KwPublic },
    { "register",        TokenKind::KwRegister },
    { "reinterpret_cast",TokenKind::KwReinterpret_cast },
    { "requires",        TokenKind::KwRequires },
    { "return",          TokenKind::KwReturn },
    { "short",           TokenKind::KwShort },
    { "signed",          TokenKind::KwSigned },
    { "sizeof",          TokenKind::KwSizeof },
    { "static",          TokenKind::KwStatic },
    { "static_assert",   TokenKind::KwStatic_assert },
    { "static_cast",     TokenKind::KwStatic_cast },
    { "struct",          TokenKind::KwStruct },
    { "switch",          TokenKind::KwSwitch },
    { "template",        TokenKind::KwTemplate },
    { "this",            TokenKind::KwThis },
    { "thread_local",    TokenKind::KwThread_local },
    { "throw",           TokenKind::KwThrow },
    { "true",            TokenKind::KwTrue },
    { "try",             TokenKind::KwTry },
    { "typedef",         TokenKind::KwTypedef },
    { "typeid",          TokenKind::KwTypeid },
    { "typename",        TokenKind::KwTypename },
    { "union",           TokenKind::KwUnion },
    { "unsigned",        TokenKind::KwUnsigned },
    { "using",           TokenKind::KwUsing },
    { "virtual",         TokenKind::KwVirtual },
    { "void",            TokenKind::KwVoid },
    { "volatile",        TokenKind::KwVolatile },
    { "wchar_t",         TokenKind::KwChar32_t },   // MSVC: wchar_t is UTF-16
    { "while",           TokenKind::KwWhile },
};

static constexpr size_type kKeywordCount = sizeof(kKeywords) / sizeof(kKeywords[0]);

TokenKind keyword_id(const char* text, size_type length) {
    // Binary search over the sorted table.
    size_type lo = 0, hi = kKeywordCount;
    while (lo < hi) {
        size_type mid = lo + (hi - lo) / 2;
        const char* s = kKeywords[mid].spelling;
        size_type slen = rawrstd::strlen_raw(s);
        size_type n = length < slen ? length : slen;
        int c = rawrstd::memcmp_raw(text, s, n);
        if (c == 0) {
            if (length == slen) return kKeywords[mid].kind;
            c = length < slen ? -1 : 1;
        }
        if (c < 0) hi = mid;
        else lo = mid + 1;
    }
    return TokenKind::Identifier;
}

const char* keyword_spelling(TokenKind k) {
    for (size_type i = 0; i < kKeywordCount; ++i) {
        if (kKeywords[i].kind == k) return kKeywords[i].spelling;
    }
    return "";
}

bool is_keyword(TokenKind k) {
    return k >= TokenKind::KwAlignas && k <= TokenKind::KwWhile;
}

bool is_punctuator(TokenKind k) {
    return k >= TokenKind::LParen && k <= TokenKind::HashHash;
}

bool is_primary_expression_start(TokenKind k) {
    switch (k) {
    case TokenKind::Identifier:
    case TokenKind::IntegerLiteral:
    case TokenKind::FloatingLiteral:
    case TokenKind::CharacterLiteral:
    case TokenKind::StringLiteral:
    case TokenKind::WideStringLiteral:
    case TokenKind::Char8StringLiteral:
    case TokenKind::Char16StringLiteral:
    case TokenKind::Char32StringLiteral:
    case TokenKind::WideCharacterLiteral:
    case TokenKind::Char8CharacterLiteral:
    case TokenKind::Char16CharacterLiteral:
    case TokenKind::Char32CharacterLiteral:
    case TokenKind::UserDefinedLiteral:
    case TokenKind::KwTrue:
    case TokenKind::KwFalse:
    case TokenKind::KwNullptr:
    case TokenKind::KwThis:
    case TokenKind::LParen:
    case TokenKind::LBracket:
    case TokenKind::KwDecltype:
    case TokenKind::KwNoexcept:
    case TokenKind::KwStatic_cast:
    case TokenKind::KwConst_cast:
    case TokenKind::KwReinterpret_cast:
    case TokenKind::KwDynamic_cast:
        return true;
    default:
        return false;
    }
}

} // namespace rawr
