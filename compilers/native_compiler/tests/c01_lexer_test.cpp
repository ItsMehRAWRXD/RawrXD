// C01 - Lexer certification.
//
// Tokenizes a corpus of C++20 constructs and verifies the resulting token
// stream: kinds, spellings, literal decoding, and source locations.

#include "common/Diagnostics.h"
#include "common/SourceManager.h"
#include "frontend/Lexer.h"

#include "rawrstd/sys.h"

using namespace rawr;
using rawrstd::String;

static int g_pass = 0;
static int g_fail = 0;

static void ok(const char* what) {
    rawrstd::write_stdout("  [PASS] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("\n", 1);
    ++g_pass;
}

static void bad(const char* what, const String& detail) {
    rawrstd::write_stdout("  [FAIL] ", 9);
    rawrstd::write_stdout(what, rawrstd::strlen_raw(what));
    rawrstd::write_stdout("  -- ", 4);
    rawrstd::write_stdout(detail.data(), detail.size());
    rawrstd::write_stdout("\n", 1);
    ++g_fail;
}

static void check(bool cond, const char* what) {
    if (cond) ok(what);
    else bad(what, String("condition false"));
}

static void check_eq(const String& actual, const char* expected, const char* what) {
    if (actual == expected) ok(what);
    else bad(what, String("expected '") + expected + "', got '" + actual + "'");
}

// Lexes `source` and returns the token stream. Errors are reported through
// the diagnostic engine.
struct LexResult {
    rawrstd::Vector<Token> tokens;
    DiagnosticEngine* diags = nullptr;
};

static LexResult lex_text(SourceManager& sm, DiagnosticEngine& diags, const char* source) {
    LexResult r;
    r.diags = &diags;
    uint32 id = sm.add_buffer("test.cpp", source, rawrstd::strlen_raw(source));
    Lexer lexer(&sm, &diags, id);
    for (;;) {
        Token t;
        if (!lexer.next(&t)) break;
        r.tokens.push_back(t);
    }
    return r;
}

static String kind_name(TokenKind k) {
    switch (k) {
    case TokenKind::Identifier: return "id";
    case TokenKind::IntegerLiteral: return "int";
    case TokenKind::FloatingLiteral: return "float";
    case TokenKind::CharacterLiteral: return "char";
    case TokenKind::StringLiteral: return "str";
    case TokenKind::WideStringLiteral: return "wstr";
    case TokenKind::Char8StringLiteral: return "u8str";
    case TokenKind::Char16StringLiteral: return "u16str";
    case TokenKind::Char32StringLiteral: return "u32str";
    case TokenKind::UserDefinedLiteral: return "udl";
    case TokenKind::LParen: return "(";
    case TokenKind::RParen: return ")";
    case TokenKind::LBracket: return "[";
    case TokenKind::RBracket: return "]";
    case TokenKind::LBrace: return "{";
    case TokenKind::RBrace: return "}";
    case TokenKind::Scope: return "::";
    case TokenKind::Arrow: return "->";
    case TokenKind::ArrowStar: return "->*";
    case TokenKind::Spaceship: return "<=>";
    case TokenKind::Ellipsis: return "...";
    case TokenKind::PlusPlus: return "++";
    case TokenKind::MinusMinus: return "--";
    case TokenKind::Shl: return "<<";
    case TokenKind::Shr: return ">>";
    case TokenKind::AmpAmp: return "&&";
    case TokenKind::PipePipe: return "||";
    case TokenKind::LessEqual: return "<=";
    case TokenKind::GreaterEqual: return ">=";
    case TokenKind::EqualEqual: return "==";
    case TokenKind::NotEqual: return "!=";
    case TokenKind::PlusEqual: return "+=";
    case TokenKind::MinusEqual: return "-=";
    case TokenKind::StarEqual: return "*=";
    case TokenKind::SlashEqual: return "/=";
    case TokenKind::PercentEqual: return "%=";
    case TokenKind::AmpEqual: return "&=";
    case TokenKind::PipeEqual: return "|=";
    case TokenKind::CaretEqual: return "^=";
    case TokenKind::ShiftLeftEqual: return "<<=";
    case TokenKind::ShiftRightEqual: return ">>=";
    case TokenKind::HashHash: return "##";
    case TokenKind::KwClass: return "class";
    case TokenKind::KwConstexpr: return "constexpr";
    case TokenKind::KwConsteval: return "consteval";
    case TokenKind::KwConstinit: return "constinit";
    case TokenKind::KwTemplate: return "template";
    case TokenKind::KwTypename: return "typename";
    case TokenKind::KwRequires: return "requires";
    case TokenKind::KwConcept: return "concept";
    case TokenKind::KwCo_await: return "co_await";
    case TokenKind::KwCo_return: return "co_return";
    case TokenKind::KwCo_yield: return "co_yield";
    case TokenKind::KwChar8_t: return "char8_t";
    case TokenKind::KwTrue: return "true";
    case TokenKind::KwFalse: return "false";
    case TokenKind::KwNullptr: return "nullptr";
    case TokenKind::KwOperator: return "operator";
    case TokenKind::EndOfFile: return "eof";
    default: {
        String s;
        s << "kind" << (uint32)k;
        return s;
    }
    }
}

int main() {
    rawrstd::write_stdout("C01 Lexer certification\n", 25);
    rawrstd::write_stdout("================================\n", 33);

    SourceManager sm;
    DiagnosticEngine diags(&sm);

    // -----------------------------------------------------------------
    // 1. Identifiers and keywords
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags, "int alpha _beta19 class constexpr");
        check(r.tokens.size() == 5, "token count");
        check(r.tokens[0].kind == TokenKind::KwInt, "keyword int");
        check(r.tokens[1].kind == TokenKind::Identifier, "identifier alpha");
        check_eq(r.tokens[2].text, "_beta19", "identifier _beta19");
        check(r.tokens[3].kind == TokenKind::KwClass, "keyword class");
        check(r.tokens[4].kind == TokenKind::KwConstexpr, "keyword constexpr");
    }

    // -----------------------------------------------------------------
    // 2. Integer and floating literals
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags,
            "0 42 0x1F 0b1010 0777 1'000'000 1u 2L 3ULL 1.5 1e10 1.5e-3 0x1p3 2.0f 3.0L");
        check(r.tokens.size() == 15, "numeric token count");

        check(r.tokens[0].kind == TokenKind::IntegerLiteral, "int 0");
        check(r.tokens[1].kind == TokenKind::IntegerLiteral, "int 42");
        check(r.tokens[2].kind == TokenKind::IntegerLiteral, "int 0x1F");
        check(r.tokens[3].kind == TokenKind::IntegerLiteral, "int 0b1010");
        check(r.tokens[4].kind == TokenKind::IntegerLiteral, "int 0777");

        // Digit separators: the C++14 rule allows them between digits, so
        // 1'000'000 lexes as one pp-number.
        check(r.tokens[5].kind == TokenKind::IntegerLiteral, "int with digit separators");

        check(r.tokens[6].kind == TokenKind::IntegerLiteral, "int 1u");
        check(r.tokens[6].is_unsigned, "int 1u unsigned flag");
        check(r.tokens[7].kind == TokenKind::IntegerLiteral, "int 2L");
        check(r.tokens[7].is_long, "int 2L long flag");
        check(r.tokens[8].kind == TokenKind::IntegerLiteral, "int 3ULL");
        check(r.tokens[8].is_unsigned, "int 3ULL unsigned flag");
        check(r.tokens[8].is_long_long, "int 3ULL long long flag");

        check(r.tokens[9].kind == TokenKind::FloatingLiteral, "float 1.5");
        check(r.tokens[10].kind == TokenKind::FloatingLiteral, "float 1e10");
        check(r.tokens[11].kind == TokenKind::FloatingLiteral, "float 1.5e-3");
        check(r.tokens[12].kind == TokenKind::FloatingLiteral, "float 0x1p3");
        check(r.tokens[13].kind == TokenKind::FloatingLiteral, "float 2.0f");
        check(r.tokens[13].is_float, "float 2.0f float flag");
        check(r.tokens[14].kind == TokenKind::FloatingLiteral, "float 3.0L");
        check(r.tokens[14].is_long_double, "float 3.0L long double flag");
    }

    // -----------------------------------------------------------------
    // 3. User-defined literals
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags, "42_km 1.5_deg \"text\"_s");
        check(r.tokens.size() == 3, "udl token count");
        check(r.tokens[0].kind == TokenKind::UserDefinedLiteral, "udl integer");
        check_eq(r.tokens[0].suffix, "_km", "udl integer suffix");
        check(r.tokens[1].kind == TokenKind::UserDefinedLiteral, "udl float");
        check_eq(r.tokens[1].suffix, "_deg", "udl float suffix");
        check(r.tokens[2].kind == TokenKind::UserDefinedLiteral, "udl string");
        check_eq(r.tokens[2].suffix, "_s", "udl string suffix");
    }

    // -----------------------------------------------------------------
    // 4. String and character literals
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags,
            "\"plain\" \"esc\\n\\t\\\\\" 'a' '\\n' L\"wide\" u8\"utf8\" u\"utf16\" U\"utf32\"");
        check(r.tokens.size() == 8, "literal token count");
        if (r.tokens.size() != 8) {
            String dbg;
            dbg << "actual=" << r.tokens.size() << " kinds:";
            for (size_type i = 0; i < r.tokens.size(); ++i) {
                dbg << " " << kind_name(r.tokens[i].kind);
            }
            bad("literal token count (detail)", dbg);
        }

        check(r.tokens[0].kind == TokenKind::StringLiteral, "plain string");
        check_eq(r.tokens[1].text, "esc\n\t\\", "escape decoding");
        check(r.tokens[2].kind == TokenKind::CharacterLiteral, "char literal");
        check_eq(r.tokens[3].text, "\n", "char escape decoding");
        check(r.tokens[4].kind == TokenKind::WideStringLiteral, "wide string");
        check(r.tokens[5].kind == TokenKind::Char8StringLiteral, "utf8 string");
        check(r.tokens[6].kind == TokenKind::Char16StringLiteral, "utf16 string");
        check(r.tokens[7].kind == TokenKind::Char32StringLiteral, "utf32 string");
    }

    // -----------------------------------------------------------------
    // 5. Raw string literals
    //
    // Per [lex.string.raw], a raw string is terminated by the FIRST
    // occurrence of the delimiter followed by a quote. So the third literal
    // below ends at the first )" and the remainder lexes as separate tokens.
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags, "R\"(raw \\\" content )\" R\"delim(body)delim\"");
        check(r.tokens.size() == 2, "raw string token count");
        check(r.tokens[0].kind == TokenKind::StringLiteral, "raw string kind");
        check_eq(r.tokens[0].text, "raw \\\" content ", "raw string content");
        check_eq(r.tokens[1].text, "body", "raw string with delimiter");

        // A raw string whose content contains )" ends at the first one.
        LexResult r2 = lex_text(sm, diags, "R\"(has )\" inside)\"");
        check(r2.tokens.size() >= 1, "raw string with embedded terminator");
        check_eq(r2.tokens[0].text, "has ", "raw string terminates at first terminator");
    }

    // -----------------------------------------------------------------
    // 6. Raw string with encoding prefix
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags, "u8R\"(utf8 raw)\" LR\"(wide raw)\"");
        check(r.tokens.size() == 2, "prefixed raw string count");
        check(r.tokens[0].kind == TokenKind::Char8StringLiteral, "u8 raw string kind");
        check_eq(r.tokens[0].text, "utf8 raw", "u8 raw string content");
        check(r.tokens[1].kind == TokenKind::WideStringLiteral, "L raw string kind");
    }

    // -----------------------------------------------------------------
    // 7. Punctuators, including the C++20 three-way comparison
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags,
            "a::b -> c ->* d <=> e ... f++ g-- h<< i>> j&& k|| l+= m<<= n>>=");
        // 14 name/punctuator pairs = 28 tokens.
        check(r.tokens.size() == 28, "punctuator token count");
        check(r.tokens[1].kind == TokenKind::Scope, "scope resolution");
        check(r.tokens[3].kind == TokenKind::Arrow, "arrow");
        check(r.tokens[5].kind == TokenKind::ArrowStar, "arrow star");
        check(r.tokens[7].kind == TokenKind::Spaceship, "spaceship");
        check(r.tokens[9].kind == TokenKind::Ellipsis, "ellipsis");
        check(r.tokens[11].kind == TokenKind::PlusPlus, "plus plus");
        check(r.tokens[13].kind == TokenKind::MinusMinus, "minus minus");
        check(r.tokens[15].kind == TokenKind::Shl, "shift left");
        check(r.tokens[17].kind == TokenKind::Shr, "shift right");
        check(r.tokens[19].kind == TokenKind::AmpAmp, "logical and");
        check(r.tokens[21].kind == TokenKind::PipePipe, "logical or");
        check(r.tokens[23].kind == TokenKind::PlusEqual, "plus assign");
        check(r.tokens[25].kind == TokenKind::ShiftLeftEqual, "shift left assign");
        check(r.tokens[27].kind == TokenKind::ShiftRightEqual, "shift right assign");
    }

    // -----------------------------------------------------------------
    // 8. C++20 keywords
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags,
            "concept requires consteval constinit co_await co_return co_yield char8_t");
        check(r.tokens.size() == 8, "c++20 keyword count");
        check(r.tokens[0].kind == TokenKind::KwConcept, "concept");
        check(r.tokens[1].kind == TokenKind::KwRequires, "requires");
        check(r.tokens[2].kind == TokenKind::KwConsteval, "consteval");
        check(r.tokens[3].kind == TokenKind::KwConstinit, "constinit");
        check(r.tokens[4].kind == TokenKind::KwCo_await, "co_await");
        check(r.tokens[5].kind == TokenKind::KwCo_return, "co_return");
        check(r.tokens[6].kind == TokenKind::KwCo_yield, "co_yield");
        check(r.tokens[7].kind == TokenKind::KwChar8_t, "char8_t");
    }

    // -----------------------------------------------------------------
    // 9. Comments and line splicing
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags,
            "a /* block */ b // line comment\n"
            "c /* nested /* inner */ still outer */ d\n"
            "e \\\n f\n");
        check(r.tokens.size() == 6, "comment token count");
        check_eq(r.tokens[0].text, "a", "token before block comment");
        check_eq(r.tokens[1].text, "b", "token after block comment");
        check_eq(r.tokens[2].text, "c", "token before nested comment");
        check_eq(r.tokens[3].text, "d", "token after nested comment");
        check_eq(r.tokens[4].text, "e", "token before line splice");
        check_eq(r.tokens[5].text, "f", "token after line splice");
    }

    // -----------------------------------------------------------------
    // 10. Source locations
    // -----------------------------------------------------------------
    {
        LexResult r = lex_text(sm, diags, "alpha\nbeta\ngamma\n");
        check(r.tokens.size() == 3, "location token count");
        uint32 line = 0, col = 0;
        sm.locate(r.tokens[0].loc.file_id, r.tokens[0].loc.offset, &line, &col);
        check(line == 1 && col == 1, "first token at 1:1");
        sm.locate(r.tokens[1].loc.file_id, r.tokens[1].loc.offset, &line, &col);
        check(line == 2 && col == 1, "second token at 2:1");
        sm.locate(r.tokens[2].loc.file_id, r.tokens[2].loc.offset, &line, &col);
        check(line == 3 && col == 1, "third token at 3:1");
    }

    // -----------------------------------------------------------------
    // 11. Error detection: unterminated literals
    // -----------------------------------------------------------------
    {
        DiagnosticEngine errs(&sm);
        errs.set_suppressed(true);
        LexResult r = lex_text(sm, errs, "\"unterminated\n");
        check(errs.error_count() == 1, "unterminated string reported");
        check(errs.diagnostics().size() == 1, "one diagnostic recorded");
        if (!errs.diagnostics().empty()) {
            const Diagnostic& d = errs.diagnostics()[0];
            check(d.line == 1, "error on correct line");
            check(d.severity == DiagnosticSeverity::Error, "severity is error");
        }
    }

    // -----------------------------------------------------------------
    // 12. Determinism: same input, same token stream
    // -----------------------------------------------------------------
    {
        const char* src = "template<class T> constexpr T square(T v){ return v*v; }";
        LexResult a = lex_text(sm, diags, src);
        LexResult b = lex_text(sm, diags, src);
        bool same = a.tokens.size() == b.tokens.size();
        for (size_type i = 0; same && i < a.tokens.size(); ++i) {
            if (a.tokens[i].kind != b.tokens[i].kind) same = false;
            if (a.tokens[i].text != b.tokens[i].text) same = false;
        }
        check(same, "deterministic tokenization");
        // template < class T > constexpr T square ( T v ) { return v * v ; }
        check(a.tokens.size() == 19, "realistic program token count");
    }

    // -----------------------------------------------------------------
    // 13. Every punctuator round-trips through kind_name
    // -----------------------------------------------------------------
    {
        const char* ops = "+ - * / % ^ & | ~ ! = < > , ; : ? . ( ) [ ] { }";
        LexResult r = lex_text(sm, diags, ops);
        check(r.tokens.size() == 24, "single punctuator count");
        bool all_known = true;
        for (size_type i = 0; i < r.tokens.size(); ++i) {
            if (!is_punctuator(r.tokens[i].kind)) all_known = false;
        }
        check(all_known, "all single punctuators classified");
    }

    // -----------------------------------------------------------------
    // Summary
    // -----------------------------------------------------------------
    rawrstd::write_stdout("--------------------------------\n", 33);
    String summary;
    summary << "C01 result: " << g_pass << " passed, " << g_fail << " failed\n";
    rawrstd::write_stdout(summary.data(), summary.size());

    return g_fail == 0 ? 0 : 1;
}
