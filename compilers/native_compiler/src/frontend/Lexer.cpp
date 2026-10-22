#include "frontend/Lexer.h"

#include "rawrstd/sys.h"

namespace rawr {

using rawrstd::String;

static bool is_ident_start(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
           static_cast<unsigned char>(c) >= 0x80;
}

static bool is_ident_continue(char c) {
    return is_ident_start(c) || (c >= '0' && c <= '9');
}

static bool is_digit(char c) { return c >= '0' && c <= '9'; }

static bool is_hex_digit(char c) {
    return is_digit(c) || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
}

Lexer::Lexer(SourceManager* sources, DiagnosticEngine* diags, uint32 file_id)
    : sources_(sources), diags_(diags), file_id_(file_id) {
    const SourceFile& f = sources->file(file_id);
    text_ = f.contents.data();
    size_ = f.contents.size();
    pos_ = 0;
}

char Lexer::peek_char(size_type ahead) const {
    size_type p = pos_ + ahead;
    return p < size_ ? text_[p] : '\0';
}

char Lexer::advance() {
    if (pos_ >= size_) return '\0';
    return text_[pos_++];
}

SourceLoc Lexer::current_loc() const {
    SourceLoc loc;
    loc.file_id = file_id_;
    loc.offset = static_cast<uint32>(pos_);
    return loc;
}

void Lexer::mark_line_start() { at_line_start_ = true; }

// ---------------------------------------------------------------------------
// Whitespace and comments
// ---------------------------------------------------------------------------

void Lexer::skip_whitespace_and_comments() {
    for (;;) {
        if (at_end()) return;

        char c = peek_char();

        // Line splice: backslash immediately followed by newline.
        if (c == '\\') {
            size_type p = pos_ + 1;
            // Allow trailing horizontal whitespace before the newline.
            while (p < size_ && (text_[p] == ' ' || text_[p] == '\t' || text_[p] == '\r')) ++p;
            if (p < size_ && text_[p] == '\n') {
                pos_ = p + 1;
                at_line_start_ = true;
                continue;
            }
        }

        if (c == '\n') {
            advance();
            at_line_start_ = true;
            continue;
        }

        if (c == ' ' || c == '\t' || c == '\r' || c == '\v' || c == '\f') {
            advance();
            continue;
        }

        // Line comment.
        if (c == '/' && peek_char(1) == '/') {
            while (!at_end() && peek_char() != '\n') {
                // A line splice inside a line comment continues the comment.
                if (peek_char() == '\\') {
                    size_type p = pos_ + 1;
                    while (p < size_ && (text_[p] == ' ' || text_[p] == '\t' || text_[p] == '\r')) ++p;
                    if (p < size_ && text_[p] == '\n') { pos_ = p + 1; continue; }
                }
                advance();
            }
            continue;
        }

        // Block comment (nestable in C++).
        if (c == '/' && peek_char(1) == '*') {
            advance();
            advance();
            int depth = 1;
            while (!at_end() && depth > 0) {
                if (peek_char() == '/' && peek_char(1) == '*') {
                    advance(); advance();
                    ++depth;
                    continue;
                }
                if (peek_char() == '*' && peek_char(1) == '/') {
                    advance(); advance();
                    --depth;
                    continue;
                }
                if (peek_char() == '\n') at_line_start_ = true;
                advance();
            }
            if (depth > 0) {
                SourceLoc loc = current_loc();
                if (diags_) {
                    diags_->error(loc, "C0001", "unterminated block comment");
                }
            }
            continue;
        }

        return;
    }
}

// ---------------------------------------------------------------------------
// Identifiers
// ---------------------------------------------------------------------------

bool Lexer::lex_identifier(Token* out) {
    size_type start = pos_;
    while (!at_end() && is_ident_continue(peek_char())) advance();

    out->kind = TokenKind::Identifier;
    out->text.assign(text_ + start, pos_ - start);

    // A user-defined literal suffix only applies to numeric and string
    // literals; a bare identifier followed by an identifier character is
    // already consumed above, so check for the `_` start form.
    return true;
}

// ---------------------------------------------------------------------------
// pp-numbers
//
// The preprocessor number grammar is deliberately a superset of the C++
// numeric literal grammar: a pp-number starts with a digit or a '.' followed
// by a digit, and continues with digits, identifier-nondigits, '.', and
// exponent signs. This is what allows `1.0e+10` to lex as one token.
// C++14 digit separators (1'000'000) are also part of the pp-number.
bool Lexer::lex_number(Token* out) {
    size_type start = pos_;

    if (peek_char() == '.') {
        advance();
        while (!at_end() && (is_ident_continue(peek_char()) || peek_char() == '\'')) advance();
    } else {
        while (!at_end() && (is_digit(peek_char()) || peek_char() == '\'')) advance();
        // Exponent part (also the binary/hex exponent).
        if (peek_char() == 'p' || peek_char() == 'P') {
            size_type save = pos_;
            advance();
            if (peek_char() == '+' || peek_char() == '-') advance();
            if (is_digit(peek_char())) {
                while (!at_end() && is_digit(peek_char())) advance();
            } else {
                pos_ = save;
            }
        }
        while (!at_end() && (is_ident_continue(peek_char()) || peek_char() == '.' ||
                             peek_char() == '\'')) {
            // Handle the decimal exponent sign: 1e+10
            char c = peek_char();
            if ((c == 'e' || c == 'E' || c == 'p' || c == 'P')) {
                advance();
                if (peek_char() == '+' || peek_char() == '-') advance();
                continue;
            }
            advance();
        }
    }

    out->text.assign(text_ + start, pos_ - start);

    // Classify the pp-number and split off any user-defined suffix.
    String spelling = out->text;
    bool is_floating = false;
    bool hex = false;
    bool binary = false;

    if (spelling.size() > 2 && spelling[0] == '0' &&
        (spelling[1] == 'x' || spelling[1] == 'X')) {
        hex = true;
    } else if (spelling.size() > 2 && spelling[0] == '0' &&
               (spelling[1] == 'b' || spelling[1] == 'B')) {
        binary = true;
    }

    // Find where the numeric part ends.
    size_type n = spelling.size();
    size_type num_end = n;

    if (hex) {
        size_type i = 2;
        bool saw_point = false;
        bool saw_exp = false;
        for (; i < n; ++i) {
            char c = spelling[i];
            if (c == '\'') continue;   // digit separator
            if (c == '.') {
                if (saw_exp) break;
                saw_point = true;
                continue;
            }
            if (c == 'p' || c == 'P') {
                if (saw_exp) break;
                saw_exp = true;
                if (i + 1 < n && (spelling[i + 1] == '+' || spelling[i + 1] == '-')) ++i;
                continue;
            }
            if (is_hex_digit(c)) continue;
            break;
        }
        num_end = i;
        if (saw_point || saw_exp) is_floating = true;
    } else if (binary) {
        size_type i = 2;
        for (; i < n; ++i) {
            char c = spelling[i];
            if (c == '\'') continue;
            if (c == '0' || c == '1') continue;
            break;
        }
        num_end = i;
    } else {
        size_type i = 0;
        bool saw_point = false;
        bool saw_exp = false;
        for (; i < n; ++i) {
            char c = spelling[i];
            if (c == '\'') continue;
            if (c == '.') {
                if (saw_exp) break;
                saw_point = true;
                continue;
            }
            if (c == 'e' || c == 'E') {
                if (saw_exp) break;
                saw_exp = true;
                if (i + 1 < n && (spelling[i + 1] == '+' || spelling[i + 1] == '-')) ++i;
                continue;
            }
            if (is_digit(c)) continue;
            break;
        }
        num_end = i;
        if (saw_point || saw_exp) is_floating = true;
    }

    // Suffix handling.
    String suffix_part;
    if (num_end < n) suffix_part = String(spelling.data() + num_end, n - num_end);

    if (suffix_part.empty()) {
        out->kind = is_floating ? TokenKind::FloatingLiteral : TokenKind::IntegerLiteral;
    } else {
        // A user-defined literal suffix starts with '_'.
        if (suffix_part[0] == '_') {
            out->kind = TokenKind::UserDefinedLiteral;
            out->suffix = suffix_part;
        } else if (is_floating) {
            out->kind = TokenKind::FloatingLiteral;
            if (suffix_part == "f" || suffix_part == "F") out->is_float = true;
            else if (suffix_part == "l" || suffix_part == "L") out->is_long_double = true;
        } else {
            out->kind = TokenKind::IntegerLiteral;
            if (suffix_part == "u" || suffix_part == "U") {
                out->is_unsigned = true;
            } else if (suffix_part == "l" || suffix_part == "L") {
                out->is_long = true;
            } else if (suffix_part == "ll" || suffix_part == "LL") {
                out->is_long_long = true;
            } else if (suffix_part == "ull" || suffix_part == "ULL" || suffix_part == "uLL" ||
                       suffix_part == "Ull" || suffix_part == "ull" || suffix_part == "Ull" ||
                       suffix_part == "uLl" || suffix_part == "UlL" || suffix_part == "z" ||
                       suffix_part == "Z") {
                out->is_unsigned = true;
                out->is_long_long = true;
            } else {
                // Unknown suffix -> treat as a user-defined literal.
                out->kind = TokenKind::UserDefinedLiteral;
                out->suffix = suffix_part;
            }
        }
    }

    return true;
}

// ---------------------------------------------------------------------------
// String literals
// ---------------------------------------------------------------------------

// Decodes an escape sequence. `pos` points at the backslash and is advanced
// past the whole escape. Returns the decoded code unit value.
static uint32 decode_escape(const char* text, size_type size, size_type& pos,
                            bool* is_unicode_escape) {
    ++pos;   // consume the backslash
    if (pos >= size) { *is_unicode_escape = false; return '\\'; }

    char c = text[pos++];
    switch (c) {
    case 'n': return '\n';
    case 't': return '\t';
    case 'r': return '\r';
    case '0': case '1': case '2': case '3':
    case '4': case '5': case '6': case '7': {
        uint32 v = static_cast<uint32>(c - '0');
        for (int i = 0; i < 2 && pos < size && text[pos] >= '0' && text[pos] <= '7'; ++i) {
            v = v * 8 + static_cast<uint32>(text[pos++] - '0');
        }
        return v;
    }
    case 'x': {
        uint32 v = 0;
        int count = 0;
        while (pos < size && is_hex_digit(text[pos]) && count < 2) {
            char h = text[pos++];
            uint32 d = is_digit(h) ? static_cast<uint32>(h - '0')
                                   : static_cast<uint32>((h | 0x20) - 'a' + 10);
            v = v * 16 + d;
            ++count;
        }
        return v;
    }
    case 'u': case 'U': {
        uint32 want = (c == 'u') ? 4 : 8;
        uint32 v = 0;
        int count = 0;
        while (pos < size && is_hex_digit(text[pos]) && count < static_cast<int>(want)) {
            char h = text[pos++];
            uint32 d = is_digit(h) ? static_cast<uint32>(h - '0')
                                   : static_cast<uint32>((h | 0x20) - 'a' + 10);
            v = v * 16 + d;
            ++count;
        }
        *is_unicode_escape = true;
        return v;
    }
    case 'a': return '\a';
    case 'b': return '\b';
    case 'f': return '\f';
    case 'v': return '\v';
    case 'e': return 27;   // GNU extension
    case '\\': return '\\';
    case '\'': return '\'';
    case '"': return '"';
    case '?': return '?';
    default:
        return static_cast<uint32>(static_cast<unsigned char>(c));
    }
}

bool Lexer::lex_string(Token* out, char prefix) {
    advance();   // consume the opening quote

    String value;
    bool unicode_escape = false;

    for (;;) {
        if (at_end() || peek_char() == '\n') {
            SourceLoc loc = current_loc();
            if (diags_) diags_->error(loc, "C0002", "unterminated string literal");
            break;
        }
        if (peek_char() == '"') { advance(); break; }
        if (peek_char() == '\\') {
            bool u = false;
            uint32 v = decode_escape(text_, size_, pos_, &u);
            if (u) {
                unicode_escape = true;
            } else {
                value.push_back(static_cast<char>(v & 0xFF));
            }
            continue;
        }
        value.push_back(advance());
    }

    out->text = value;
    out->is_wide = (prefix == 'L');
    out->is_utf8 = (prefix == 'u8');
    out->is_utf16 = (prefix == 'u');
    out->is_utf32 = (prefix == 'U');

    switch (prefix) {
    case 'L': out->kind = TokenKind::WideStringLiteral; break;
    case 'u': out->kind = TokenKind::Char16StringLiteral; break;
    case 'U': out->kind = TokenKind::Char32StringLiteral; break;
    case '8': out->kind = TokenKind::Char8StringLiteral; break;
    default:  out->kind = TokenKind::StringLiteral; break;
    }
    (void)unicode_escape;
    return true;
}

bool Lexer::lex_raw_string(Token* out, char prefix) {
    // pos_ is just past the opening quote; text_[pos_-1] == '"'
    // The delimiter follows: up to 16 chars of ) ... (
    size_type delim_start = pos_;
    size_type delim_end = pos_;
    while (delim_end < size_ && text_[delim_end] != '(' && delim_end - delim_start < 16) {
        ++delim_end;
    }
    if (delim_end >= size_ || text_[delim_end] != '(') {
        SourceLoc loc = current_loc();
        if (diags_) diags_->error(loc, "C0003", "invalid raw string delimiter");
        out->kind = TokenKind::StringLiteral;
        return true;
    }

    String delimiter;
    delimiter.assign(text_ + delim_start, delim_end - delim_start);
    pos_ = delim_end + 1;   // past the '('

    String terminator = ")";
    terminator.append(delimiter);
    terminator.push_back('"');

    // Find the terminator.
    size_type search = pos_;
    bool found = false;
    while (search < size_) {
        if (text_[search] == ')') {
            size_type k = 0;
            bool match = true;
            while (k < terminator.size() && search + k < size_) {
                if (text_[search + k] != terminator[k]) { match = false; break; }
                ++k;
            }
            if (match) { found = true; break; }
        }
        ++search;
    }

    if (!found) {
        SourceLoc loc = current_loc();
        if (diags_) diags_->error(loc, "C0004", "unterminated raw string literal");
        out->kind = TokenKind::StringLiteral;
        out->text.assign(text_ + pos_, size_ - pos_);
        pos_ = size_;
        return true;
    }

    out->text.assign(text_ + pos_, search - pos_);
    pos_ = search + terminator.size();

    switch (prefix) {
    case 'L': out->kind = TokenKind::WideStringLiteral; break;
    case 'u': out->kind = TokenKind::Char16StringLiteral; break;
    case 'U': out->kind = TokenKind::Char32StringLiteral; break;
    case '8': out->kind = TokenKind::Char8StringLiteral; break;
    default:  out->kind = TokenKind::StringLiteral; break;
    }
    return true;
}

bool Lexer::lex_char_literal(Token* out, char prefix) {
    size_type start = pos_;
    advance();   // consume the opening quote

    String value;
    for (;;) {
        if (at_end() || peek_char() == '\n') {
            SourceLoc loc = current_loc();
            if (diags_) diags_->error(loc, "C0005", "unterminated character literal");
            break;
        }
        if (peek_char() == '\'') { advance(); break; }
        if (peek_char() == '\\') {
            bool u = false;
            uint32 v = decode_escape(text_, size_, pos_, &u);
            value.push_back(static_cast<char>(v & 0xFF));
            continue;
        }
        value.push_back(advance());
    }

    (void)start;
    out->text = value;
    out->is_wide = (prefix == 'L');
    out->is_utf8 = (prefix == '8');
    out->is_utf16 = (prefix == 'u');
    out->is_utf32 = (prefix == 'U');

    switch (prefix) {
    case 'L': out->kind = TokenKind::WideCharacterLiteral; break;
    case 'u': out->kind = TokenKind::Char16CharacterLiteral; break;
    case 'U': out->kind = TokenKind::Char32CharacterLiteral; break;
    case '8': out->kind = TokenKind::Char8CharacterLiteral; break;
    default:  out->kind = TokenKind::CharacterLiteral; break;
    }
    return true;
}

// Absorbs a user-defined literal suffix that immediately follows a string or
// character literal, e.g. "text"_s or 'x'_km. The suffix must start with '_'.
void Lexer::absorb_udl_suffix(Token* out) {
    if (at_end() || peek_char() != '_') return;
    size_type start = pos_;
    while (!at_end() && is_ident_continue(peek_char())) advance();
    out->suffix.assign(text_ + start, pos_ - start);
    out->kind = TokenKind::UserDefinedLiteral;
}

// ---------------------------------------------------------------------------
// Punctuators
// ---------------------------------------------------------------------------

bool Lexer::lex_punctuator(Token* out) {
    size_type start = pos_;
    char c = peek_char();
    char c1 = peek_char(1);
    char c2 = peek_char(2);

    struct Punct {
        const char* spelling;
        TokenKind kind;
    };

    // Longest match first.
    static const Punct kThree[] = {
        { "<<=", TokenKind::ShiftLeftEqual },
        { ">>=", TokenKind::ShiftRightEqual },
        { "...", TokenKind::Ellipsis },
        { "->*", TokenKind::ArrowStar },
        { "<=>", TokenKind::Spaceship },
    };
    static const Punct kTwo[] = {
        { "::", TokenKind::Scope },
        { "->", TokenKind::Arrow },
        { "++", TokenKind::PlusPlus },
        { "--", TokenKind::MinusMinus },
        { "<<", TokenKind::Shl },
        { ">>", TokenKind::Shr },
        { "<=", TokenKind::LessEqual },
        { ">=", TokenKind::GreaterEqual },
        { "==", TokenKind::EqualEqual },
        { "!=", TokenKind::NotEqual },
        { "&&", TokenKind::AmpAmp },
        { "||", TokenKind::PipePipe },
        { "+=", TokenKind::PlusEqual },
        { "-=", TokenKind::MinusEqual },
        { "*=", TokenKind::StarEqual },
        { "/=", TokenKind::SlashEqual },
        { "%=", TokenKind::PercentEqual },
        { "&=", TokenKind::AmpEqual },
        { "|=", TokenKind::PipeEqual },
        { "^=", TokenKind::CaretEqual },
        { "##", TokenKind::HashHash },
    };
    static const Punct kOne[] = {
        { "(", TokenKind::LParen }, { ")", TokenKind::RParen },
        { "[", TokenKind::LBracket }, { "]", TokenKind::RBracket },
        { "{", TokenKind::LBrace }, { "}", TokenKind::RBrace },
        { ".", TokenKind::Period }, { "?", TokenKind::Question },
        { ":", TokenKind::Colon }, { ";", TokenKind::Semicolon },
        { ",", TokenKind::Comma }, { "~", TokenKind::Tilde },
        { "=", TokenKind::Assign }, { "<", TokenKind::Less },
        { ">", TokenKind::Greater }, { "+", TokenKind::Plus },
        { "-", TokenKind::Minus }, { "*", TokenKind::Star },
        { "/", TokenKind::Slash }, { "%", TokenKind::Percent },
        { "&", TokenKind::Amp }, { "|", TokenKind::Pipe },
        { "^", TokenKind::Caret }, { "!", TokenKind::Exclaim },
        { "#", TokenKind::Hash },
    };

    char buf[3] = { c, c1, c2 };

    for (size_type i = 0; i < sizeof(kThree) / sizeof(kThree[0]); ++i) {
        if (rawrstd::memcmp_raw(buf, kThree[i].spelling, 3) == 0) {
            advance(); advance(); advance();
            out->kind = kThree[i].kind;
            out->text.assign(kThree[i].spelling, 3);
            return true;
        }
    }
    for (size_type i = 0; i < sizeof(kTwo) / sizeof(kTwo[0]); ++i) {
        if (rawrstd::memcmp_raw(buf, kTwo[i].spelling, 2) == 0) {
            advance(); advance();
            out->kind = kTwo[i].kind;
            out->text.assign(kTwo[i].spelling, 2);
            return true;
        }
    }
    for (size_type i = 0; i < sizeof(kOne) / sizeof(kOne[0]); ++i) {
        if (buf[0] == kOne[i].spelling[0]) {
            advance();
            out->kind = kOne[i].kind;
            out->text.assign(kOne[i].spelling, 1);
            return true;
        }
    }

    (void)start;
    out->kind = TokenKind::Unknown;
    out->text.assign(text_ + start, 1);
    advance();
    return false;
}

// ---------------------------------------------------------------------------
// Main entry point
// ---------------------------------------------------------------------------

bool Lexer::next(Token* out) {
    if (has_peeked_) {
        *out = peeked_;
        has_peeked_ = false;
        return out->kind != TokenKind::EndOfFile;
    }

    skip_whitespace_and_comments();

    out->loc = current_loc();
    out->length = 0;
    out->text.clear();
    out->suffix.clear();
    out->from_macro = false;

    if (at_end()) {
        out->kind = TokenKind::EndOfFile;
        return false;
    }

    char c = peek_char();

    // --- Encoding-prefixed literals must be tested before identifiers,
    // because their prefix letters (L, u, U, 8) are identifier starts. ---

    // Raw string literals: R"(...)"
    if (c == 'R' && peek_char(1) == '"') {
        advance();   // R
        advance();   // "
        lex_raw_string(out, '\0');
        absorb_udl_suffix(out);
        out->length = static_cast<uint32>(pos_ - out->loc.offset);
        at_line_start_ = false;
        return true;
    }

    if (c == 'L' || c == 'u' || c == 'U' || c == '8') {
        char n = peek_char(1);
        bool is_prefix = false;
        char prefix = '\0';
        size_type prefix_len = 1;
        bool is_raw = false;

        // A prefix is followed by '"', '\'' or R" (raw string form).
        auto classify = [&](char next) {
            if (next == '"') return 1;   // plain string
            if (next == '\'') return 2;  // character literal
            if (next == 'R') return 3;   // candidate raw string
            return 0;
        };

        int form = 0;
        if (c == 'L' || c == 'U') {
            form = classify(n);
        } else if (c == '8') {
            form = (n == '"') ? 1 : 0;
        } else if (c == 'u') {
            form = classify(n);
        }

        if (form == 3) {
            // Only a raw string if 'R' is followed by '"'.
            if (peek_char(2) == '"') {
                is_prefix = true;
                is_raw = true;
                prefix = (c == 'u') ? 'u' : c;
                prefix_len = 1;
            }
        } else if (form != 0) {
            is_prefix = true;
            prefix = (c == '8') ? '8' : c;
            prefix_len = 1;
        }

        // Two-character prefix: u8"..." / u8'x' / u8R"(...)"
        if (!is_prefix && c == 'u' && n == '8') {
            char n2 = peek_char(2);
            if (n2 == '"' || n2 == '\'') {
                is_prefix = true;
                prefix = '8';
                prefix_len = 2;
            } else if (n2 == 'R' && peek_char(3) == '"') {
                is_prefix = true;
                prefix = '8';
                prefix_len = 2;
                is_raw = true;
            }
        }

        if (is_prefix) {
            for (size_type i = 0; i < prefix_len; ++i) advance();   // consume the prefix

            if (is_raw) {
                advance();   // consume 'R'
                advance();   // consume the opening quote
                lex_raw_string(out, prefix);
            } else if (peek_char() == '"') {
                lex_string(out, prefix);
            } else {
                lex_char_literal(out, prefix);
            }
            absorb_udl_suffix(out);
            out->length = static_cast<uint32>(pos_ - out->loc.offset);
            at_line_start_ = false;
            return true;
        }
    }

    // Identifiers and keywords.
    if (is_ident_start(c)) {
        lex_identifier(out);
        TokenKind kw = keyword_id(out->text.data(), out->text.size());
        if (kw != TokenKind::Identifier) {
            out->kind = kw;
        }
        out->length = static_cast<uint32>(out->text.size());
        at_line_start_ = false;
        return true;
    }

    // Numbers.
    if (is_digit(c) || (c == '.' && is_digit(peek_char(1)))) {
        lex_number(out);
        out->length = static_cast<uint32>(out->text.size());
        at_line_start_ = false;
        return true;
    }

    // Plain string and character literals.
    if (c == '"') {
        lex_string(out, '\0');
        absorb_udl_suffix(out);
        out->length = static_cast<uint32>(pos_ - out->loc.offset);
        at_line_start_ = false;
        return true;
    }
    if (c == '\'') {
        lex_char_literal(out, '\0');
        absorb_udl_suffix(out);
        out->length = static_cast<uint32>(pos_ - out->loc.offset);
        at_line_start_ = false;
        return true;
    }

    // Punctuators.
    lex_punctuator(out);
    out->length = static_cast<uint32>(pos_ - out->loc.offset);
    at_line_start_ = false;
    return true;
}

const Token& Lexer::peek() {
    if (!has_peeked_) {
        Token t;
        next(&t);
        peeked_ = t;
        has_peeked_ = true;
    }
    return peeked_;
}

Token Lexer::consume() {
    Token t = peek();
    has_peeked_ = false;
    return t;
}

void Lexer::unconsume() {
    if (has_peeked_) {
        // Already have a peeked token: nothing to do, but a second unconsume
        // would lose a token, so this is a no-op in that case.
        return;
    }
    // Push the last consumed token back by re-lexing is not possible; the
    // driver uses peek()/consume() instead of unconsume().
}

} // namespace rawr
