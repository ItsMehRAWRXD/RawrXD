#include "frontend/Preprocessor.h"

#include "frontend/Lexer.h"
#include "rawrstd/sys.h"

namespace rawr {

using rawrstd::String;
using rawrstd::Vector;
using rawrstd::size_type;
using rawrstd::int64;
using rawrstd::uint32;
using rawrstd::uint64;

// ---------------------------------------------------------------------------
// Small helpers
// ---------------------------------------------------------------------------

static bool is_ident_char(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '_';
}

// Formats an integer. The compiler does not use the C runtime, so the
// formatting comes from rawrstd.
static String to_text(int64 value) {
    String out;
    out.append_i64(value);
    return out;
}
// Parses an integer literal spelling. Returns false when the text is not a
// valid integer.
static bool parse_integer(const String& text, int64* out) {
    size_type i = 0;
    int base = 10;
    bool negative = false;

    if (i < text.size() && (text[i] == '+' || text[i] == '-')) {
        negative = (text[i] == '-');
        ++i;
    }
    if (i + 1 < text.size() && text[i] == '0' && (text[i + 1] == 'x' || text[i + 1] == 'X')) {
        base = 16;
        i += 2;
    } else if (i + 1 < text.size() && text[i] == '0' && (text[i + 1] == 'b' || text[i + 1] == 'B')) {
        base = 2;
        i += 2;
    } else if (i < text.size() && text[i] == '0') {
        // Octal. The leading zero is a digit of the number, so the scan is
        // left where it is. Skipping it would leave "0" with no digits at
        // all, and the literal would be rejected.
        base = 8;
    }

    uint64 value = 0;
    size_type digits = 0;
    for (; i < text.size(); ++i) {
        const char c = text[i];
        if (c == '\'') continue;              // a digit separator
        int digit = -1;
        if (c >= '0' && c <= '9') digit = c - '0';
        else if (c >= 'a' && c <= 'f') digit = c - 'a' + 10;
        else if (c >= 'A' && c <= 'F') digit = c - 'A' + 10;
        if (digit < 0 || digit >= base) break;
        value = value * static_cast<uint64>(base) + static_cast<uint64>(digit);
        ++digits;
    }
    if (digits == 0) return false;
    // The suffix is not part of the value.
    *out = negative ? -static_cast<int64>(value) : static_cast<int64>(value);
    return true;
}

// Decodes a character literal spelling into its value.
static bool parse_character(const String& text, int64* out) {
    // Skip an encoding prefix and the opening quote.
    size_type i = 0;
    while (i < text.size() && text[i] != '\'') ++i;
    if (i >= text.size()) return false;
    ++i;
    if (i >= text.size()) return false;

    int64 value = 0;
    if (text[i] == '\\') {
        ++i;
        if (i >= text.size()) return false;
        const char c = text[i];
        switch (c) {
            case 'n': value = '\n'; break;
            case 't': value = '\t'; break;
            case 'r': value = '\r'; break;
            case '0': value = 0; break;
            case 'a': value = 7; break;
            case 'b': value = 8; break;
            case 'f': value = 12; break;
            case 'v': value = 11; break;
            case '\\': value = '\\'; break;
            case '\'': value = '\''; break;
            case '"': value = '"'; break;
            case '?': value = '?'; break;
            case 'x': {
                ++i;
                int64 hex = 0;
                for (; i < text.size(); ++i) {
                    const char h = text[i];
                    int d = -1;
                    if (h >= '0' && h <= '9') d = h - '0';
                    else if (h >= 'a' && h <= 'f') d = h - 'a' + 10;
                    else if (h >= 'A' && h <= 'F') d = h - 'A' + 10;
                    if (d < 0) break;
                    hex = hex * 16 + d;
                }
                value = hex;
                break;
            }
            default: value = static_cast<unsigned char>(c); break;
        }
    } else {
        value = static_cast<unsigned char>(text[i]);
    }
    *out = value;
    return true;
}

// ---------------------------------------------------------------------------
// Construction
// ---------------------------------------------------------------------------

Preprocessor::Preprocessor(SourceManager* sources, DiagnosticEngine* diags)
    : sources_(sources), diags_(diags) {
    // The predefined macros. The values are the ones a C++20 compiler is
    // required to provide.
    define("__cplusplus", "202002L");
    define("__STDC__", "1");
    define("__STDC_VERSION__", "202002L");
    define("__STDC_HOSTED__", "1");
    define("_WIN32", "1");
    define("_WIN64", "1");
    define("__x86_64__", "1");
    define("__x86_64", "1");
    define("__amd64__", "1");
    define("__amd64", "1");
    define("__linux__", "0");
    define("__unix__", "0");
    define("__APPLE__", "0");
    define("__CHAR_BIT__", "8");
    define("__SIZEOF_INT__", "4");
    define("__SIZEOF_LONG__", "4");
    define("__SIZEOF_LONG_LONG__", "8");
    define("__SIZEOF_POINTER__", "8");
    define("__SIZE_TYPE__", "unsigned long long");
    define("__PTRDIFF_TYPE__", "long long");
    define("__INT_MAX__", "2147483647");
    define("__LONG_MAX__", "2147483647L");
    define("__LONG_LONG_MAX__", "9223372036854775807LL");
    define("__CHAR16_MAX__", "65535");
    define("__CHAR32_MAX__", "4294967295U");
    define("__WCHAR_MAX__", "4294967295U");
    define("__INT64_MAX__", "9223372036854775807LL");
    define("__UINT64_MAX__", "18446744073709551615ULL");

    // The macros whose value depends on where they appear.
    Macro file_macro;
    file_macro.name = "__FILE__";
    file_macro.builtin = true;
    macros_.insert("__FILE__", file_macro);

    Macro line_macro;
    line_macro.name = "__LINE__";
    line_macro.builtin = true;
    macros_.insert("__LINE__", line_macro);

    Macro date_macro;
    date_macro.name = "__DATE__";
    date_macro.builtin = true;
    macros_.insert("__DATE__", date_macro);

    Macro time_macro;
    time_macro.name = "__TIME__";
    time_macro.builtin = true;
    macros_.insert("__TIME__", time_macro);

    Macro counter_macro;
    counter_macro.name = "__COUNTER__";
    counter_macro.builtin = true;
    macros_.insert("__COUNTER__", counter_macro);

    Macro level_macro;
    level_macro.name = "__INCLUDE_LEVEL__";
    level_macro.builtin = true;
    macros_.insert("__INCLUDE_LEVEL__", level_macro);
}

void Preprocessor::add_include_dir(const char* dir) {
    if (dir && dir[0]) sources_->add_include_dir(dir);
}

void Preprocessor::define(const char* name, const char* value) {
    if (!name || !name[0]) return;

    // The definition is lexed straight from memory, so a command line define
    // does not add a file to the source manager.
    String text;
    text << name;
    if (value && value[0]) text << " " << value;

    Vector<PPToken> tokens;
    {
        Lexer lexer(sources_, diags_, text.data(), text.size());
        for (;;) {
            PPToken entry;
            Token token;
            if (!lexer.next(&token)) break;
            entry.token = token;
            entry.space_before = token.space_before;
            tokens.push_back(entry);
        }
    }
    if (tokens.empty() || tokens[0].token.kind != TokenKind::Identifier) return;

    Macro macro;
    macro.name = tokens[0].token.text;
    for (size_type i = 1; i < tokens.size(); ++i) macro.replacement.push_back(tokens[i].token);
    macros_.insert(macro.name, macro);
}

void Preprocessor::undefine(const char* name) {
    if (!name || !name[0]) return;
    macros_.erase(name);
}

// ---------------------------------------------------------------------------
// The token stream
// ---------------------------------------------------------------------------

bool Preprocessor::next_raw(PPToken* out) {
    for (;;) {
        if (!pushback_.empty()) {
            *out = pushback_.back();
            pushback_.pop_back();
            return true;
        }
        if (!frames_.empty()) {
            Frame& frame = frames_.back();
            if (frame.pos < frame.tokens.size()) {
                *out = frame.tokens[frame.pos++];
                return true;
            }
            pop_frame();
            continue;
        }
        if (isolated_) return false;
        if (file_pos_ < file_tokens_.size()) {
            *out = file_tokens_[file_pos_++];
            return true;
        }
        return false;
    }
}
void Preprocessor::push_token(const PPToken& token) {
    pushback_.push_back(token);
}

void Preprocessor::push_expansion(const Vector<PPToken>& tokens, const String& macro_name) {
    Frame frame;
    frame.tokens = tokens;
    frame.pos = 0;
    frame.expanding_macro = macro_name;
    frames_.push_back(frame);
}

void Preprocessor::pop_frame() {
    if (frames_.empty()) return;
    const String name = frames_.back().expanding_macro;
    frames_.pop_back();
    if (!name.empty()) {
        Macro* macro = macros_.find(name);
        if (macro) macro->expanding = false;
    }
}

bool Preprocessor::region_active() const {
    for (size_type i = 0; i < conditionals_.size(); ++i) {
        if (!conditionals_[i].active) return false;
    }
    return true;
}

// ---------------------------------------------------------------------------
// File handling
// ---------------------------------------------------------------------------

bool Preprocessor::load_file_tokens(uint32 file_id, Vector<PPToken>* out) {
    Lexer lexer(sources_, diags_, file_id);
    for (;;) {
        PPToken entry;
        Token token;
        if (!lexer.next(&token)) break;
        entry.at_line_start = token.at_line_start;
        entry.token = token;
        entry.space_before = token.space_before;
        out->push_back(entry);
    }
    return true;
}

void Preprocessor::process_current_file() {
    for (;;) {
        PPToken token;
        if (!next_raw(&token)) break;

        // A directive is a '#' at the start of a logical line that did not
        // come out of a macro expansion.
        if (!token.from_expansion && token.at_line_start &&
            token.token.kind == TokenKind::Hash) {
            handle_directive();
            continue;
        }

        // Everything in an inactive conditional region is dropped, and a
        // macro is not expanded there either.
        if (!region_active()) continue;

        if (expand_macro(token)) continue;

        tokens_.push_back(token.token);
    }
}

bool Preprocessor::process_include(uint32 file_id) {
    Vector<PPToken> included;
    if (!load_file_tokens(file_id, &included)) return false;

    Vector<PPToken> saved_tokens = file_tokens_;
    const size_type saved_pos = file_pos_;
    const size_type saved_conditionals = conditionals_.size();

    file_tokens_ = included;
    file_pos_ = 0;
    ++include_depth_;
    process_current_file();
    --include_depth_;

    file_tokens_ = saved_tokens;
    file_pos_ = saved_pos;

    // A conditional region has to balance inside the file it was opened in.
    if (conditionals_.size() != saved_conditionals) {
        for (size_type i = saved_conditionals; i < conditionals_.size(); ++i) {
            if (diags_) {
                diags_->error(conditionals_[i].loc, "C0104",
                              "unterminated conditional directive in an included file");
            }
        }
        conditionals_.resize(saved_conditionals);
        failed_ = true;
    }
    return true;
}

// ---------------------------------------------------------------------------
// Directives
// ---------------------------------------------------------------------------

void Preprocessor::read_line(Vector<PPToken>* out) {
    while (file_pos_ < file_tokens_.size()) {
        const PPToken& token = file_tokens_[file_pos_];
        if (token.at_line_start) break;
        out->push_back(token);
        ++file_pos_;
    }
}

void Preprocessor::handle_directive() {
    Vector<PPToken> line;
    read_line(&line);
    if (line.empty()) return;      // a null directive

    const Token& name = line[0].token;
    // The name of a directive is an identifier, but some of them are also
    // keywords, so "if" and "else" have to be accepted as well.
    if (name.kind != TokenKind::Identifier && !is_keyword(name.kind)) {
        // An unknown directive. Inside an inactive region it is ignored, and
        // outside one it is an error.
        if (region_active() && diags_) {
            diags_->error(name.loc, "C0100", "unknown preprocessing directive");
            failed_ = true;
        }
        return;
    }

    // The tokens that follow the directive name.
    Vector<PPToken> rest;
    for (size_type i = 1; i < line.size(); ++i) rest.push_back(line[i]);

    // The name is compared as a whole string. Reading the spelling one
    // character at a time would read past the end of a short name.
    const char* spelling = name.text.data();
    if (rawrstd::strcmp_raw(spelling, "include") == 0) {
        handle_include(name.loc, rest);
    } else if (rawrstd::strcmp_raw(spelling, "define") == 0) {
        handle_define(name.loc, rest);
    } else if (rawrstd::strcmp_raw(spelling, "undef") == 0) {
        handle_undef(name.loc, rest);
    } else if (rawrstd::strcmp_raw(spelling, "ifdef") == 0) {
        handle_if(name.loc, ConditionalKind::NameDefined, rest);
    } else if (rawrstd::strcmp_raw(spelling, "ifndef") == 0) {
        handle_if(name.loc, ConditionalKind::NameNotDefined, rest);
    } else if (rawrstd::strcmp_raw(spelling, "if") == 0) {
        handle_if(name.loc, ConditionalKind::Expression, rest);
    } else if (rawrstd::strcmp_raw(spelling, "elif") == 0) {
        handle_elif(name.loc, rest);
    } else if (rawrstd::strcmp_raw(spelling, "else") == 0) {
        handle_else(name.loc, rest);
    } else if (rawrstd::strcmp_raw(spelling, "endif") == 0) {
        handle_endif(name.loc, rest);
    } else if (rawrstd::strcmp_raw(spelling, "error") == 0) {
        handle_error(name.loc, true, rest);
    } else if (rawrstd::strcmp_raw(spelling, "warning") == 0) {
        handle_error(name.loc, false, rest);
    } else if (rawrstd::strcmp_raw(spelling, "pragma") == 0) {
        // #pragma is accepted and ignored.
    } else if (rawrstd::strcmp_raw(spelling, "line") == 0) {
        // #line is accepted and ignored.
    } else {
        if (region_active() && diags_) {
            diags_->error(name.loc, "C0100", "unknown preprocessing directive");
            failed_ = true;
        }
    }
}

void Preprocessor::handle_include(const SourceLoc& loc, Vector<PPToken>& line) {
    if (!region_active()) return;
    if (line.empty()) {
        if (diags_) {
            diags_->error(loc, "C0101", "#include expects a file name");
            failed_ = true;
        }
        return;
    }

    String header;
    bool is_system = false;
    bool resolved = false;

    if (line[0].token.kind == TokenKind::StringLiteral && line.size() == 1) {
        header = line[0].token.text;
        resolved = true;
    } else if (line[0].token.kind == TokenKind::Less) {
        is_system = true;
        for (size_type i = 1; i < line.size(); ++i) {
            if (line[i].token.kind == TokenKind::Greater) break;
            header << line[i].token.text;
        }
        resolved = true;
    } else {
        // The file name comes from a macro.
        Vector<PPToken> expanded;
        expand_list(line, &expanded);
        if (!expanded.empty() && expanded[0].token.kind == TokenKind::StringLiteral &&
            expanded.size() == 1) {
            header = expanded[0].token.text;
            resolved = true;
        } else if (!expanded.empty() && expanded[0].token.kind == TokenKind::Less) {
            is_system = true;
            for (size_type i = 1; i < expanded.size(); ++i) {
                if (expanded[i].token.kind == TokenKind::Greater) break;
                header << expanded[i].token.text;
            }
            resolved = true;
        }
    }

    if (!resolved || header.empty()) {
        if (diags_) {
            diags_->error(loc, "C0101", "#include expects a file name");
            failed_ = true;
        }
        return;
    }

    if (include_depth_ >= 64) {
        if (diags_) {
            diags_->error(loc, "C0102", "#include nested too deeply");
            failed_ = true;
        }
        return;
    }

    const String path = sources_->resolve_include(header.data(), is_system);
    if (path.empty()) {
        if (diags_) {
            diags_->error(loc, "C0103", "cannot find the included file");
            failed_ = true;
        }
        return;
    }

    uint32 id = 0;
    String error;
    if (!sources_->load_file(path.data(), is_system, &id, &error)) {
        if (diags_) {
            diags_->error(loc, "C0103", "cannot read the included file");
            failed_ = true;
        }
        return;
    }
    ++include_count_;
    process_include(id);
}

void Preprocessor::handle_define(const SourceLoc& loc, Vector<PPToken>& line) {
    if (!region_active()) return;
    if (line.empty()) {
        if (diags_) {
            diags_->error(loc, "C0105", "#define expects a name");
            failed_ = true;
        }
        return;
    }
    if (line[0].token.kind != TokenKind::Identifier) {
        if (diags_) {
            diags_->error(line[0].token.loc, "C0105", "#define expects a name");
            failed_ = true;
        }
        return;
    }

    Macro macro;
    macro.name = line[0].token.text;
    macro.loc = loc;

    size_type i = 1;
    // A function-like macro has the '(' immediately after the name, with no
    // space between them.
    if (i < line.size() && line[i].token.kind == TokenKind::LParen &&
        !line[i].space_before) {
        macro.function_like = true;
        ++i;
        bool expect_parameter = true;
        while (i < line.size() && line[i].token.kind != TokenKind::RParen) {
            if (line[i].token.kind == TokenKind::Comma) {
                if (expect_parameter) {
                    if (diags_) {
                        diags_->error(line[i].token.loc, "C0106",
                                      "a macro parameter list cannot start with a comma");
                        failed_ = true;
                    }
                }
                expect_parameter = true;
                ++i;
                continue;
            }
            if (line[i].token.kind == TokenKind::Ellipsis) {
                macro.variadic = true;
                // The variadic argument is a parameter of its own, so the
                // parameter list holds one name for it.
                macro.parameters.push_back(String("__VA_ARGS__"));
                ++i;
                continue;
            }
            if (line[i].token.kind != TokenKind::Identifier) {
                if (diags_) {
                    diags_->error(line[i].token.loc, "C0106",
                                  "a macro parameter has to be a name");
                    failed_ = true;
                }
                ++i;
                continue;
            }
            if (macro.variadic) {
                if (diags_) {
                    diags_->error(line[i].token.loc, "C0106",
                                  "a variadic parameter has to be the last one");
                    failed_ = true;
                }
            }
            macro.parameters.push_back(line[i].token.text);
            expect_parameter = false;
            ++i;
        }
        if (i < line.size()) ++i;   // skip the ')'
    }

    for (; i < line.size(); ++i) {
        macro.replacement.push_back(line[i].token);
    }

    macros_.insert(macro.name, macro);
}

void Preprocessor::handle_undef(const SourceLoc& loc, Vector<PPToken>& line) {
    if (!region_active()) return;
    if (line.empty() || line[0].token.kind != TokenKind::Identifier) {
        if (diags_) {
            diags_->error(loc, "C0107", "#undef expects a name");
            failed_ = true;
        }
        return;
    }
    macros_.erase(line[0].token.text);
}

void Preprocessor::handle_if(const SourceLoc& loc, ConditionalKind kind, Vector<PPToken>& line) {

    Conditional state;
    state.parent_active = region_active();
    state.loc = loc;

    bool value = false;
    if (state.parent_active) {
        if (kind == ConditionalKind::Expression) {
            int64 condition = 0;
            if (!evaluate_expression(line, &condition)) {
                condition = 0;
            }
            value = condition != 0;
        } else {
            // #ifdef and #ifndef take a name, not an expression.
            if (line.empty() || line[0].token.kind != TokenKind::Identifier) {
                if (diags_) {
                    diags_->error(loc, "C0108", "this directive expects a name");
                    failed_ = true;
                }
            } else {
                const bool defined = macros_.contains(line[0].token.text);
                value = (kind == ConditionalKind::NameDefined) ? defined : !defined;
            }
        }
    }

    state.active = state.parent_active && value;
    state.taken = state.active;
    conditionals_.push_back(state);
}

void Preprocessor::handle_elif(const SourceLoc& loc, Vector<PPToken>& line) {

    if (conditionals_.empty()) {
        if (diags_) {
            diags_->error(loc, "C0109", "#elif without a matching #if");
            failed_ = true;
        }
        return;
    }

    Conditional& state = conditionals_.back();
    if (state.seen_else) {
        if (diags_) {
            diags_->error(loc, "C0109", "#elif after #else");
            failed_ = true;
        }
        return;
    }

    bool value = false;
    if (state.parent_active && !state.taken) {
        int64 condition = 0;
        if (!evaluate_expression(line, &condition)) condition = 0;
        value = condition != 0;
    }
    state.active = state.parent_active && !state.taken && value;
    if (state.active) state.taken = true;
}

void Preprocessor::handle_else(const SourceLoc& loc, Vector<PPToken>& line) {
    if (conditionals_.empty()) {
        if (diags_) {
            diags_->error(loc, "C0109", "#else without a matching #if");
            failed_ = true;
        }
        return;
    }
    Conditional& state = conditionals_.back();
    if (state.seen_else) {
        if (diags_) {
            diags_->error(loc, "C0109", "#else after #else");
            failed_ = true;
        }
        return;
    }
    state.seen_else = true;
    state.active = state.parent_active && !state.taken;
    if (state.active) state.taken = true;
}

void Preprocessor::handle_endif(const SourceLoc& loc, Vector<PPToken>& line) {
    if (conditionals_.empty()) {
        if (diags_) {
            diags_->error(loc, "C0109", "#endif without a matching #if");
            failed_ = true;
        }
        return;
    }
    conditionals_.pop_back();
}

void Preprocessor::handle_error(const SourceLoc& loc, bool is_error, Vector<PPToken>& line) {
    if (!region_active()) return;

    String message;
    for (size_type i = 0; i < line.size(); ++i) {
        if (i > 0 && line[i].space_before) message << " ";
        message << line[i].token.text;
    }

    if (diags_) {
        if (is_error) {
            diags_->error(loc, "C0110", message);
        } else {
            diags_->warning(loc, "C0111", message);
        }
    }
    if (is_error) failed_ = true;
}

// ---------------------------------------------------------------------------
// Macro expansion
// ---------------------------------------------------------------------------

int Preprocessor::parameter_index(const Macro& macro, const String& name) const {
    for (size_type i = 0; i < macro.parameters.size(); ++i) {
        if (macro.parameters[i] == name) return static_cast<int>(i);
    }
    return -1;
}

bool Preprocessor::expand_macro(const PPToken& token) {
    if (token.token.kind != TokenKind::Identifier) return false;
    if (token.no_expand) return false;

    Macro* macro = macros_.find(token.token.text);
    if (!macro || macro->expanding) return false;

    // The macros whose value depends on where they appear.
    if (macro->builtin) {
        PPToken value;
        value.token.loc = token.token.loc;
        value.space_before = token.space_before;
        if (macro->name == "__LINE__") {
            uint32 line = 0;
            uint32 column = 0;
            if (token.token.loc.file_id) {
                sources_->locate(token.token.loc.file_id, token.token.loc.offset, &line, &column);
            }
            value.token.kind = TokenKind::IntegerLiteral;
            value.token.text = to_text(line);
        } else if (macro->name == "__FILE__") {
            value.token.kind = TokenKind::StringLiteral;
            if (token.token.loc.file_id) {
                value.token.text = sources_->file(token.token.loc.file_id).path;
            } else {
                value.token.text = "";
            }
        } else if (macro->name == "__DATE__") {
            value.token.kind = TokenKind::StringLiteral;
            value.token.text = "Jan  1 2026";
        } else if (macro->name == "__TIME__") {
            value.token.kind = TokenKind::StringLiteral;
            value.token.text = "00:00:00";
        } else if (macro->name == "__COUNTER__") {
            value.token.kind = TokenKind::IntegerLiteral;
            value.token.text = to_text(counter_++);
        } else if (macro->name == "__INCLUDE_LEVEL__") {
            value.token.kind = TokenKind::IntegerLiteral;
            value.token.text = to_text(include_depth_);
        } else {
            return false;
        }
        tokens_.push_back(value.token);
        return true;
    }

    if (!macro->function_like) {
        Vector<PPToken> expansion;
        Vector<Vector<PPToken>> no_arguments;
        substitute(*macro, no_arguments, &expansion);
        macro->expanding = true;
        push_expansion(expansion, macro->name);
        return true;
    }

    // A function-like macro is only replaced when the next token is an
    // opening parenthesis.
    PPToken next;
    if (!next_raw(&next)) return false;
    if (next.token.kind != TokenKind::LParen) {
        // The name is not an invocation. It is put back, marked so that it
        // is not expanded again, and the caller emits it as it is.
        PPToken name = token;
        name.no_expand = true;
        // The pushback stack is read last in first out, so the name goes in
        // last to be read first.
        push_token(next);
        push_token(name);
        // The name is emitted from the stream, so the caller must not emit
        // it as well.
        return true;
    }

    Vector<Vector<PPToken>> arguments;
    if (!collect_arguments(*macro, &arguments)) {
        push_token(token);
        return false;
    }

    Vector<PPToken> expansion;
    substitute(*macro, arguments, &expansion);
    macro->expanding = true;
    push_expansion(expansion, macro->name);
    return true;
}

bool Preprocessor::collect_arguments(const Macro& macro, Vector<Vector<PPToken>>* out) {
    Vector<PPToken> current;
    int depth = 0;

    for (;;) {
        PPToken token;
        if (!next_raw(&token)) {
            if (diags_) {
                diags_->error(macro.loc, "C0112", "a macro argument list is not closed");
                failed_ = true;
            }
            return false;
        }
        if (token.token.kind == TokenKind::LParen) {
            ++depth;
            current.push_back(token);
            continue;
        }
        if (token.token.kind == TokenKind::RParen) {
            if (depth == 0) {
                out->push_back(current);
                break;
            }
            --depth;
            current.push_back(token);
            continue;
        }
        if (token.token.kind == TokenKind::Comma && depth == 0) {
            out->push_back(current);
            current.clear();
            continue;
        }
        current.push_back(token);
    }

    // A macro with no parameters that is invoked with an empty list has no
    // arguments at all. A macro with one parameter that is invoked with an
    // empty list has one empty argument.
    if (macro.parameters.empty() && out->size() == 1 && (*out)[0].empty()) {
        out->clear();
    } else if (!macro.variadic && macro.parameters.size() == 1 && out->empty()) {
        out->push_back(Vector<PPToken>());
    }

    if (macro.variadic) {
        // The variadic parameter takes everything that is left, with the
        // commas between the arguments kept.
        if (out->size() > macro.parameters.size()) {
            Vector<PPToken> tail;
            for (size_type i = macro.parameters.size(); i < out->size(); ++i) {
                if (i > macro.parameters.size()) {
                    PPToken comma;
                    comma.token.kind = TokenKind::Comma;
                    comma.token.text = ",";
                    tail.push_back(comma);
                }
                const Vector<PPToken>& part = (*out)[i];
                for (size_type k = 0; k < part.size(); ++k) tail.push_back(part[k]);
            }
            out->resize(macro.parameters.size());
            (*out)[macro.parameters.size() - 1] = tail;
        } else {
            while (out->size() < macro.parameters.size()) out->push_back(Vector<PPToken>());
        }
    } else if (out->size() != macro.parameters.size()) {
        if (diags_) {
            diags_->error(macro.loc, "C0113",
                          "the macro was invoked with the wrong number of arguments");
            failed_ = true;
        }
        return false;
    }
    return true;
}

void Preprocessor::substitute(const Macro& macro, const Vector<Vector<PPToken>>& arguments,
                               Vector<PPToken>* out) {
    const Vector<Token>& replacement = macro.replacement;

    for (size_type i = 0; i < replacement.size(); ++i) {
        const Token& token = replacement[i];

        // The # operator turns an argument into a string literal.
        if (token.kind == TokenKind::Hash && macro.function_like && i + 1 < replacement.size()) {
            const int index = parameter_index(macro, replacement[i + 1].text);
            if (index >= 0) {
                PPToken value;
                value.token = stringify(index < static_cast<int>(arguments.size())
                                            ? arguments[index]
                                            : Vector<PPToken>());
                value.token.loc = token.loc;
                value.space_before = out->empty() ? false : true;
                out->push_back(value);
                ++i;
                continue;
            }
        }

        // The ## operator pastes two tokens together.
        if (token.kind == TokenKind::HashHash) {
            if (i + 1 >= replacement.size() || out->empty()) continue;

            Vector<PPToken> right;
            const Token& next = replacement[i + 1];
            const int index = (next.kind == TokenKind::Identifier)
                                  ? parameter_index(macro, next.text)
                                  : -1;
            if (index >= 0) {
                if (index < static_cast<int>(arguments.size())) right = arguments[index];
            } else {
                PPToken single;
                single.token = next;
                single.token.loc = next.loc;
                right.push_back(single);
            }

            if (!right.empty()) {
                PPToken pasted;
                if (paste(out->back(), right[0], &pasted)) {
                    out->back() = pasted;
                } else if (diags_) {
                    diags_->error(token.loc, "C0114",
                                  "the pasted tokens do not form a single token");
                    failed_ = true;
                }
                for (size_type k = 1; k < right.size(); ++k) out->push_back(right[k]);
            }
            ++i;
            continue;
        }

        // A parameter.
        if (token.kind == TokenKind::Identifier && macro.function_like) {
            const int index = parameter_index(macro, token.text);
            if (index >= 0) {
                const bool next_is_paste = (i + 1 < replacement.size() &&
                                            replacement[i + 1].kind == TokenKind::HashHash);
                const bool previous_is_paste = (i > 0 &&
                                                replacement[i - 1].kind == TokenKind::HashHash);
                Vector<PPToken> value = index < static_cast<int>(arguments.size())
                                            ? arguments[index]
                                            : Vector<PPToken>();
                if (next_is_paste || previous_is_paste) {
                    // An argument next to ## is used as it is written.
                    for (size_type k = 0; k < value.size(); ++k) out->push_back(value[k]);
                } else {
                    // Everywhere else the argument is expanded first.
                    Vector<PPToken> expanded;
                    expand_list(value, &expanded);
                    for (size_type k = 0; k < expanded.size(); ++k) out->push_back(expanded[k]);
                }
                continue;
            }
        }

        PPToken single;
        single.token = token;
        single.token.loc = token.loc;
        out->push_back(single);
    }
}

void Preprocessor::expand_list(const Vector<PPToken>& in, Vector<PPToken>* out) {
    // The list is expanded on its own, so a macro inside an argument cannot
    // reach past the end of the argument.
    Vector<PPToken> saved_pushback = pushback_;
    Vector<Frame> saved_frames = frames_;
    const bool saved_isolated = isolated_;

    pushback_.clear();
    frames_.clear();
    isolated_ = true;

    Frame frame;
    frame.tokens = in;
    frame.pos = 0;
    frames_.push_back(frame);

    for (;;) {
        PPToken token;
        if (!next_raw(&token)) break;
        if (expand_macro(token)) continue;
        out->push_back(token);
    }

    pushback_ = saved_pushback;
    frames_ = saved_frames;
    isolated_ = saved_isolated;
}

Token Preprocessor::stringify(const Vector<PPToken>& tokens) {
    // The argument is written out as a string literal, with every run of
    // white space between the tokens collapsed into a single space.
    String spelling;
    spelling.push_back('"');
    for (size_type i = 0; i < tokens.size(); ++i) {
        if (i > 0 && tokens[i].space_before) spelling.push_back(' ');
        const String& text = tokens[i].token.text;
        for (size_type k = 0; k < text.size(); ++k) {
            const char c = text[k];
            if (c == '"' || c == '\\') spelling.push_back('\\');
            spelling.push_back(c);
        }
    }
    spelling.push_back('"');

    // The literal is run through the lexer, so the result carries the same
    // decoded value as any other string literal.
    Token out;
    Lexer lexer(sources_, diags_, spelling.data(), spelling.size());
    if (!lexer.next(&out)) {
        out = Token();
        out.kind = TokenKind::StringLiteral;
        out.text = spelling;
    }
    return out;
}

bool Preprocessor::paste(const PPToken& left, const PPToken& right, PPToken* out) {
    String spelling = left.token.text + right.token.text;

    Lexer lexer(sources_, diags_, spelling.data(), spelling.size());
    Token token;
    if (!lexer.next(&token)) return false;
    if (token.kind == TokenKind::EndOfFile) return false;

    // The two tokens have to form exactly one token.
    Token extra;
    if (lexer.next(&extra) && extra.kind != TokenKind::EndOfFile) return false;

    out->token = token;
    out->token.loc = left.token.loc;
    out->space_before = left.space_before;
    out->at_line_start = false;
    out->from_expansion = true;
    out->no_expand = false;
    return true;
}

// ---------------------------------------------------------------------------
// Conditional expressions
// ---------------------------------------------------------------------------

bool Preprocessor::evaluate_expression(Vector<PPToken> tokens, int64* out) {
    // The "defined" operator is resolved before the macros are expanded.
    Vector<PPToken> resolved;
    for (size_type i = 0; i < tokens.size(); ++i) {
        if (tokens[i].token.kind != TokenKind::Identifier ||
            tokens[i].token.text != "defined") {
            resolved.push_back(tokens[i]);
            continue;
        }
        size_type j = i + 1;
        bool parenthesised = false;
        if (j < tokens.size() && tokens[j].token.kind == TokenKind::LParen) {
            parenthesised = true;
            ++j;
        }
        if (j >= tokens.size() || tokens[j].token.kind != TokenKind::Identifier) {
            if (diags_) {
                diags_->error(tokens[i].token.loc, "C0115",
                              "the defined operator expects a name");
                failed_ = true;
            }
            return false;
        }
        PPToken value;
        value.token.kind = TokenKind::IntegerLiteral;
        value.token.text = macros_.contains(tokens[j].token.text) ? "1" : "0";
        value.token.loc = tokens[j].token.loc;
        resolved.push_back(value);
        ++j;
        if (parenthesised) {
            if (j >= tokens.size() || tokens[j].token.kind != TokenKind::RParen) {
                if (diags_) {
                    diags_->error(tokens[i].token.loc, "C0115",
                                  "the defined operator expects a name in brackets");
                    failed_ = true;
                }
                return false;
            }
            ++j;
        }
        i = j - 1;
    }

    Vector<PPToken> expanded;
    expand_list(resolved, &expanded);

    size_type pos = 0;
    int64 value = 0;
    if (!eval_conditional(expanded, pos, &value)) return false;
    if (pos != expanded.size()) {
        if (diags_) {
            diags_->error(expanded[pos].token.loc, "C0116",
                          "unexpected token in a conditional expression");
            failed_ = true;
        }
        return false;
    }
    *out = value;
    return true;
}

bool Preprocessor::eval_conditional(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 condition = 0;
    if (!eval_logical_or(t, pos, &condition)) return false;
    if (pos < t.size() && t[pos].token.kind == TokenKind::Question) {
        ++pos;
        int64 when_true = 0;
        int64 when_false = 0;
        if (!eval_conditional(t, pos, &when_true)) return false;
        if (pos >= t.size() || t[pos].token.kind != TokenKind::Colon) {
            if (diags_) {
                diags_->error(t[pos].token.loc, "C0116", "expected a colon");
                failed_ = true;
            }
            return false;
        }
        ++pos;
        if (!eval_conditional(t, pos, &when_false)) return false;
        *out = condition ? when_true : when_false;
        return true;
    }
    *out = condition;
    return true;
}

bool Preprocessor::eval_logical_or(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_logical_and(t, pos, &left)) return false;
    while (pos < t.size() && t[pos].token.kind == TokenKind::PipePipe) {
        ++pos;
        int64 right = 0;
        if (!eval_logical_and(t, pos, &right)) return false;
        left = (left || right) ? 1 : 0;
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_logical_and(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_inclusive_or(t, pos, &left)) return false;
    while (pos < t.size() && t[pos].token.kind == TokenKind::AmpAmp) {
        ++pos;
        int64 right = 0;
        if (!eval_inclusive_or(t, pos, &right)) return false;
        left = (left && right) ? 1 : 0;
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_inclusive_or(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_exclusive_or(t, pos, &left)) return false;
    while (pos < t.size() && t[pos].token.kind == TokenKind::Pipe) {
        ++pos;
        int64 right = 0;
        if (!eval_exclusive_or(t, pos, &right)) return false;
        left |= right;
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_exclusive_or(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_and_expr(t, pos, &left)) return false;
    while (pos < t.size() && t[pos].token.kind == TokenKind::Caret) {
        ++pos;
        int64 right = 0;
        if (!eval_and_expr(t, pos, &right)) return false;
        left ^= right;
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_and_expr(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_equality(t, pos, &left)) return false;
    while (pos < t.size() && t[pos].token.kind == TokenKind::Amp) {
        ++pos;
        int64 right = 0;
        if (!eval_equality(t, pos, &right)) return false;
        left &= right;
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_equality(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_relational(t, pos, &left)) return false;
    for (;;) {
        if (pos >= t.size()) break;
        const TokenKind kind = t[pos].token.kind;
        if (kind != TokenKind::EqualEqual && kind != TokenKind::NotEqual) break;
        ++pos;
        int64 right = 0;
        if (!eval_relational(t, pos, &right)) return false;
        left = (kind == TokenKind::EqualEqual) ? (left == right) : (left != right);
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_relational(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_shift(t, pos, &left)) return false;
    for (;;) {
        if (pos >= t.size()) break;
        const TokenKind kind = t[pos].token.kind;
        if (kind != TokenKind::Less && kind != TokenKind::Greater &&
            kind != TokenKind::LessEqual && kind != TokenKind::GreaterEqual) {
            break;
        }
        ++pos;
        int64 right = 0;
        if (!eval_shift(t, pos, &right)) return false;
        switch (kind) {
            case TokenKind::Less: left = (left < right); break;
            case TokenKind::Greater: left = (left > right); break;
            case TokenKind::LessEqual: left = (left <= right); break;
            default: left = (left >= right); break;
        }
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_shift(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_additive(t, pos, &left)) return false;
    for (;;) {
        if (pos >= t.size()) break;
        const TokenKind kind = t[pos].token.kind;
        if (kind != TokenKind::Shl && kind != TokenKind::Shr) break;
        ++pos;
        int64 right = 0;
        if (!eval_additive(t, pos, &right)) return false;
        if (kind == TokenKind::Shl) {
            left = static_cast<int64>(static_cast<uint64>(left) << (right & 63));
        } else {
            left = left >> (right & 63);
        }
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_additive(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_multiplicative(t, pos, &left)) return false;
    for (;;) {
        if (pos >= t.size()) break;
        const TokenKind kind = t[pos].token.kind;
        if (kind != TokenKind::Plus && kind != TokenKind::Minus) break;
        ++pos;
        int64 right = 0;
        if (!eval_multiplicative(t, pos, &right)) return false;
        left = (kind == TokenKind::Plus) ? (left + right) : (left - right);
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_multiplicative(Vector<PPToken>& t, size_type& pos, int64* out) {
    int64 left = 0;
    if (!eval_unary(t, pos, &left)) return false;
    for (;;) {
        if (pos >= t.size()) break;
        const TokenKind kind = t[pos].token.kind;
        if (kind != TokenKind::Star && kind != TokenKind::Slash && kind != TokenKind::Percent) {
            break;
        }
        ++pos;
        int64 right = 0;
        if (!eval_unary(t, pos, &right)) return false;
        if (kind == TokenKind::Star) {
            left = left * right;
        } else {
            if (right == 0) {
                if (diags_) {
                    diags_->error(t[pos].token.loc, "C0117", "division by zero");
                    failed_ = true;
                }
                return false;
            }
            left = (kind == TokenKind::Slash) ? (left / right) : (left % right);
        }
    }
    *out = left;
    return true;
}

bool Preprocessor::eval_unary(Vector<PPToken>& t, size_type& pos, int64* out) {
    if (pos >= t.size()) {
        if (diags_) {
            diags_->error(t[0].token.loc, "C0116", "the expression is not complete");
            failed_ = true;
        }
        return false;
    }
    const TokenKind kind = t[pos].token.kind;
    if (kind == TokenKind::Exclaim || kind == TokenKind::Minus || kind == TokenKind::Plus ||
        kind == TokenKind::Tilde) {
        ++pos;
        int64 value = 0;
        if (!eval_unary(t, pos, &value)) return false;
        switch (kind) {
            case TokenKind::Exclaim: *out = value ? 0 : 1; break;
            case TokenKind::Minus: *out = -value; break;
            case TokenKind::Tilde: *out = ~value; break;
            default: *out = value; break;
        }
        return true;
    }
    return eval_primary(t, pos, out);
}

bool Preprocessor::eval_primary(Vector<PPToken>& t, size_type& pos, int64* out) {
    if (pos >= t.size()) {
        if (diags_) {
            diags_->error(t[t.size() - 1].token.loc, "C0116", "the expression is not complete");
            failed_ = true;
        }
        return false;
    }

    const Token& token = t[pos].token;
    if (token.kind == TokenKind::IntegerLiteral) {
        int64 value = 0;
        if (!parse_integer(token.text, &value)) {
            if (diags_) {
                diags_->error(token.loc, "C0118", "the literal is not an integer");
                failed_ = true;
            }
            return false;
        }
        ++pos;
        *out = value;
        return true;
    }
    if (token.kind == TokenKind::CharacterLiteral) {
        int64 value = 0;
        if (!parse_character(token.text, &value)) {
            if (diags_) {
                diags_->error(token.loc, "C0118", "the character literal is not valid");
                failed_ = true;
            }
            return false;
        }
        ++pos;
        *out = value;
        return true;
    }
    if (token.kind == TokenKind::LParen) {
        ++pos;
        int64 value = 0;
        if (!eval_conditional(t, pos, &value)) return false;
        if (pos >= t.size() || t[pos].token.kind != TokenKind::RParen) {
            if (diags_) {
                diags_->error(token.loc, "C0116", "expected a closing bracket");
                failed_ = true;
            }
            return false;
        }
        ++pos;
        *out = value;
        return true;
    }
    if (token.kind == TokenKind::Identifier) {
        // An identifier that survived the expansion has the value zero, with
        // the exception of the two boolean keywords.
        ++pos;
        if (token.text == "true") {
            *out = 1;
        } else if (token.text == "false") {
            *out = 0;
        } else {
            *out = 0;
        }
        return true;
    }

    if (diags_) {
        diags_->error(token.loc, "C0116", "the expression is not valid here");
        failed_ = true;
    }
    return false;
}

// ---------------------------------------------------------------------------
// The entry point
// ---------------------------------------------------------------------------

bool Preprocessor::run(uint32 file_id, Vector<Token>* out) {
    tokens_.clear();
    failed_ = false;

    if (!load_file_tokens(file_id, &file_tokens_)) return false;
    file_pos_ = 0;
    conditionals_.clear();

    process_current_file();

    if (!conditionals_.empty()) {
        for (size_type i = 0; i < conditionals_.size(); ++i) {
            if (diags_) {
                diags_->error(conditionals_[i].loc, "C0104",
                              "a conditional directive is not closed");
            }
        }
        conditionals_.clear();
        failed_ = true;
    }

    *out = tokens_;
    return !failed_;
}

} // namespace rawr
