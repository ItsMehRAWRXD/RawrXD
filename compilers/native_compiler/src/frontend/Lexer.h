// C++20 lexer for the RawrXD native compiler.
//
// Produces preprocessing tokens. Handles:
//   - identifiers (including universal character names)
//   - pp-numbers (the preprocessor's number grammar, superset of C++ literals)
//   - string/character literals with all C++20 encodings and raw strings
//   - user-defined literal suffixes
//   - all C++20 punctuators including the three-way <=> and digraphs
//   - line-splicing (backslash-newline) and trigraph-free C++20
//   - comments (line, block, nestable block)

#ifndef RAWR_COMPILER_LEXER_H
#define RAWR_COMPILER_LEXER_H

#include "common/Diagnostics.h"
#include "frontend/Token.h"

namespace rawr {

class Lexer {
public:
    Lexer(SourceManager* sources, DiagnosticEngine* diags, uint32 file_id);

    // Reads the next token. Returns false at end of file.
    bool next(Token* out);

    // Peeks the next token without consuming it.
    const Token& peek();

    // Consumes the peeked token.
    Token consume();

    // Current source location.
    SourceLoc current_loc() const;

    // Puts the last token back so the next next() returns it again.
    void unconsume();

    // True when the next token begins a new logical line.
    bool at_line_start() const { return at_line_start_; }

private:
    char peek_char(size_type ahead = 0) const;
    char advance();
    bool at_end() const { return pos_ >= size_; }
    void skip_whitespace_and_comments();
    bool lex_number(Token* out);
    bool lex_string(Token* out, char prefix);
    bool lex_raw_string(Token* out, char prefix);
    bool lex_char_literal(Token* out, char prefix);
    bool lex_identifier(Token* out);
    bool lex_punctuator(Token* out);
    void absorb_udl_suffix(Token* out);
    void handle_line_continuation();
    void mark_line_start();

    SourceManager* sources_ = nullptr;
    DiagnosticEngine* diags_ = nullptr;
    uint32 file_id_ = 0;
    const char* text_ = nullptr;
    size_type size_ = 0;    size_type pos_ = 0;

    bool at_line_start_ = true;
    bool has_peeked_ = false;
    Token peeked_;
};

} // namespace rawr

#endif // RAWR_COMPILER_LEXER_H
