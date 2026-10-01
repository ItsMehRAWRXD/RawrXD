// ============================================================================
// ScopeTree.hpp — RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// One lexical pass over one file yields every structural fact the repository
// index needs: a scope tree, symbol definitions with line spans, call edges,
// include edges, and the identifier set each scope mentions.
//
// This is the AST-aware chunker. It is a real structural analyzer, not a
// text splitter: it tracks comment/string/char-raw-string/preprocessor states,
// so a brace inside a string or a comment cannot open a scope, and it
// separates class bodies from function bodies from initializer lists by
// recording what the scope was introduced with. It is NOT a semantic C++
// parse — no template instantiation, no overload resolution, no type
// checking. The receipt states which of those it is; see CHUNKER and
// FULL_CPP_AST in the measured fields.
// ============================================================================
#pragma once

#include <cstdint>
#include <string>
#include <vector>

namespace rawrxd {
namespace repointel {

enum class ScopeKind : uint8_t {
    TranslationUnit,
    Namespace,
    Class,
    Struct,
    Union,
    Enum,
    Function,
    Block,
    Initializer,
    TemplateBrace,
    Unknown
};

const char* scopeKindName(ScopeKind k);

enum class SymbolKind : uint8_t {
    Function,
    Method,
    Class,
    Struct,
    Union,
    Enum,
    EnumConstant,
    Namespace,
    Macro,
    TypeAlias,
    Variable,
    Field,
    Unknown
};

const char* symbolKindName(SymbolKind k);

// Lexical classes retained after comments and whitespace are dropped.
enum class TokenKind : uint8_t {
    Identifier,
    Keyword,
    Number,
    StringLiteral,
    CharLiteral,
    Directive,
    Punct,
    EndOfFile
};

struct Token {
    TokenKind kind = TokenKind::EndOfFile;
    uint32_t begin = 0;  // byte offset into the file buffer
    uint32_t length = 0;
    uint32_t line = 1;   // 1-based
};

// A comment, retained as a span so the indexer can index its words without
// the analyzer having to hold comment text for every file at once.
struct CommentSpan {
    uint32_t begin = 0;
    uint32_t length = 0;
    uint32_t line = 1;
};

// A contiguous, scope-accurate region of one file. Function bodies, class
// bodies, namespace bodies, enum bodies and initializer lists are all chunks.
struct FileChunk {
    std::string qualified;  // ns::Outer::Inner::name
    std::string name;       // innermost name only
    ScopeKind   scope = ScopeKind::Unknown;
    SymbolKind  symbolKind = SymbolKind::Unknown;
    uint32_t    beginLine = 0;
    uint32_t    endLine = 0;
    uint32_t    beginByte = 0;
    uint32_t    endByte = 0;
    uint32_t    depth = 0;
};

struct FileSymbol {
    std::string name;
    std::string qualified;
    SymbolKind  kind = SymbolKind::Unknown;
    uint32_t    beginLine = 0;
    uint32_t    endLine = 0;
    uint32_t    beginByte = 0;
    uint32_t    endByte = 0;
    uint32_t    chunkIndex = 0xFFFFFFFFu;
};

struct IncludeEdge {
    std::string spelling;  // exactly as written between the delimiters
    bool        angled = false;
    uint32_t    line = 0;
    uint32_t    resolvedFileIdx = 0xFFFFFFFFu;  // filled by the indexer
};

// Identifiers unique to this file, in first-appearance order. Index space for
// every local identifier reference in this file.
struct FileAnalysis {
    std::vector<Token>                tokens;
    std::vector<CommentSpan>          comments;
    std::vector<FileChunk>            chunks;
    std::vector<FileSymbol>           symbols;
    std::vector<IncludeEdge>          includes;
    std::vector<std::string>          uniqueIdents;
    std::vector<uint32_t>             identLocalIndex;   // local id -> uniqueIdents slot
    std::vector<uint32_t>             chunkIdents;       // chunk -> local ids, deduped
    std::vector<uint32_t>             chunkIdentCursor;  // internal: chunkIdents offsets
    // (chunkIndex, localIdentIndex) — a call edge when the callee name is
    // followed by '(' and is not a language keyword.
    std::vector<std::pair<uint32_t, uint32_t>> calls;
    uint32_t                          lineCount = 0;
    uint32_t                          tokenCount = 0;
    uint32_t                          commentCount = 0;
    uint32_t                          unbalancedBraces = 0;
    uint32_t                          openStringAtEof = 0;
    bool                              analyzed = false;
};

// Analyze one already-read buffer. `label` is used only for diagnostics.
// Never throws; a truncated or non-UTF8 buffer yields a partial analysis with
// unbalancedBraces / openStringAtEof reporting the truncation.
FileAnalysis analyzeSource(const std::string& text);

}  // namespace repointel
}  // namespace rawrxd
