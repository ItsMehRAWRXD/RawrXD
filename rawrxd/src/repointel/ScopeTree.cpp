// ============================================================================
// ScopeTree.cpp — RAWRXD_REPOSITORY_INTELLIGENCE_001
//
// Two stages over one buffer.
//
// Stage 1 lexes: it drops comments and whitespace, keeps code tokens with byte
// offsets and line numbers, records comment spans for the search index, and
// classifies every token. It tracks line comments, block comments, string
// literals, character literals, raw strings (R"delim(...)delim") and
// preprocessor directives including backslash continuations. A brace inside any
// of those never becomes a token, so it can never open a scope.
//
// Stage 2 walks the token stream in statement segments delimited by ; { } and
// classifies each segment by its head token: namespace, class/struct/union
// body, enum body, function body, or anonymous block. Each scope owns an
// identifier bucket, so chunk-level identifier sets are scope-accurate rather
// than file-accurate.
//
// This is a structural scope analyzer. It is not a semantic C++ parse: no
// template instantiation, no overload resolution, no type checking. Field
// detection is a heuristic and is labelled FIELD_DETECTION=HEURISTIC in the
// receipt.
// ============================================================================
#include "repointel/ScopeTree.hpp"

#include <algorithm>
#include <cstring>
#include <unordered_map>
#include <unordered_set>

namespace rawrxd {
namespace repointel {
namespace {

bool isIdentStart(char c) {
    return (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' ||
           static_cast<unsigned char>(c) >= 0x80;
}
bool isIdentBody(char c) { return isIdentStart(c) || (c >= '0' && c <= '9'); }
bool isDigit(char c) { return c >= '0' && c <= '9'; }

const std::unordered_set<std::string>& keywords() {
    static const std::unordered_set<std::string> kw = {
        "alignas", "alignof", "and", "and_eq", "asm", "auto", "bitand",
        "bitor", "bool", "break", "case", "catch", "char", "char8_t",
        "char16_t", "char32_t", "class", "compl", "concept", "const",
        "consteval", "constexpr", "constinit", "const_cast", "continue",
        "co_await", "co_return", "co_yield", "decltype", "default", "delete",
        "do", "double", "dynamic_cast", "else", "enum", "explicit", "export",
        "extern", "false", "float", "for", "friend", "goto", "if", "inline",
        "int", "long", "mutable", "namespace", "new", "noexcept", "not",
        "not_eq", "nullptr", "operator", "or", "or_eq", "private",
        "protected", "public", "register", "reinterpret_cast", "requires",
        "restrict", "return", "short", "signed", "sizeof", "static",
        "static_assert", "static_cast", "struct", "switch", "template",
        "this", "thread_local", "throw", "true", "try", "typedef", "typeid",
        "typename", "union", "unsigned", "using", "virtual", "void", "volatile",
        "wchar_t", "while", "xor", "xor_eq", "interface", "property", "event",
        "delegate", "value", "ref", "params", "__int64", "__int32", "__int16",
        "__int8", "nullptr_t"};
    return kw;
}

// Keywords after which an identifier followed by '(' is a use, never a
// declaration.
const std::unordered_set<std::string>& postfixKeywords() {
    static const std::unordered_set<std::string> s = {
        "return", "case",  "delete",  "sizeof", "new",    "throw",
        "co_return", "co_await", "and", "or", "not",  "else",
        "do",     "goto",  "asm",     "alignas", "typeid", "decltype",
        "static_cast", "dynamic_cast", "const_cast", "reinterpret_cast",
        "requires", "noexcept", "if", "while", "switch", "for", "catch",
        "typedef", "using", "export", "explicit", "friend", "virtual",
        "static", "inline", "constexpr", "consteval", "operator", "template",
        "class", "struct", "enum", "namespace", "union", "typename"};
    return s;
}

bool isTypeQualifier(const std::string& s) {
    return s == "static" || s == "extern" || s == "inline" || s == "virtual" ||
           s == "explicit" || s == "constexpr" || s == "consteval" ||
           s == "friend" || s == "mutable" || s == "const" || s == "volatile" ||
           s == "typename" || s == "noexcept" || s == "override" ||
           s == "final" || s == "thread_local" || s == "register" ||
           s == "__declspec" || s == "__forceinline" || s == "__inline" ||
           s == "__restrict" || s == "restrict" || s == "_Noreturn";
}

struct Lexer {
    const std::string& src;
    size_t             pos = 0;
    uint32_t           line = 1;
    FileAnalysis*      out = nullptr;

    Lexer(const std::string& s, FileAnalysis* o) : src(s), out(o) {}

    bool eof() const { return pos >= src.size(); }
    char cur() const { return pos < src.size() ? src[pos] : '\0'; }
    char at(size_t k) const { return pos + k < src.size() ? src[pos + k] : '\0'; }

    void bump() {
        if (pos >= src.size()) return;
        if (src[pos] == '\n') ++line;
        ++pos;
    }

    void run() {
        while (!eof()) {
            const char c = cur();

            if (c == '\n' || c == '\r' || c == ' ' || c == '\t' || c == '\f' ||
                c == '\v') {
                bump();
                continue;
            }

            if (c == '/' && at(1) == '/') {
                const uint32_t startLine = line;
                const size_t   startPos = pos;
                while (!eof() && cur() != '\n') bump();
                out->comments.push_back({static_cast<uint32_t>(startPos),
                                         static_cast<uint32_t>(pos - startPos),
                                         startLine});
                ++out->commentCount;
                continue;
            }

            if (c == '/' && at(1) == '*') {
                const uint32_t startLine = line;
                const size_t   startPos = pos;
                bump();
                bump();
                while (!eof() && !(cur() == '*' && at(1) == '/')) bump();
                if (!eof()) {
                    bump();
                    bump();
                } else {
                    ++out->unbalancedBraces;
                }
                out->comments.push_back({static_cast<uint32_t>(startPos),
                                         static_cast<uint32_t>(pos - startPos),
                                         startLine});
                ++out->commentCount;
                continue;
            }

            // Raw string, with optional encoding prefix (R, LR, u8R, uR, UR).
            if ((c == 'R' || c == 'L' || c == 'u' || c == 'U') &&
                (at(1) == '"' ||
                 ((at(1) == 'u' || at(1) == 'U' || at(1) == '8') &&
                  at(2) == '"'))) {
                const size_t q = (at(1) == '"') ? 1u : 2u;
                if (at(q) == '"') {
                    size_t      d = pos + q + 1;
                    std::string delim;
                    while (d < src.size() && src[d] != '(' &&
                           delim.size() < 16 && src[d] != '\\' &&
                           src[d] != ' ' && src[d] != ')') {
                        delim.push_back(src[d]);
                        ++d;
                    }
                    if (d < src.size() && src[d] == '(') {
                        const uint32_t    startLine = line;
                        const size_t      startPos = pos;
                        const std::string closer = ")" + delim + "\"";
                        size_t            k = d + 1;
                        bool              closed = false;
                        while (k < src.size()) {
                            if (src[k] == ')' &&
                                k + closer.size() <= src.size() &&
                                src.compare(k, closer.size(), closer) == 0) {
                                k += closer.size();
                                closed = true;
                                break;
                            }
                            if (src[k] == '\n') ++line;
                            ++k;
                        }
                        out->tokens.push_back(
                            {TokenKind::StringLiteral,
                             static_cast<uint32_t>(startPos),
                             static_cast<uint32_t>(k - startPos), startLine});
                        ++out->tokenCount;
                        while (pos < k) bump();
                        if (!closed) ++out->openStringAtEof;
                        continue;
                    }
                }
            }

            if (c == '"') {
                const uint32_t startLine = line;
                const size_t   startPos = pos;
                bump();
                bool closed = false;
                while (!eof()) {
                    if (cur() == '\\') {
                        bump();
                        if (!eof()) bump();
                        continue;
                    }
                    if (cur() == '"') {
                        bump();
                        closed = true;
                        break;
                    }
                    if (cur() == '\n') break;
                    bump();
                }
                if (!closed) ++out->openStringAtEof;
                out->tokens.push_back(
                    {TokenKind::StringLiteral, static_cast<uint32_t>(startPos),
                     static_cast<uint32_t>(pos - startPos), startLine});
                ++out->tokenCount;
                continue;
            }

            if (c == '\'' && !(isDigit(at(1)) && isIdentBody(at(2)))) {
                const uint32_t startLine = line;
                const size_t   startPos = pos;
                bump();
                bool closed = false;
                while (!eof()) {
                    if (cur() == '\\') {
                        bump();
                        if (!eof()) bump();
                        continue;
                    }
                    if (cur() == '\'') {
                        bump();
                        closed = true;
                        break;
                    }
                    if (cur() == '\n') break;
                    bump();
                }
                if (!closed) ++out->openStringAtEof;
                out->tokens.push_back(
                    {TokenKind::CharLiteral, static_cast<uint32_t>(startPos),
                     static_cast<uint32_t>(pos - startPos), startLine});
                ++out->tokenCount;
                continue;
            }

            if (c == '#') {
                const uint32_t startLine = line;
                const size_t   startPos = pos;
                bump();
                while (!eof()) {
                    if (cur() == '\\') {
                        bump();
                        if (cur() == '\r') bump();
                        if (cur() == '\n') bump();
                        continue;
                    }
                    if (cur() == '/' && at(1) == '/') {
                        while (!eof() && cur() != '\n') bump();
                        continue;
                    }
                    if (cur() == '/' && at(1) == '*') {
                        bump();
                        bump();
                        while (!eof() && !(cur() == '*' && at(1) == '/')) bump();
                        if (!eof()) {
                            bump();
                            bump();
                        }
                        continue;
                    }
                    if (cur() == '\n') break;
                    bump();
                }
                out->tokens.push_back(
                    {TokenKind::Directive, static_cast<uint32_t>(startPos),
                     static_cast<uint32_t>(pos - startPos), startLine});
                ++out->tokenCount;
                continue;
            }

            if (isIdentStart(c)) {
                const uint32_t startLine = line;
                const size_t   startPos = pos;
                while (!eof() && isIdentBody(cur())) bump();
                const std::string text = src.substr(startPos, pos - startPos);
                out->tokens.push_back({keywords().count(text) ? TokenKind::Keyword
                                                            : TokenKind::Identifier,
                                       static_cast<uint32_t>(startPos),
                                       static_cast<uint32_t>(pos - startPos),
                                       startLine});
                ++out->tokenCount;
                continue;
            }

            if (isDigit(c) || (c == '.' && isDigit(at(1)))) {
                const uint32_t startLine = line;
                const size_t   startPos = pos;
                bump();
                while (!eof()) {
                    const char d = cur();
                    if (isIdentBody(d) || d == '.') {
                        bump();
                        continue;
                    }
                    if ((d == '+' || d == '-') && pos > startPos) {
                        const char prev = src[pos - 1];
                        if (prev == 'e' || prev == 'E' || prev == 'p' ||
                            prev == 'P') {
                            bump();
                            continue;
                        }
                    }
                    break;
                }
                out->tokens.push_back(
                    {TokenKind::Number, static_cast<uint32_t>(startPos),
                     static_cast<uint32_t>(pos - startPos), startLine});
                ++out->tokenCount;
                continue;
            }

            out->tokens.push_back(
                {TokenKind::Punct, static_cast<uint32_t>(pos), 1, line});
            ++out->tokenCount;
            bump();
        }

        out->tokens.push_back(
            {TokenKind::EndOfFile, static_cast<uint32_t>(src.size()), 0, line});
        out->lineCount = line;
    }
};

std::string tokenText(const std::string& src, const Token& t) {
    if (static_cast<size_t>(t.begin) + t.length > src.size())
        return std::string();
    return src.substr(t.begin, t.length);
}

char punctChar(const std::string& src, const Token& t) {
    return (t.kind == TokenKind::Punct && t.length == 1) ? src[t.begin] : '\0';
}

struct OpenScope {
    ScopeKind  kind = ScopeKind::Unknown;
    SymbolKind symKind = SymbolKind::Unknown;
    std::string name;
    uint32_t   beginLine = 0;
    uint32_t   beginByte = 0;
    uint32_t   depth = 0;
    uint32_t   chunkIndex = 0xFFFFFFFFu;  // into out->chunks
    std::vector<std::pair<std::string, uint32_t>> enumConstants;
};

struct Stage2 {
    const std::string&        src;
    const std::vector<Token>& toks;
    FileAnalysis*             out;

    std::vector<OpenScope>                    stack;
    std::vector<std::vector<uint32_t>>        buckets;
    std::unordered_map<std::string, uint32_t> localIdent;
    std::vector<std::vector<uint32_t>>        chunkIdents;
    std::vector<std::pair<uint32_t, uint32_t>> calls;

    Stage2(const std::string& s, const std::vector<Token>& t, FileAnalysis* o)
        : src(s), toks(t), out(o) {
        stack.reserve(64);
        buckets.reserve(64);
        stack.push_back(OpenScope{});
        buckets.emplace_back();
    }

    uint32_t intern(const std::string& s) {
        auto it = localIdent.find(s);
        if (it != localIdent.end()) return it->second;
        const uint32_t id = static_cast<uint32_t>(out->uniqueIdents.size());
        out->uniqueIdents.push_back(s);
        localIdent.emplace(s, id);
        return id;
    }

    std::string qualified(const std::string& leaf) const {
        std::string q;
        for (size_t i = 1; i < stack.size(); ++i) {
            const std::string& n = stack[i].name;
            if (n.empty()) continue;
            if (!q.empty()) q += "::";
            q += n;
        }
        if (!leaf.empty()) {
            if (!q.empty()) q += "::";
            q += leaf;
        }
        return q;
    }

    // First significant token of a statement segment, skipping leading template
    // argument lists, attributes and declspecs.
    size_t segmentHead(size_t a, size_t b) const {
        size_t i = a;
        while (i < b) {
            const char c = punctChar(src, toks[i]);
            if (c == '<' || c == '(' || c == '[') {
                const char close = (c == '<') ? '>' : (c == '(') ? ')' : ']';
                int    depth = 0;
                size_t k = i;
                for (; k < b; ++k) {
                    const char d = punctChar(src, toks[k]);
                    if (d == c) {
                        ++depth;
                    } else if (d == close) {
                        if (--depth == 0) {
                            ++k;
                            break;
                        }
                    }
                }
                if (k >= b) return b;
                i = k;
                continue;
            }
            if (toks[i].kind == TokenKind::Identifier ||
                toks[i].kind == TokenKind::Keyword)
                return i;
            ++i;
        }
        return b;
    }

    struct SegInfo {
        std::vector<uint32_t>     idents;
        bool                     hasTopParen = false;
        long                     parenIndex = -1;
        long                     nameIndex = -1;
        bool                     hasTopAngle = false;
        bool                     hasAssign = false;
        bool                     hasMemberAccess = false;
        bool                     hasCallAfter = false;
        std::vector<std::string> topNames;
    };

    SegInfo scan(size_t a, size_t b) {
        SegInfo si;
        int     paren = 0, angle = 0, brack = 0;
        for (size_t i = a; i < b; ++i) {
            const Token& t = toks[i];
            if (t.kind == TokenKind::Punct) {
                const char c = punctChar(src, t);
                if (c == '(') {
                    if (paren == 0 && angle == 0 && brack == 0 && !si.hasTopParen) {
                        si.hasTopParen = true;
                        si.parenIndex = static_cast<long>(i);
                        si.nameIndex = static_cast<long>(i) - 1;
                    }
                    ++paren;
                    continue;
                }
                if (c == ')') { --paren; continue; }
                if (c == '<') {
                    if (paren == 0 && angle == 0) si.hasTopAngle = true;
                    ++angle;
                    continue;
                }
                if (c == '>') { --angle; continue; }
                if (c == '[') { ++brack; continue; }
                if (c == ']') { --brack; continue; }
                if (c == '=' && paren == 0 && angle == 0) si.hasAssign = true;
                if (c == '.' && paren == 0 && angle == 0) si.hasMemberAccess = true;
                if (c == '-' && paren == 0 && angle == 0 && i + 1 < b &&
                    punctChar(src, toks[i + 1]) == '>')
                    si.hasMemberAccess = true;
                continue;
            }
            if (t.kind == TokenKind::Identifier) {
                const uint32_t id = intern(tokenText(src, t));
                si.idents.push_back(id);
                if (paren == 0 && angle == 0 && brack == 0)
                    si.topNames.push_back(tokenText(src, t));
                continue;
            }
            if (t.kind == TokenKind::Keyword && paren == 0 && angle == 0 &&
                i + 1 < b && punctChar(src, toks[i + 1]) == '(' &&
                postfixKeywords().count(tokenText(src, t)) != 0)
                si.hasCallAfter = true;
        }
        return si;
    }

    // After the parameter list, only qualifiers and a trailing return type may
    // appear before the body brace.
    bool tailIsQualifiersOnly(long parenIndex, size_t b) const {
        size_t i = static_cast<size_t>(parenIndex);
        int    depth = 0;
        bool   closed = false;
        for (; i < b; ++i) {
            const char c = punctChar(src, toks[i]);
            if (c == '(') {
                ++depth;
            } else if (c == ')') {
                if (--depth == 0) {
                    closed = true;
                    ++i;
                    break;
                }
            }
        }
        if (!closed) return false;
        for (size_t k = i; k < b; ++k) {
            const Token& t = toks[k];
            if (t.kind == TokenKind::Punct) {
                const char c = punctChar(src, t);
                if (c == ';' || c == '=' || c == ',' || c == '{' || c == '}')
                    return false;
                continue;  // ':', '*', '&', '>', '~' belong to a return type
            }
            if (t.kind == TokenKind::Keyword) {
                const std::string kw = tokenText(src, t);
                if (kw == "const" || kw == "noexcept" || kw == "override" ||
                    kw == "final" || kw == "volatile" || kw == "throw" ||
                    kw == "mutable" || kw == "constexpr")
                    continue;
                return false;
            }
            // Identifiers here are a trailing return type.
        }
        return true;
    }

    void emitSymbol(const std::string& name, SymbolKind kind, uint32_t bLine,
                    uint32_t bByte, uint32_t eLine, uint32_t eByte,
                    uint32_t chunkIndex) {
        if (name.empty()) return;
        FileSymbol s;
        s.name = name;
        s.qualified = qualified(name);
        s.kind = kind;
        s.beginLine = bLine;
        s.endLine = eLine;
        s.beginByte = bByte;
        s.endByte = eByte;
        s.chunkIndex = chunkIndex;
        out->symbols.push_back(std::move(s));
    }

    uint32_t pushChunk(ScopeKind kind, SymbolKind symKind, const std::string& name,
                       uint32_t bLine, uint32_t bByte, uint32_t depth,
                       std::vector<uint32_t> idents) {
        FileChunk c;
        c.qualified = qualified(name);
        c.name = name;
        c.scope = kind;
        c.symbolKind = symKind;
        c.beginLine = bLine;
        c.endLine = bLine;
        c.beginByte = bByte;
        c.endByte = bByte;
        c.depth = depth;
        std::sort(idents.begin(), idents.end());
        idents.erase(std::unique(idents.begin(), idents.end()), idents.end());
        chunkIdents.push_back(std::move(idents));
        out->chunks.push_back(std::move(c));
        return static_cast<uint32_t>(out->chunks.size() - 1);
    }

    void closeScope(uint32_t endLine, uint32_t endByte) {
        const OpenScope sc = stack.back();
        stack.pop_back();
        std::vector<uint32_t> ids = buckets.back();
        buckets.pop_back();

        if (!sc.name.empty() && sc.chunkIndex != 0xFFFFFFFFu &&
            sc.chunkIndex < out->chunks.size()) {
            // The chunk was created when the scope opened; close it here rather
            // than emitting a second one for the same scope.
            FileChunk& c = out->chunks[sc.chunkIndex];
            c.endLine = endLine;
            c.endByte = endByte;
            std::vector<uint32_t>& own = chunkIdents[sc.chunkIndex];
            own.insert(own.end(), ids.begin(), ids.end());
            std::sort(own.begin(), own.end());
            own.erase(std::unique(own.begin(), own.end()), own.end());
            emitSymbol(sc.name, sc.symKind, sc.beginLine, sc.beginByte, endLine,
                       endByte, sc.chunkIndex);
        }
        for (const auto& ec : sc.enumConstants) {
            FileSymbol s;
            s.name = ec.first;
            s.qualified = qualified(ec.first);
            s.kind = SymbolKind::EnumConstant;
            s.beginLine = ec.second;
            s.endLine = ec.second;
            out->symbols.push_back(std::move(s));
        }
    }

    void flushChunkIdents() {
        out->chunkIdentCursor.clear();
        for (const auto& v : chunkIdents) {
            out->chunkIdentCursor.push_back(
                static_cast<uint32_t>(out->chunkIdents.size()));
            out->chunkIdents.insert(out->chunkIdents.end(), v.begin(), v.end());
        }
        out->chunkIdentCursor.push_back(
            static_cast<uint32_t>(out->chunkIdents.size()));
        chunkIdents.clear();
    }

    size_t directiveWordEnd(const std::string& dir, size_t from) const {
        size_t k = from;
        while (k < dir.size() && (dir[k] == ' ' || dir[k] == '\t')) ++k;
        const size_t w = k;
        while (k < dir.size() && isIdentBody(dir[k])) ++k;
        return k == w ? std::string::npos : w;
    }

    void handleDirective(const Token& t) {
        const std::string dir = tokenText(src, t);
        if (dir.size() < 2 || dir[0] != '#') return;
        const size_t ws = directiveWordEnd(dir, 1);
        if (ws == std::string::npos) return;
        std::string word;
        for (size_t k = ws; k < dir.size() && isIdentBody(dir[k]); ++k)
            word.push_back(dir[k]);

        if (word == "define") {
            const size_t ns = directiveWordEnd(dir, ws + word.size());
            if (ns == std::string::npos) return;
            std::string name;
            for (size_t k = ns; k < dir.size() && isIdentBody(dir[k]); ++k)
                name.push_back(dir[k]);
            emitSymbol(name, SymbolKind::Macro, t.line, t.begin, t.line, t.begin,
                       0xFFFFFFFFu);
        }
        return;
    }

    void handleIncludeDirective(const Token& t) {
        const std::string dir = tokenText(src, t);
        if (dir.size() < 2 || dir[0] != '#') return;
        const size_t ws = directiveWordEnd(dir, 1);
        if (ws == std::string::npos) return;
        std::string word;
        for (size_t k = ws; k < dir.size() && isIdentBody(dir[k]); ++k)
            word.push_back(dir[k]);
        if (word != "include" && word != "include_next" && word != "import")
            return;
        // The lexer consumes the whole directive line as one token, so the
        // target is parsed out of the directive text rather than taken from the
        // next token.
        size_t p = ws + word.size();
        while (p < dir.size() && (dir[p] == ' ' || dir[p] == '\t')) ++p;
        if (p >= dir.size()) return;
        const char open = dir[p];
        if (open != '"' && open != '<') return;
        const char close = (open == '"') ? '"' : '>';
        const size_t start = ++p;
        while (p < dir.size() && dir[p] != close) ++p;
        if (p >= dir.size() || p == start) return;
        IncludeEdge e;
        e.spelling = dir.substr(start, p - start);
        e.angled = (open == '<');
        e.line = t.line;
        out->includes.push_back(std::move(e));
    }

    SymbolKind functionKindForParent() const {
        const ScopeKind parent = stack.size() >= 2
                                     ? stack[stack.size() - 2].kind
                                     : ScopeKind::TranslationUnit;
        if (parent == ScopeKind::Class || parent == ScopeKind::Struct ||
            parent == ScopeKind::Union)
            return SymbolKind::Method;
        return SymbolKind::Function;
    }

    void run() {
        const size_t n = toks.size();
        size_t       segStart = 0;
        size_t       i = 0;

        while (i < n && toks[i].kind != TokenKind::EndOfFile) {
            const Token& t = toks[i];

            if (t.kind == TokenKind::Directive) {
                handleDirective(t);
                handleIncludeDirective(t);
                segStart = i + 1;
                ++i;
                continue;
            }

            if (t.kind == TokenKind::Identifier) {
                const std::string name = tokenText(src, t);
                const uint32_t    id = intern(name);
                buckets.back().push_back(id);
                if (i + 1 < n && punctChar(src, toks[i + 1]) == '(') {
                    const bool call =
                        i == 0 ||
                        postfixKeywords().count(tokenText(src, toks[i - 1])) == 0;
                    if (call) {
                        // Attribute the call to the innermost function scope.
                        for (size_t k = stack.size(); k-- > 0;) {
                            if (stack[k].kind != ScopeKind::Function) continue;
                            calls.emplace_back(stack[k].chunkIndex, id);
                            break;
                        }
                    }
                }
                ++i;
                continue;
            }

            const char c = punctChar(src, t);

            if (c == '{') {
                const size_t  head = segmentHead(segStart, i);
                const SegInfo si = scan(segStart, i);

                std::string headWord;
                if (head < i &&
                    (toks[head].kind == TokenKind::Keyword ||
                     toks[head].kind == TokenKind::Identifier))
                    headWord = tokenText(src, toks[head]);

                OpenScope sc;
                sc.depth = static_cast<uint32_t>(stack.size());
                bool named = false;

                if (headWord == "namespace") {
                    sc.kind = ScopeKind::Namespace;
                    sc.symKind = SymbolKind::Namespace;
                    if (head + 1 < i &&
                        toks[head + 1].kind == TokenKind::Identifier)
                        sc.name = tokenText(src, toks[head + 1]);
                    named = true;
                } else if (headWord == "class" || headWord == "struct" ||
                           headWord == "union") {
                    sc.kind = headWord == "class"   ? ScopeKind::Class
                              : headWord == "struct" ? ScopeKind::Struct
                                                    : ScopeKind::Union;
                    sc.symKind = headWord == "class"   ? SymbolKind::Class
                                 : headWord == "struct" ? SymbolKind::Struct
                                                        : SymbolKind::Union;
                    if (head + 1 < i &&
                        toks[head + 1].kind == TokenKind::Identifier)
                        sc.name = tokenText(src, toks[head + 1]);
                    named = true;
                } else if (headWord == "enum") {
                    sc.kind = ScopeKind::Enum;
                    sc.symKind = SymbolKind::Enum;
                    size_t k = head + 1;
                    if (k < i && toks[k].kind == TokenKind::Keyword &&
                        tokenText(src, toks[k]) == "class")
                        ++k;
                    if (k < i && toks[k].kind == TokenKind::Identifier)
                        sc.name = tokenText(src, toks[k]);
                    named = true;
                } else if (si.hasTopParen && si.nameIndex >= 0 &&
                           toks[static_cast<size_t>(si.nameIndex)].kind ==
                               TokenKind::Identifier &&
                           tailIsQualifiersOnly(si.parenIndex, i)) {
                    const size_t ni = static_cast<size_t>(si.nameIndex);
                    sc.kind = ScopeKind::Function;
                    sc.symKind = functionKindForParent();
                    sc.name = tokenText(src, toks[ni]);
                    sc.beginLine = toks[ni].line;
                    sc.beginByte = toks[ni].begin;
                    named = true;
                }

                if (named) {
                    if (sc.beginLine == 0) {
                        sc.beginLine = toks[head < i ? head : i].line;
                        sc.beginByte = toks[head < i ? head : i].begin;
                    }
                    std::vector<uint32_t> merged = si.idents;
                    merged.insert(merged.end(), buckets.back().begin(),
                                  buckets.back().end());
                    sc.chunkIndex = pushChunk(sc.kind, sc.symKind, sc.name,
                                              sc.beginLine, sc.beginByte,
                                              sc.depth, std::move(merged));
                    stack.push_back(sc);
                    buckets.emplace_back();
                } else {
                    stack.push_back(sc);
                    buckets.emplace_back();
                }

                segStart = i + 1;
                ++i;
                continue;
            }

            if (c == '}') {
                if (stack.size() > 1) {
                    if (stack.back().kind == ScopeKind::Enum) {
                        for (const uint32_t id : buckets.back()) {
                            const std::string& nm = out->uniqueIdents[id];
                            if (nm == "enum" || nm == "class") continue;
                            stack.back().enumConstants.emplace_back(nm, t.line);
                        }
                        std::sort(
                            stack.back().enumConstants.begin(),
                            stack.back().enumConstants.end(),
                            [](const std::pair<std::string, uint32_t>& a,
                               const std::pair<std::string, uint32_t>& b) {
                                return a.first < b.first;
                            });
                        stack.back().enumConstants.erase(
                            std::unique(stack.back().enumConstants.begin(),
                                        stack.back().enumConstants.end(),
                                        [](const std::pair<std::string, uint32_t>& a,
                                           const std::pair<std::string, uint32_t>& b) {
                                            return a.first == b.first;
                                        }),
                            stack.back().enumConstants.end());
                    }
                    closeScope(t.line, t.begin);
                } else {
                    ++out->unbalancedBraces;
                }
                segStart = i + 1;
                ++i;
                continue;
            }

            if (c == ';') {
                classifyDeclarationSegment(segStart, i);
                segStart = i + 1;
                ++i;
                continue;
            }

            ++i;
        }

        while (stack.size() > 1) {
            closeScope(out->lineCount, static_cast<uint32_t>(src.size()));
            ++out->unbalancedBraces;
        }
        flushChunkIdents();
        out->calls = std::move(calls);
    }

    void classifyDeclarationSegment(size_t a, size_t b) {
        if (a >= b) return;
        const size_t head = segmentHead(a, b);
        if (head >= b) return;
        if (toks[head].kind != TokenKind::Keyword &&
            toks[head].kind != TokenKind::Identifier)
            return;
        const std::string headWord = tokenText(src, toks[head]);

        static const std::unordered_set<std::string> skipHeads = {
            "typedef", "using",     "template",  "public",  "private",
            "protected", "friend",  "static_assert", "return", "delete",
            "sizeof",  "if",        "for",       "while",   "switch",
            "do",      "goto",      "try",       "case",    "break",
            "continue", "throw",    "extern",   "class",   "struct",
            "enum",    "union",     "namespace", "static_assert", "export",
            "constexpr", "consteval", "inline",  "explicit", "goto",
            "co_return", "co_await", "co_yield", "asm", "operator"};

        if (headWord == "typedef" || headWord == "using") {
            if (headWord == "using" && head + 1 < b &&
                punctChar(src, toks[head + 1]) == ':')
                return;  // using-directive
            std::string name;
            uint32_t    line = toks[head].line;
            for (size_t k = b; k > head; --k) {
                if (toks[k - 1].kind != TokenKind::Identifier) continue;
                const std::string s = tokenText(src, toks[k - 1]);
                if (keywords().count(s)) continue;
                name = s;
                line = toks[k - 1].line;
                break;
            }
            if (!name.empty())
                emitSymbol(name, SymbolKind::TypeAlias, line, 0, line, 0,
                           0xFFFFFFFFu);
            return;
        }
        if (headWord == "namespace") {
            if (head + 2 < b && toks[head + 1].kind == TokenKind::Identifier &&
                punctChar(src, toks[head + 2]) == '=')
                emitSymbol(tokenText(src, toks[head + 1]), SymbolKind::TypeAlias,
                           toks[head].line, 0, toks[head].line, 0, 0xFFFFFFFFu);
            return;
        }
        if (skipHeads.count(headWord)) return;

        const SegInfo si = scan(a, b);
        if (si.hasTopParen || si.hasMemberAccess || si.hasCallAfter) return;
        if (si.topNames.empty()) return;

        const ScopeKind parent =
            stack.size() >= 2 ? stack[stack.size() - 2].kind
                              : ScopeKind::TranslationUnit;

        std::string name;
        uint32_t    line = toks[b - 1].line;
        if (si.hasAssign) {
            size_t eq = a;
            for (size_t k = a; k < b; ++k) {
                if (punctChar(src, toks[k]) == '=') {
                    eq = k;
                    break;
                }
            }
            for (size_t k = eq; k-- > a;) {
                if (punctChar(src, toks[k]) == ',' ||
                    punctChar(src, toks[k]) == '(')
                    break;
                if (toks[k].kind == TokenKind::Identifier) {
                    name = tokenText(src, toks[k]);
                    line = toks[k].line;
                    break;
                }
            }
        } else {
            name = si.topNames.back();
            for (size_t k = b; k > a; --k) {
                if (toks[k - 1].kind == TokenKind::Identifier) {
                    line = toks[k - 1].line;
                    break;
                }
            }
        }
        if (name.empty() || isTypeQualifier(name) || keywords().count(name))
            return;

        if (parent == ScopeKind::Class || parent == ScopeKind::Struct ||
            parent == ScopeKind::Union) {
            if (si.hasTopAngle) return;  // `Type<T> x;` — not a field
            emitSymbol(name, SymbolKind::Field, line, 0, line, 0, 0xFFFFFFFFu);
        } else if (parent == ScopeKind::Namespace ||
                   parent == ScopeKind::TranslationUnit) {
            if (si.hasTopAngle) return;
            emitSymbol(name, SymbolKind::Variable, line, 0, line, 0,
                       0xFFFFFFFFu);
        }
    }
};

}  // namespace

const char* scopeKindName(ScopeKind k) {
    switch (k) {
        case ScopeKind::TranslationUnit: return "TRANSLATION_UNIT";
        case ScopeKind::Namespace:        return "NAMESPACE";
        case ScopeKind::Class:            return "CLASS";
        case ScopeKind::Struct:           return "STRUCT";
        case ScopeKind::Union:            return "UNION";
        case ScopeKind::Enum:             return "ENUM";
        case ScopeKind::Function:         return "FUNCTION";
        case ScopeKind::Block:            return "BLOCK";
        case ScopeKind::Initializer:      return "INITIALIZER";
        case ScopeKind::TemplateBrace:    return "TEMPLATE_BRACE";
        default:                          return "UNKNOWN";
    }
}

const char* symbolKindName(SymbolKind k) {
    switch (k) {
        case SymbolKind::Function:     return "FUNCTION";
        case SymbolKind::Method:       return "METHOD";
        case SymbolKind::Class:        return "CLASS";
        case SymbolKind::Struct:       return "STRUCT";
        case SymbolKind::Union:        return "UNION";
        case SymbolKind::Enum:         return "ENUM";
        case SymbolKind::EnumConstant: return "ENUM_CONSTANT";
        case SymbolKind::Namespace:    return "NAMESPACE";
        case SymbolKind::Macro:        return "MACRO";
        case SymbolKind::TypeAlias:    return "TYPE_ALIAS";
        case SymbolKind::Variable:     return "VARIABLE";
        case SymbolKind::Field:        return "FIELD";
        default:                       return "UNKNOWN";
    }
}

FileAnalysis analyzeSource(const std::string& text) {
    FileAnalysis out;
    out.lineCount = 1;
    Lexer        lx(text, &out);
    lx.run();

    Stage2 s2(text, out.tokens, &out);
    s2.run();

    out.identLocalIndex.clear();
    out.analyzed = true;
    return out;
}

}  // namespace repointel
}  // namespace rawrxd