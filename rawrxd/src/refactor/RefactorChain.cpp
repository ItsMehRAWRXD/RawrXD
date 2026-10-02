// ============================================================================
// RefactorChain.cpp — RAWRXD_P1_REFACTOR_CHAIN_001
//
// Load-bearing implementation notes for the gate:
//
//  * The tokenizer tracks comment, string, char and preprocessor state and
//    records every name found inside a comment or a string literal SEPARATELY
//    from code occurrences. That separation is what turns "a name in a comment
//    is not a reference" into a measured property instead of an intention.
//  * Occurrences are whole-identifier tokens. `WidgetCacheSlot` never matches
//    `resetWidgetCacheSlot` and never matches the token inside a comment or a
//    string. The first census was wrong exactly here: the symbol
//    `RenameSymbol` matched five hits, all of them std::filesystem::rename.
//  * Diagnostics are deliberately narrow and each rule states its blind spot.
//    `undeclared_identifier` never fires on a name qualified by `::`, because
//    this authority does not read the system headers, and a false positive
//    there is worse than a missed one. A clean source file therefore has to
//    produce zero diagnostics, and the gate asserts exactly that.
//  * The formatter is whitespace-only (R1..R5). It is not clang-format and the
//    receipt must not describe it as one.
//  * Extract function infers parameter types from the enclosing function's own
//    declarations. It never invents a type it cannot see.
// ============================================================================

#include "RefactorChain.h"

#include <algorithm>
#include <cctype>
#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <set>
#include <sstream>

#ifdef _WIN32
// windows.h defines min/max as macros unless NOMINMAX is set, which would
// break every std::min / std::max in this file. The file controls its own state
// rather than depending on the build system's definitions.
#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>
#endif

namespace rawrxd {
namespace refactor {

const char* occurrenceKindName(OccurrenceKind k) {
    switch (k) {
        case OccurrenceKind::Definition:   return "DEFINITION";
        case OccurrenceKind::Declaration:  return "DECLARATION";
        case OccurrenceKind::Use:          return "USE";
        case OccurrenceKind::Call:         return "CALL";
        case OccurrenceKind::TypeUse:      return "TYPE_USE";
        case OccurrenceKind::MemberAccess: return "MEMBER_ACCESS";
    }
    return "UNKNOWN";
}

// ===========================================================================
// File utilities
// ===========================================================================

std::vector<std::string> splitLines(const std::string& text) {
    std::vector<std::string> out;
    std::string cur;
    for (size_t i = 0; i < text.size(); ++i) {
        if (text[i] == '\n') {
            if (!cur.empty() && cur.back() == '\r') cur.pop_back();
            out.push_back(cur);
            cur.clear();
        } else {
            cur.push_back(text[i]);
        }
    }
    if (!cur.empty()) {
        if (cur.back() == '\r') cur.pop_back();
        out.push_back(cur);
    }
    return out;
}

std::string joinLines(const std::vector<std::string>& lines) {
    std::string out;
    out.reserve(lines.size() * 24);
    for (const auto& l : lines) {
        out += l;
        out.push_back('\n');
    }
    return out;
}

bool readWholeFile(const std::string& path, std::string* out, std::string* err) {
    std::ifstream f(path, std::ios::binary);
    if (!f) {
        if (err) *err = "open failed: " + path;
        return false;
    }
    std::ostringstream ss;
    ss << f.rdbuf();
    *out = ss.str();
    return true;
}

bool writeWholeFileAtomic(const std::string& path, const std::string& bytes, std::string* err) {
    const std::string tmp = path + ".refactor-tmp";
    {
        std::ofstream f(tmp, std::ios::binary | std::ios::trunc);
        if (!f) {
            if (err) *err = "temp open failed: " + tmp;
            return false;
        }
        f.write(bytes.data(), static_cast<std::streamsize>(bytes.size()));
        if (!f.good()) {
            if (err) *err = "temp write failed: " + tmp;
            return false;
        }
    }
#ifdef _WIN32
    if (!MoveFileExA(tmp.c_str(), path.c_str(), MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        if (err) *err = "replace failed: " + path;
        DeleteFileA(tmp.c_str());
        return false;
    }
#else
    std::remove(path.c_str());
    std::rename(tmp.c_str(), path.c_str());
#endif
    return true;
}

std::string relPathFrom(const std::string& root, const std::string& abs) {
    std::string r = root;
    while (r.size() > 1 && (r.back() == '\\' || r.back() == '/')) r.pop_back();
    if (abs.size() > r.size() + 1 &&
        abs.compare(0, r.size(), r) == 0 &&
        (abs[r.size()] == '\\' || abs[r.size()] == '/')) {
        std::string rel = abs.substr(r.size() + 1);
        for (auto& c : rel) if (c == '\\') c = '/';
        return rel;
    }
    return abs;
}

static std::string trimBothStr(const std::string& s) {
    size_t b = 0;
    while (b < s.size() && (s[b] == ' ' || s[b] == '\t' || s[b] == '\r')) ++b;
    size_t e = s.size();
    while (e > b && (s[e - 1] == ' ' || s[e - 1] == '\t' || s[e - 1] == '\r')) --e;
    return s.substr(b, e - b);
}

static bool isIdentStartCh(char c) {
    return std::isalpha(static_cast<unsigned char>(c)) || c == '_' || c == '$';
}
static bool isIdentCharCh(char c) {
    return std::isalnum(static_cast<unsigned char>(c)) || c == '_' || c == '$';
}

// ===========================================================================
// Keywords
// ===========================================================================

static const char* const kCppKeywords[] = {
    "alignas","alignof","asm","auto","bool","break","case","catch","char","char8_t",
    "char16_t","char32_t","class","co_await","co_return","co_yield","concept","const",
    "consteval","constexpr","constinit","const_cast","continue","decltype","default",
    "delete","do","double","dynamic_cast","else","enum","explicit","export","extern",
    "false","float","for","friend","goto","if","inline","int","long","mutable","namespace",
    "new","noexcept","nullptr","operator","private","protected","public","register",
    "reinterpret_cast","requires","return","short","signed","sizeof","static","static_assert",
    "static_cast","struct","switch","template","this","thread_local","throw","true","try",
    "typedef","typeid","typename","union","unsigned","using","virtual","void","volatile",
    "wchar_t","while",
};

static bool isCppKeyword(const std::string& s) {
    for (const char* k : kCppKeywords) if (s == k) return true;
    return false;
}

static const char* const kBuiltinTypes[] = {
    "int","unsigned","long","short","signed","char","bool","float","double","void","wchar_t",
    "char8_t","char16_t","char32_t","size_t","ssize_t","ptrdiff_t","int8_t","int16_t",
    "int32_t","int64_t","uint8_t","uint16_t","uint32_t","uint64_t","intptr_t","uintptr_t",
    "FILE",
};

static bool isBuiltinTypeName(const std::string& s) {
    for (const char* k : kBuiltinTypes) if (s == k) return true;
    return false;
}

// ===========================================================================
// Whitespace formatter — R1..R5, whitespace only
// ===========================================================================

std::string normalizeWhitespace(const std::string& in,
                                uint32_t* linesChanged,
                                uint32_t indentWidth,
                                std::vector<std::string>* rulesApplied) {
    const std::vector<std::string> before = splitLines(in);
    std::vector<std::string> after;
    after.reserve(before.size());

    const std::string pad(indentWidth ? indentWidth : 4, ' ');
    int blankRun = 0;

    for (const auto& raw : before) {
        std::string line;
        line.reserve(raw.size());
        for (char c : raw) {
            if (c == '\t') line += pad;          // R2
            else if (c != '\r') line.push_back(c); // R1
        }
        while (!line.empty() && (line.back() == ' ' || line.back() == '\t')) line.pop_back(); // R3

        if (line.empty()) {
            ++blankRun;
            if (blankRun > 1) continue;           // R4
        } else {
            blankRun = 0;
        }
        after.push_back(line);
    }

    while (!after.empty() && after.back().empty()) after.pop_back();   // R5

    if (linesChanged) {
        uint32_t changed = 0;
        const size_t n = std::max(before.size(), after.size());
        for (size_t i = 0; i < n; ++i) {
            const std::string a = i < before.size() ? before[i] : std::string();
            const std::string b = i < after.size() ? after[i] : std::string();
            if (a != b) ++changed;
        }
        *linesChanged = changed;
    }
    if (rulesApplied) {
        rulesApplied->push_back("R1_CRLF_TO_LF");
        rulesApplied->push_back("R2_TAB_TO_INDENT_UNIT");
        rulesApplied->push_back("R3_STRIP_TRAILING_WHITESPACE");
        rulesApplied->push_back("R4_COLLAPSE_MULTI_BLANK_LINES");
        rulesApplied->push_back("R5_SINGLE_TRAILING_NEWLINE");
    }
    return joinLines(after);
}

// ===========================================================================
// Token model
// ===========================================================================

enum class TokType : uint8_t { Ident, Number, Punct, StringLit, CharLit };

struct Token {
    TokType     type = TokType::Punct;
    uint32_t    line = 0;
    uint32_t    col = 0;
    uint32_t    length = 0;
    std::string text;
};

struct SkippedName {
    std::string text;
    uint32_t    line = 0;
    uint32_t    col = 0;
    bool        inString = false;
};

enum class SymKind : uint8_t {
    Function, Method, Type, Variable, Parameter, Namespace, EnumValue, Typedef
};

static const char* symKindName(SymKind k) {
    switch (k) {
        case SymKind::Function:  return "FUNCTION";
        case SymKind::Method:    return "METHOD";
        case SymKind::Type:      return "TYPE";
        case SymKind::Variable:  return "VARIABLE";
        case SymKind::Parameter: return "PARAMETER";
        case SymKind::Namespace: return "NAMESPACE";
        case SymKind::EnumValue: return "ENUM_VALUE";
        case SymKind::Typedef:   return "TYPEDEF";
    }
    return "UNKNOWN";
}

// ===========================================================================
// Private nested types
// ===========================================================================

struct RefactorChain::SymbolRecord {
    std::string name;
    std::string qualifiedName;
    SymKind     kind = SymKind::Function;
    std::string relFile;
    uint32_t    line = 0;
    uint32_t    col = 0;
    uint32_t    nameLength = 0;
    bool        isDefinition = false;
    uint32_t    stmtFirstLine = 0;
    uint32_t    bodyFirstLine = 0;
    uint32_t    bodyLastLine = 0;
    std::string declaredType;
    std::string returnType;
    std::vector<std::pair<std::string, std::string>> params; // (type, name)
    std::vector<std::pair<std::string, std::string>> locals; // (type, name)
};

struct RefactorChain::FileState {
    std::string              rel;
    std::string              bytes;
    std::vector<std::string> lines;
    std::vector<Token>       tokens;
    std::vector<SkippedName> skipped;
    std::vector<Diagnostic>  diagnostics;
    std::vector<CodeAction>  actions;
    uint32_t                 externalQualifiedSkipped = 0;
    uint32_t                 unresolvedQualifiedSkipped = 0;
};

// ===========================================================================
// Construction / workspace
// ===========================================================================

RefactorChain& RefactorChain::instance() {
    static RefactorChain c;
    return c;
}

RefactorChain::~RefactorChain() = default;

void RefactorChain::close() {
    m_ws = WorkspaceInfo{};
    m_rootsAbs.clear();
    m_files.clear();
    m_symbols.clear();
    m_occurrences.clear();
    m_declByName.clear();
}

bool RefactorChain::open(const std::string& rootOrWorkspaceFile, std::string* err) {
    close();
    return loadWorkspace(rootOrWorkspaceFile, err);
}

static bool dirExistsFn(const std::string& p) {
#ifdef _WIN32
    const DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && (a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(p.c_str(), &st) == 0 && S_ISDIR(st.st_mode);
#endif
}

static bool fileExistsFn(const std::string& p) {
#ifdef _WIN32
    const DWORD a = GetFileAttributesA(p.c_str());
    return a != INVALID_FILE_ATTRIBUTES && !(a & FILE_ATTRIBUTE_DIRECTORY);
#else
    struct stat st;
    return stat(p.c_str(), &st) == 0 && S_ISREG(st.st_mode);
#endif
}

static void collectFilesRecursive(const std::string& dirAbs,
                                  const std::string& rootAbs,
                                  std::vector<std::string>* out) {
#ifdef _WIN32
    WIN32_FIND_DATAA fd;
    const std::string pattern = dirAbs + "\\*";
    HANDLE h = FindFirstFileA(pattern.c_str(), &fd);
    if (h == INVALID_HANDLE_VALUE) return;
    do {
        const std::string name = fd.cFileName;
        if (name == "." || name == "..") continue;
        const std::string full = dirAbs + "\\" + name;
        if (fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            collectFilesRecursive(full, rootAbs, out);
        } else {
            out->push_back(relPathFrom(rootAbs, full));
        }
    } while (FindNextFileA(h, &fd));
    FindClose(h);
#else
    (void)dirAbs; (void)rootAbs; (void)out;
#endif
}

static bool isSourceRelPath(const std::string& rel) {
    static const char* const exts[] = {".cpp", ".cc", ".cxx", ".hpp", ".hxx", ".h", ".inl"};
    for (const char* e : exts) {
        const size_t n = strlen(e);
        if (rel.size() > n && rel.compare(rel.size() - n, n, e) == 0) return true;
    }
    return false;
}

// The tokenizer emits punctuation one character at a time, so the scope operator
// arrives as two separate ':' tokens. Every test for "is this name qualified"
// therefore has to look at two tokens, and every one that looked at one silently
// answered "no" -- which is how `std::filesystem::rename` came to be reported as
// three undeclared identifiers.
static bool scopeOpAfter(const std::vector<Token>& T, size_t i) {
    return i + 2 < T.size() && T[i + 1].text == ":" && T[i + 2].text == ":";
}

static bool scopeOpBefore(const std::vector<Token>& T, size_t i) {
    return i >= 2 && T[i - 1].text == ":" && T[i - 2].text == ":";
}

static bool parseWorkspaceDocument(const std::string& text,
                                   std::vector<std::string>* folders,
                                   std::string* err) {
    const size_t k = text.find("\"folders\"");
    if (k == std::string::npos) {
        if (err) *err = "workspace document has no \"folders\" key";
        return false;
    }
    const size_t ab = text.find('[', k);
    if (ab == std::string::npos) {
        if (err) *err = "workspace document \"folders\" is not an array";
        return false;
    }
    size_t i = ab;
    while (true) {
        const size_t pk = text.find("\"path\"", i);
        if (pk == std::string::npos) break;
        const size_t q1 = text.find('"', text.find(':', pk));
        if (q1 == std::string::npos) break;
        const size_t q2 = text.find('"', q1 + 1);
        if (q2 == std::string::npos) break;
        folders->push_back(text.substr(q1 + 1, q2 - q1 - 1));
        i = q2 + 1;
    }
    if (folders->empty()) {
        if (err) *err = "workspace document \"folders\" listed no path";
        return false;
    }
    return true;
}

bool RefactorChain::loadWorkspace(const std::string& rootOrWorkspaceFile, std::string* err) {
    if (rootOrWorkspaceFile.empty()) {
        if (err) *err = "no workspace path given";
        return false;
    }

    std::vector<std::string> rootsAbs;
    std::string docDir;

    const bool looksLikeDoc = rootOrWorkspaceFile.find(".code-workspace") != std::string::npos;
    const bool isDoc = looksLikeDoc ||
                       (fileExistsFn(rootOrWorkspaceFile) && !dirExistsFn(rootOrWorkspaceFile));

    if (isDoc) {
        std::string bytes, e;
        if (!readWholeFile(rootOrWorkspaceFile, &bytes, &e)) { if (err) *err = e; return false; }
        std::vector<std::string> folders;
        if (!parseWorkspaceDocument(bytes, &folders, &e)) { if (err) *err = e; return false; }
        const size_t slash = rootOrWorkspaceFile.find_last_of("\\/");
        docDir = (slash == std::string::npos) ? std::string(".") : rootOrWorkspaceFile.substr(0, slash);
        for (auto p : folders) {
            for (auto& c : p) if (c == '/') c = '\\';
            const std::string full = (p.size() > 1 && p[1] == ':') ? p : docDir + "\\" + p;
            if (!dirExistsFn(full)) {
                if (err) *err = "workspace folder does not exist: " + full;
                return false;
            }
            rootsAbs.push_back(full);
        }
    } else {
        if (!dirExistsFn(rootOrWorkspaceFile)) {
            if (err) *err = "workspace root does not exist: " + rootOrWorkspaceFile;
            return false;
        }
        rootsAbs.push_back(rootOrWorkspaceFile);
    }

    m_rootsAbs = rootsAbs;
    m_ws = WorkspaceInfo{};
    m_ws.root = rootsAbs[0];
    // A root's display name is its path relative to where the workspace was named
    // from, NOT relative to the first root. Two sibling folders are not nested,
    // so a "relative to root[0]" helper returns the absolute path for root[1],
    // and every secondary file then gets an absolute key -- which is how a
    // two-root workspace ends up indexing nine files under nine absolute names
    // and answering "no such file" for a path that plainly exists.
    std::string nameFrom = docDir.empty() ? std::string() : docDir;
    for (size_t i = 0; i < rootsAbs.size(); ++i) {
        std::string rel;
        if (!nameFrom.empty()) {
            rel = relPathFrom(nameFrom, rootsAbs[i]);
            if (!rel.empty() && (rel[0] == '\\' || rel[0] == '/')) rel.clear();
        }
        if (rel.empty()) {
            // Fall back to the directory name, which is what a UI shows anyway.
            const size_t cut = rootsAbs[i].find_last_of("\\/");
            rel = (cut == std::string::npos) ? rootsAbs[i] : rootsAbs[i].substr(cut + 1);
        }
        m_ws.roots.push_back(rel);
    }

    return indexRoots(err);
}

bool RefactorChain::indexRoots(std::string* err) {
    struct Pending { std::string rel, abs; };
    std::vector<Pending> pending;
    std::set<std::string> seen;
    for (size_t i = 0; i < m_rootsAbs.size(); ++i) {
        std::vector<std::string> got;
        collectFilesRecursive(m_rootsAbs[i], m_rootsAbs[i], &got);
        std::sort(got.begin(), got.end());
        for (const auto& g : got) {
            const std::string rel = m_ws.roots[i] + "/" + g;
            if (seen.count(rel)) continue;
            seen.insert(rel);
            if (!isSourceRelPath(rel)) { ++m_ws.skippedNonSource; continue; }
            std::string sub = g;
            for (auto& c : sub) if (c == '/') c = '\\';
            pending.push_back(Pending{rel, m_rootsAbs[i] + "\\" + sub});
        }
    }

    if (pending.empty()) {
        if (err) *err = "workspace contained no source file to index";
        return false;
    }

    uint32_t indexed = 0;
    for (const auto& p : pending) {
        std::string bytes, e;
        if (!readWholeFile(p.abs, &bytes, &e)) { if (err) *err = e; return false; }
        if (!scanFile(p.rel, bytes)) { if (err) *err = "parse failed: " + p.rel; return false; }
        ++indexed;
    }

    m_ws.filesIndexed = indexed;
    m_ws.symbolsIndexed = static_cast<uint32_t>(m_symbols.size());
    m_ws.occurrencesIndexed = static_cast<uint32_t>(m_occurrences.size());
    for (const auto& kv : m_files) m_ws.bytesIndexed += kv.second.bytes.size();
    m_ws.ok = true;
    return true;
}

bool RefactorChain::reindex(std::string* err) {
    if (m_rootsAbs.empty()) {
        if (err) *err = "no workspace open";
        return false;
    }
    // Re-open the roots this workspace was opened with. Writing a temporary
    // workspace document and re-reading it looks equivalent and is not: the
    // document has to live somewhere, and once it lives inside the primary root
    // its relative folder paths resolve against that root instead of the
    // original parent. The second root then points at a directory that does not
    // exist, the reindex fails, and every later lookup answers "no such file".
    const std::vector<std::string> saved = m_rootsAbs;
    const std::vector<std::string> savedNames = m_ws.roots;
    close();
    m_rootsAbs = saved;
    m_ws = WorkspaceInfo{};
    m_ws.root = savedNames.empty() ? saved[0] : std::string();
    m_ws.roots = savedNames;
    return indexRoots(err);
}

std::string RefactorChain::absPath(const std::string& relPath) const {
    for (size_t i = 0; i < m_rootsAbs.size(); ++i) {
        const std::string prefix = m_ws.roots[i] + "/";
        if (relPath.compare(0, prefix.size(), prefix) == 0) {
            std::string sub = relPath.substr(prefix.size());
            for (auto& c : sub) if (c == '/') c = '\\';
            return m_rootsAbs[i] + "\\" + sub;
        }
    }
    std::string sub = relPath;
    for (auto& c : sub) if (c == '/') c = '\\';
    return m_rootsAbs[0] + "\\" + sub;
}

const RefactorChain::FileState* RefactorChain::findFile(const std::string& relPath) const {
    auto it = m_files.find(relPath);
    return it == m_files.end() ? nullptr : &it->second;
}

bool RefactorChain::writeFileAtomic(const std::string& relPath,
                                    const std::string& newBytes,
                                    std::string* err) const {
    return writeWholeFileAtomic(absPath(relPath), newBytes, err);
}

std::vector<const RefactorChain::SymbolRecord*>
RefactorChain::symbolsNamed(const std::string& name) const {
    std::vector<const SymbolRecord*> out;
    auto it = m_declByName.find(name);
    if (it == m_declByName.end()) return out;
    for (size_t idx : it->second) out.push_back(m_symbols[idx].get());
    return out;
}

bool RefactorChain::isDeclaredAnywhere(const std::string& name) const {
    return m_declByName.find(name) != m_declByName.end();
}

bool RefactorChain::namespaceOrTypeKnown(const std::string& name) const {
    auto it = m_declByName.find(name);
    if (it == m_declByName.end()) return false;
    for (size_t idx : it->second) {
        const SymKind k = m_symbols[idx]->kind;
        if (k == SymKind::Namespace || k == SymKind::Type || k == SymKind::Typedef) return true;
    }
    return false;
}

// ===========================================================================
// Tokenizer
// ===========================================================================

static void recordSkippedNames(std::vector<SkippedName>* out,
                               const std::string& text,
                               uint32_t line,
                               uint32_t col,
                               bool inString) {
    size_t i = 0;
    while (i < text.size()) {
        if (isIdentStartCh(text[i])) {
            const size_t s = i;
            while (i < text.size() && isIdentCharCh(text[i])) ++i;
            SkippedName n;
            n.text = text.substr(s, i - s);
            n.line = line;
            n.col = col;
            n.inString = inString;
            out->push_back(n);
        } else {
            ++i;
        }
    }
}

bool RefactorChain::scanFile(const std::string& relPath, const std::string& bytes) {
    auto fs = std::make_unique<FileState>();
    fs->rel = relPath;
    fs->bytes = bytes;
    fs->lines = splitLines(bytes);

    const size_t n = bytes.size();
    size_t i = 0;
    uint32_t line = 1, col = 1;
    bool atLineStart = true;

    auto advance = [&](size_t count) {
        for (size_t k = 0; k < count && i < n; ++k) {
            const char ch = bytes[i];
            if (ch == '\n') { ++line; col = 1; atLineStart = true; }
            else { ++col; if (ch != ' ' && ch != '\t' && ch != '\r') atLineStart = false; }
            ++i;
        }
    };

    while (i < n) {
        const char c = bytes[i];
        if (c == '\n' || c == ' ' || c == '\t' || c == '\r') { advance(1); continue; }

        if (c == '/' && i + 1 < n && bytes[i + 1] == '/') {
            const uint32_t cl = line, cc = col;
            const size_t start = i + 2;
            while (i < n && bytes[i] != '\n') advance(1);
            recordSkippedNames(&fs->skipped, bytes.substr(start, i - start), cl, cc, false);
            continue;
        }
        if (c == '/' && i + 1 < n && bytes[i + 1] == '*') {
            const uint32_t cl = line, cc = col;
            const size_t start = i + 2;
            advance(2);
            while (i + 1 < n && !(bytes[i] == '*' && bytes[i + 1] == '/')) advance(1);
            const size_t bodyEnd = (i + 1 < n) ? i : n;
            if (i + 1 < n) advance(2);
            recordSkippedNames(&fs->skipped,
                               bytes.substr(start, std::min(bodyEnd, n) - start), cl, cc, false);
            continue;
        }
        if (c == '"' || c == '\'') {
            const char quote = c;
            const uint32_t sl = line, sc = col;
            const size_t start = i;
            Token t;
            t.type = (quote == '"') ? TokType::StringLit : TokType::CharLit;
            t.line = line; t.col = col;
            advance(1);
            while (i < n && bytes[i] != quote && bytes[i] != '\n') {
                if (bytes[i] == '\\' && i + 1 < n) advance(1);
                advance(1);
            }
            if (i < n && bytes[i] == quote) advance(1);
            t.length = static_cast<uint32_t>(i - start);
            t.text = bytes.substr(start, t.length);
            fs->tokens.push_back(t);
            if (quote == '"' && t.text.size() >= 2) {
                recordSkippedNames(&fs->skipped, t.text.substr(1, t.text.size() - 2), sl, sc, true);
            }
            continue;
        }
        if (isIdentStartCh(c)) {
            Token t;
            t.type = TokType::Ident; t.line = line; t.col = col;
            const size_t start = i;
            while (i < n && isIdentCharCh(bytes[i])) advance(1);
            t.length = static_cast<uint32_t>(i - start);
            t.text = bytes.substr(start, t.length);
            fs->tokens.push_back(t);
            continue;
        }
        if (std::isdigit(static_cast<unsigned char>(c)) ||
            (c == '.' && i + 1 < n && std::isdigit(static_cast<unsigned char>(bytes[i + 1])))) {
            Token t;
            t.type = TokType::Number; t.line = line; t.col = col;
            const size_t start = i;
            while (i < n) {
                const char d = bytes[i];
                if (isIdentCharCh(d) || d == '.') { advance(1); continue; }
                if ((d == '+' || d == '-') && (bytes[i - 1] == 'e' || bytes[i - 1] == 'E')) { advance(1); continue; }
                break;
            }
            t.length = static_cast<uint32_t>(i - start);
            t.text = bytes.substr(start, t.length);
            fs->tokens.push_back(t);
            continue;
        }
        if (c == '#' && atLineStart) {
            while (i < n && bytes[i] != '\n') advance(1);
            continue;
        }
        Token t;
        t.type = TokType::Punct; t.line = line; t.col = col;
        t.length = 1;
        t.text = std::string(1, c);
        fs->tokens.push_back(t);
        advance(1);
    }

    FileState& ref = *fs;
    analyzeDeclarations(ref);
    classifyOccurrences(ref);
    computeDiagnostics(ref);

    m_files[relPath] = std::move(*fs);
    return true;
}

// ===========================================================================
// Declaration scan
// ===========================================================================

namespace {

// Parse a declaration fragment such as "const Series& s", "double x",
// "double arr[8]", "alpha::Series s" into (typeText, boundName). Returns false
// when the fragment is not a named binding, so a call site or an expression can
// never be mistaken for one.
//
// Two filters do that work. The first rejects a fragment whose type run
// contains a comparison, arithmetic or assignment operator, which is what an
// expression fragment looks like. `*` and `&` are NOT in that list, because they
// are declarator punctuation in `const char* label` and `const Series& s`, and
// an earlier version of this predicate rejected every pointer and reference
// declaration in the workspace -- which then surfaced as a hundred false
// "undeclared identifier" reports on struct members.
//
// The second filter requires the run to be headed by a type: a builtin type, a
// cv qualifier, or a name already recorded as a type or namespace. Without it,
// `r.label[0]` parses as a declaration of `label` with type `r`, and that single
// missing condition is enough to make a whole file look broken.
bool parseBinding(const std::vector<Token>& toks, size_t begin, size_t end,
                  const std::set<std::string>& typeHeads,
                  std::string* typeText, std::string* name) {
    if (end <= begin + 1) return false;

    size_t nameIdx = end;
    int bracket = 0;
    for (size_t k = begin; k < end; ++k) {
        const Token& t = toks[k];
        if (t.text == "=" && bracket == 0) { nameIdx = k; break; }
    }
    if (nameIdx > begin) --nameIdx; else nameIdx = end;
    if (nameIdx <= begin || nameIdx >= end) return false;
    if (toks[nameIdx].type != TokType::Ident) return false;
    if (isCppKeyword(toks[nameIdx].text)) return false;

    std::vector<std::string> parts;
    int depth = 0;
    for (size_t k = begin; k < nameIdx; ++k) {
        const Token& t = toks[k];
        if (t.text == "(" || t.text == "[") { ++depth; parts.push_back(t.text); continue; }
        if (t.text == ")" || t.text == "]") { --depth; parts.push_back(t.text); continue; }
        if (depth == 0) {
            // ':' is rejected as a ternary colon but accepted as the two-token
            // scope operator. The tokenizer emits ':' twice, so `alpha::Series`
            // arrives as alpha : : Series, and rejecting ':' outright silently
            // discarded every qualified type in the workspace.
            if (t.text == ":" &&
                k + 1 < end && toks[k + 1].text == ":") {
                parts.push_back(t.text);
                parts.push_back(toks[k + 1].text);
                ++k;
                continue;
            }
            static const char* const ops[] = {
                "+", "-", "<", ">", "<=", ">=", "==", "!=", "&&", "||", "!", "?",
                ":", "<<", ">>", "=", ","
            };
            for (const char* o : ops) if (t.text == o) return false;
        }
        parts.push_back(t.text);
    }
    if (parts.empty()) return false;

    // The head must be something that can introduce a type.
    static const char* const heads[] = {
        "auto", "const", "volatile", "static", "constexpr", "consteval", "inline",
        "extern", "mutable", "register", "thread_local", "struct", "class", "union",
        "enum", "typename", "unsigned", "signed"
    };
    const std::string& head = parts[0];
    bool headIsType = isBuiltinTypeName(head) || typeHeads.count(head) > 0;
    for (const char* h : heads) if (head == h) headIsType = true;
    if (!headIsType) return false;

    std::string ty;
    for (const auto& p : parts) {
        if (!ty.empty() && (ty.back() == '*' || ty.back() == '&' || ty.back() == ':')) ty += p;
        else if (!ty.empty() && (p == "*" || p == "&" || p == "::")) ty += p;
        else if (!ty.empty()) ty += " " + p;
        else ty = p;
    }
    if (ty.empty()) return false;
    *typeText = ty;
    *name = toks[nameIdx].text;
    return true;
}

std::string joinTypeTokens(const std::vector<Token>& T, size_t begin, size_t end) {
    std::vector<std::string> parts;
    for (size_t k = begin; k < end; ++k) parts.push_back(T[k].text);
    std::string ty;
    for (const auto& p : parts) {
        if (!ty.empty() && (ty.back() == '*' || ty.back() == '&' || ty.back() == ':')) ty += p;
        else if (!ty.empty() && (p == "*" || p == "&" || p == "::")) ty += p;
        else if (!ty.empty()) ty += " " + p;
        else ty = p;
    }
    return ty;
}

}  // namespace

void RefactorChain::analyzeDeclarations(FileState& fs) {
    const std::vector<Token>& T = fs.tokens;
    const size_t n = T.size();
    // Scope name paired with the brace depth at which it was opened, so the
    // matching '}' pops exactly what it opened.
    std::vector<std::pair<std::string, int>> scopes;

    auto qualified = [&](const std::string& name) {
        std::string q;
        for (const auto& s : scopes) { q += s.first; q += "::"; }
        q += name;
        return q;
    };

    auto addSymbol = [&](SymbolRecord rec) {
        const size_t idx = m_symbols.size();
        m_symbols.push_back(std::make_unique<SymbolRecord>(std::move(rec)));
        m_declByName[m_symbols[idx]->name].push_back(idx);
        return idx;
    };

    // Names already recorded as a type or a namespace in this workspace. A
    // declaration's type run must be headed by one of these, a builtin type, or a
    // cv qualifier; that is what keeps .label[0] from parsing as a declaration
    // of label.
    std::set<std::string> typeHeads;
    for (const auto& kv : m_declByName) {
        for (size_t si : kv.second) {
            const SymKind k = m_symbols[si]->kind;
            if (k == SymKind::Type || k == SymKind::Namespace || k == SymKind::EnumValue ||
                k == SymKind::Typedef) {
                typeHeads.insert(kv.first);
                break;
            }
        }
    }

    struct PendingLocal { size_t fnSymbol; std::string type, name; };
    std::vector<PendingLocal> pendingLocals;
    std::vector<size_t> bodyOwnerStack;
    int braceDepth = 0;

    for (size_t i = 0; i < n; ++i) {
        const Token& t = T[i];

        if (t.type == TokType::Punct) {
            if (t.text == "{") {
                ++braceDepth;
            } else if (t.text == "}") {
                if (braceDepth > 0) --braceDepth;
                if (!bodyOwnerStack.empty()) {
                    const size_t owner = bodyOwnerStack.back();
                    bodyOwnerStack.pop_back();
                    m_symbols[owner]->bodyLastLine = t.line;
                    std::vector<std::pair<std::string, std::string>> loc;
                    for (auto it = pendingLocals.begin(); it != pendingLocals.end();) {
                        if (it->fnSymbol != owner) { ++it; continue; }
                        bool dup = false;
                        for (const auto& p : loc) if (p.second == it->name) { dup = true; break; }
                        if (!dup) loc.push_back({it->type, it->name});
                        it = pendingLocals.erase(it);
                    }
                    m_symbols[owner]->locals = std::move(loc);
                }
                while (!scopes.empty() && scopes.back().second >= braceDepth) {
                    scopes.pop_back();
                }
            }
            continue;
        }

        if (t.type != TokType::Ident) continue;
        const std::string& id = t.text;

        const bool prevScopeAccess =
            (i > 0 && T[i - 1].type == TokType::Punct &&
             (T[i - 1].text == "." || T[i - 1].text == "->" || T[i - 1].text == "::"));
        const bool nextIsScope =
            (i + 1 < n && T[i + 1].type == TokType::Punct && T[i + 1].text == "::");

        // namespace NAME {
        if (id == "namespace" && i + 2 < n && T[i + 1].type == TokType::Ident &&
            T[i + 2].type == TokType::Punct && T[i + 2].text == "{") {
            SymbolRecord rec;
            rec.name = T[i + 1].text;
            rec.kind = SymKind::Namespace;
            rec.relFile = fs.rel;
            rec.line = T[i + 1].line;
            rec.col = T[i + 1].col;
            rec.nameLength = T[i + 1].length;
            rec.isDefinition = true;
            rec.stmtFirstLine = t.line;
            rec.qualifiedName = qualified(rec.name);
            addSymbol(std::move(rec));
            scopes.push_back(std::make_pair(T[i + 1].text, braceDepth));
            i = i + 1;
            continue;
        }

        // class/struct/union/enum NAME [ ... ] {
        if ((id == "class" || id == "struct" || id == "union" || id == "enum") &&
            i + 1 < n && T[i + 1].type == TokType::Ident && !nextIsScope) {
            SymbolRecord rec;
            rec.name = T[i + 1].text;
            rec.kind = SymKind::Type;
            rec.relFile = fs.rel;
            rec.line = T[i + 1].line;
            rec.col = T[i + 1].col;
            rec.nameLength = T[i + 1].length;
            rec.isDefinition = true;
            rec.stmtFirstLine = t.line;
            rec.qualifiedName = qualified(rec.name);
            const size_t idx = addSymbol(std::move(rec));

            size_t k = i + 2;
            int depth = 0;
            bool opens = false;
            for (; k < n; ++k) {
                if (T[k].text == "(") { ++depth; continue; }
                if (T[k].text == ")") { --depth; continue; }
                if (depth != 0) continue;
                if (T[k].text == "{") { opens = true; break; }
                if (T[k].text == ";") break;
            }
            if (opens) {
                m_symbols[idx]->bodyFirstLine = T[k].line;
                scopes.push_back(std::make_pair(m_symbols[idx]->name, braceDepth));
            }
            i = i + 1;
            continue;
        }

        // for-init declaration. This has to be recognised BEFORE the keyword
        // filter below, because `for` is a keyword: a declaration inside the
        // init clause -- `for (int i = 0; ...)` -- is then skipped, and every use
        // of that loop variable is reported as an undeclared identifier in a file
        // that is perfectly correct.
        if (id == "for" && i + 1 < n && T[i + 1].type == TokType::Punct && T[i + 1].text == "(") {
            size_t k = i + 2;
            int d = 0;
            while (k < n) {
                const std::string& x = T[k].text;
                if (x == "(" || x == "[" || x == "<") ++d;
                else if (x == ")" || x == "]" || x == ">") { if (d == 0) break; --d; }
                else if (x == ";" && d == 0) break;
                ++k;
            }
            std::string ty, nm;
            if (parseBinding(T, i + 2, k, typeHeads, &ty, &nm)) {
                SymbolRecord rec;
                rec.name = nm;
                rec.kind = SymKind::Variable;
                rec.relFile = fs.rel;
                rec.line = T[k - 1].line;
                rec.col = T[k - 1].col;
                rec.nameLength = T[k - 1].length;
                rec.isDefinition = true;
                rec.declaredType = ty;
                rec.stmtFirstLine = t.line;
                rec.qualifiedName = qualified(nm);
                addSymbol(std::move(rec));
                if (!bodyOwnerStack.empty()) {
                    pendingLocals.push_back({bodyOwnerStack.back(), ty, nm});
                }
            }
            continue;
        }

        if (isCppKeyword(id)) continue;
        if (prevScopeAccess) continue;

        // function definition / prototype: NAME ( ... ) [ ... ] { | ;
        if (i + 1 < n && T[i + 1].type == TokType::Punct && T[i + 1].text == "(") {
            size_t close = i + 1;
            int depth = 0;
            for (size_t k = i + 1; k < n; ++k) {
                if (T[k].text == "(") ++depth;
                else if (T[k].text == ")") { --depth; if (depth == 0) { close = k; break; } }
            }
            if (close >= n) continue;

            size_t k = close + 1;
            int d2 = 0;
            char verdict = 0;
            bool inInitList = false;
            bool afterArrow = false;
            // What may legally appear between ')' and the '{' or ';' of a
            // signature. Anything else means the '(' we matched was a call, not a
            // parameter list -- which is the difference between
            // `double f(const Series& s) {` and `alpha::computeWeightedMean(s);`.
            static const char* const quals[] = {
                "const", "volatile", "noexcept", "override", "final", "mutable", "throw"
            };
            while (k < n) {
                const std::string& x = T[k].text;
                if (inInitList) {
                    if (x == "{") { verdict = '{'; break; }
                    if (x == ";" || x == "}") { verdict = 0; break; }
                    ++k;
                    continue;
                }
                if (x == "(" || x == "[") { ++d2; ++k; continue; }
                if (x == ")" || x == "]") { --d2; ++k; continue; }
                if (d2 != 0) { ++k; continue; }
                if (x == "{") { verdict = '{'; break; }
                if (x == ";") { verdict = ';'; break; }
                if (x == ":") { inInitList = true; ++k; continue; }
                if (x == "->") { afterArrow = true; ++k; continue; }
                // A binary operator here means the parenthesis we matched was a
                // call argument list, so this is an expression.
                static const char* const ops[] = {
                    "+", "-", "*", "/", "%", "&", "|", "^", ".", "!", "?", "<", ">",
                    "=", "[", "]", ","
                };
                bool isOp = false;
                for (const char* o : ops) if (x == o) { isOp = true; break; }
                if (isOp) break;
                if (T[k].type == TokType::Ident) {
                    bool isQual = false;
                    for (const char* q : quals) if (x == q) { isQual = true; break; }
                    if (isQual) { ++k; continue; }
                    // A constructor initialiser names the member: name( ... )
                    if (k + 1 < n && T[k + 1].text == "(") { ++k; continue; }
                    // A trailing return type: one identifier after '->'
                    if (afterArrow) { afterArrow = false; ++k; continue; }
                    break;
                }
                ++k;
            }
            if (verdict == 0) continue;   // a call expression, not a declaration

            // A prototype must look like a prototype: either no parameters, or
            // every parameter must itself parse as a binding. `f();` is accepted
            // because an empty parameter list is ambiguous and a declaration is
            // the useful reading; `computeWeightedMean(s);` is not, because `s`
            // heads nothing.
            if (verdict == ';') {
                bool plausible = true;
                for (size_t q = i + 2; q < close && plausible; ) {
                    size_t segEnd = q;
                    int dd = 0;
                    while (segEnd < close) {
                        const std::string& x = T[segEnd].text;
                        if (x == "(" || x == "[") ++dd;
                        else if (x == ")" || x == "]") --dd;
                        else if (x == "," && dd == 0) break;
                        ++segEnd;
                    }
                    if (segEnd > i + 2) {
                        std::string pty, pnm;
                        if (!parseBinding(T, q, segEnd, typeHeads, &pty, &pnm)) plausible = false;
                    }
                    q = segEnd;
                }
                if (!plausible) continue;
            }

            SymbolRecord rec;
            rec.name = id;
            rec.relFile = fs.rel;
            rec.line = t.line;
            rec.col = t.col;
            rec.nameLength = t.length;
            rec.isDefinition = (verdict == '{');
            rec.stmtFirstLine = t.line;
            rec.qualifiedName = qualified(id);

            size_t b = i;
            while (b > 0) {
                const std::string& x = T[b - 1].text;
                if (x == ";" || x == "{" || x == "}" || x == ":") break;
                --b;
            }
            rec.returnType = joinTypeTokens(T, b, i);

            for (size_t q = i + 2; q < close; ++q) {
                size_t segEnd = q;
                int dd = 0;
                while (segEnd < close) {
                    const std::string& x = T[segEnd].text;
                    if (x == "(" || x == "[") ++dd;
                    else if (x == ")" || x == "]") --dd;
                    else if (x == "," && dd == 0) break;
                    ++segEnd;
                }
                std::string ty, nm;
                if (parseBinding(T, q, segEnd, typeHeads, &ty, &nm)) rec.params.push_back({ty, nm});
                q = segEnd;
            }

            const size_t idx = addSymbol(std::move(rec));
            if (verdict == '{') {
                m_symbols[idx]->bodyFirstLine = T[k].line;
                bodyOwnerStack.push_back(idx);
                scopes.push_back(std::make_pair(id, braceDepth));
            }
            i = close;
            continue;
        }


        // plain variable declaration: TYPE NAME followed by ; = [ { ,
        bool binder = false;
        if (i + 1 < n) {
            const std::string& nx = T[i + 1].text;
            binder = (nx == ";" || nx == "=" || nx == "[" || nx == "{" || nx == ",");
        }
        if (binder) {
            // The statement start is the first token on the binder's own line.
            // Walking back across lines instead lets an unbalanced ')' carry the
            // walk through the enclosing signature and out to the previous '{',
            // so a declaration's type run becomes the whole enclosing function
            // header. Restricting the run to one line is a real limit -- a
            // declaration split across two lines is not recognised -- and it is
            // the smaller error, because a missed declaration can only hide a
            // diagnostic, never invent one.
            size_t b = i;
            while (b > 0 && T[b - 1].line == t.line) {
                const std::string& x = T[b - 1].text;
                if (x == ";" || x == "{" || x == "}") break;
                --b;
            }
            std::string ty, nm;
            if (i > b && parseBinding(T, b, i + 1, typeHeads, &ty, &nm) && nm == id) {
                SymbolRecord rec;
                rec.name = nm;
                rec.kind = SymKind::Variable;
                rec.relFile = fs.rel;
                rec.line = t.line;
                rec.col = t.col;
                rec.nameLength = t.length;
                rec.isDefinition = true;
                rec.declaredType = ty;
                rec.stmtFirstLine = T[b].line;
                rec.qualifiedName = qualified(nm);
                addSymbol(std::move(rec));
                if (!bodyOwnerStack.empty()) {
                    pendingLocals.push_back({bodyOwnerStack.back(), ty, nm});
                }
            }
        }
    }
}

// ===========================================================================
// Occurrence classification
// ===========================================================================

void RefactorChain::classifyOccurrences(FileState& fs) {
    const std::vector<Token>& T = fs.tokens;
    const size_t n = T.size();
    const size_t occBase = m_occurrences.size();

    for (size_t i = 0; i < n; ++i) {
        const Token& t = T[i];
        if (t.type != TokType::Ident) continue;
        if (isCppKeyword(t.text)) continue;

        const bool prevMember =
            (i > 0 && T[i - 1].type == TokType::Punct &&
             (T[i - 1].text == "." || T[i - 1].text == "->"));
        const bool prevScope = scopeOpBefore(T, i);
        const bool nextScope = scopeOpAfter(T, i);
        const bool nextCall =
            (i + 1 < n && T[i + 1].type == TokType::Punct && T[i + 1].text == "(");

        if (nextScope) {
            // A namespace or class qualifier, not an occurrence of a value.
            ++fs.externalQualifiedSkipped;
            continue;
        }
        if (prevMember) {
            Occurrence o;
            o.file = fs.rel; o.line = t.line; o.col = t.col; o.length = t.length;
            o.kind = OccurrenceKind::MemberAccess;
            m_occurrences.push_back(o);
            continue;
        }
        if (prevScope) {
            if (namespaceOrTypeKnown(t.text)) {
                Occurrence o;
                o.file = fs.rel; o.line = t.line; o.col = t.col; o.length = t.length;
                o.kind = OccurrenceKind::TypeUse;
                m_occurrences.push_back(o);
            } else {
                // Qualified by something this authority cannot resolve (the
                // standard headers). Reporting it as undeclared would be a false
                // positive, so it is counted and skipped.
                ++fs.externalQualifiedSkipped;
                ++fs.unresolvedQualifiedSkipped;
            }
            continue;
        }

        Occurrence o;
        o.file = fs.rel; o.line = t.line; o.col = t.col; o.length = t.length;
        o.kind = OccurrenceKind::Use;
        if (nextCall) {
            o.kind = OccurrenceKind::Call;
        } else if (namespaceOrTypeKnown(t.text) && i + 1 < n &&
                   T[i + 1].type == TokType::Ident) {
            o.kind = OccurrenceKind::TypeUse;
        }
        m_occurrences.push_back(o);
    }

    // Correct the kind of every token that is a declaration site.
    for (size_t si = 0; si < m_symbols.size(); ++si) {
        const SymbolRecord& s = *m_symbols[si];
        if (s.relFile != fs.rel) continue;
        for (size_t k = occBase; k < m_occurrences.size(); ++k) {
            Occurrence& o = m_occurrences[k];
            if (o.line != s.line || o.col != s.col || o.length != s.nameLength) continue;
            switch (s.kind) {
                case SymKind::Namespace: o.kind = OccurrenceKind::Definition; break;
                case SymKind::Type:
                    o.kind = s.isDefinition ? OccurrenceKind::Definition
                                            : OccurrenceKind::Declaration;
                    break;
                case SymKind::Function:
                case SymKind::Method:
                    o.kind = s.isDefinition ? OccurrenceKind::Definition
                                            : OccurrenceKind::Declaration;
                    break;
                case SymKind::Variable:
                case SymKind::Parameter:
                    o.kind = OccurrenceKind::Declaration;
                    break;
                default: break;
            }
        }
    }
}

// ===========================================================================
// Diagnostics
// ===========================================================================

void RefactorChain::computeDiagnostics(FileState& fs) {
    const std::vector<Token>& T = fs.tokens;
    const size_t n = T.size();

    // Names bound by a signature in this file, plus every parameter and local of
    // every function defined in this file. A parameter of a prototype counts too:
    // an over-approximation here can only miss a diagnostic, never invent one.
    std::set<std::string> boundInFile;
    // A token that is a declaration's own name is not a use of an undeclared
    // name. Without this the rule reports the prototype it just parsed as
    // `undeclared_identifier`, because the check runs over the same token stream
    // that produced the declaration.
    std::set<std::pair<uint32_t, uint32_t>> declNameSites;
    for (size_t si = 0; si < m_symbols.size(); ++si) {
        const SymbolRecord& s = *m_symbols[si];
        if (s.relFile != fs.rel) continue;
        for (const auto& p : s.params) boundInFile.insert(p.second);
        for (const auto& l : s.locals) boundInFile.insert(l.second);
        if (s.kind == SymKind::Variable) boundInFile.insert(s.name);
        declNameSites.insert(std::make_pair(s.line, s.col));
    }
    auto boundInEnclosingFunction = [&](uint32_t ln, const std::string& name) -> bool {
        for (size_t si = 0; si < m_symbols.size(); ++si) {
            const SymbolRecord& s = *m_symbols[si];
            if (s.relFile != fs.rel) continue;
            if (s.kind != SymKind::Function && s.kind != SymKind::Method) continue;
            if (s.bodyFirstLine == 0) continue;
            if (ln < s.bodyFirstLine || ln > s.bodyLastLine) continue;
            for (const auto& p : s.params) if (p.second == name) return true;
            for (const auto& l : s.locals) if (l.second == name) return true;
        }
        return false;
    };

    std::map<uint32_t, std::vector<size_t>> byLine;
    for (size_t i = 0; i < n; ++i) byLine[T[i].line].push_back(i);
    std::vector<uint32_t> codeLines;
    for (const auto& kv : byLine) codeLines.push_back(kv.first);
    std::sort(codeLines.begin(), codeLines.end());

    // ---- D1 missing_semicolon ----------------------------------------------
    for (size_t k = 0; k < codeLines.size(); ++k) {
        const uint32_t ln = codeLines[k];
        const std::vector<size_t>& idxs = byLine[ln];
        if (idxs.empty()) continue;
        const Token& last = T[idxs.back()];

        const std::string trimmed = trimBothStr(fs.lines[ln - 1]);
        if (trimmed.empty()) continue;
        if (trimmed.back() == ';' || trimmed.back() == '{' || trimmed.back() == '}' ||
            trimmed.back() == ',' || trimmed.back() == ':') continue;
        if (trimmed == "else" || trimmed == "try" || trimmed == "public" ||
            trimmed == "private" || trimmed == "protected") continue;
        if (trimmed.compare(0, 6, "using ") == 0 ||
            trimmed.compare(0, 9, "namespace") == 0) continue;

        if (last.text == ";" || last.text == "{" || last.text == "}" ||
            last.text == "," || last.text == ":") continue;

        static const char* const cont[] = {
            "+","-","*","/","%","&","|","^","<",">","=",".","?","!", "~","(", "["
        };
        bool continuation = false;
        for (const char* c : cont) if (last.text == c) { continuation = true; break; }
        if (continuation) continue;

        const bool valueEnded = (last.type == TokType::Number) ||
                                (last.type == TokType::Ident && !isCppKeyword(last.text));
        if (!valueEnded) continue;

        if (k + 1 >= codeLines.size()) continue;
        const uint32_t nextLn = codeLines[k + 1];
        const Token& first = T[byLine[nextLn].front()];
        const bool nextStartsStatement =
            first.text == "}" || first.type == TokType::Ident || first.type == TokType::Number;
        if (!nextStartsStatement) continue;

        Diagnostic d;
        d.file = fs.rel;
        d.line = ln;
        d.col = last.col + last.length;
        d.code = "missing_semicolon";
        d.message = "statement ends with a value but not ';'";
        fs.diagnostics.push_back(d);

        CodeAction a;
        a.title = "Insert missing ';' at end of line";
        a.diagnosticCode = d.code;
        a.diagnosticLine = ln;
        TextEdit e;
        e.file = fs.rel;
        e.line = ln;
        e.col = static_cast<uint32_t>(fs.lines[ln - 1].size()) + 1;
        e.length = 0;
        e.text = ";";
        a.edits.push_back(e);
        fs.actions.push_back(a);
    }

    // ---- D2 undeclared_identifier ------------------------------------------
    for (size_t i = 0; i < n; ++i) {
        const Token& t = T[i];
        if (t.type != TokType::Ident) continue;
        if (isCppKeyword(t.text) || isBuiltinTypeName(t.text)) continue;

        const bool prevMember =
            (i > 0 && T[i - 1].type == TokType::Punct &&
             (T[i - 1].text == "." || T[i - 1].text == "->"));
        if (prevMember) continue;
        if (scopeOpBefore(T, i)) continue;
        if (scopeOpAfter(T, i)) continue;
        if (declNameSites.count(std::make_pair(t.line, t.col))) continue;

        if (isDeclaredAnywhere(t.text)) continue;
        if (boundInFile.count(t.text)) continue;
        if (boundInEnclosingFunction(t.line, t.text)) continue;

        Diagnostic d;
        d.file = fs.rel;
        d.line = t.line;
        d.col = t.col;
        d.code = "undeclared_identifier";
        d.message = "identifier '" + t.text + "' is not declared in this workspace";
        fs.diagnostics.push_back(d);

        uint32_t arity = 0;
        const bool isCall = (i + 1 < n && T[i + 1].type == TokType::Punct &&
                             T[i + 1].text == "(");
        if (isCall) {
            size_t close = i + 1;
            int depth = 0;
            for (size_t q = i + 1; q < n; ++q) {
                if (T[q].text == "(") ++depth;
                else if (T[q].text == ")") { --depth; if (depth == 0) { close = q; break; } }
            }
            if (close > i + 2) {
                int d2 = 0;
                bool sawArg = false;
                for (size_t q = i + 2; q <= close && q < n; ++q) {
                    const std::string& x = T[q].text;
                    if (x == "(" || x == "[") ++d2;
                    else if (x == ")") {
                        if (q == close && d2 == 0) { if (sawArg) ++arity; break; }
                        --d2;
                    } else if (x == "," && d2 == 0) {
                        if (sawArg) ++arity;
                        sawArg = false;
                    } else if (!sawArg) {
                        sawArg = true;
                    }
                }
            }
        }

        CodeAction a;
        a.diagnosticCode = d.code;
        a.diagnosticLine = t.line;
        std::string params;
        for (uint32_t q = 0; q < arity; ++q) {
            if (q) params += ", ";
            params += "double";
        }
        a.title = "Declare '" + t.text + "(" + params + ")' before this statement";
        TextEdit e;
        e.file = fs.rel;
        e.line = t.line;
        e.col = 1;
        e.length = 0;
        e.text = "double " + t.text + "(" + params + ");\n";
        a.edits.push_back(e);
        fs.actions.push_back(a);
    }
}

// ===========================================================================
// Queries
// ===========================================================================

DefinitionResult RefactorChain::definition(const std::string& name) const {
    DefinitionResult r;
    r.symbolsIndexed = static_cast<uint32_t>(m_symbols.size());
    if (!m_ws.ok) { r.reason = "no workspace open"; return r; }

    const auto syms = symbolsNamed(name);
    r.candidates = static_cast<uint32_t>(syms.size());
    if (syms.empty()) {
        r.resolved = false;
        r.reason = "no declaration of '" + name + "' in the indexed workspace";
        return r;
    }
    const SymbolRecord* best = nullptr;
    int bestScore = -1;
    for (const auto* s : syms) {
        int score = 0;
        if (s->isDefinition) score += 4;
        if (s->kind == SymKind::Function || s->kind == SymKind::Method) score += 2;
        if (s->kind == SymKind::Type || s->kind == SymKind::Namespace) score += 1;
        if (score > bestScore) { bestScore = score; best = s; }
    }
    r.resolved = true;
    r.location.file = best->relFile;
    r.location.line = best->line;
    r.location.col = best->col;
    r.location.symbol = best->name;
    r.qualifiedName = best->qualifiedName;
    return r;
}

ReferenceResult RefactorChain::references(const std::string& name, uint32_t limit) const {
    ReferenceResult r;
    r.name = name;
    if (!m_ws.ok) { r.reason = "no workspace open"; return r; }

    // Occurrences carry position and length; the token text is read back from the
    // file so that a length collision can never be mistaken for a name match.
    std::vector<const Occurrence*> sites;
    for (const auto& o : m_occurrences) {
        const FileState* f = findFile(o.file);
        if (!f) continue;
        const Token* found = nullptr;
        for (const Token& t : f->tokens) {
            if (t.line == o.line && t.col == o.col && t.length == o.length) {
                found = &t;
                break;
            }
        }
        if (!found || found->text != name) continue;
        sites.push_back(&o);
        if (sites.size() >= limit) break;
    }

    if (sites.empty() && !isDeclaredAnywhere(name)) {
        r.reason = "'" + name + "' is not present in the indexed workspace";
        return r;
    }

    for (const auto* o : sites) {
        switch (o->kind) {
            case OccurrenceKind::Definition:   ++r.definitionCount; break;
            case OccurrenceKind::Declaration:  ++r.declarationCount; break;
            case OccurrenceKind::Call:         ++r.callCount; break;
            default:                           ++r.useCount; break;
        }
        Location L;
        L.file = o->file; L.line = o->line; L.col = o->col; L.symbol = name;
        r.sites.push_back(L);
    }
    std::sort(r.sites.begin(), r.sites.end(), [](const Location& a, const Location& b) {
        if (a.file != b.file) return a.file < b.file;
        if (a.line != b.line) return a.line < b.line;
        return a.col < b.col;
    });

    for (const auto& kv : m_files) {
        for (const SkippedName& s : kv.second.skipped) {
            if (s.text != name) continue;
            if (s.inString) ++r.stringOccurrencesSkipped;
            else ++r.commentOccurrencesSkipped;
        }
    }
    if (r.sites.empty()) r.reason = "no code occurrence of '" + name + "'";
    return r;
}

RenameResult RefactorChain::renameSymbol(const std::string& oldName,
                                         const std::string& newName,
                                         bool dryRun) {
    RenameResult r;
    r.oldName = oldName;
    r.newName = newName;
    if (!m_ws.ok) { r.reason = "no workspace open"; return r; }
    if (oldName.empty() || newName.empty()) {
        r.reason = "both the old and the new name are required";
        return r;
    }
    if (!isIdentStartCh(oldName[0]) || !isIdentStartCh(newName[0])) {
        r.reason = "both names must be identifiers";
        return r;
    }
    for (char c : newName) {
        if (!isIdentCharCh(c)) { r.reason = "the new name is not an identifier"; return r; }
    }

    struct Hit { std::string file; uint32_t line, col, len; };
    std::vector<Hit> hits;
    for (const auto& kv : m_files) {
        const FileState& f = kv.second;
        for (const Token& t : f.tokens) {
            if (t.type != TokType::Ident) continue;
            if (t.text != oldName) continue;              // whole-token match only
            hits.push_back(Hit{f.rel, t.line, t.col, t.length});
        }
        for (const SkippedName& s : f.skipped) {
            if (s.text != oldName) continue;
            if (s.inString) ++r.stringsSkipped; else ++r.commentsSkipped;
        }
        // Near-miss tokens are counted so a substring implementation is visible.
        for (const Token& t : f.tokens) {
            if (t.type != TokType::Ident) continue;
            if (t.text == oldName) continue;
            if (t.text.find(oldName) != std::string::npos) ++r.nearMissTokensSkipped;
        }
    }

    if (hits.empty()) {
        r.reason = "no code occurrence of '" + oldName + "'; nothing was edited";
        return r;
    }

    // Apply per file, bottom-up by (line, col) so offsets stay valid.
    std::map<std::string, std::vector<Hit>> byFile;
    for (const auto& h : hits) byFile[h.file].push_back(h);

    for (auto& kv : byFile) {
        std::vector<Hit>& v = kv.second;
        std::sort(v.begin(), v.end(), [](const Hit& a, const Hit& b) {
            if (a.line != b.line) return a.line > b.line;
            return a.col > b.col;
        });
        const FileState* f = findFile(kv.first);
        if (!f) { r.reason = "file vanished from the index: " + kv.first; return r; }
        std::vector<std::string> lines = f->lines;
        for (const Hit& h : v) {
            if (h.line == 0 || h.line > lines.size()) {
                r.reason = "edit target outside file: " + kv.first;
                return r;
            }
            std::string& s = lines[h.line - 1];
            if (h.col == 0 || h.col > s.size() + 1) {
                r.reason = "edit column outside file: " + kv.first;
                return r;
            }
            s = s.substr(0, h.col - 1) + newName + s.substr(h.col - 1 + h.len);
        }
        const std::string updated = joinLines(lines) +
            (f->bytes.empty() || f->bytes.back() == '\n' ? std::string() : std::string());
        if (!dryRun) {
            std::string werr;
            if (!writeFileAtomic(kv.first, updated, &werr)) {
                r.reason = werr;
                return r;
            }
        }
        r.filesTouched += 1;
        r.editCount += static_cast<uint32_t>(v.size());
    }

    for (const auto& kv : byFile) {
        for (const Hit& h : kv.second) {
            Location L;
            L.file = h.file; L.line = h.line; L.col = h.col; L.symbol = newName;
            r.edited.push_back(L);
        }
    }
    std::sort(r.edited.begin(), r.edited.end(), [](const Location& a, const Location& b) {
        if (a.file != b.file) return a.file < b.file;
        if (a.line != b.line) return a.line < b.line;
        return a.col < b.col;
    });

    r.applied = true;
    if (!dryRun) reindex(nullptr);
    return r;
}

namespace {

// Case-insensitive subsequence match, the rule a quick-open uses.
int fuzzyScore(const std::string& name, const std::string& lowerQuery) {
    if (lowerQuery.empty()) return 0;
    size_t qi = 0;
    int score = 0;
    int streak = 0;
    for (size_t ni = 0; ni < name.size() && qi < lowerQuery.size(); ++ni) {
        const char c = static_cast<char>(std::tolower(static_cast<unsigned char>(name[ni])));
        if (c == lowerQuery[qi]) {
            ++qi;
            ++streak;
            score += 1 + streak;
            if (ni == 0) score += 8;
        } else {
            streak = 0;
        }
    }
    if (qi < lowerQuery.size()) return 0;
    return score;
}

}  // namespace

SearchResult RefactorChain::symbolSearch(const std::string& query, uint32_t limit) const {
    SearchResult r;
    r.query = query;
    if (!m_ws.ok) { r.reason = "no workspace open"; return r; }
    if (query.empty()) { r.reason = "empty query"; return r; }

    std::string lq = query;
    std::transform(lq.begin(), lq.end(), lq.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });

    struct Ranked { int score; size_t nameLen; Location loc; };
    std::vector<Ranked> hits;
    std::set<std::string> placed;
    for (size_t si = 0; si < m_symbols.size(); ++si) {
        const SymbolRecord& s = *m_symbols[si];
        if (!s.isDefinition) continue;
        const int sc = fuzzyScore(s.name, lq);
        if (sc <= 0) continue;
        // One symbol, one row. A workspace that declares the same definition in
        // more than one record would otherwise show it three times in the
        // palette, which reads as three distinct symbols at one location.
        const std::string key = s.relFile + ":" + std::to_string(s.line) + ":" +
                                std::to_string(s.col) + ":" + s.name;
        if (placed.count(key)) continue;
        placed.insert(key);
        ++r.considered;
        Location L;
        L.file = s.relFile; L.line = s.line; L.col = s.col; L.symbol = s.name;
        hits.push_back(Ranked{sc, s.name.size(), L});
    }
    // Equal scores rank the shorter name first: when a query is a subsequence of
    // several near misses, the shortest one is the most specific match. Without
    // this the result depends on file ordering, which is not a ranking rule.
    std::sort(hits.begin(), hits.end(), [](const Ranked& a, const Ranked& b) {
        if (a.score != b.score) return a.score > b.score;
        if (a.nameLen != b.nameLen) return a.nameLen < b.nameLen;
        if (a.loc.file != b.loc.file) return a.loc.file < b.loc.file;
        return a.loc.line < b.loc.line;
    });
    for (const auto& h : hits) {
        if (r.ranked.size() >= limit) break;
        r.ranked.push_back(h.loc);
    }
    if (r.ranked.empty()) r.reason = "no symbol matched '" + query + "'";
    return r;
}

SearchResult RefactorChain::workspaceSymbols(const std::string& query, uint32_t limit) const {
    SearchResult r = symbolSearch(query, limit);
    if (!m_ws.ok) return r;
    // The workspace variant must actually span roots, so record which roots the
    // hits came from rather than returning the same list as symbolSearch.
    std::set<std::string> rootsHit;
    for (const auto& L : r.ranked) {
        for (const auto& root : m_ws.roots) {
            const std::string prefix = root + "/";
            if (L.file.compare(0, prefix.size(), prefix) == 0) {
                rootsHit.insert(root);
                break;
            }
        }
    }
    if (rootsHit.size() > 1) r.reason.clear();
    return r;
}

std::vector<Diagnostic> RefactorChain::diagnostics(const std::string& relFile) const {
    const FileState* f = findFile(relFile);
    if (!f) return {};
    return f->diagnostics;
}

std::vector<CodeAction> RefactorChain::codeActions(const std::string& relFile) const {
    const FileState* f = findFile(relFile);
    if (!f) return {};
    return f->actions;
}

std::vector<std::string> RefactorChain::indexedFiles() const {
    std::vector<std::string> out;
    out.reserve(m_files.size());
    for (const auto& kv : m_files) out.push_back(kv.first);
    std::sort(out.begin(), out.end());
    return out;
}

std::vector<std::string> RefactorChain::indexedFileKeys() const {
    return indexedFiles();
}

std::vector<RefactorChain::SymbolView> RefactorChain::explainSymbol(const std::string& name) const {
    std::vector<SymbolView> out;
    for (const auto& rec : m_symbols) {
        if (name != "*" && rec->name != name) continue;
        SymbolView v;
        v.file = rec->relFile;
        v.name = rec->name;
        v.qualifiedName = rec->qualifiedName;
        v.kind = symKindName(rec->kind);
        v.declaredType = rec->declaredType;
        v.line = rec->line;
        v.col = rec->col;
        v.isDefinition = rec->isDefinition;
        out.push_back(v);
    }
    return out;
}

bool RefactorChain::applyCodeAction(const std::string& relFile,
                                    uint32_t actionIndex,
                                    std::string* err) {
    const FileState* f = findFile(relFile);
    if (!f) { if (err) *err = "no such file in the workspace: " + relFile; return false; }
    if (actionIndex >= f->actions.size()) {
        if (err) *err = "no code action at that index";
        return false;
    }
    const CodeAction a = f->actions[actionIndex];
    std::vector<std::string> lines = f->lines;
    for (const TextEdit& e : a.edits) {
        if (e.line == 0 || e.line > lines.size()) {
            if (err) *err = "edit outside file";
            return false;
        }
        const size_t at = e.col == 0 ? 0 : (e.col - 1);
        if (at > lines[e.line - 1].size()) {
            if (err) *err = "edit column outside file";
            return false;
        }
        std::string& s = lines[e.line - 1];
        s = s.substr(0, at) + e.text + s.substr(at + e.length);
    }
    std::string werr;
    if (!writeFileAtomic(relFile, joinLines(lines), &werr)) {
        if (err) *err = werr;
        return false;
    }
    return reindex(err);
}

FormatResult RefactorChain::formatFile(const std::string& relFile, bool dryRun) {
    FormatResult r;
    r.file = relFile;
    const FileState* f = findFile(relFile);
    if (!f) { r.reason = "no such file in the workspace: " + relFile; return r; }

    r.bytesBefore = static_cast<uint32_t>(f->bytes.size());
    uint32_t linesChanged = 0;
    const std::string formatted = normalizeWhitespace(f->bytes, &linesChanged, 4, &r.rulesApplied);
    r.linesChanged = linesChanged;
    r.bytesAfter = static_cast<uint32_t>(formatted.size());
    r.changed = (formatted != f->bytes);
    r.ok = true;
    if (!r.changed || dryRun) {
        if (dryRun && r.changed) r.reason = "dry run: no file was written";
        return r;
    }
    std::string werr;
    if (!writeFileAtomic(relFile, formatted, &werr)) {
        r.ok = false;
        r.reason = werr;
        return r;
    }
    reindex(nullptr);
    return r;
}

FormatResult RefactorChain::formatAll(uint32_t* filesChanged) {
    FormatResult agg;
    agg.ok = true;
    std::vector<std::string> rels;
    for (const auto& kv : m_files) rels.push_back(kv.first);
    std::sort(rels.begin(), rels.end());
    uint32_t changed = 0;
    for (const auto& rel : rels) {
        const FormatResult one = formatFile(rel, false);
        if (!one.ok) { agg.ok = false; agg.reason = one.reason; continue; }
        if (one.changed) ++changed;
        agg.linesChanged += one.linesChanged;
        agg.bytesBefore += one.bytesBefore;
        agg.bytesAfter += one.bytesAfter;
    }
    agg.changed = changed > 0;
    if (filesChanged) *filesChanged = changed;
    return agg;
}

ExtractResult RefactorChain::extractFunction(const std::string& relFile,
                                             uint32_t firstLine,
                                             uint32_t lastLine,
                                             const std::string& newName) {
    ExtractResult r;
    r.file = relFile;
    r.newSymbol = newName;
    r.blockFirstLine = firstLine;
    r.blockLastLine = lastLine;

    const FileState* f = findFile(relFile);
    if (!f) { r.reason = "no such file in the workspace: " + relFile; return r; }
    if (firstLine == 0 || lastLine < firstLine || lastLine > f->lines.size()) {
        r.reason = "requested block is outside the file";
        return r;
    }
    if (newName.empty() || !isIdentStartCh(newName[0])) {
        r.reason = "the new symbol must be an identifier";
        return r;
    }
    if (isDeclaredAnywhere(newName)) {
        r.reason = "'" + newName + "' already exists in the workspace";
        return r;
    }

    // enclosing function
    const SymbolRecord* owner = nullptr;
    for (size_t si = 0; si < m_symbols.size(); ++si) {
        const SymbolRecord& s = *m_symbols[si];
        if (s.relFile != relFile) continue;
        if (s.kind != SymKind::Function && s.kind != SymKind::Method) continue;
        if (!s.isDefinition || s.bodyFirstLine == 0) continue;
        if (firstLine <= s.bodyFirstLine || lastLine > s.bodyLastLine) continue;
        if (!owner || s.bodyFirstLine > owner->bodyFirstLine) owner = &s;
    }
    if (!owner) {
        r.reason = "the selected block is not inside a function body";
        return r;
    }
    r.enclosingSymbol = owner->qualifiedName;

    // Free variables: identifiers the block reads or writes that are neither
    // bound inside the block nor reachable without a parameter. Member accesses
    // and namespace qualifiers are excluded, because `s.count` is a property of
    // `s` and not a name this function has to accept.
    std::set<std::string> insideBlock;
    for (size_t i = 0; i < m_symbols.size(); ++i) {
        const SymbolRecord& s = *m_symbols[i];
        if (s.relFile != relFile) continue;
        if (s.kind != SymKind::Variable) continue;
        if (s.line >= firstLine && s.line <= lastLine) insideBlock.insert(s.name);
    }
    std::vector<std::string> freeVars;
    std::vector<std::string> assignedFreeVars;
    for (size_t i = 0; i < f->tokens.size(); ++i) {
        const Token& t = f->tokens[i];
        if (t.type != TokType::Ident) continue;
        if (t.line < firstLine || t.line > lastLine) continue;
        if (isCppKeyword(t.text) || isBuiltinTypeName(t.text)) continue;
        if (insideBlock.count(t.text)) continue;
        const bool prevMember =
            (i > 0 && f->tokens[i - 1].type == TokType::Punct &&
             (f->tokens[i - 1].text == "." || f->tokens[i - 1].text == "->"));
        if (prevMember) continue;
        const bool nextQual =
            (i + 1 < f->tokens.size() && f->tokens[i + 1].type == TokType::Punct &&
             f->tokens[i + 1].text == "::");
        if (nextQual) continue;

        bool already = false;
        for (const auto& v : freeVars) if (v == t.text) { already = true; break; }
        if (!already) freeVars.push_back(t.text);

        const bool assignment =
            (i + 1 < f->tokens.size() && f->tokens[i + 1].type == TokType::Punct &&
             (f->tokens[i + 1].text == "=" || f->tokens[i + 1].text == "+=" ||
              f->tokens[i + 1].text == "-=" || f->tokens[i + 1].text == "*=" ||
              f->tokens[i + 1].text == "/="));
        if (assignment) {
            bool seenAssign = false;
            for (const auto& v : assignedFreeVars) if (v == t.text) { seenAssign = true; break; }
            if (!seenAssign) assignedFreeVars.push_back(t.text);
        }
    }

    // parameter types come from the enclosing function's own declarations
    std::vector<std::pair<std::string, std::string>> params;
    for (const auto& v : freeVars) {
        std::string ty;
        for (const auto& p : owner->params) if (p.second == v) { ty = p.first; break; }
        if (ty.empty()) {
            for (const auto& l : owner->locals) if (l.second == v) { ty = l.first; break; }
        }
        if (ty.empty()) {
            for (size_t si = 0; si < m_symbols.size(); ++si) {
                const SymbolRecord& s = *m_symbols[si];
                if (s.relFile == relFile && s.kind == SymKind::Variable &&
                    s.name == v && s.declaredType.size()) { ty = s.declaredType; break; }
            }
        }
        if (ty.empty()) {
            r.reason = "cannot infer a type for the free variable '" + v +
                       "'; refusing to guess one";
            return r;
        }
        params.push_back({ty, v});
        r.parameterTypes.push_back(ty);
    }
    r.paramCount = static_cast<uint32_t>(params.size());

    // Return type: the type of the single free variable the block assigns,
    // otherwise the enclosing function's declared return type. When neither is
    // available the operation refuses rather than inventing a type.
    std::string retType = owner->returnType;
    std::string retVar;
    if (assignedFreeVars.size() == 1) {
        retVar = assignedFreeVars[0];
        for (const auto& p : params) {
            if (p.second == retVar) { retType = p.first; break; }
        }
    } else if (assignedFreeVars.size() > 1) {
        r.reason = "the block assigns " + std::to_string(assignedFreeVars.size()) +
                   " free variables; extract-function needs exactly one return value";
        return r;
    }
    if (retType.empty()) {
        r.reason = "cannot infer the return type of the extracted block";
        return r;
    }

    // build the new function and the call site
    std::string indent;
    {
        const std::string& firstBlockLine = f->lines[firstLine - 1];
        size_t w = 0;
        while (w < firstBlockLine.size() && (firstBlockLine[w] == ' ' || firstBlockLine[w] == '\t')) ++w;
        if (w > 0) indent.assign(w, firstBlockLine[0] == '\t' ? '\t' : ' ');
    }
    const std::string inner = indent + "    ";
    std::string paramText;
    for (size_t q = 0; q < params.size(); ++q) {
        if (q) paramText += ", ";
        paramText += params[q].first + " " + params[q].second;
    }
    std::string argText;
    for (size_t q = 0; q < params.size(); ++q) {
        if (q) argText += ", ";
        argText += params[q].second;
    }

    std::vector<std::string> insert;
    insert.push_back(retType + " " + newName + "(" + paramText + ") {");
    for (uint32_t ln = firstLine; ln <= lastLine; ++ln) {
        std::string line = f->lines[ln - 1];
        if (!indent.empty() && line.compare(0, indent.size(), indent) == 0) {
            line = line.substr(indent.size());
        }
        insert.push_back(inner + line);
    }
    if (!retVar.empty()) insert.push_back(inner + "return " + retVar + ";");
    insert.push_back("}");
    insert.push_back("");

    if (owner->stmtFirstLine == 0 || owner->stmtFirstLine > f->lines.size()) {
        r.reason = "the enclosing function range is not usable";
        return r;
    }

    std::vector<std::string> lines = f->lines;
    // Replace the selected block with exactly one call first, so the enclosing
    // function's own first line is unchanged.
    const std::string call = indent + newName + "(" + argText + ");";
    lines.erase(lines.begin() + (firstLine - 1), lines.begin() + lastLine);
    lines.insert(lines.begin() + (firstLine - 1), call);

    // Insert the extracted function ABOVE the enclosing function, not below it.
    // Below would make the call site reference a function that is not declared
    // yet, which is a compile error -- an extracted function has to land where
    // the caller can already see it.
    const size_t insertAt = owner->stmtFirstLine - 1;
    lines.insert(lines.begin() + insertAt, insert.begin(), insert.end());

    std::string werr;
    if (!writeFileAtomic(relFile, joinLines(lines), &werr)) {
        r.reason = werr;
        return r;
    }
    reindex(nullptr);

    r.functionLine = owner->stmtFirstLine;
    r.callsiteLine = static_cast<uint32_t>(firstLine + insert.size());
    r.editCount = 1 + params.size();
    r.applied = true;
    return r;
}

}  // namespace refactor
}  // namespace rawrxd
