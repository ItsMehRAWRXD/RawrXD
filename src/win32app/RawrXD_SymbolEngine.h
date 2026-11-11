#pragma once

#include <cstdint>
#include <memory>
#include <string>
#include <string_view>
#include <vector>
#include <map>
#include <mutex>
#include <shared_mutex>
#include <functional>
#include <windows.h>

namespace RawrXD::SymbolEngine {

// ============================================================================
// Range — LSP-style position range
// ============================================================================
struct Range {
    UINT lineStart = 0;
    UINT colStart = 0;
    UINT lineEnd = 0;
    UINT colEnd = 0;
};

// ============================================================================
// SymbolKind — LSP-compatible symbol kinds
// ============================================================================
enum class SymbolKind : int {
    File = 1,
    Module = 2,
    Namespace = 3,
    Package = 4,
    Class = 5,
    Method = 6,
    Property = 7,
    Field = 8,
    Constructor = 9,
    Enum = 10,
    Interface = 11,
    Function = 12,
    Variable = 13,
    Constant = 14,
    String = 15,
    Number = 16,
    Boolean = 17,
    Array = 18,
    Object = 19,
    Key = 20,
    Null = 21,
    EnumMember = 22,
    Struct = 23,
    Event = 24,
    Operator = 25,
    TypeParameter = 26
};

// ============================================================================
// Symbol — AST node
// ============================================================================
class Symbol;
using SymbolPtr = std::shared_ptr<Symbol>;

class Symbol {
public:
    UINT64 id = 0;
    std::wstring name;
    std::wstring detail;
    SymbolKind kind = SymbolKind::File;
    Range range{};
    Range selectionRange{};
    std::wstring sourceUri;
    bool deprecated = false;
    std::vector<SymbolPtr> children;
    std::weak_ptr<Symbol> parent;

    std::wstring ToAIContext() const;
    bool IsContainer() const;
};

// ============================================================================
// SymbolDatabase — persistent symbol index
// ============================================================================
class SymbolDatabase {
public:
    std::vector<SymbolPtr> SearchWorkspace(std::wstring_view query, int maxResults) const;
    SymbolPtr FindById(UINT64 id) const;
    std::vector<SymbolPtr> GetSymbolsAtLine(std::wstring_view uri, UINT line) const;
    std::vector<SymbolPtr> GetContextSymbols(std::wstring_view uri, const Range& range, int maxDepth) const;
    void IndexDocument(std::wstring_view uri, SymbolPtr root);
    void RemoveDocument(std::wstring_view uri);
    SymbolPtr GetDocumentRoot(std::wstring_view uri) const;
    void removeFromWorkspaceIndex(const SymbolPtr& sym);
    void Clear();

private:
    SymbolPtr getDocumentRootLocked(std::wstring_view uri) const;
    void removeDocumentLocked(std::wstring_view uri);
    void indexSymbolRecursive(const SymbolPtr& sym, const std::wstring& docUri);

    mutable std::shared_mutex mutex_;
    std::map<std::wstring, SymbolPtr> documentRoots_;
    std::map<std::wstring, std::vector<SymbolPtr>> workspaceIndex_;
    std::map<UINT64, SymbolPtr> idIndex_;
    UINT64 nextId_ = 1;
};

SymbolDatabase& GlobalSymbolDatabase();

// ============================================================================
// ILanguageParser — pluggable parser interface
// ============================================================================
class ILanguageParser {
public:
    virtual ~ILanguageParser() = default;
    virtual bool CanParse(std::wstring_view filename) const = 0;
    virtual SymbolPtr ParseDocument(std::wstring_view uri, std::string_view content) = 0;
};

// ============================================================================
// GenericCodeParser — regex-based parser for common languages
// ============================================================================
class GenericCodeParser : public ILanguageParser {
public:
    bool CanParse(std::wstring_view filename) const override;
    SymbolPtr ParseDocument(std::wstring_view uri, std::string_view content) override;

private:
    void Tokenize(std::string_view content, std::vector<std::pair<std::string, Range>>& tokens);
};

// ============================================================================
// SymbolIndexer — manages parsers and database
// ============================================================================
class SymbolIndexer {
public:
    explicit SymbolIndexer(SymbolDatabase& db);
    void RegisterParser(std::unique_ptr<ILanguageParser> parser);
    void IndexFile(std::wstring_view uri, std::string_view content);
    void IndexWorkspace(std::wstring_view rootPath);

private:
    SymbolDatabase& db_;
    std::vector<std::unique_ptr<ILanguageParser>> parsers_;
    std::mutex parseMutex_;
};

// ============================================================================
// LSP helpers
// ============================================================================
namespace lsp {

std::string PathToFileUri(std::wstring_view path);
std::string EscapeJsonUtf8(std::string_view s);
std::string SymbolToJsonUtf8(const Symbol& sym, bool includeChildren, std::wstring_view locationUri);
std::string DocumentSymbolResultArrayUtf8(const std::vector<SymbolPtr>& roots);
std::string WorkspaceSymbolResultArrayUtf8(const std::vector<SymbolPtr>& symbols, std::wstring_view defaultUri);
std::wstring ParseWorkspaceSymbolQueryUtf8(std::string_view json);

} // namespace lsp

// ============================================================================
// AISymbolContext — AI-facing symbol context
// ============================================================================
class AISymbolContext {
public:
    explicit AISymbolContext(SymbolDatabase& db);
    std::wstring BuildPromptContext(std::wstring_view uri, UINT line, UINT col, int maxSymbols);
    std::wstring ResolveAtReference(std::wstring_view query);
    std::vector<UINT64> ExtractSymbolRefs(std::wstring_view aiResponse);

private:
    SymbolDatabase& db_;
};

// ============================================================================
// StickyScrollController — sticky header computation
// ============================================================================
class StickyScrollController {
public:
    struct StickyLine {
        std::wstring text;
        SymbolKind kind;
        UINT originalLine = 0;
        int indentLevel = 0;
    };

    explicit StickyScrollController(SymbolDatabase& db);
    std::vector<StickyLine> ComputeStickyLines(std::wstring_view uri, UINT topVisibleLine, int maxLines);

private:
    SymbolDatabase& db_;
};

// ============================================================================
// RawrXDSymbolHost — combined host for all symbol services
// ============================================================================
class RawrXDSymbolHost {
public:
    RawrXDSymbolHost();
    void IndexFile(std::wstring_view uri, std::string_view content);
    void IndexWorkspace(std::wstring_view rootPath);
    void Clear();

    std::string DocumentSymbolLspResultUtf8(std::wstring_view uri) const;
    std::string WorkspaceSymbolLspResultUtf8(std::string_view queryUtf8) const;

    SymbolDatabase& Db() { return db_; }
    AISymbolContext& AiContext() { return ai_; }

private:
    SymbolDatabase db_;
    SymbolIndexer indexer_;
    AISymbolContext ai_;
    StickyScrollController sticky_;
};

RawrXDSymbolHost& GlobalSymbolHost();
SymbolDatabase& GlobalSymbolDatabase();
AISymbolContext& GlobalAISymbolContext();

void IndexFileAsync(std::wstring uri, std::string content);

} // namespace RawrXD::SymbolEngine
