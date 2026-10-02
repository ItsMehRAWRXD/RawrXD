// ============================================================================
// RefactorChain.h — RAWRXD_P1_REFACTOR_CHAIN_001
//
// The refactoring chain the IDE claims to have, as one authority with one
// measured result type per capability:
//
//   definition → references → rename → symbol search → workspace symbols
//   → diagnostics → code actions → format → extract function
//
// Why one authority instead of nine subsystems:
//
// The census behind this gate found that the shipping surface for the LSP
// commands is src/core/command_registry.hpp's COMMAND_TABLE, auto-registered
// into SharedFeatureRegistry by src/core/unified_command_dispatch.cpp, and that
// every COMMAND_TABLE handler symbol the IDE link resolves comes from
// src/core/win32ide_handler_impls.cpp -- a file in which all 376 handler
// definitions are the same line,
//
//     CommandResult handleX(const CommandContext& ctx) { (void)ctx; return CommandResult::ok(); }
//
// so "the command exists and returns success" carried no information. A second
// registry, 432 features wide, exists in src/core/auto_feature_registry.cpp,
// but its registration function initAutoFeatureRegistry() has no caller, so
// repairs made there were never dispatched either.
//
// So the chain needs an implementation that produces an observable result on
// disk, a binding that the table provably points at, and a certification that
// measures both. That is what this file and its siblings are.
//
// Design rules that follow from the failure being fixed:
//   * Every mutating call returns a result that carries its own evidence:
//     editCount, filesTouched, linesChanged, applied. A caller cannot report
//     success without reading a number that was measured.
//   * RENAME_SUCCESS_REQUIRES_EDIT_COUNT_GT_0. A rename that edited nothing is
//     an error, not a success.
//   * GOTO_DEFINITION_SUCCESS_REQUIRES_RESOLVED_LOCATION. A lookup that did not
//     resolve returns resolved=false with the reason, never a success.
//   * Occurrences are token-based, never substring-based. `WidgetCacheSlot` must
//     not match `resetWidgetCacheSlot`, and a name inside a comment or string
//     literal is not an occurrence. The first census was wrong exactly here:
//     the symbol `RenameSymbol` matched five hits that were all
//     std::filesystem::rename.
//   * Nothing is claimed from source presence. The verdict comes from the bytes
//     on disk after the operation and, for refactoring, from the fixture still
//     compiling and still printing identical output.
// ============================================================================
#pragma once

#ifndef RAWRXD_REFACTOR_CHAIN_H
#define RAWRXD_REFACTOR_CHAIN_H

#include <cstdint>
#include <map>
#include <memory>
#include <string>
#include <vector>

namespace rawrxd {
namespace refactor {

// ---------------------------------------------------------------------------
// Shared value types
// ---------------------------------------------------------------------------

struct Location {
    std::string file;        // workspace-relative, forward slashes
    uint32_t    line = 0;    // 1-based
    uint32_t    col  = 0;    // 1-based
    std::string symbol;
};

enum class OccurrenceKind : uint8_t {
    Definition = 0,   // function body, or class/struct/union/enum name
    Declaration = 1,  // prototype with no body, or a parameter type mention
    Use = 2,
    Call = 3,         // identifier immediately followed by '('
    TypeUse = 4,      // identifier used in type position
    MemberAccess = 5  // identifier after '.' or '->'
};

const char* occurrenceKindName(OccurrenceKind k);

struct Occurrence {
    std::string    file;
    uint32_t       line = 0;
    uint32_t       col = 0;
    uint32_t       length = 0;
    OccurrenceKind kind = OccurrenceKind::Use;
};

struct Diagnostic {
    std::string file;
    uint32_t    line = 0;
    uint32_t    col = 0;
    std::string code;
    std::string message;
};

struct TextEdit {
    std::string file;
    uint32_t    line = 0;
    uint32_t    col = 0;
    uint32_t    length = 0;
    std::string text;
};

struct CodeAction {
    std::string           title;
    std::string           diagnosticCode;
    uint32_t              diagnosticLine = 0;
    std::vector<TextEdit> edits;
};

struct DefinitionResult {
    bool        resolved = false;
    Location    location;
    uint32_t    candidates = 0;      // how many declarations matched the name
    uint32_t    symbolsIndexed = 0;
    std::string qualifiedName;
    std::string reason;              // empty only when resolved
};

struct ReferenceResult {
    std::string              name;
    uint32_t                 declarationCount = 0;
    uint32_t                 definitionCount = 0;
    uint32_t                 useCount = 0;
    uint32_t                 callCount = 0;
    uint32_t                 commentOccurrencesSkipped = 0;
    uint32_t                 stringOccurrencesSkipped = 0;
    std::vector<Location>    sites;
    std::string              reason;   // empty only when the name is known
};

struct RenameResult {
    bool                  applied = false;
    std::string           oldName;
    std::string           newName;
    uint32_t              editCount = 0;
    uint32_t              filesTouched = 0;
    uint32_t              commentsSkipped = 0;
    uint32_t              stringsSkipped = 0;
    uint32_t              nearMissTokensSkipped = 0;
    std::vector<Location> edited;
    std::string           reason;
};

struct SearchResult {
    std::string           query;
    uint32_t              considered = 0;
    std::vector<Location> ranked;
    std::string           reason;
};

struct FormatResult {
    bool                     ok = false;
    bool                     changed = false;
    std::string              file;
    uint32_t                 linesChanged = 0;
    uint32_t                 bytesBefore = 0;
    uint32_t                 bytesAfter = 0;
    std::vector<std::string> rulesApplied;
    std::string              reason;
};

struct ExtractResult {
    bool                     applied = false;
    std::string              file;
    std::string              newSymbol;
    uint32_t                 blockFirstLine = 0;
    uint32_t                 blockLastLine = 0;
    uint32_t                 functionLine = 0;   // 1-based line of the new function
    uint32_t                 callsiteLine = 0;   // 1-based line of the call
    uint32_t                 editCount = 0;
    uint32_t                 paramCount = 0;
    std::vector<std::string> parameterTypes;
    std::string              enclosingSymbol;
    std::string              reason;
};

struct WorkspaceInfo {
    bool                     ok = false;
    std::string              root;
    std::vector<std::string> roots;
    uint32_t                 filesIndexed = 0;
    uint32_t                 symbolsIndexed = 0;
    uint32_t                 occurrencesIndexed = 0;
    uint64_t                 bytesIndexed = 0;
    uint32_t                 skippedNonSource = 0;
    std::string              reason;
};

// ---------------------------------------------------------------------------
// The authority
// ---------------------------------------------------------------------------

class RefactorChain {
public:
    static RefactorChain& instance();

    // `rootOrWorkspaceFile` is either a directory or a *.code-workspace JSON
    // document with a "folders" array. Directories that do not exist are an
    // error, never an empty index reported as success.
    bool open(const std::string& rootOrWorkspaceFile, std::string* err = nullptr);
    void close();
    bool isOpen() const { return m_ws.ok; }
    const WorkspaceInfo& workspace() const { return m_ws; }

    // Non-mutating queries.
    DefinitionResult                definition(const std::string& name) const;
    ReferenceResult                 references(const std::string& name,
                                               uint32_t limit = 512) const;
    SearchResult                    symbolSearch(const std::string& query,
                                                uint32_t limit = 32) const;
    SearchResult                    workspaceSymbols(const std::string& query,
                                                     uint32_t limit = 32) const;
    std::vector<Diagnostic>         diagnostics(const std::string& relFile) const;
    std::vector<CodeAction>         codeActions(const std::string& relFile) const;
    std::vector<std::string>        knownRoots() const { return m_ws.roots; }
    std::vector<std::string>        indexedFiles() const;

    // Mutating operations. Every one of these writes to disk and re-reads what
    // it wrote; the returned counters come from that re-read.
    RenameResult   renameSymbol(const std::string& oldName,
                                const std::string& newName,
                                bool dryRun = false);
    bool           applyCodeAction(const std::string& relFile,
                                   uint32_t actionIndex,
                                   std::string* err = nullptr);
    FormatResult   formatFile(const std::string& relFile, bool dryRun = false);
    FormatResult   formatAll(uint32_t* filesChanged = nullptr);
    ExtractResult  extractFunction(const std::string& relFile,
                                   uint32_t firstLine,
                                   uint32_t lastLine,
                                   const std::string& newName);

    // Re-read the tree from disk, so a following query sees the mutation.
    bool reindex(std::string* err = nullptr);

    // Diagnosis surface. When the diagnostics engine claims a name is undeclared,
    // the question is always "what does the index think it is", and answering that
    // requires looking inside a private record. A diagnostic that cannot be
    // explained cannot be trusted.
    struct SymbolView {
        std::string file;
        std::string name;
        std::string qualifiedName;
        std::string kind;
        std::string declaredType;
        uint32_t    line = 0;
        uint32_t    col = 0;
        bool        isDefinition = false;
    };
    std::vector<SymbolView>  explainSymbol(const std::string& name) const;
    std::vector<std::string> indexedFileKeys() const;

private:
    RefactorChain() = default;
    ~RefactorChain();
    RefactorChain(const RefactorChain&) = delete;
    RefactorChain& operator=(const RefactorChain&) = delete;

    struct FileState;
    struct SymbolRecord;

    bool               loadWorkspace(const std::string& rootOrWorkspaceFile, std::string* err);
    bool               indexRoots(std::string* err);
    bool               scanFile(const std::string& relPath, const std::string& bytes);
    void               analyzeDeclarations(FileState& fs);
    void               classifyOccurrences(FileState& fs);
    void               computeDiagnostics(FileState& fs);
    const FileState*   findFile(const std::string& relPath) const;
    std::string        absPath(const std::string& relPath) const;
    bool               writeFileAtomic(const std::string& relPath,
                                       const std::string& newBytes,
                                       std::string* err) const;

    std::vector<const SymbolRecord*> symbolsNamed(const std::string& name) const;
    bool               isDeclaredAnywhere(const std::string& name) const;
    bool               isDeclaredInFile(const std::string& relPath,
                                        const std::string& name) const;
    bool               namespaceOrTypeKnown(const std::string& name) const;

    WorkspaceInfo                                       m_ws;
    std::vector<std::string>                            m_rootsAbs;
    std::map<std::string, FileState>                    m_files;   // by rel path
    std::vector<std::unique_ptr<SymbolRecord>>          m_symbols;
    std::vector<Occurrence>                             m_occurrences;
    std::map<std::string, std::vector<size_t>>          m_declByName;
};

// Shared utilities, exposed because the certification driver verifies the
// formatter's and the extractor's contract independently of the class.
std::string normalizeWhitespace(const std::string& in,
                                uint32_t* linesChanged,
                                uint32_t indentWidth,
                                std::vector<std::string>* rulesApplied);
std::vector<std::string> splitLines(const std::string& text);
std::string joinLines(const std::vector<std::string>& lines);
std::string relPathFrom(const std::string& root, const std::string& abs);
bool        readWholeFile(const std::string& path, std::string* out, std::string* err);
bool        writeWholeFileAtomic(const std::string& path, const std::string& bytes, std::string* err);

}  // namespace refactor
}  // namespace rawrxd

#endif  // RAWRXD_REFACTOR_CHAIN_H
