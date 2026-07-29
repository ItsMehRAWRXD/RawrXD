// ============================================================================
// IDEEditor.hpp - Core IDE Editor Features
// Code folding, bracket matching, go to definition, references, hover, code actions
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

// Editor position
struct EditorPosition {
    uint32_t line;
    uint32_t column;
};

// Editor range
struct EditorRange {
    EditorPosition start;
    EditorPosition end;
};

// Folding region
struct FoldingRegion {
    EditorRange range;
    std::string placeholder;
    bool isCollapsed;
    int level;
};

// Bracket match
struct BracketMatch {
    EditorPosition open;
    EditorPosition close;
    char bracket;
};

// Definition location
struct DefinitionLocation {
    std::string file;
    EditorPosition position;
    std::string symbolName;
};

// Reference
struct Reference {
    std::string file;
    EditorRange range;
    std::string context;
};

// Hover info
struct HoverInfo {
    std::string signature;
    std::string documentation;
    std::string returnType;
    std::vector<std::string> parameters;
};

// Code action
struct CodeAction {
    std::string title;
    std::string kind;
    std::function<bool()> apply;
    bool isPreferred;
};

// Diagnostic
struct Diagnostic {
    EditorRange range;
    int severity; // 1=error, 2=warning, 3=info, 4=hint
    std::string message;
    std::string code;
    std::string source;
    std::vector<CodeAction> quickFixes;
};

// Editor engine
class IDEEditor {
public:
    IDEEditor();
    ~IDEEditor();

    bool Initialize();
    void Shutdown();

    // Code folding
    std::vector<FoldingRegion> ComputeFoldingRegions(const std::string& code, const std::string& language);
    bool IsFoldable(const std::string& code, uint32_t line) const;

    // Bracket matching
    std::vector<BracketMatch> FindBrackets(const std::string& code);
    BracketMatch FindMatchingBracket(const std::string& code, EditorPosition pos);

    // Go to definition
    DefinitionLocation GoToDefinition(const std::string& symbol, const std::string& workspace);
    DefinitionLocation GoToDefinitionAtPosition(const std::string& file, EditorPosition pos);

    // Find references
    std::vector<Reference> FindReferences(const std::string& symbol, const std::string& workspace);
    std::vector<Reference> FindReferencesAtPosition(const std::string& file, EditorPosition pos);

    // Hover
    HoverInfo GetHoverInfo(const std::string& file, EditorPosition pos);
    HoverInfo GetHoverInfoForSymbol(const std::string& symbol);

    // Code actions
    std::vector<CodeAction> GetCodeActions(const std::string& file, EditorRange range, const std::vector<Diagnostic>& diagnostics);
    std::vector<CodeAction> GetRefactorings(const std::string& file, EditorRange range);

    // Diagnostics
    std::vector<Diagnostic> ComputeDiagnostics(const std::string& code, const std::string& file, const std::string& language);
    std::vector<CodeAction> GetQuickFixes(const Diagnostic& diagnostic);

    // Error squiggles
    std::vector<EditorRange> ComputeErrorRanges(const std::vector<Diagnostic>& diagnostics);

    struct EditorStats { uint64_t totalDefinitions; uint64_t totalReferences; uint64_t totalHovers; uint64_t totalActions; };
    EditorStats GetStats() const { return stats_; }

private:
    EditorStats stats_;
    bool initialized_ = false;
    mutable std::mutex mutex_;
    
    std::vector<std::string> Tokenize(const std::string& code) const;
    bool IsBracket(char c) const;
    char GetMatchingBracket(char c) const;
};

} // namespace Sovereign
