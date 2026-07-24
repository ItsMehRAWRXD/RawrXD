// ============================================================================
// IntelliSense.hpp - IntelliSense Engine for Sovereign IDE
// Auto-completion, parameter hints, signature help
// ============================================================================

#pragma once
#include <cstdint>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace Sovereign {

struct CompletionItem {
    std::string label;
    std::string detail;
    std::string documentation;
    std::string insertText;
    std::string kind; // function, class, variable, keyword, snippet
    float score;
    std::vector<std::string> additionalTextEdits;
};

struct ParameterHint {
    std::string label;
    std::string documentation;
    bool isOptional;
};

struct SignatureHelp {
    std::string signature;
    std::string documentation;
    std::vector<ParameterHint> parameters;
    int activeParameter;
    int activeSignature;
};

class IntelliSense {
public:
    IntelliSense();
    ~IntelliSense();

    bool Initialize();
    void Shutdown();

    // Auto-completion
    std::vector<CompletionItem> AutoComplete(const std::string& context, const std::string& prefix, const std::string& language);
    std::vector<CompletionItem> AutoCompleteAtPosition(const std::string& file, uint32_t line, uint32_t column);
    std::vector<CompletionItem> GetSymbolCompletions(const std::string& prefix, const std::vector<std::string>& symbols);

    // Parameter hints
    ParameterHint GetParameterHint(const std::string& function, int paramIndex);
    std::vector<ParameterHint> GetParameterHints(const std::string& function);

    // Signature help
    SignatureHelp GetSignatureHelp(const std::string& file, uint32_t line, uint32_t column);
    SignatureHelp GetSignatureHelpForFunction(const std::string& function);

    // Snippets
    std::vector<CompletionItem> GetSnippets(const std::string& prefix, const std::string& language);
    void RegisterSnippet(const std::string& name, const std::string& prefix, const std::string& body, const std::string& language);

    // Context-aware completion
    std::vector<CompletionItem> GetContextCompletions(const std::string& code, uint32_t line, uint32_t column, const std::string& language);

    struct IntelliSenseStats { uint64_t totalCompletions; uint64_t totalSignatures; uint64_t totalSnippets; };
    IntelliSenseStats GetStats() const { return stats_; }

private:
    IntelliSenseStats stats_;
    bool initialized_ = false;
    
    struct Snippet { std::string name; std::string prefix; std::string body; std::string language; };
    std::vector<Snippet> snippets_;
    
    mutable std::mutex mutex_;
    
    void InitializeDefaultSnippets();
    std::vector<CompletionItem> GetLanguageKeywords(const std::string& language) const;
    std::vector<CompletionItem> GetLanguageSnippets(const std::string& prefix, const std::string& language) const;
};

} // namespace Sovereign
