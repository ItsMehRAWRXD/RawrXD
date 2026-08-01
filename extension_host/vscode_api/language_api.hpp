// language_api.hpp — VS Code Language API
#pragma once
#include <string>
#include <vector>
#include <functional>

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

struct Diagnostic {
    enum class Severity { Error, Warning, Information, Hint };
    std::string message;
    std::string filePath;
    int line = 0;
    int column = 0;
    Severity severity = Severity::Error;
    std::string code;
};

struct CompletionItem {
    std::string label;
    std::string detail;
    std::string documentation;
    std::string insertText;
    int kind = 0; // Method, Function, Class, etc.
};

struct HoverItem {
    std::string contents;
    int line = 0;
    int column = 0;
};

class Language {
public:
    static Language& Get();

    // Diagnostics
    void SetDiagnostics(const std::string& filePath, const std::vector<Diagnostic>& diagnostics);
    std::vector<Diagnostic> GetDiagnostics(const std::string& filePath) const;
    void ClearDiagnostics(const std::string& filePath);

    // Completions
    using CompletionProvider = std::function<std::vector<CompletionItem>(const std::string& filePath, int line, int column)>;
    void RegisterCompletionProvider(const std::string& languageId, CompletionProvider provider);
    std::vector<CompletionItem> ProvideCompletions(const std::string& languageId, const std::string& filePath, int line, int column);

    // Hover
    using HoverProvider = std::function<HoverItem(const std::string& filePath, int line, int column)>;
    void RegisterHoverProvider(const std::string& languageId, HoverProvider provider);
    HoverItem ProvideHover(const std::string& languageId, const std::string& filePath, int line, int column);

    // Language registration
    void RegisterLanguage(const std::string& id, const std::vector<std::string>& extensions);

private:
    Language() = default;
    std::map<std::string, std::vector<Diagnostic>> m_diagnostics;
    std::map<std::string, CompletionProvider> m_completionProviders;
    std::map<std::string, HoverProvider> m_hoverProviders;
    std::map<std::string, std::vector<std::string>> m_languages;
};

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
