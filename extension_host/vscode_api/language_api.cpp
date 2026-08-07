// language_api.cpp — VS Code Language API Implementation
#include "language_api.hpp"

namespace RawrXD {
namespace ExtensionHost {
namespace VSCODE {

Language& Language::Get() {
    static Language instance;
    return instance;
}

void Language::SetDiagnostics(const std::string& filePath, const std::vector<Diagnostic>& diagnostics) {
    m_diagnostics[filePath] = diagnostics;
}

std::vector<Diagnostic> Language::GetDiagnostics(const std::string& filePath) const {
    auto it = m_diagnostics.find(filePath);
    return it != m_diagnostics.end() ? it->second : std::vector<Diagnostic>{};
}

void Language::ClearDiagnostics(const std::string& filePath) {
    m_diagnostics.erase(filePath);
}

void Language::RegisterCompletionProvider(const std::string& languageId, CompletionProvider provider) {
    m_completionProviders[languageId] = std::move(provider);
}

std::vector<CompletionItem> Language::ProvideCompletions(const std::string& languageId, const std::string& filePath, int line, int column) {
    auto it = m_completionProviders.find(languageId);
    if (it != m_completionProviders.end()) {
        return it->second(filePath, line, column);
    }
    return {};
}

void Language::RegisterHoverProvider(const std::string& languageId, HoverProvider provider) {
    m_hoverProviders[languageId] = std::move(provider);
}

HoverItem Language::ProvideHover(const std::string& languageId, const std::string& filePath, int line, int column) {
    auto it = m_hoverProviders.find(languageId);
    if (it != m_hoverProviders.end()) {
        return it->second(filePath, line, column);
    }
    return HoverItem{};
}

void Language::RegisterLanguage(const std::string& id, const std::vector<std::string>& extensions) {
    m_languages[id] = extensions;
}

} // namespace VSCODE
} // namespace ExtensionHost
} // namespace RawrXD
