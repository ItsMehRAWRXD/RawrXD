#include "Win32IDE.h"

#include <algorithm>
#include <cctype>
#include <sstream>
#include <string>
#include <vector>

namespace {

std::string lowerExt(const std::string& path) {
    const size_t dot = path.find_last_of('.');
    if (dot == std::string::npos) {
        return {};
    }
    std::string ext = path.substr(dot);
    std::transform(ext.begin(), ext.end(), ext.begin(),
                   [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
    return ext;
}

}  // namespace

void Win32IDE::initLanguagePlugin() {
    if (!m_languageManager) {
        m_languageManager = new LanguagePluginManager();
    }
}

void Win32IDE::updateSyntaxHighlighting() {
    if (!m_languageManager) {
        initLanguagePlugin();
    }
    applySyntaxColoring();
}

void Win32IDE::applySyntaxHighlighting(const std::vector<IDEPlugin::SyntaxToken>&) {
    applySyntaxColoring();
}

void Win32IDE::showCodeCompletions(int) {
    if (!m_languageManager) {
        initLanguagePlugin();
    }
    const std::string language = m_languageManager->detectLanguage(m_currentFile, getEditorText());
    const auto items = m_languageManager->completions(language);

    std::ostringstream oss;
    oss << "[Language] Completion candidates for " << language << ":\n";
    const size_t maxItems = std::min<size_t>(items.size(), 30);
    for (size_t i = 0; i < maxItems; ++i) {
        oss << "  - " << items[i].label << "\n";
    }
    if (items.size() > maxItems) {
        oss << "  ... (" << (items.size() - maxItems) << " more)\n";
    }
    appendToOutput(oss.str(), "Language", OutputSeverity::Info);
}

void Win32IDE::updateDiagnostics() {
    if (!m_languageManager) {
        initLanguagePlugin();
    }

    clearDiagnostics();
    const std::string code = getEditorText();
    const std::string language = m_languageManager->detectLanguage(m_currentFile, code);
    const auto diagnostics = m_languageManager->diagnostics(language, code);
    for (const auto& d : diagnostics) {
        addDiagnostic(d);
    }
}

void Win32IDE::clearDiagnostics() {
    appendToOutput("[Language] Diagnostics cleared.\n", "Problems", OutputSeverity::Debug);
}

void Win32IDE::addDiagnostic(const IDEPlugin::Diagnostic& diagnostic) {
    std::ostringstream oss;
    oss << "[" << diagnostic.severity << "] "
        << diagnostic.source << "(" << diagnostic.line << ":" << diagnostic.column << "): "
        << diagnostic.message << "\n";
    appendToOutput(oss.str(), "Problems", OutputSeverity::Warning);
}

bool Win32IDE::initializeLanguageServer(const std::string& filename) {
    const std::string ext = lowerExt(filename);
    LSPLanguage lang = LSPLanguage::Cpp;

    if (ext == ".py" || ext == ".pyw" || ext == ".pyi") {
        lang = LSPLanguage::Python;
    } else if (ext == ".js" || ext == ".jsx") {
        lang = LSPLanguage::TypeScript;
    } else if (ext == ".ts" || ext == ".tsx") {
        lang = LSPLanguage::TypeScript;
    } else if (ext == ".json") {
        lang = LSPLanguage::TypeScript;
    }

    return startLSPServer(lang);
}

std::vector<std::string> Win32IDE::getSupportedLanguages() const {
    if (!m_languageManager) {
        return {};
    }
    return m_languageManager->supportedLanguages();
}
