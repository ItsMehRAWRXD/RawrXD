// Win32IDE_LanguagePlugin.h — LanguagePluginManager (complete type for unique_ptr)
#pragma once

#include "IDEPlugin.h"

#include <algorithm>
#include <cctype>
#include <string>
#include <unordered_map>
#include <vector>

class LanguagePluginManager {
public:
    LanguagePluginManager() {
        registerLanguage("cpp", {".c", ".cc", ".cpp", ".cxx", ".h", ".hpp", ".hxx"},
                         {"int", "float", "double", "char", "bool", "void", "class", "struct", "namespace", "template", "return"});
        registerLanguage("python", {".py", ".pyw", ".pyi"},
                         {"def", "class", "import", "from", "if", "elif", "else", "for", "while", "return", "try", "except"});
    }

    std::vector<std::string> supportedLanguages() const {
        std::vector<std::string> out;
        out.reserve(m_languages.size());
        for (const auto& kv : m_languages) {
            out.push_back(kv.first);
        }
        std::sort(out.begin(), out.end());
        return out;
    }

    std::string detectLanguage(const std::string& filePath, const std::string&) const {
        const size_t dot = filePath.find_last_of('.');
        std::string ext;
        if (dot != std::string::npos) {
            ext = filePath.substr(dot);
            std::transform(ext.begin(), ext.end(), ext.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        }
        auto it = m_extToLang.find(ext);
        return it == m_extToLang.end() ? std::string("plaintext") : it->second;
    }

    std::vector<IDEPlugin::SyntaxToken> tokenize(const std::string& language, const std::string& code) const {
        std::vector<IDEPlugin::SyntaxToken> tokens;
        auto langIt = m_languages.find(language);
        const auto& keywords = (langIt != m_languages.end()) ? langIt->second : m_emptyMap;

        int tokenStart = -1;
        for (size_t i = 0; i <= code.size(); ++i) {
            const bool end = i == code.size();
            const char c = end ? '\0' : code[i];
            const bool isWordChar = !end && (std::isalnum(static_cast<unsigned char>(c)) || c == '_');
            if (isWordChar) {
                if (tokenStart < 0) {
                    tokenStart = static_cast<int>(i);
                }
                continue;
            }
            if (tokenStart >= 0) {
                const int len = static_cast<int>(i) - tokenStart;
                const std::string word = code.substr(static_cast<size_t>(tokenStart), static_cast<size_t>(len));
                IDEPlugin::SyntaxToken token;
                auto kit = keywords.find(word);
                if (kit != keywords.end()) {
                    token.type = kit->second;
                } else {
                    bool isNum = !word.empty() &&
                        std::all_of(word.begin(), word.end(),
                                    [](unsigned char ch) { return std::isdigit(ch) != 0; });
                    token.type = isNum ? IDEPlugin::TokenType::Number : IDEPlugin::TokenType::Identifier;
                }
                token.start = tokenStart;
                token.length = len;
                token.text = word;
                tokens.push_back(std::move(token));
                tokenStart = -1;
            }
        }
        return tokens;
    }

    std::vector<IDEPlugin::CompletionItem> completions(const std::string& language) const {
        std::vector<IDEPlugin::CompletionItem> out;
        auto it = m_languages.find(language);
        if (it == m_languages.end()) {
            return out;
        }
        out.reserve(it->second.size());
        for (const auto& kw : it->second) {
            IDEPlugin::CompletionItem item;
            item.label = kw.first;
            item.detail = language + " keyword";
            item.documentation = "";
            item.kind = IDEPlugin::CompletionItemKind::Keyword;
            item.insertText = kw.first;
            out.push_back(std::move(item));
        }
        return out;
    }

    std::vector<IDEPlugin::Diagnostic> diagnostics(const std::string&, const std::string& code) const {
        std::vector<IDEPlugin::Diagnostic> out;
        int line = 1;
        int col = 1;
        int balance = 0;
        for (char c : code) {
            if (c == '\n') {
                ++line;
                col = 1;
                continue;
            }
            if (c == '{') {
                ++balance;
            } else if (c == '}') {
                --balance;
                if (balance < 0) {
                    IDEPlugin::Diagnostic d;
                    d.source = "language-plugin";
                    d.line = line;
                    d.column = col;
                    d.message = "Unmatched closing brace";
                    d.severity = "error";
                    out.push_back(std::move(d));
                    balance = 0;
                }
            }
            ++col;
        }
        if (balance > 0) {
            IDEPlugin::Diagnostic d;
            d.source = "language-plugin";
            d.line = line;
            d.column = 1;
            d.message = "Unclosed block: missing }";
            d.severity = "warning";
            out.push_back(std::move(d));
        }
        return out;
    }

private:
    void registerLanguage(const std::string& id,
                          const std::vector<std::string>& extensions,
                          const std::vector<std::string>& keywords) {
        std::unordered_map<std::string, IDEPlugin::TokenType> map;
        for (const auto& kw : keywords) {
            map[kw] = IDEPlugin::TokenType::Keyword;
        }
        m_languages[id] = std::move(map);
        for (const auto& ext : extensions) {
            m_extToLang[ext] = id;
        }
    }

    std::unordered_map<std::string, std::unordered_map<std::string, IDEPlugin::TokenType>> m_languages;
    std::unordered_map<std::string, std::string> m_extToLang;
    const std::unordered_map<std::string, IDEPlugin::TokenType> m_emptyMap;
};
