#include "Win32IDE.h"
#include <richedit.h>

std::pair<int, int> Win32IDE::getCursorPosition() const {
    if (!m_hwndEditor) return {0, 0};
    CHARRANGE cr{};
    SendMessageA(m_hwndEditor, EM_EXGETSEL, 0, (LPARAM)&cr);
    int line = (int)SendMessageA(m_hwndEditor, EM_LINEFROMCHAR, cr.cpMin, 0);
    int lineStart = (int)SendMessageA(m_hwndEditor, EM_LINEINDEX, line, 0);
    int col = cr.cpMin - lineStart;
    return {line, col};
}

std::vector<Win32IDE::HybridCompletionItem> Win32IDE::requestHybridCompletion(
    const std::string& filePath, int line, int column) {
    std::vector<HybridCompletionItem> items;

    // Real LSP completion (code intelligence) when a language server is running.
    // Falls through to the keyword list only when LSP yields nothing.
    if (!filePath.empty()) {
        std::string uri = "file:///";
        for (char c : filePath) uri += (c == '\\') ? '/' : c;
        const auto lsp = lspCompletion(uri, line, column);
        items.reserve(lsp.size());
        for (const auto& c : lsp) {
            HybridCompletionItem it;
            it.label = c.label;
            it.insertText = c.insertText;
            it.detail = c.detail;
            it.source = "lsp";
            it.confidence = 0.9f;
            items.push_back(std::move(it));
        }
    }

    // Keyword fallback so the popup has real items when LSP is offline.
    if (items.empty()) {
        static const char* kKeywords[] = {
            "if", "else", "for", "while", "return", "class", "struct", "namespace",
            "public", "private", "protected", "virtual", "override", "const", "auto"
        };
        for (const char* kw : kKeywords) {
            HybridCompletionItem item;
            item.label = kw;
            item.insertText = kw;
            item.detail = "keyword";
            item.source = "keyword";
            item.confidence = 0.5f;
            items.push_back(item);
        }
    }
    return items;
}
