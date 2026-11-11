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
    (void)filePath;
    (void)line;
    (void)column;
    // Keyword fallback so the popup has real items when LSP is offline.
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
    return items;
}
