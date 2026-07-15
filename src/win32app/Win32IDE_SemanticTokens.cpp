// ============================================================================
// Win32IDE_SemanticTokens.cpp — LSP Semantic Tokens (Syntax Highlighting)
// ============================================================================
// Implements LSP 3.16 semanticTokens feature for advanced syntax highlighting:
//   - textDocument/semanticTokens/full
//   - textDocument/semanticTokens/range
//   - textDocument/semanticTokens/full/delta
//   - Semantic token types: namespace, type, class, enum, interface, etc.
//   - Semantic token modifiers: declaration, definition, readonly, etc.
//
// Pattern: No exceptions, PatchResult-compatible
// Threading: Background LSP request, UI thread for rendering
// ============================================================================

#include "Win32IDE.h"
#include "IDELogger.h"
#include <nlohmann/json.hpp>
#include <thread>
#include <mutex>
#include <atomic>
#include <vector>
#include <map>

using json = nlohmann::json;

// ============================================================================
// SEMANTIC TOKEN STRUCTURES
// ============================================================================

struct SemanticToken {
    int line;
    int character;
    int length;
    int tokenType;
    int tokenModifiers;
};

struct SemanticTokensLegend {
    std::vector<std::string> tokenTypes;
    std::vector<std::string> tokenModifiers;
};

struct SemanticTokensResult {
    std::string resultId;
    std::vector<SemanticToken> tokens;
    bool valid;
};

// Static legend cache
static std::map<LSPLanguage, SemanticTokensLegend> s_legends;
static std::mutex s_legendMutex;

// ============================================================================
// SEMANTIC TOKENS IMPLEMENTATION
// ============================================================================

SemanticTokensLegend Win32IDE::getSemanticTokensLegend(LSPLanguage lang) {
    std::lock_guard<std::mutex> lock(s_legendMutex);
    
    auto it = s_legends.find(lang);
    if (it != s_legends.end()) {
        return it->second;
    }

    // Request legend from server
    if (m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return SemanticTokensLegend{};
    }

    // Default legend (LSP 3.16 standard)
    SemanticTokensLegend legend;
    legend.tokenTypes = {
        "namespace", "type", "class", "enum", "interface",
        "struct", "typeParameter", "parameter", "variable", "property",
        "enumMember", "event", "function", "method", "macro",
        "keyword", "modifier", "comment", "string", "number",
        "regexp", "operator", "decorator"
    };
    legend.tokenModifiers = {
        "declaration", "definition", "readonly", "static",
        "deprecated", "abstract", "async", "modification",
        "documentation", "defaultLibrary"
    };

    s_legends[lang] = legend;
    return legend;
}

SemanticTokensResult Win32IDE::lspSemanticTokensFull(const std::string& uri) {
    SemanticTokensResult result;
    result.valid = false;

    LSPLanguage lang = detectLanguageForFile(uriToFilePath(uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return result;
    }

    json params;
    params["textDocument"]["uri"] = uri;

    int id = sendLSPRequest(lang, "textDocument/semanticTokens/full", params);
    if (id < 0) {
        return result;
    }

    json resp = readLSPResponse(lang, id, 10000);
    m_lspStats.totalSemanticTokensRequests++;

    if (!resp.contains("result") || resp["result"].is_null()) {
        return result;
    }

    const auto& tokenResult = resp["result"];
    result.resultId = tokenResult.value("resultId", "");

    if (!tokenResult.contains("data") || !tokenResult["data"].is_array()) {
        return result;
    }

    // Decode semantic tokens (delta encoding)
    const auto& data = tokenResult["data"];
    int line = 0;
    int character = 0;

    for (size_t i = 0; i + 4 < data.size(); i += 5) {
        int deltaLine = data[i].get<int>();
        int deltaChar = data[i + 1].get<int>();
        int length = data[i + 2].get<int>();
        int tokenType = data[i + 3].get<int>();
        int tokenModifiers = data[i + 4].get<int>();

        if (deltaLine == 0) {
            character += deltaChar;
        } else {
            line += deltaLine;
            character = deltaChar;
        }

        SemanticToken token;
        token.line = line;
        token.character = character;
        token.length = length;
        token.tokenType = tokenType;
        token.tokenModifiers = tokenModifiers;

        result.tokens.push_back(token);
    }

    result.valid = true;
    return result;
}

SemanticTokensResult Win32IDE::lspSemanticTokensRange(const std::string& uri, int startLine, int startChar,
                                                       int endLine, int endChar) {
    SemanticTokensResult result;
    result.valid = false;

    LSPLanguage lang = detectLanguageForFile(uriToFilePath(uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return result;
    }

    json params;
    params["textDocument"]["uri"] = uri;
    params["range"]["start"]["line"] = startLine;
    params["range"]["start"]["character"] = startChar;
    params["range"]["end"]["line"] = endLine;
    params["range"]["end"]["character"] = endChar;

    int id = sendLSPRequest(lang, "textDocument/semanticTokens/range", params);
    if (id < 0) {
        return result;
    }

    json resp = readLSPResponse(lang, id, 10000);

    if (!resp.contains("result") || resp["result"].is_null()) {
        return result;
    }

    const auto& tokenResult = resp["result"];
    result.resultId = tokenResult.value("resultId", "");

    if (!tokenResult.contains("data") || !tokenResult["data"].is_array()) {
        return result;
    }

    // Decode semantic tokens
    const auto& data = tokenResult["data"];
    int line = 0;
    int character = 0;

    for (size_t i = 0; i + 4 < data.size(); i += 5) {
        int deltaLine = data[i].get<int>();
        int deltaChar = data[i + 1].get<int>();
        int length = data[i + 2].get<int>();
        int tokenType = data[i + 3].get<int>();
        int tokenModifiers = data[i + 4].get<int>();

        if (deltaLine == 0) {
            character += deltaChar;
        } else {
            line += deltaLine;
            character = deltaChar;
        }

        SemanticToken token;
        token.line = line;
        token.character = character;
        token.length = length;
        token.tokenType = tokenType;
        token.tokenModifiers = tokenModifiers;

        result.tokens.push_back(token);
    }

    result.valid = true;
    return result;
}

// ============================================================================
// SEMANTIC TOKEN COLOR MAPPING
// ============================================================================

static COLORREF getTokenColor(int tokenType, int tokenModifiers, const SemanticTokensLegend& legend) {
    // VS Code dark theme colors
    static const COLORREF colors[] = {
        RGB(206, 145, 120),   // namespace - orange
        RGB(78, 201, 176),    // type - teal
        RGB(78, 201, 176),    // class - teal
        RGB(206, 145, 120),   // enum - orange
        RGB(181, 206, 168),   // interface - light green
        RGB(206, 145, 120),   // struct - orange
        RGB(206, 145, 120),   // typeParameter - orange
        RGB(220, 220, 170),   // parameter - yellow
        RGB(220, 220, 170),   // variable - yellow
        RGB(220, 220, 170),   // property - yellow
        RGB(206, 145, 120),   // enumMember - orange
        RGB(206, 145, 120),   // event - orange
        RGB(220, 220, 170),   // function - yellow
        RGB(220, 220, 170),   // method - yellow
        RGB(206, 145, 120),   // macro - orange
        RGB(86, 156, 214),    // keyword - blue
        RGB(86, 156, 214),    // modifier - blue
        RGB(106, 153, 85),    // comment - green
        RGB(206, 145, 120),   // string - orange
        RGB(181, 206, 168),   // number - light green
        RGB(206, 145, 120),   // regexp - orange
        RGB(212, 212, 212),   // operator - gray
        RGB(206, 145, 120),   // decorator - orange
    };

    if (tokenType >= 0 && tokenType < (int)(sizeof(colors) / sizeof(colors[0]))) {
        return colors[tokenType];
    }

    return RGB(212, 212, 212);  // default gray
}

// ============================================================================
// APPLY SEMANTIC TOKENS TO EDITOR
// ============================================================================

void Win32IDE::applySemanticTokens(const std::vector<SemanticToken>& tokens, const SemanticTokensLegend& legend) {
    if (!m_hwndEditor || tokens.empty()) {
        return;
    }

    // Store tokens for rendering
    m_semanticTokens = tokens;
    m_semanticTokensLegend = legend;
    m_semanticTokensValid = true;

    // Invalidate editor to trigger repaint
    InvalidateRect(m_hwndEditor, nullptr, FALSE);

    LOG_INFO("[SemanticTokens] Applied " << tokens.size() << " semantic tokens");
}

void Win32IDE::clearSemanticTokens() {
    m_semanticTokens.clear();
    m_semanticTokensValid = false;
    if (m_hwndEditor) {
        InvalidateRect(m_hwndEditor, nullptr, FALSE);
    }
}

// ============================================================================
// RENDER SEMANTIC TOKENS (Custom Paint)
// ============================================================================

void Win32IDE::renderSemanticTokens(HDC hdc, int firstLine, int lastLine) {
    if (!m_semanticTokensValid || m_semanticTokens.empty()) {
        return;
    }

    // Get editor font
    HFONT hFont = reinterpret_cast<HFONT>(SendMessage(m_hwndEditor, WM_GETFONT, 0, 0));
    HFONT hOldFont = static_cast<HFONT>(SelectObject(hdc, hFont));

    // Set text color mode
    SetBkMode(hdc, TRANSPARENT);

    // Render tokens in visible range
    for (const auto& token : m_semanticTokens) {
        if (token.line < firstLine || token.line > lastLine) {
            continue;
        }

        // Get token color
        COLORREF color = getTokenColor(token.tokenType, token.tokenModifiers, m_semanticTokensLegend);
        SetTextColor(hdc, color);

        // Calculate position
        // Note: This is a simplified rendering - real implementation would need
        // to get the actual character positions from the editor
        POINT pt;
        pt.x = token.character * 8;  // Approximate character width
        pt.y = (token.line - firstLine) * 16;  // Approximate line height

        // Draw token (simplified - would need actual text extraction)
        // Real implementation would use EM_POSFROMCHAR and DrawText
    }

    SelectObject(hdc, hOldFont);
}

// ============================================================================
// COMMANDS
// ============================================================================

void Win32IDE::cmdRefreshSemanticTokens() {
    if (m_currentFile.empty() || !m_hwndEditor) {
        appendToOutput("[SemanticTokens] No file open.", "General", OutputSeverity::Warning);
        return;
    }

    std::string uri = filePathToUri(m_currentFile);

    // Run in background thread
    std::thread([this, uri]() {
        auto result = lspSemanticTokensFull(uri);

        if (result.valid) {
            auto legend = getSemanticTokensLegend(detectLanguageForFile(uriToFilePath(uri)));

            // Post to UI thread
            PostMessageA(m_hwndMain, WM_APP + 520, 
                reinterpret_cast<WPARAM>(new std::vector<SemanticToken>(result.tokens)),
                reinterpret_cast<LPARAM>(new SemanticTokensLegend(legend)));
        } else {
            PostMessageA(m_hwndMain, WM_APP + 521, 0, 0);
        }
    }).detach();

    appendToOutput("[SemanticTokens] Refreshing semantic tokens...", "General", OutputSeverity::Info);
}

void Win32IDE::cmdToggleSemanticHighlighting() {
    m_semanticHighlightingEnabled = !m_semanticHighlightingEnabled;

    if (m_semanticHighlightingEnabled) {
        cmdRefreshSemanticTokens();
        appendToOutput("[SemanticTokens] Semantic highlighting enabled.", "General", OutputSeverity::Info);
    } else {
        clearSemanticTokens();
        appendToOutput("[SemanticTokens] Semantic highlighting disabled.", "General", OutputSeverity::Info);
    }
}

// ============================================================================
// SEMANTIC TOKENS DELTA (Incremental Updates)
// ============================================================================

SemanticTokensResult Win32IDE::lspSemanticTokensDelta(const std::string& uri, const std::string& previousResultId) {
    SemanticTokensResult result;
    result.valid = false;

    LSPLanguage lang = detectLanguageForFile(uriToFilePath(uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return result;
    }

    json params;
    params["textDocument"]["uri"] = uri;
    params["previousResultId"] = previousResultId;

    int id = sendLSPRequest(lang, "textDocument/semanticTokens/full/delta", params);
    if (id < 0) {
        return result;
    }

    json resp = readLSPResponse(lang, id, 10000);

    if (!resp.contains("result") || resp["result"].is_null()) {
        return result;
    }

    const auto& tokenResult = resp["result"];
    result.resultId = tokenResult.value("resultId", "");

    // Check if result is unchanged
    if (tokenResult.value("unchanged", false)) {
        result.valid = true;
        return result;
    }

    // Handle edits
    if (tokenResult.contains("edits") && tokenResult["edits"].is_array()) {
        // Apply edits to existing tokens
        // This is a simplified implementation - real delta handling would be more complex
        for (const auto& edit : tokenResult["edits"]) {
            int start = edit.value("start", 0);
            int deleteCount = edit.value("deleteCount", 0);
            
            if (edit.contains("data") && edit["data"].is_array()) {
                // Insert new tokens at position
                // Simplified: just request full tokens instead
                return lspSemanticTokensFull(uri);
            }
        }
    }

    result.valid = true;
    return result;
}