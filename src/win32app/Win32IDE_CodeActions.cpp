// ============================================================================
// Win32IDE_CodeActions.cpp — LSP Code Actions (Quick Fixes)
// ============================================================================
// Implements LSP textDocument/codeAction for quick fixes from diagnostics:
//   - Quick fix suggestions from LSP server
//   - Refactor actions (extract method, rename, etc.)
//   - Organize imports
//   - Fix all (auto-fix all diagnostics in file)
//   - Source actions (generate getters/setters, etc.)
//
// Pattern: No exceptions, PatchResult-compatible
// Threading: Background LSP request, UI thread for applying edits
// ============================================================================

#include "Win32IDE.h"
#include "IDELogger.h"
#include <nlohmann/json.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>

using json = nlohmann::json;

// ============================================================================
// LSP CODE ACTION REQUEST/RESPONSE
// ============================================================================

std::vector<Win32IDE::LSPCodeAction> Win32IDE::lspCodeActions(const std::string& uri, int line, int startChar,
                                                                 int endChar, const std::vector<std::string>& diagnosticCodes) {
    std::vector<LSPCodeAction> actions;
    LSPLanguage lang = detectLanguageForFile(uriToFilePath(uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return actions;
    }

    // Build code action request
    json params;
    params["textDocument"]["uri"] = uri;
    params["range"]["start"]["line"] = line;
    params["range"]["start"]["character"] = startChar;
    params["range"]["end"]["line"] = line;
    params["range"]["end"]["character"] = endChar;

    // Include diagnostics context
    json diagArray = json::array();
    for (const auto& code : diagnosticCodes) {
        json d;
        d["code"] = code;
        diagArray.push_back(d);
    }
    params["context"]["diagnostics"] = diagArray;

    // Request only quick fixes and refactors
    params["context"]["only"] = json::array({"quickfix", "refactor", "source"});

    int id = sendLSPRequest(lang, "textDocument/codeAction", params);
    if (id < 0) {
        return actions;
    }

    json resp = readLSPResponse(lang, id, 5000);
    m_lspStats.totalCodeActionRequests++;

    if (!resp.contains("result") || resp["result"].is_null() || !resp["result"].is_array()) {
        return actions;
    }

    // Parse code actions
    for (const auto& actionJson : resp["result"]) {
        LSPCodeAction action;
        action.title = actionJson.value("title", "");
        action.kind = actionJson.value("kind", "");
        action.hasEdit = actionJson.contains("edit");
        if (action.hasEdit) {
            action.edit = actionJson["edit"];
        }
        if (actionJson.contains("command")) {
            action.command = actionJson["command"].value("command", "");
        }
        actions.push_back(action);
    }

    return actions;
}

// ============================================================================
// APPLY CODE ACTION
// ============================================================================

void Win32IDE::applyCodeAction(const CodeAction& action) {
    if (action.lspEditJson.empty()) return;

    json editJson = json::parse(action.lspEditJson, nullptr, false);
    if (editJson.is_discarded()) return;

    if (editJson.contains("changes")) {
        for (auto it = editJson["changes"].begin(); it != editJson["changes"].end(); ++it) {
            if (it.value().is_array()) {
                for (const auto& textEdit : it.value()) {
                    LSPWorkspaceEdit::TextEdit te;
                    te.newText = textEdit.value("newText", "");
                    if (textEdit.contains("range")) {
                        const auto& r = textEdit["range"];
                        te.range.start.line = r["start"].value("line", 0);
                        te.range.start.character = r["start"].value("character", 0);
                        te.range.end.line = r["end"].value("line", 0);
                        te.range.end.character = r["end"].value("character", 0);
                    }
                    applyTextEdit(te);
                }
            }
        }
    }
}

void Win32IDE::applyTextEdit(const LSPWorkspaceEdit::TextEdit& edit) {
    if (!m_hwndEditor) return;

    // Convert line/character to character position
    int startPos = 0;
    int endPos = 0;

    // Get line start positions
    int lineCount = SendMessage(m_hwndEditor, EM_GETLINECOUNT, 0, 0);
    
    // Calculate start position
    for (int i = 0; i < edit.range.start.line && i < lineCount; i++) {
        int lineLen = SendMessage(m_hwndEditor, EM_LINELENGTH, 
            SendMessage(m_hwndEditor, EM_LINEINDEX, i, 0), 0);
        startPos += lineLen;
    }
    startPos += edit.range.start.character;

    // Calculate end position
    for (int i = 0; i < edit.range.end.line && i < lineCount; i++) {
        int lineLen = SendMessage(m_hwndEditor, EM_LINELENGTH,
            SendMessage(m_hwndEditor, EM_LINEINDEX, i, 0), 0);
        endPos += lineLen;
    }
    endPos += edit.range.end.character;

    // Select range and replace
    CHARRANGE cr;
    cr.cpMin = startPos;
    cr.cpMax = endPos;
    SendMessage(m_hwndEditor, EM_EXSETSEL, 0, reinterpret_cast<LPARAM>(&cr));
    SendMessage(m_hwndEditor, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(edit.newText.c_str()));

    m_fileModified = true;
}

// ============================================================================
// FIX ALL DIAGNOSTICS
// ============================================================================

void Win32IDE::cmdFixAllDiagnostics() {
    if (m_currentFile.empty() || !m_hwndEditor) {
        appendToOutput("[CodeAction] No file open.", "General", OutputSeverity::Warning);
        return;
    }

    std::string uri = filePathToUri(m_currentFile);
    
    // Get all diagnostics for current file
    std::vector<std::string> codes;
    {
        std::lock_guard<std::mutex> lock(m_lspDiagnosticsMutex);
        auto it = m_lspDiagnostics.find(uri);
        if (it != m_lspDiagnostics.end()) {
            for (const auto& diag : it->second) {
                codes.push_back(diag.code);
            }
        }
    }

    if (codes.empty()) {
        appendToOutput("[CodeAction] No diagnostics to fix.", "General", OutputSeverity::Info);
        return;
    }

    // Request code actions for all diagnostics
    auto actions = lspCodeActions(uri, 0, 0, 0, codes);

    // Filter for "fix all" actions
    std::vector<LSPCodeAction> fixAllActions;
    for (const auto& action : actions) {
        if (action.kind.find("source.fixAll") != std::string::npos ||
            action.kind.find("quickfix.fixAll") != std::string::npos) {
            fixAllActions.push_back(action);
        }
    }

    if (fixAllActions.empty()) {
        appendToOutput("[CodeAction] No fix-all actions available.", "General", OutputSeverity::Info);
        return;
    }

    // Apply first fix-all action
    if (fixAllActions[0].hasEdit && !fixAllActions[0].edit.is_null()) {
        json editJson = fixAllActions[0].edit;
        if (editJson.contains("changes")) {
            for (auto it = editJson["changes"].begin(); it != editJson["changes"].end(); ++it) {
                if (it.value().is_array()) {
                    for (const auto& textEdit : it.value()) {
                        LSPWorkspaceEdit::TextEdit te;
                        te.newText = textEdit.value("newText", "");
                        if (textEdit.contains("range")) {
                            const auto& r = textEdit["range"];
                            te.range.start.line = r["start"].value("line", 0);
                            te.range.start.character = r["start"].value("character", 0);
                            te.range.end.line = r["end"].value("line", 0);
                            te.range.end.character = r["end"].value("character", 0);
                        }
                        applyTextEdit(te);
                    }
                }
            }
        }
    }

    appendToOutput("[CodeAction] Applied fix all.", "General", OutputSeverity::Info);
}

// ============================================================================
// ORGANIZE IMPORTS
// ============================================================================

void Win32IDE::cmdOrganizeImports() {
    if (m_currentFile.empty() || !m_hwndEditor) {
        appendToOutput("[CodeAction] No file open.", "General", OutputSeverity::Warning);
        return;
    }

    std::string uri = filePathToUri(m_currentFile);
    LSPLanguage lang = detectLanguageForFile(m_currentFile);
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        appendToOutput("[CodeAction] LSP server not running.", "General", OutputSeverity::Warning);
        return;
    }

    // Request organize imports action
    json params;
    params["textDocument"]["uri"] = uri;
    params["range"]["start"]["line"] = 0;
    params["range"]["start"]["character"] = 0;
    params["range"]["end"]["line"] = 999999;
    params["range"]["end"]["character"] = 999999;
    params["context"]["only"] = json::array({"source.organizeImports"});

    int id = sendLSPRequest(lang, "textDocument/codeAction", params);
    if (id < 0) {
        appendToOutput("[CodeAction] Failed to request organize imports.", "General", OutputSeverity::Error);
        return;
    }

    json resp = readLSPResponse(lang, id, 5000);

    if (resp.contains("result") && resp["result"].is_array() && !resp["result"].empty()) {
        const auto& action = resp["result"].at(0);
        if (action.contains("edit")) {
            json editJson = action["edit"];
            if (editJson.contains("changes")) {
                for (auto it = editJson["changes"].begin(); it != editJson["changes"].end(); ++it) {
                    if (it.value().is_array()) {
                        for (const auto& textEdit : it.value()) {
                            LSPWorkspaceEdit::TextEdit te;
                            te.newText = textEdit.value("newText", "");
                            if (textEdit.contains("range")) {
                                const auto& r = textEdit["range"];
                                te.range.start.line = r["start"].value("line", 0);
                                te.range.start.character = r["start"].value("character", 0);
                                te.range.end.line = r["end"].value("line", 0);
                                te.range.end.character = r["end"].value("character", 0);
                            }
                            applyTextEdit(te);
                        }
                    }
                }
            }
        }
        appendToOutput("[CodeAction] Organized imports.", "General", OutputSeverity::Info);
    } else {
        appendToOutput("[CodeAction] No organize imports action available.", "General", OutputSeverity::Warning);
    }
}

// ============================================================================
// SHOW CODE ACTIONS (CONTEXT MENU)
// ============================================================================

void Win32IDE::showCodeActions(int line, int character) {
    if (m_currentFile.empty()) return;

    std::string uri = filePathToUri(m_currentFile);

    // Get diagnostics for this line
    std::vector<std::string> lineCodes;
    {
        std::lock_guard<std::mutex> lock(m_lspDiagnosticsMutex);
        auto it = m_lspDiagnostics.find(uri);
        if (it != m_lspDiagnostics.end()) {
            for (const auto& diag : it->second) {
                if (diag.range.start.line == line) {
                    lineCodes.push_back(diag.code);
                }
            }
        }
    }

    // Request code actions
    auto actions = lspCodeActions(uri, line, character, character, lineCodes);

    if (actions.empty()) {
        appendToOutput("[CodeAction] No actions available at this location.", "General", OutputSeverity::Info);
        return;
    }

    // Build context menu
    HMENU hMenu = CreatePopupMenu();
    int menuId = 1000;

    for (const auto& action : actions) {
        std::string label = action.title;
        AppendMenuA(hMenu, MF_STRING, menuId++, label.c_str());
    }

    // Show menu at cursor position
    POINT pt;
    GetCursorPos(&pt);

    int result = TrackPopupMenu(hMenu, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD,
        pt.x, pt.y, 0, m_hwndMain, nullptr);

    if (result >= 1000) {
        int actionIndex = result - 1000;
        if (actionIndex >= 0 && actionIndex < (int)actions.size()) {
            // Convert LSPCodeAction to CodeAction and apply
            CodeAction ca;
            ca.title = actions[actionIndex].title;
            ca.kind = actions[actionIndex].kind;
            ca.isFromLSP = true;
            if (actions[actionIndex].hasEdit) {
                ca.lspEditJson = actions[actionIndex].edit.dump();
            }
            applyCodeAction(ca);
        }
    }

    DestroyMenu(hMenu);
}

// ============================================================================
// EXECUTE LSP COMMAND
// ============================================================================

void Win32IDE::executeLSPCommand(const std::string& command, const json& arguments) {
    if (m_currentFile.empty()) return;

    LSPLanguage lang = detectLanguageForFile(m_currentFile);
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return;
    }

    json params;
    params["command"] = command;
    if (!arguments.is_null()) {
        params["arguments"] = arguments;
    }

    sendLSPRequest(lang, "workspace/executeCommand", params);
    // Note: executeCommand typically doesn't return a result
}