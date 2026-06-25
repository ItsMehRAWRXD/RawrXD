// ============================================================================
// Win32IDE_Hierarchy.cpp — Call Hierarchy & Type Hierarchy Navigation
// ============================================================================
// Implements LSP 3.16+ hierarchy features:
//   - textDocument/callHierarchy/incomingCalls
//   - textDocument/callHierarchy/outgoingCalls
//   - textDocument/typeHierarchy/subtypes
//   - textDocument/typeHierarchy/supertypes
//
// Pattern: No exceptions, PatchResult-compatible
// Threading: Background LSP request, UI thread for rendering
// ============================================================================

#include "Win32IDE.h"
#include "IDELogger.h"
#include <nlohmann/json.hpp>
#include <thread>
#include <mutex>
#include <condition_variable>
#include <atomic>
#include <commctrl.h>

using json = nlohmann::json;
using namespace RawrXD;

// ============================================================================
// CALL HIERARCHY IMPLEMENTATION
// ============================================================================

Win32IDE::CallHierarchyItem Win32IDE::lspPrepareCallHierarchy(const std::string& uri, int line, int character) {
    CallHierarchyItem result;
    LSPLanguage lang = detectLanguageForFile(uriToFilePath(uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return result;
    }

    json params;
    params["textDocument"]["uri"] = uri;
    params["position"]["line"] = line;
    params["position"]["character"] = character;

    int id = sendLSPRequest(lang, "textDocument/prepareCallHierarchy", params);
    if (id < 0) {
        return result;
    }

    json resp = readLSPResponse(lang, id, 5000);
    m_lspStats.totalCallHierarchyRequests++;

    if (!resp.contains("result") || resp["result"].is_null() || !resp["result"].is_array()) {
        return result;
    }

    if (!resp["result"].empty()) {
        const auto& item = resp["result"].at(0);
        result.name = item.value("name", "");
        result.kind = item.value("kind", "");
        result.detail = item.value("detail", "");
        result.uri = item.value("uri", "");

        if (item.contains("range")) {
            const auto& r = item["range"];
            result.range.start.line = r["start"].value("line", 0);
            result.range.start.character = r["start"].value("character", 0);
            result.range.end.line = r["end"].value("line", 0);
            result.range.end.character = r["end"].value("character", 0);
        }

        if (item.contains("selectionRange")) {
            const auto& sr = item["selectionRange"];
            result.selectionRange.start.line = sr["start"].value("line", 0);
            result.selectionRange.start.character = sr["start"].value("character", 0);
            result.selectionRange.end.line = sr["end"].value("line", 0);
            result.selectionRange.end.character = sr["end"].value("character", 0);
        }
    }

    return result;
}

std::vector<Win32IDE::CallHierarchyCall> Win32IDE::lspIncomingCalls(const CallHierarchyItem& item) {
    std::vector<Win32IDE::CallHierarchyCall> calls;
    LSPLanguage lang = detectLanguageForFile(uriToFilePath(item.uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return calls;
    }

    json params;
    json itemJson;
    itemJson["name"] = item.name;
    itemJson["kind"] = item.kind;
    itemJson["uri"] = item.uri;
    itemJson["range"]["start"]["line"] = item.range.start.line;
    itemJson["range"]["start"]["character"] = item.range.start.character;
    itemJson["range"]["end"]["line"] = item.range.end.line;
    itemJson["range"]["end"]["character"] = item.range.end.character;
    itemJson["selectionRange"]["start"]["line"] = item.selectionRange.start.line;
    itemJson["selectionRange"]["start"]["character"] = item.selectionRange.start.character;
    itemJson["selectionRange"]["end"]["line"] = item.selectionRange.end.line;
    itemJson["selectionRange"]["end"]["character"] = item.selectionRange.end.character;
    params["item"] = itemJson;

    int id = sendLSPRequest(lang, "callHierarchy/incomingCalls", params);
    if (id < 0) {
        return calls;
    }

    json resp = readLSPResponse(lang, id, 10000);

    if (!resp.contains("result") || !resp["result"].is_array()) {
        return calls;
    }

    for (const auto& call : resp["result"]) {
        Win32IDE::CallHierarchyCall chc;

        // Parse "from" item
        if (call.contains("from")) {
            const auto& from = call["from"];
            chc.from.name = from.value("name", "");
            chc.from.kind = from.value("kind", "");
            chc.from.uri = from.value("uri", "");

            if (from.contains("range")) {
                const auto& r = from["range"];
                chc.from.range.start.line = r["start"].value("line", 0);
                chc.from.range.start.character = r["start"].value("character", 0);
                chc.from.range.end.line = r["end"].value("line", 0);
                chc.from.range.end.character = r["end"].value("character", 0);
            }
        }

        // Parse "fromRanges"
        if (call.contains("fromRanges") && call["fromRanges"].is_array()) {
            for (const auto& fr : call["fromRanges"]) {
                chc.fromRanges.start.line = fr["start"].value("line", 0);
                chc.fromRanges.start.character = fr["start"].value("character", 0);
                chc.fromRanges.end.line = fr["end"].value("line", 0);
                chc.fromRanges.end.character = fr["end"].value("character", 0);
                break;  // Just use first range
            }
        }

        calls.push_back(chc);
    }

    return calls;
}

std::vector<Win32IDE::CallHierarchyCall> Win32IDE::lspOutgoingCalls(const CallHierarchyItem& item) {
    std::vector<Win32IDE::CallHierarchyCall> calls;
    LSPLanguage lang = detectLanguageForFile(uriToFilePath(item.uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return calls;
    }

    json params;
    json itemJson;
    itemJson["name"] = item.name;
    itemJson["kind"] = item.kind;
    itemJson["uri"] = item.uri;
    itemJson["range"]["start"]["line"] = item.range.start.line;
    itemJson["range"]["start"]["character"] = item.range.start.character;
    itemJson["range"]["end"]["line"] = item.range.end.line;
    itemJson["range"]["end"]["character"] = item.range.end.character;
    itemJson["selectionRange"]["start"]["line"] = item.selectionRange.start.line;
    itemJson["selectionRange"]["start"]["character"] = item.selectionRange.start.character;
    itemJson["selectionRange"]["end"]["line"] = item.selectionRange.end.line;
    itemJson["selectionRange"]["end"]["character"] = item.selectionRange.end.character;
    params["item"] = itemJson;

    int id = sendLSPRequest(lang, "callHierarchy/outgoingCalls", params);
    if (id < 0) {
        return calls;
    }

    json resp = readLSPResponse(lang, id, 10000);

    if (!resp.contains("result") || !resp["result"].is_array()) {
        return calls;
    }

    for (const auto& call : resp["result"]) {
        Win32IDE::CallHierarchyCall chc;

        // Parse "to" item
        if (call.contains("to")) {
            const auto& to = call["to"];
            chc.to.name = to.value("name", "");
            chc.to.kind = to.value("kind", "");
            chc.to.uri = to.value("uri", "");

            if (to.contains("range")) {
                const auto& r = to["range"];
                chc.to.range.start.line = r["start"].value("line", 0);
                chc.to.range.start.character = r["start"].value("character", 0);
                chc.to.range.end.line = r["end"].value("line", 0);
                chc.to.range.end.character = r["end"].value("character", 0);
            }
        }

        // Parse "fromRanges"
        if (call.contains("fromRanges") && call["fromRanges"].is_array()) {
            for (const auto& fr : call["fromRanges"]) {
                chc.fromRanges.start.line = fr["start"].value("line", 0);
                chc.fromRanges.start.character = fr["start"].value("character", 0);
                chc.fromRanges.end.line = fr["end"].value("line", 0);
                chc.fromRanges.end.character = fr["end"].value("character", 0);
                break;
            }
        }

        calls.push_back(chc);
    }

    return calls;
}

// ============================================================================
// TYPE HIERARCHY IMPLEMENTATION
// ============================================================================

Win32IDE::TypeHierarchyItem Win32IDE::lspPrepareTypeHierarchy(const std::string& uri, int line, int character) {
    Win32IDE::TypeHierarchyItem result;
    LSPLanguage lang = detectLanguageForFile(uriToFilePath(uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return result;
    }

    json params;
    params["textDocument"]["uri"] = uri;
    params["position"]["line"] = line;
    params["position"]["character"] = character;

    int id = sendLSPRequest(lang, "textDocument/prepareTypeHierarchy", params);
    if (id < 0) {
        return result;
    }

    json resp = readLSPResponse(lang, id, 5000);
    m_lspStats.totalTypeHierarchyRequests++;

    if (!resp.contains("result") || resp["result"].is_null() || !resp["result"].is_array()) {
        return result;
    }

    if (!resp["result"].empty()) {
        const auto& item = resp["result"].at(0);
        result.name = item.value("name", "");
        result.kind = item.value("kind", "");
        result.detail = item.value("detail", "");
        result.uri = item.value("uri", "");

        if (item.contains("range")) {
            const auto& r = item["range"];
            result.range.start.line = r["start"].value("line", 0);
            result.range.start.character = r["start"].value("character", 0);
            result.range.end.line = r["end"].value("line", 0);
            result.range.end.character = r["end"].value("character", 0);
        }

        if (item.contains("selectionRange")) {
            const auto& sr = item["selectionRange"];
            result.selectionRange.start.line = sr["start"].value("line", 0);
            result.selectionRange.start.character = sr["start"].value("character", 0);
            result.selectionRange.end.line = sr["end"].value("line", 0);
            result.selectionRange.end.character = sr["end"].value("character", 0);
        }
    }

    return result;
}

std::vector<Win32IDE::TypeHierarchyItem> Win32IDE::lspSupertypes(const TypeHierarchyItem& item) {
    std::vector<Win32IDE::TypeHierarchyItem> supertypes;
    LSPLanguage lang = detectLanguageForFile(uriToFilePath(item.uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return supertypes;
    }

    json params;
    json itemJson;
    itemJson["name"] = item.name;
    itemJson["kind"] = item.kind;
    itemJson["uri"] = item.uri;
    itemJson["range"]["start"]["line"] = item.range.start.line;
    itemJson["range"]["start"]["character"] = item.range.start.character;
    itemJson["range"]["end"]["line"] = item.range.end.line;
    itemJson["range"]["end"]["character"] = item.range.end.character;
    itemJson["selectionRange"]["start"]["line"] = item.selectionRange.start.line;
    itemJson["selectionRange"]["start"]["character"] = item.selectionRange.start.character;
    itemJson["selectionRange"]["end"]["line"] = item.selectionRange.end.line;
    itemJson["selectionRange"]["end"]["character"] = item.selectionRange.end.character;
    params["item"] = itemJson;

    int id = sendLSPRequest(lang, "typeHierarchy/supertypes", params);
    if (id < 0) {
        return supertypes;
    }

    json resp = readLSPResponse(lang, id, 10000);

    if (!resp.contains("result") || !resp["result"].is_array()) {
        return supertypes;
    }

    for (const auto& sup : resp["result"]) {
        Win32IDE::TypeHierarchyItem thi;
        thi.name = sup.value("name", "");
        thi.kind = sup.value("kind", "");
        thi.detail = sup.value("detail", "");
        thi.uri = sup.value("uri", "");

        if (sup.contains("range")) {
            const auto& r = sup["range"];
            thi.range.start.line = r["start"].value("line", 0);
            thi.range.start.character = r["start"].value("character", 0);
            thi.range.end.line = r["end"].value("line", 0);
            thi.range.end.character = r["end"].value("character", 0);
        }

        supertypes.push_back(thi);
    }

    return supertypes;
}

std::vector<Win32IDE::TypeHierarchyItem> Win32IDE::lspSubtypes(const TypeHierarchyItem& item) {
    std::vector<Win32IDE::TypeHierarchyItem> subtypes;
    LSPLanguage lang = detectLanguageForFile(uriToFilePath(item.uri));
    if (lang >= LSPLanguage::Count || m_lspStatuses[(size_t)lang].state != LSPServerState::Running) {
        return subtypes;
    }

    json params;
    json itemJson;
    itemJson["name"] = item.name;
    itemJson["kind"] = item.kind;
    itemJson["uri"] = item.uri;
    itemJson["range"]["start"]["line"] = item.range.start.line;
    itemJson["range"]["start"]["character"] = item.range.start.character;
    itemJson["range"]["end"]["line"] = item.range.end.line;
    itemJson["range"]["end"]["character"] = item.range.end.character;
    itemJson["selectionRange"]["start"]["line"] = item.selectionRange.start.line;
    itemJson["selectionRange"]["start"]["character"] = item.selectionRange.start.character;
    itemJson["selectionRange"]["end"]["line"] = item.selectionRange.end.line;
    itemJson["selectionRange"]["end"]["character"] = item.selectionRange.end.character;
    params["item"] = itemJson;

    int id = sendLSPRequest(lang, "typeHierarchy/subtypes", params);
    if (id < 0) {
        return subtypes;
    }

    json resp = readLSPResponse(lang, id, 10000);

    if (!resp.contains("result") || !resp["result"].is_array()) {
        return subtypes;
    }

    for (const auto& sub : resp["result"]) {
        Win32IDE::TypeHierarchyItem thi;
        thi.name = sub.value("name", "");
        thi.kind = sub.value("kind", "");
        thi.detail = sub.value("detail", "");
        thi.uri = sub.value("uri", "");

        if (sub.contains("range")) {
            const auto& r = sub["range"];
            thi.range.start.line = r["start"].value("line", 0);
            thi.range.start.character = r["start"].value("character", 0);
            thi.range.end.line = r["end"].value("line", 0);
            thi.range.end.character = r["end"].value("character", 0);
        }

        subtypes.push_back(thi);
    }

    return subtypes;
}

// ============================================================================
// UI COMMANDS
// ============================================================================

void Win32IDE::cmdShowCallHierarchy() {
    if (m_currentFile.empty() || !m_hwndEditor) {
        appendToOutput("[CallHierarchy] No file open.", "General", OutputSeverity::Warning);
        return;
    }

    // Get cursor position
    CHARRANGE sel;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
    int line = SendMessage(m_hwndEditor, EM_LINEFROMCHAR, sel.cpMin, 0);
    int lineStart = SendMessage(m_hwndEditor, EM_LINEINDEX, line, 0);
    int character = sel.cpMin - lineStart;

    std::string uri = filePathToUri(m_currentFile);

    // Prepare call hierarchy
    CallHierarchyItem item = lspPrepareCallHierarchy(uri, line, character);

    if (item.name.empty()) {
        appendToOutput("[CallHierarchy] No call hierarchy available at this location.", "General", OutputSeverity::Info);
        return;
    }

    // Show incoming/outgoing calls
    std::thread([this, item]() {
        auto incoming = lspIncomingCalls(item);
        auto outgoing = lspOutgoingCalls(item);

        // Post results to UI thread
        std::string result = "Call Hierarchy for: " + item.name + "\n\n";
        result += "=== Incoming Calls (" + std::to_string(incoming.size()) + ") ===\n";
        for (const auto& call : incoming) {
            result += "  " + call.from.name + " (" + call.from.kind + ") - " + call.from.uri + ":" + std::to_string(call.fromRanges.start.line + 1) + "\n";
        }
        result += "\n=== Outgoing Calls (" + std::to_string(outgoing.size()) + ") ===\n";
        for (const auto& call : outgoing) {
            result += "  " + call.to.name + " (" + call.to.kind + ") - " + call.to.uri + ":" + std::to_string(call.fromRanges.start.line + 1) + "\n";
        }

        // Store result and notify UI
        {
            std::lock_guard<std::mutex> lock(m_callHierarchyMutex);
            m_lastCallHierarchyResult = result;
        }
        PostMessageA(m_hwndMain, WM_APP + 510, 0, 0);
    }).detach();

    appendToOutput("[CallHierarchy] Loading call hierarchy...", "General", OutputSeverity::Info);
}

void Win32IDE::cmdShowTypeHierarchy() {
    if (m_currentFile.empty() || !m_hwndEditor) {
        appendToOutput("[TypeHierarchy] No file open.", "General", OutputSeverity::Warning);
        return;
    }

    // Get cursor position
    CHARRANGE sel;
    SendMessage(m_hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&sel));
    int line = SendMessage(m_hwndEditor, EM_LINEFROMCHAR, sel.cpMin, 0);
    int lineStart = SendMessage(m_hwndEditor, EM_LINEINDEX, line, 0);
    int character = sel.cpMin - lineStart;

    std::string uri = filePathToUri(m_currentFile);

    // Prepare type hierarchy
    Win32IDE::TypeHierarchyItem item = lspPrepareTypeHierarchy(uri, line, character);

    if (item.name.empty()) {
        appendToOutput("[TypeHierarchy] No type hierarchy available at this location.", "General", OutputSeverity::Info);
        return;
    }

    // Show supertypes/subtypes
    std::thread([this, item]() {
        auto supertypes = lspSupertypes(item);
        auto subtypes = lspSubtypes(item);

        // Build result string
        std::string result = "Type Hierarchy for: " + item.name + " (" + item.kind + ")\n\n";
        result += "=== Supertypes (" + std::to_string(supertypes.size()) + ") ===\n";
        for (const auto& sup : supertypes) {
            result += "  " + sup.name + " (" + sup.kind + ")";
            if (!sup.detail.empty()) result += " - " + sup.detail;
            result += "\n";
        }
        result += "\n=== Subtypes (" + std::to_string(subtypes.size()) + ") ===\n";
        for (const auto& sub : subtypes) {
            result += "  " + sub.name + " (" + sub.kind + ")";
            if (!sub.detail.empty()) result += " - " + sub.detail;
            result += "\n";
        }

        // Store result and notify UI
        {
            std::lock_guard<std::mutex> lock(m_typeHierarchyMutex);
            m_lastTypeHierarchyResult = result;
        }
        PostMessageA(m_hwndMain, WM_APP + 511, 0, 0);
    }).detach();

    appendToOutput("[TypeHierarchy] Loading type hierarchy...", "General", OutputSeverity::Info);
}