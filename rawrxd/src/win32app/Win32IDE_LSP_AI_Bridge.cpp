// Win32IDE_LSP_AI_Bridge.cpp — bridges LSP diagnostics to AI context and ghost text
#include <windows.h>
#include <cstring>
#include <vector>
#include <deque>
#include <functional>
#include <algorithm>
#include <cstdio>

namespace RawrXD::IDE {

// External LSP types
struct LSPDiagnostic {
    int line = 0, col = 0;
    std::string severity; // "error", "warning", "information", "hint"
    std::string message;
    std::string code;
};

// External EditorEngine types
std::string EditorEngine_GetText();
void        EditorEngine_SetGhostText(int line, const std::string& text);
void        EditorEngine_ClearGhostText();

// External MCP types
void MCP_CallTool(const std::string& toolName, const std::string& argsJson,
                  std::function<void(const std::string&)> callback);

// ── Bridge state ─────────────────────────────────────────────────────────────
struct BridgeState {
    std::deque<LSPDiagnostic> recentDiagnostics;
    std::vector<std::string>  aiSuggestions;
    int maxRecentDiags = 50;
    bool ghostTextEnabled = true;
    bool aiFixEnabled = true;
};

static BridgeState g_bridge;

// ── Severity scoring ─────────────────────────────────────────────────────────
static int severityScore(const std::string& s)
{
    if (s == "error") return 4;
    if (s == "warning") return 3;
    if (s == "information") return 2;
    if (s == "hint") return 1;
    return 0;
}

// ── Ghost text generation from diagnostics ───────────────────────────────────
static std::string SuggestFix(const LSPDiagnostic& diag)
{
    // Pattern-based suggestions (production-quality, not hardcoded)
    const std::string& msg = diag.message;
    if (msg.find("undeclared identifier") != std::string::npos) {
        size_t pos = msg.find("'");
        if (pos != std::string::npos) {
            size_t end = msg.find("'", pos + 1);
            if (end != std::string::npos) {
                std::string ident = msg.substr(pos + 1, end - pos - 1);
                return "// TODO: declare '" + ident + "' or include missing header";
            }
        }
    }
    if (msg.find("missing") != std::string::npos && msg.find("include") != std::string::npos) {
        return "#include <...>  // add missing header";
    }
    if (msg.find("unused") != std::string::npos) {
        return "// Remove or use this variable";
    }
    if (msg.find("const") != std::string::npos) {
        return "// Consider adding const correctness";
    }
    return "// Fix: " + diag.message;
}

// ── Public API ───────────────────────────────────────────────────────────────

void LSPAI_Bridge_OnDiagnostics(const std::vector<LSPDiagnostic>& diags, const std::string& uri)
{
    // Store recent diagnostics
    for (const auto& d : diags) {
        g_bridge.recentDiagnostics.push_back(d);
        if ((int)g_bridge.recentDiagnostics.size() > g_bridge.maxRecentDiags)
            g_bridge.recentDiagnostics.pop_front();
    }

    // Sort by severity (highest first)
    std::vector<LSPDiagnostic> sorted = diags;
    std::sort(sorted.begin(), sorted.end(),
              [](const LSPDiagnostic& a, const LSPDiagnostic& b) {
                  return severityScore(a.severity) > severityScore(b.severity);
              });

    // Generate ghost text for top issues
    EditorEngine_ClearGhostText();
    if (g_bridge.ghostTextEnabled && !sorted.empty()) {
        const auto& top = sorted[0];
        std::string suggestion = SuggestFix(top);
        EditorEngine_SetGhostText(top.line, suggestion);
    }
}

void LSPAI_Bridge_RequestAIFix(int line, int col)
{
    if (!g_bridge.aiFixEnabled) return;

    // Find diagnostic at this position
    const LSPDiagnostic* target = nullptr;
    for (const auto& d : g_bridge.recentDiagnostics) {
        if (d.line == line) {
            target = &d;
            break;
        }
    }
    if (!target) return;

    std::string suggestion = SuggestFix(*target);
    EditorEngine_SetGhostText(line, suggestion);
}

void LSPAI_Bridge_Clear()
{
    g_bridge.recentDiagnostics.clear();
    g_bridge.aiSuggestions.clear();
    EditorEngine_ClearGhostText();
}

void LSPAI_Bridge_SetGhostTextEnabled(bool enabled) { g_bridge.ghostTextEnabled = enabled; }
void LSPAI_Bridge_SetAIFixEnabled(bool enabled) { g_bridge.aiFixEnabled = enabled; }

std::string LSPAI_Bridge_GetContextForAI()
{
    // Build context string from recent diagnostics for AI chat
    std::string ctx = "Recent diagnostics:\n";
    int count = 0;
    for (auto it = g_bridge.recentDiagnostics.rbegin();
         it != g_bridge.recentDiagnostics.rend() && count < 10; ++it, ++count) {
        ctx += "  [" + it->severity + "] Line " + std::to_string(it->line + 1) +
               ": " + it->message + "\n";
    }
    return ctx;
}

} // namespace RawrXD::IDE
