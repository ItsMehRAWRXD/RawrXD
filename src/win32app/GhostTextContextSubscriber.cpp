// GhostTextContextSubscriber.cpp — Ghost Text adapter for ContextFusionEngine
// Makes ghost text consume unified context instead of building its own.

#include "GhostTextContextSubscriber.h"
#include <chrono>

namespace RawrXD {

GhostTextContextSubscriber::GhostTextContextSubscriber(Win32IDE_GhostText* ghostText)
    : m_ghostText(ghostText) {
}

void GhostTextContextSubscriber::OnContextUpdate(const ContextFrame& frame) {
    if (!m_enabled || !m_ghostText) return;
    
    // Debounce: don't request on every keystroke
    auto now = std::chrono::steady_clock::now();
    auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
        now - m_lastUpdate).count();
    
    if (elapsed < m_debounceMs) {
        return; // Too soon
    }
    
    // Only request if context actually changed
    if (frame.version == m_lastVersion) {
        return; // No change
    }
    
    m_lastVersion = frame.version;
    m_lastUpdate = now;
    
    // Check if we should request ghost text
    if (ShouldRequest(frame)) {
        RequestGhostText(frame);
    }
}

void GhostTextContextSubscriber::OnContextEvent(const ContextEvent& event) {
    // Handle specific events
    switch (event.type) {
        case ContextEvent::AI_ACCEPTED:
            // Clear ghost text on accept
            if (m_ghostText) {
                m_ghostText->Clear();
            }
            break;
            
        case ContextEvent::AI_REJECTED:
            // Clear ghost text on reject
            if (m_ghostText) {
                m_ghostText->Clear();
            }
            break;
            
        case ContextEvent::CURSOR_MOVED:
            // Hide ghost text when cursor moves
            if (m_ghostText) {
                m_ghostText->Hide();
            }
            break;
            
        default:
            break;
    }
}

bool GhostTextContextSubscriber::ShouldRequest(const ContextFrame& frame) const {
    // Don't request if:
    // 1. No file open
    if (frame.filePath.empty()) return false;
    
    // 2. Cursor at end of empty line (no context)
    std::string currentLine = frame.CurrentLine();
    if (currentLine.empty() && frame.cursor.column == 0) return false;
    
    // 3. Selection active (user is selecting, not typing)
    if (frame.HasSelection()) return false;
    
    // 4. Language not supported
    if (frame.languageId == "plaintext") return false;
    
    // 5. In string literal or comment (optional, can be enhanced)
    // For now, allow everywhere
    
    return true;
}

void GhostTextContextSubscriber::RequestGhostText(const ContextFrame& frame) {
    if (!m_ghostText) return;
    
    // Build context for ghost text request
    // Use unified context instead of building our own
    std::string context = frame.CurrentLine();
    std::string prefix = context.substr(0, frame.cursor.column);
    std::string suffix = "";
    if (frame.cursor.column < (int)context.length()) {
        suffix = context.substr(frame.cursor.column);
    }
    
    // Get recent symbols from LSP for context enrichment
    std::vector<std::string> symbols;
    for (const auto& sym : frame.symbols) {
        if (sym.line >= frame.visible.startLine && sym.line <= frame.visible.endLine) {
            symbols.push_back(sym.name);
        }
    }
    
    // Request ghost text through existing pipeline
    // The pipeline now receives unified context instead of ad-hoc data
    m_ghostText->RequestSuggestion(
        prefix,
        suffix,
        frame.filePath,
        frame.languageId,
        symbols,
        frame.diagnostics
    );
}

} // namespace RawrXD