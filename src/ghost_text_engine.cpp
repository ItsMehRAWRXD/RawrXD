// ============================================================================
// ghost_text_engine.cpp — Ghost Text Core Implementation (Day 1)
// ============================================================================
// Thread-safe buffer and bridge wiring for inline completion suggestions.
//
// DAY 1 DELIVERABLES:
// - GhostTextBuffer singleton with atomic operations
// - Bridge_OnSuggestionReady production implementation
// - UTF-8/UTF-16 conversion utilities
// - Global initialization/shutdown
// ============================================================================

#include "ghost_text_engine.h"
#include <codecvt>
#include <locale>

namespace RawrXD {

// ============================================================================
// GhostTextBuffer Implementation
// ============================================================================

GhostTextBuffer& GhostTextBuffer::Instance() {
    static GhostTextBuffer instance;
    return instance;
}

void GhostTextBuffer::SetSuggestion(const std::string& text) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_suggestion = text;
    m_hasNewData.store(true, std::memory_order_release);
    m_visible.store(!text.empty(), std::memory_order_release);
    
    // Increment generation ID for stale protection
    uint64_t newGen = ++m_generationId;
    
    // Post message to IDE to trigger repaint (if we have a target window)
    if (m_notifyHwnd && IsWindow(m_notifyHwnd)) {
        PostMessage(m_notifyHwnd, WM_GHOST_TEXT_UPDATE, 
                    static_cast<WPARAM>(newGen), 0);
    }
}

void GhostTextBuffer::SetSuggestion(std::string&& text) {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_suggestion = std::move(text);
    m_hasNewData.store(true, std::memory_order_release);
    m_visible.store(!m_suggestion.empty(), std::memory_order_release);
}

void GhostTextBuffer::Clear() {
    std::lock_guard<std::mutex> lock(m_mutex);
    m_suggestion.clear();
    m_visible.store(false, std::memory_order_release);
    m_hasNewData.store(false, std::memory_order_release);
}

bool GhostTextBuffer::HasSuggestion() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return !m_suggestion.empty() && m_visible.load(std::memory_order_acquire);
}

std::string GhostTextBuffer::GetSuggestion() const {
    std::lock_guard<std::mutex> lock(m_mutex);
    return m_suggestion;
}

std::optional<std::string> GhostTextBuffer::TakeSuggestion() {
    std::lock_guard<std::mutex> lock(m_mutex);
    if (m_suggestion.empty()) {
        return std::nullopt;
    }
    std::string result = std::move(m_suggestion);
    m_suggestion.clear();
    m_visible.store(false, std::memory_order_release);
    return result;
}

void GhostTextBuffer::SetCursorPosition(int line, int column) {
    m_cursorLine = line;
    m_cursorColumn = column;
}

void GhostTextBuffer::GetCursorPosition(int& line, int& column) const {
    line = m_cursorLine;
    column = m_cursorColumn;
}

// ============================================================================
// Bridge Functions — Called from inference engine (C interface)
// ============================================================================

// Convert wide string to UTF-8
static std::string WideToUtf8(const wchar_t* text, int len) {
    if (!text || len <= 0) return "";
    
    // Use Windows API for conversion (more reliable than codecvt on Windows)
    int utf8Len = WideCharToMultiByte(CP_UTF8, 0, text, len, nullptr, 0, nullptr, nullptr);
    if (utf8Len <= 0) return "";
    
    std::string result(utf8Len, '\0');
    WideCharToMultiByte(CP_UTF8, 0, text, len, &result[0], utf8Len, nullptr, nullptr);
    return result;
}

} // extern "C"

// Called when a new suggestion is ready (from inference thread)
extern "C" void Bridge_OnSuggestionReady(const wchar_t* text, int len) {
    if (!text || len <= 0) return;
    
    // Convert to UTF-8 and store in buffer
    std::string utf8Text = RawrXD::WideToUtf8(text, len);
    if (!utf8Text.empty()) {
        RawrXD::GhostTextBuffer::Instance().SetSuggestion(std::move(utf8Text));
    }
}

// Called to clear current suggestion
extern "C" void Bridge_ClearSuggestion() {
    RawrXD::GhostTextBuffer::Instance().Clear();
}

// Called when suggestion generation completes
extern "C" void Bridge_OnSuggestionComplete() {
    // Suggestion is already in buffer, just mark as complete
    // Future: could trigger UI notification here
}

namespace RawrXD {

// ============================================================================
// UI Integration Functions
// ============================================================================

static HWND g_hwndGhostParent = nullptr;

void GhostText_Initialize() {
    // Reset buffer state
    GhostTextBuffer::Instance().Clear();
    g_hwndGhostParent = nullptr;
}

void GhostText_Shutdown() {
    GhostTextBuffer::Instance().Clear();
    g_hwndGhostParent = nullptr;
}

bool GhostText_IsActive() {
    return GhostTextBuffer::Instance().IsVisible() && 
           GhostTextBuffer::Instance().HasSuggestion();
}

std::string GhostText_GetCurrentText() {
    return GhostTextBuffer::Instance().GetSuggestion();
}

bool GhostText_Accept(HWND hwndEditor) {
    if (!hwndEditor || !GhostText_IsActive()) {
        return false;
    }
    
    auto suggestion = GhostTextBuffer::Instance().TakeSuggestion();
    if (!suggestion.has_value() || suggestion->empty()) {
        return false;
    }
    
    // Convert UTF-8 to wide string for Windows
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, suggestion->c_str(), -1, nullptr, 0);
    if (wideLen <= 0) return false;
    
    std::wstring wideText(wideLen - 1, L'\0');  // -1 for null terminator
    MultiByteToWideChar(CP_UTF8, 0, suggestion->c_str(), -1, &wideText[0], wideLen);
    
    // Insert text at current cursor position using EM_REPLACESEL
    SendMessageW(hwndEditor, EM_REPLACESEL, TRUE, reinterpret_cast<LPARAM>(wideText.c_str()));
    
    return true;
}

void GhostText_Dismiss() {
    GhostTextBuffer::Instance().Clear();
}

bool GhostText_OnEditorChange(HWND hwndEditor) {
    if (!GhostText_IsActive()) {
        return false;
    }
    
    // Get current cursor position
    CHARRANGE cr;
    SendMessageW(hwndEditor, EM_EXGETSEL, 0, reinterpret_cast<LPARAM>(&cr));
    
    int currentLine = static_cast<int>(SendMessageW(hwndEditor, EM_EXLINEFROMCHAR, 0, cr.cpMin));
    int lineStart = static_cast<int>(SendMessageW(hwndEditor, EM_LINEINDEX, currentLine, 0));
    int currentColumn = cr.cpMin - lineStart;
    
    // Get stored position
    int storedLine, storedColumn;
    GhostTextBuffer::Instance().GetCursorPosition(storedLine, storedColumn);
    
    // If cursor moved from where suggestion started, dismiss it
    if (currentLine != storedLine || currentColumn != storedColumn) {
        GhostText_Dismiss();
        return true;
    }
    
    return false;
}

// ============================================================================
// GhostTextRenderer — Stub for Day 3
// ============================================================================

void GhostTextRenderer::Draw(HDC hdc, int x, int y, const std::string& text) {
    // Day 3 implementation: owner-draw gray text
    // For now, this is a stub that will be filled in
    (void)hdc;
    (void)x;
    (void)y;
    (void)text;
}

SIZE GhostTextRenderer::MeasureText(HDC hdc, const std::string& text) {
    // Day 3 implementation: measure text dimensions
    (void)hdc;
    (void)text;
    SIZE size = {0, 0};
    return size;
}

COLORREF GhostTextRenderer::GetGhostTextColor() {
    // Gray color for ghost text (RGB 128, 128, 128)
    return RGB(128, 128, 128);
}

// ============================================================================
// Ghost Text Telemetry Implementation
// ============================================================================

static GhostTextTelemetryCallback g_telemetryCallback = nullptr;
static std::atomic<uint64_t> g_nextRequestId{1};

void GhostText_SetTelemetryCallback(GhostTextTelemetryCallback callback) {
    g_telemetryCallback = callback;
}

void GhostText_RecordTelemetry(const GhostTextTelemetry& telemetry) {
    // Update metrics counters
    switch (telemetry.event) {
        case GhostTextEvent::SHOWN:
            g_metrics.shown.fetch_add(1, std::memory_order_relaxed);
            break;
        case GhostTextEvent::ACCEPTED:
            g_metrics.accepted.fetch_add(1, std::memory_order_relaxed);
            break;
        case GhostTextEvent::REJECTED:
            g_metrics.rejected.fetch_add(1, std::memory_order_relaxed);
            break;
        case GhostTextEvent::EXPIRED:
            g_metrics.expired.fetch_add(1, std::memory_order_relaxed);
            break;
        case GhostTextEvent::STALE:
            g_metrics.stale.fetch_add(1, std::memory_order_relaxed);
            break;
    }
    
    // Call registered callback
    if (g_telemetryCallback) {
        g_telemetryCallback(telemetry);
    }
}

uint64_t GhostText_GetNextRequestId() {
    return g_nextRequestId.fetch_add(1, std::memory_order_relaxed);
}

// ============================================================================
// Ghost Text Acceptance Metrics Implementation
// ============================================================================

static GhostAcceptanceMetrics g_metrics;

GhostAcceptanceMetrics& GhostText_GetMetrics() {
    return g_metrics;
}

void GhostText_ResetMetrics() {
    g_metrics.shown.store(0);
    g_metrics.accepted.store(0);
    g_metrics.rejected.store(0);
    g_metrics.expired.store(0);
    g_metrics.stale.store(0);
}

} // namespace RawrXD
