// ============================================================================
// ghost_text_engine.h — Ghost Text Core Infrastructure (Day 1)
// ============================================================================
// Thread-safe buffer and bridge wiring for inline completion suggestions.
// This is the foundation for the ghost text overlay system.
//
// DAY 1 DELIVERABLES:
// - Thread-safe atomic buffer for ghost text
// - Bridge_OnSuggestionReady implementation
// - WM_APP message definitions for ghost text
// - Global access functions for UI integration
// ============================================================================

#pragma once

#include <atomic>
#include <string>
#include <mutex>
#include <optional>

#ifndef NOMINMAX
#define NOMINMAX
#endif
#include <windows.h>

namespace RawrXD {

// ============================================================================
// WM_APP Message IDs for Ghost Text System
// ============================================================================
// These are sent from inference thread to UI thread
constexpr UINT WM_GHOST_TEXT_UPDATE = WM_APP + 400;    // New suggestion available
constexpr UINT WM_GHOST_TEXT_CLEAR = WM_APP + 401;     // Clear current suggestion
constexpr UINT WM_GHOST_TEXT_ACCEPT = WM_APP + 402;   // Accept suggestion (Tab pressed)
constexpr UINT WM_GHOST_TEXT_DISMISS = WM_APP + 403;   // Dismiss suggestion (Escape pressed)

// ============================================================================
// GhostTextBuffer — Thread-safe storage for inline completions
// ============================================================================
class GhostTextBuffer {
public:
    static GhostTextBuffer& Instance();

    // Thread-safe setters (called from inference thread)
    void SetSuggestion(const std::string& text);
    void SetSuggestion(std::string&& text);
    void Clear();

    // Thread-safe getters (called from UI thread)
    bool HasSuggestion() const;
    std::string GetSuggestion() const;
    std::optional<std::string> TakeSuggestion();  // Returns and clears atomically

    // Position tracking (where suggestion starts in editor)
    void SetCursorPosition(int line, int column);
    void GetCursorPosition(int& line, int& column) const;

    // State management
    bool IsVisible() const { return m_visible.load(std::memory_order_acquire); }
    void SetVisible(bool visible) { m_visible.store(visible, std::memory_order_release); }

    // For WM_GHOST_TEXT_UPDATE - check if new data arrived
    bool HasNewData() const { return m_hasNewData.exchange(false, std::memory_order_acq_rel); }
    
    // Set notification window for WM_APP messages
    void SetNotificationWindow(HWND hwnd) { m_notifyHwnd = hwnd; }
    HWND GetNotificationWindow() const { return m_notifyHwnd; }
    
    // Generation ID for stale suggestion protection
    uint64_t GetNextGenerationId() { return ++m_generationId; }
    uint64_t GetCurrentGenerationId() const { return m_generationId.load(); }

private:
    HWND m_notifyHwnd = nullptr;
    std::atomic<uint64_t> m_generationId{0};
    GhostTextBuffer() = default;
    ~GhostTextBuffer() = default;
    GhostTextBuffer(const GhostTextBuffer&) = delete;
    GhostTextBuffer& operator=(const GhostTextBuffer&) = delete;

    mutable std::mutex m_mutex;
    std::string m_suggestion;
    std::atomic<bool> m_visible{false};
    std::atomic<bool> m_hasNewData{false};
    int m_cursorLine = 0;
    int m_cursorColumn = 0;
};

// ============================================================================
// Bridge Functions — Called from inference engine
// ============================================================================

// Called when a new suggestion is ready (from inference thread)
// This is the entry point from the model bridge
extern "C" void Bridge_OnSuggestionReady(const wchar_t* text, int len);

// Called to clear current suggestion
extern "C" void Bridge_ClearSuggestion();

// Called when suggestion generation completes
extern "C" void Bridge_OnSuggestionComplete();

// ============================================================================
// UI Integration Functions — Called from Win32IDE
// ============================================================================

// Initialize ghost text system (call once at startup)
void GhostText_Initialize();

// Shutdown ghost text system
void GhostText_Shutdown();

// Check if ghost text is currently showing
bool GhostText_IsActive();

// Get current ghost text (for rendering)
std::string GhostText_GetCurrentText();

// Accept current suggestion (inserts text at cursor)
// Returns true if suggestion was accepted
bool GhostText_Accept(HWND hwndEditor);

// Dismiss current suggestion
void GhostText_Dismiss();

// Handle editor notification (typing, cursor movement)
// Returns true if ghost text was dismissed due to cursor movement
bool GhostText_OnEditorChange(HWND hwndEditor);

// ============================================================================
// Ghost Text Telemetry
// ============================================================================
enum class GhostTextEvent {
    SHOWN,      // Suggestion displayed to user
    ACCEPTED,   // User accepted suggestion (Tab)
    REJECTED,   // User rejected suggestion (Escape)
    EXPIRED,    // Suggestion dismissed due to typing/cursor movement
    STALE       // Suggestion discarded (older generation)
};

struct GhostTextTelemetry {
    uint64_t request_id = 0;
    uint64_t generation_id = 0;
    GhostTextEvent event;
    size_t chars_shown = 0;
    size_t chars_accepted = 0;
    uint32_t latency_ms = 0;  // Time from request to display
    uint32_t display_duration_ms = 0;  // How long suggestion was visible
};

// Telemetry callback type
using GhostTextTelemetryCallback = void (*)(const GhostTextTelemetry& telemetry);

// Set telemetry callback (call once at initialization)
void GhostText_SetTelemetryCallback(GhostTextTelemetryCallback callback);

// Record telemetry event (internal use)
void GhostText_RecordTelemetry(const GhostTextTelemetry& telemetry);

// Get next unique request ID for telemetry
uint64_t GhostText_GetNextRequestId();

// ============================================================================
// Ghost Text Acceptance Metrics
// ============================================================================
struct GhostAcceptanceMetrics {
    std::atomic<uint64_t> shown{0};
    std::atomic<uint64_t> accepted{0};
    std::atomic<uint64_t> rejected{0};
    std::atomic<uint64_t> expired{0};
    std::atomic<uint64_t> stale{0};
    
    double GetAcceptanceRate() const {
        uint64_t total = accepted.load() + rejected.load() + expired.load();
        return total > 0 ? (static_cast<double>(accepted.load()) / total * 100.0) : 0.0;
    }
};

// Get global metrics instance
GhostAcceptanceMetrics& GhostText_GetMetrics();

// Reset metrics (for testing)
void GhostText_ResetMetrics();

// ============================================================================
// GhostTextRenderer — Platform abstraction for drawing
// ============================================================================
// This will be implemented in Day 3 (Win32 owner-draw)
class GhostTextRenderer {
public:
    // Draw ghost text at the specified position
    // hdc: device context for drawing
    // x, y: screen coordinates where ghost text should appear
    // text: the ghost text to draw
    static void Draw(HDC hdc, int x, int y, const std::string& text);

    // Calculate text dimensions
    static SIZE MeasureText(HDC hdc, const std::string& text);

    // Get gray color for ghost text
    static COLORREF GetGhostTextColor();
};

} // namespace RawrXD
