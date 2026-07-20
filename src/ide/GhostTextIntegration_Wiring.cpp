/*===========================================================================
 * GhostTextIntegration_Wiring.cpp
 * RawrXD IDE - GhostTextEngine Integration Wiring
 * 
 * Instantiates the GhostTextEngine and routes the IDE event loop
 * for async AI-powered ghost text completion.
 *===========================================================================*/

#include "RawrXD_IDE_GhostText_Engine.hpp"
#include "RawrXD_IDE_Win32.h"
#include "SovereignInferenceBridge.h"
#include "SovereignTelemetryIntegration.h"
#include <atomic>

namespace RawrXD {
namespace IDE {

/*===========================================================================
 * GLOBAL INTEGRATION STATE
 *===========================================================================*/

// GhostTextEngine instance - owned by the IDE
static GhostTextEngine* g_GhostTextEngine = nullptr;

// Event loop integration flags
static std::atomic<bool> g_GhostTextInitialized{false};
static std::atomic<bool> g_GhostTextActive{false};
static std::atomic<DWORD> g_LastGhostTextRequest{0};

// Debounce timer ID
#define IDT_GHOSTTEXT_DEBOUNCE  0x1001
#define GHOSTTEXT_DEBOUNCE_MS   150

// Custom window messages for GhostText
#define WM_GHOST_SUGGESTION       (WM_USER + 0x1000)
#define WM_GHOST_DISMISS          (WM_USER + 0x1001)
#define WM_GHOST_ACCEPT           (WM_USER + 0x1002)

/*===========================================================================
 * FORWARD DECLARATIONS
 *===========================================================================*/

static void GhostText_OnDebounceTimer(HWND hwnd);
static void GhostText_OnSuggestionReceived(HWND hwnd, WPARAM wParam, LPARAM lParam);
static void GhostText_OnEditorTextChanged(RawrXD_IDE* ide);
static bool GhostText_HandleKeyNavigation(RawrXD_IDE* ide, WPARAM key);
static void GhostText_TriggerInference(RawrXD_IDE* ide);
static void GhostText_UpdateEditorMetrics(RawrXD_IDE* ide);

/*===========================================================================
 * INITIALIZATION / SHUTDOWN
 *===========================================================================*/

/**
 * Initialize GhostTextEngine integration
 * Called during IDE startup
 */
bool GhostTextIntegration_Initialize(RawrXD_IDE* ide)
{
    if (!ide || !ide->hWndEditor) {
        OutputDebugStringA("[GhostTextIntegration] ERROR: Invalid IDE state\n");
        return false;
    }

    // Prevent double initialization
    if (g_GhostTextInitialized.load()) {
        OutputDebugStringA("[GhostTextIntegration] Already initialized\n");
        return true;
    }

    OutputDebugStringA("[GhostTextIntegration] Initializing...\n");

    // Instantiate GhostTextEngine
    g_GhostTextEngine = new (std::nothrow) GhostTextEngine(ide->hWndEditor);
    if (!g_GhostTextEngine) {
        OutputDebugStringA("[GhostTextIntegration] ERROR: Failed to allocate GhostTextEngine\n");
        return false;
    }

    // Initialize the engine
    if (!g_GhostTextEngine->Initialize()) {
        OutputDebugStringA("[GhostTextIntegration] ERROR: GhostTextEngine::Initialize() failed\n");
        delete g_GhostTextEngine;
        g_GhostTextEngine = nullptr;
        return false;
    }

    // Store reference in IDE struct
    ide->ghostEngine = g_GhostTextEngine;

    // Set up debounce timer
    SetTimer(ide->hWndMain, IDT_GHOSTTEXT_DEBOUNCE, GHOSTTEXT_DEBOUNCE_MS, nullptr);

    // Initialize telemetry
    STEL_InitializeForIDE(ide->hWndMain);

    g_GhostTextInitialized.store(true);
    g_GhostTextActive.store(true);

    OutputDebugStringA("[GhostTextIntegration] Initialized successfully\n");
    
    if (ide->hWndOutput) {
        RawrXD_IDE_OutputAppend(ide, L"[GhostText] AI completion engine ready\r\n");
    }

    return true;
}

/**
 * Shutdown GhostTextEngine integration
 * Called during IDE shutdown
 */
void GhostTextIntegration_Shutdown(RawrXD_IDE* ide)
{
    if (!g_GhostTextInitialized.load()) {
        return;
    }

    OutputDebugStringA("[GhostTextIntegration] Shutting down...\n");

    // Kill debounce timer
    if (ide && ide->hWndMain) {
        KillTimer(ide->hWndMain, IDT_GHOSTTEXT_DEBOUNCE);
    }

    // Shutdown engine
    if (g_GhostTextEngine) {
        g_GhostTextEngine->Shutdown();
        delete g_GhostTextEngine;
        g_GhostTextEngine = nullptr;
    }

    if (ide) {
        ide->ghostEngine = nullptr;
    }

    g_GhostTextInitialized.store(false);
    g_GhostTextActive.store(false);

    OutputDebugStringA("[GhostTextIntegration] Shutdown complete\n");
}

/**
 * Check if GhostText integration is available
 */
bool GhostTextIntegration_IsAvailable()
{
    return g_GhostTextInitialized.load() && g_GhostTextEngine != nullptr;
}

/*===========================================================================
 * EVENT LOOP ROUTING
 *===========================================================================*/

/**
 * Route WM_TIMER messages for GhostText debounce
 */
void GhostTextIntegration_OnTimer(RawrXD_IDE* ide, WPARAM timerId)
{
    if (timerId == IDT_GHOSTTEXT_DEBOUNCE) {
        GhostText_OnDebounceTimer(ide->hWndMain);
    }
}

/**
 * Route custom window messages for GhostText
 */
LRESULT GhostTextIntegration_OnCustomMessage(RawrXD_IDE* ide, UINT msg, WPARAM wParam, LPARAM lParam)
{
    switch (msg) {
        case WM_GHOST_SUGGESTION:
            GhostText_OnSuggestionReceived(ide->hWndMain, wParam, lParam);
            return 0;

        case WM_GHOST_DISMISS:
            if (g_GhostTextEngine) {
                g_GhostTextEngine->HideSuggestion();
            }
            return 0;

        case WM_GHOST_ACCEPT:
            if (g_GhostTextEngine && ide) {
                std::string acceptedText;
                if (g_GhostTextEngine->AcceptSuggestion(acceptedText)) {
                    // Insert text into editor
                    RawrXD_IDE_InsertText(ide, acceptedText.c_str());
                    
                    // Telemetry
                    STEL_GhostTextAccepted(acceptedText.length());
                }
            }
            return 0;
    }

    return DefWindowProc(ide->hWndMain, msg, wParam, lParam);
}

/**
 * Route editor text change events (EN_CHANGE)
 */
void GhostTextIntegration_OnTextChanged(RawrXD_IDE* ide)
{
    if (!g_GhostTextActive.load() || !ide) {
        return;
    }

    // Increment version for stale detection
    InterlockedIncrement(&ide->editorVersion);

    // Reset debounce timer
    KillTimer(ide->hWndMain, IDT_GHOSTTEXT_DEBOUNCE);
    SetTimer(ide->hWndMain, IDT_GHOSTTEXT_DEBOUNCE, GHOSTTEXT_DEBOUNCE_MS, nullptr);

    // Store timestamp
    g_LastGhostTextRequest.store(GetTickCount());
}

/**
 * Route keyboard input for GhostText navigation
 * Returns true if key was handled
 */
bool GhostTextIntegration_OnKeyDown(RawrXD_IDE* ide, WPARAM key)
{
    if (!g_GhostTextActive.load() || !g_GhostTextEngine) {
        return false;
    }

    return GhostText_HandleKeyNavigation(ide, key);
}

/**
 * Route paint messages for ghost text rendering
 */
void GhostTextIntegration_OnPaint(RawrXD_IDE* ide, HDC hdc, const RECT* editorRect)
{
    if (!g_GhostTextActive.load() || !g_GhostTextEngine) {
        return;
    }

    // Only paint if engine has active suggestion
    if (!g_GhostTextEngine->IsActive()) {
        return;
    }

    // Get editor metrics
    int lineHeight = RawrXD_IDE_GetLineHeight(ide);
    int charWidth = RawrXD_IDE_GetCharWidth(ide);
    
    POINT scrollPos = RawrXD_IDE_GetScrollPosition(ide);
    POINT cursorPos = RawrXD_IDE_GetCursorScreenPos(ide);

    // Paint ghost text
    g_GhostTextEngine->PaintGhostText(
        hdc, 
        *editorRect,
        lineHeight,
        charWidth,
        scrollPos.x,
        scrollPos.y,
        cursorPos.x,
        cursorPos.y
    );
}

/*===========================================================================
 * INTERNAL IMPLEMENTATION
 *===========================================================================*/

/**
 * Debounce timer handler - triggers inference after user stops typing
 */
static void GhostText_OnDebounceTimer(HWND hwnd)
{
    if (!g_GhostTextActive.load() || !g_GhostTextEngine) {
        return;
    }

    RawrXD_IDE* ide = RawrXD_IDE_GetFromHwnd(hwnd);
    if (!ide) {
        return;
    }

    // Check if enough time has passed since last keystroke
    DWORD elapsed = GetTickCount() - g_LastGhostTextRequest.load();
    if (elapsed < GHOSTTEXT_DEBOUNCE_MS) {
        return;  // Still typing
    }

    // Kill timer until next keystroke
    KillTimer(hwnd, IDT_GHOSTTEXT_DEBOUNCE);

    // Trigger inference
    GhostText_TriggerInference(ide);
}

/**
 * Handle async suggestion received from inference thread
 */
static void GhostText_OnSuggestionReceived(HWND hwnd, WPARAM wParam, LPARAM lParam)
{
    (void)wParam;  // Reserved
    
    if (!g_GhostTextEngine) {
        return;
    }

    // lParam points to GhostResult structure
    GhostResult* result = reinterpret_cast<GhostResult*>(lParam);
    if (!result) {
        return;
    }

    // Pass to engine
    g_GhostTextEngine->HandleInferenceResult(
        result->text,
        result->line,
        result->col,
        result->confidence
    );

    // Free result memory (allocated by inference thread)
    delete result;

    // Invalidate editor to trigger repaint
    RawrXD_IDE* ide = RawrXD_IDE_GetFromHwnd(hwnd);
    if (ide && ide->hWndEditor) {
        InvalidateRect(ide->hWndEditor, nullptr, FALSE);
    }
}

/**
 * Handle keyboard navigation for ghost text
 */
static bool GhostText_HandleKeyNavigation(RawrXD_IDE* ide, WPARAM key)
{
    if (!g_GhostTextEngine->IsActive()) {
        return false;  // Let IDE handle key
    }

    switch (key) {
        case VK_TAB:
            // Accept full suggestion
            {
                std::string acceptedText;
                if (g_GhostTextEngine->AcceptSuggestion(acceptedText)) {
                    RawrXD_IDE_InsertText(ide, acceptedText.c_str());
                    STEL_GhostTextAccepted(acceptedText.length());
                }
            }
            return true;  // Key handled

        case VK_ESCAPE:
            // Dismiss suggestion
            g_GhostTextEngine->LogDismissal();
            g_GhostTextEngine->HideSuggestion();
            InvalidateRect(ide->hWndEditor, nullptr, FALSE);
            return true;  // Key handled

        case VK_RIGHT:
            // Check for Ctrl+Right (accept partial word)
            if (GetAsyncKeyState(VK_CONTROL) & 0x8000) {
                std::string partialText;
                if (g_GhostTextEngine->AcceptPartial(partialText)) {
                    RawrXD_IDE_InsertText(ide, partialText.c_str());
                }
                return true;
            }
            // Regular Right arrow - dismiss and let editor handle
            g_GhostTextEngine->HideSuggestion();
            return false;

        case VK_UP:
        case VK_DOWN:
        case VK_PRIOR:  // Page Up
        case VK_NEXT:   // Page Down
        case VK_HOME:
        case VK_END:
            // Navigation keys dismiss suggestion
            g_GhostTextEngine->HideSuggestion();
            InvalidateRect(ide->hWndEditor, nullptr, FALSE);
            return false;  // Let editor handle navigation

        default:
            // Any other key - check if it should dismiss
            if (key >= VK_SPACE && key <= VK_DELETE) {
                // Get current line text
                char lineText[1024];
                int cursorCol = RawrXD_IDE_GetCursorColumn(ide);
                RawrXD_IDE_GetCurrentLineText(ide, lineText, sizeof(lineText));
                
                g_GhostTextEngine->CheckDismiss(lineText, cursorCol);
                
                if (!g_GhostTextEngine->IsActive()) {
                    InvalidateRect(ide->hWndEditor, nullptr, FALSE);
                }
            }
            return false;  // Let editor handle key
    }
}

/**
 * Trigger async inference request
 */
static void GhostText_TriggerInference(RawrXD_IDE* ide)
{
    if (!g_GhostTextEngine) {
        return;
    }

    // Get current editor state
    char buffer[16384];
    int cursorLine, cursorCol;
    
    if (!RawrXD_IDE_GetEditorContent(ide, buffer, sizeof(buffer), &cursorLine, &cursorCol)) {
        return;
    }

    // Update editor metrics
    GhostText_UpdateEditorMetrics(ide);

    // Telemetry
    STEL_BeginInference(nullptr);

    // Trigger engine
    g_GhostTextEngine->OnTextChanged(buffer, cursorLine, cursorCol);
}

/**
 * Update editor metrics for ghost text positioning
 */
static void GhostText_UpdateEditorMetrics(RawrXD_IDE* ide)
{
    if (!ide || !g_GhostTextEngine) {
        return;
    }

    // Metrics are queried on-demand during PaintGhostText
    // This function can be extended for proactive metric caching
}

/*===========================================================================
 * SOVEREIGN INFERENCE BRIDGE INTEGRATION
 *===========================================================================*/

/**
 * Callback for streaming tokens from SovereignInferenceBridge
 */
static void GhostText_OnSovereignToken(
    const WCHAR* token,
    uint32_t tokenIndex,
    BOOL isComplete,
    void* userData)
{
    (void)userData;
    
    if (!g_GhostTextEngine) {
        return;
    }

    // Convert token to UTF-8
    char utf8Token[1024];
    int len = WideCharToMultiByte(CP_UTF8, 0, token, -1, utf8Token, sizeof(utf8Token), nullptr, nullptr);
    if (len <= 0) {
        return;
    }

    // Accumulate tokens or handle completion
    if (tokenIndex == 0) {
        STEL_OnFirstToken(tokenIndex);
    }

    if (isComplete) {
        // Finalize suggestion
        // This would typically be handled by the GhostTextEngine's async callback
    }
}

/**
 * Initialize SovereignInferenceBridge for GhostText
 */
bool GhostTextIntegration_InitSovereignBridge()
{
    SIB_Status status = SIB_Initialize();
    if (status != SIB_OK) {
        OutputDebugStringA("[GhostTextIntegration] SIB_Initialize failed\n");
        return false;
    }

    // Register token callback
    SIB_SetTokenCallback(GhostText_OnSovereignToken, nullptr);

    OutputDebugStringA("[GhostTextIntegration] SovereignInferenceBridge initialized\n");
    return true;
}

/*===========================================================================
 * UTILITY FUNCTIONS
 *===========================================================================*/

/**
 * Force dismiss any active ghost text
 */
void GhostTextIntegration_ForceDismiss(RawrXD_IDE* ide)
{
    if (g_GhostTextEngine) {
        g_GhostTextEngine->HideSuggestion();
    }
    
    if (ide && ide->hWndEditor) {
        InvalidateRect(ide->hWndEditor, nullptr, FALSE);
    }
}

/**
 * Check if ghost text is currently active
 */
bool GhostTextIntegration_IsActive()
{
    return g_GhostTextActive.load() && 
           g_GhostTextEngine && 
           g_GhostTextEngine->IsActive();
}

/**
 * Get current suggestion info
 */
bool GhostTextIntegration_GetCurrentSuggestion(std::string& outText, float& outConfidence)
{
    if (!g_GhostTextEngine || !g_GhostTextEngine->IsActive()) {
        return false;
    }

    const GhostSuggestion& current = g_GhostTextEngine->GetCurrent();
    outText = current.text;
    outConfidence = current.confidence;
    return true;
}

/**
 * Enable/disable GhostText integration
 */
void GhostTextIntegration_SetEnabled(bool enabled)
{
    g_GhostTextActive.store(enabled);
    
    if (!enabled && g_GhostTextEngine) {
        g_GhostTextEngine->HideSuggestion();
    }
}

} // namespace IDE
} // namespace RawrXD

/*===========================================================================
 * C API FOR WIN32 IDE
 *===========================================================================*/

extern "C" {

/**
 * C API wrapper for initialization
 */
BOOL RawrXD_GhostText_Init(RawrXD_IDE* ide)
{
    return RawrXD::IDE::GhostTextIntegration_Initialize(ide) ? TRUE : FALSE;
}

/**
 * C API wrapper for shutdown
 */
void RawrXD_GhostText_Shutdown(RawrXD_IDE* ide)
{
    RawrXD::IDE::GhostTextIntegration_Shutdown(ide);
}

/**
 * C API wrapper for text change notification
 */
void RawrXD_GhostText_OnTextChanged(RawrXD_IDE* ide)
{
    RawrXD::IDE::GhostTextIntegration_OnTextChanged(ide);
}

/**
 * C API wrapper for key handling
 */
BOOL RawrXD_GhostText_OnKeyDown(RawrXD_IDE* ide, WPARAM key)
{
    return RawrXD::IDE::GhostTextIntegration_OnKeyDown(ide, key) ? TRUE : FALSE;
}

/**
 * C API wrapper for paint
 */
void RawrXD_GhostText_OnPaint(RawrXD_IDE* ide, HDC hdc, const RECT* editorRect)
{
    RawrXD::IDE::GhostTextIntegration_OnPaint(ide, hdc, editorRect);
}

/**
 * C API wrapper for timer
 */
void RawrXD_GhostText_OnTimer(RawrXD_IDE* ide, WPARAM timerId)
{
    RawrXD::IDE::GhostTextIntegration_OnTimer(ide, timerId);
}

/**
 * C API wrapper for custom messages
 */
LRESULT RawrXD_GhostText_OnCustomMessage(RawrXD_IDE* ide, UINT msg, WPARAM wParam, LPARAM lParam)
{
    return RawrXD::IDE::GhostTextIntegration_OnCustomMessage(ide, msg, wParam, lParam);
}

/**
 * C API wrapper for force dismiss
 */
void RawrXD_GhostText_ForceDismiss(RawrXD_IDE* ide)
{
    RawrXD::IDE::GhostTextIntegration_ForceDismiss(ide);
}

/**
 * C API wrapper for availability check
 */
BOOL RawrXD_GhostText_IsAvailable()
{
    return RawrXD::IDE::GhostTextIntegration_IsAvailable() ? TRUE : FALSE;
}

} // extern "C"
