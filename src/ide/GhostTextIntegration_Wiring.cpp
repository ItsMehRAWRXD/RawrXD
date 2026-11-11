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
#include "SovereignAwsBridge.h"
#include <atomic>
#include <thread>
#include <chrono>

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

// AWS Bridge completion message
#define WM_AWS_COMPLETION_READY    (WM_USER + 0x1100)

/*===========================================================================
 * AWS BEDROCK BRIDGE STATE
 *===========================================================================*/

// AWS Bridge instance - remote backend for GhostText
static SovereignAwsBridge* g_AwsBridge = nullptr;
static std::atomic<bool> g_AwsBridgeInitialized{false};
static std::atomic<bool> g_AwsBridgeEnabled{false};

// AWS credentials (loaded from environment variables - NEVER hardcode in production)
// Set these environment variables before running:
//   RAWRXD_AWS_ACCESS_KEY_ID
//   RAWRXD_AWS_SECRET_ACCESS_KEY
//   RAWRXD_AWS_REGION (defaults to us-east-1)
//   RAWRXD_AWS_MODEL_ID (defaults to anthropic.claude-3-5-sonnet)
static const char* AWS_ACCESS_KEY_ID     = nullptr;  // Loaded from env
static const char* AWS_SECRET_ACCESS_KEY = nullptr;  // Loaded from env
static const char* AWS_REGION            = "us-east-1";
static const char* AWS_MODEL_ID          = "anthropic.claude-3-5-sonnet-20241022-v2:0";

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

    // Load AWS credentials from environment (NEVER hardcode secrets)
    AWS_ACCESS_KEY_ID = getenv("RAWRXD_AWS_ACCESS_KEY_ID");
    AWS_SECRET_ACCESS_KEY = getenv("RAWRXD_AWS_SECRET_ACCESS_KEY");
    const char* envRegion = getenv("RAWRXD_AWS_REGION");
    const char* envModel = getenv("RAWRXD_AWS_MODEL_ID");
    if (envRegion) AWS_REGION = envRegion;
    if (envModel) AWS_MODEL_ID = envModel;

    // Initialize AWS Bedrock Bridge (remote backend) - only if credentials available
    if (!AWS_ACCESS_KEY_ID || !AWS_SECRET_ACCESS_KEY) {
        OutputDebugStringA("[GhostTextIntegration] AWS credentials not set (set RAWRXD_AWS_ACCESS_KEY_ID and RAWRXD_AWS_SECRET_ACCESS_KEY env vars)\n");
    } else {
        g_AwsBridge = new (std::nothrow) SovereignAwsBridge();
    if (g_AwsBridge) {
        if (SovereignAwsBridge_Initialize(
                g_AwsBridge,
                AWS_ACCESS_KEY_ID,
                AWS_SECRET_ACCESS_KEY,
                AWS_REGION,
                AWS_MODEL_ID,
                ide->hWndMain,
                WM_AWS_COMPLETION_READY)) {
            g_AwsBridgeInitialized.store(true);
            g_AwsBridgeEnabled.store(true);
            OutputDebugStringA("[GhostTextIntegration] AWS Bedrock bridge initialized\n");
            
            if (ide->hWndOutput) {
                RawrXD_IDE_OutputAppend(ide, L"[GhostText] AWS Bedrock remote backend ready\r\n");
            }
        } else {
            OutputDebugStringA("[GhostTextIntegration] AWS Bedrock bridge init failed (continuing with local only)\n");
            delete g_AwsBridge;
            g_AwsBridge = nullptr;
        }
    }

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

    // Shutdown AWS Bedrock bridge
    if (g_AwsBridgeInitialized.load() && g_AwsBridge) {
        SovereignAwsBridge_Shutdown(g_AwsBridge);
        delete g_AwsBridge;
        g_AwsBridge = nullptr;
        g_AwsBridgeInitialized.store(false);
        g_AwsBridgeEnabled.store(false);
        OutputDebugStringA("[GhostTextIntegration] AWS Bedrock bridge shut down\n");
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

        case WM_AWS_COMPLETION_READY:
            // Handle AWS Bedrock completion
            if (g_AwsBridge && g_AwsBridgeInitialized.load()) {
                AwsBridgeCompletion* awsResult = SovereignAwsBridge_GetCompletion(g_AwsBridge);
                if (awsResult && awsResult->success) {
                    // Convert to GhostResult and pass to engine
                    GhostResult* ghostResult = new GhostResult();
                    if (ghostResult) {
                        // Convert UTF-8 to wide for the engine
                        int wideLen = MultiByteToWideChar(CP_UTF8, 0, awsResult->text, -1, nullptr, 0);
                        if (wideLen > 0) {
                            ghostResult->text.resize(wideLen - 1);
                            MultiByteToWideChar(CP_UTF8, 0, awsResult->text, -1,
                                               &ghostResult->text[0], wideLen);
                        }
                        ghostResult->line = 0;  // Will be set by engine
                        ghostResult->col = 0;
                        ghostResult->confidence = awsResult->confidence;
                        
                        // Post to engine
                        PostMessage(ide->hWndMain, WM_GHOST_SUGGESTION, 0, (LPARAM)ghostResult);
                        
                        // Telemetry
                        STEL_GhostTextReceived(awsResult->text ? strlen(awsResult->text) : 0);
                    }
                    SovereignAwsBridge_FreeCompletion(awsResult);
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
 * Routes to AWS Bedrock bridge when enabled, otherwise uses local engine
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

    // Route to AWS Bedrock bridge if enabled
    if (g_AwsBridgeEnabled.load() && g_AwsBridge && g_AwsBridgeInitialized.load()) {
        uint32_t version = (uint32_t)InterlockedIncrement(&ide->editorVersion);
        
        // Build context from editor content
        char context[8192];
        int contextLen = snprintf(context, sizeof(context),
            "Line %d, Col %d\n```\n%s\n```\nComplete the code at the cursor position.",
            cursorLine, cursorCol, buffer);
        
        if (contextLen > 0) {
            SovereignAwsBridge_RequestCompletion(
                g_AwsBridge,
                version,
                context,
                (size_t)contextLen);
            
            OutputDebugStringA("[GhostTextIntegration] Request sent to AWS Bedrock\n");
        }
        return;
    }

    // Fall back to local engine
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
