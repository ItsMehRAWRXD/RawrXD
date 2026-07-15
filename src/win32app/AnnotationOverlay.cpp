// AnnotationOverlay.cpp - Native Feel Diagnostic Overlay Implementation
// Phase I: Foundation - Layered window with Scintilla sync
// Phase II: Hit-testing with WM_MOUSEMOVE and tooltips
// Author: RawrXD Engineering
// Date: 2026-06-23

// WindowsX macros for mouse coordinates - MUST be defined before windows.h is included
#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))
#endif

#include "AnnotationOverlay.h"
#include "Win32IDE.h"
#include "IDELogger.h"
#include <string>
#include <commctrl.h>

#pragma comment(lib, "comctl32.lib")

// Scintilla message constants (for editor integration)
#ifndef SCI_GETFIRSTVISIBLELINE
#define SCI_GETFIRSTVISIBLELINE 2152
#define SCI_LINESONSCREEN 2153
#define SCI_GETCURRENTPOS 2008
#define SCI_LINEFROMPOSITION 2166
#define SCI_GETLINE 2153
#define SCI_TEXTWIDTH 2276
#define SCI_TEXTHEIGHT 2481
#define SCI_GETSCROLLPOS 2080
#define SCI_SETSCROLLPOS 2081
#define SCI_GETZOOM 2374
#define SCI_GOTOLINE 2021
#endif

namespace RawrXD {
namespace UI {

// ============================================================================
// CONSTRUCTOR / DESTRUCTOR
// ============================================================================

AnnotationOverlay::AnnotationOverlay(Win32IDE* ide)
    : m_ide(ide)
    , m_hwndEditor(nullptr)
    , m_hwndOverlay(nullptr)
    , m_initialized(false)
    , m_visible(false)
    , m_agentBridgeReady(false)
    , m_squiggleHeight(DEFAULT_SQUIGGLE_HEIGHT)
    , m_opacity(DEFAULT_OPACITY)
    , m_lineHeight(0)
    , m_charWidth(0)
    , m_editorScrollPos(0)
    , m_memDC(nullptr)
    , m_memBitmap(nullptr)
    , m_brushError(nullptr)
    , m_brushWarning(nullptr)
    , m_brushInfo(nullptr)
    , m_brushHint(nullptr)
    , m_hwndTooltip(nullptr)
    , m_isMouseOverAnnotation(false)
    , m_lastHoveredLine(-1)
{
    LOG_INFO("AnnotationOverlay created");
}

AnnotationOverlay::~AnnotationOverlay()
{
    Shutdown();
    LOG_INFO("AnnotationOverlay destroyed");
}

// ============================================================================
// INITIALIZATION
// ============================================================================

bool AnnotationOverlay::Initialize(HWND hwndEditor)
{
    if (m_initialized) {
        LOG_WARNING("AnnotationOverlay already initialized");
        return true;
    }
    
    if (!hwndEditor || !IsWindow(hwndEditor)) {
        LOG_ERROR("AnnotationOverlay: Invalid editor window");
        return false;
    }
    
    m_hwndEditor = hwndEditor;
    
    // Create GDI brushes for different severities
    m_brushError = CreateSolidBrush(RGB(255, 0, 0));      // Red
    m_brushWarning = CreateSolidBrush(RGB(255, 165, 0)); // Orange
    m_brushInfo = CreateSolidBrush(RGB(0, 120, 212));    // Blue
    m_brushHint = CreateSolidBrush(RGB(128, 128, 128)); // Gray
    
    if (!CreateLayeredWindow()) {
        LOG_ERROR("AnnotationOverlay: Failed to create layered window");
        return false;
    }
    
    // Initial metrics calculation
    OnEditorZoomChanged();
    
    m_initialized = true;
    LOG_INFO("AnnotationOverlay initialized successfully");
    
    // Check if AgentBridge is already ready
    OnAgentBridgeReady();
    
    return true;
}

void AnnotationOverlay::Shutdown()
{
    if (!m_initialized) {
        return;
    }
    
    // Hide tooltip before destroying
    HideTooltip();
    
    DestroyLayeredWindow();
    
    // Clean up GDI resources
    if (m_brushError) { DeleteObject(m_brushError); m_brushError = nullptr; }
    if (m_brushWarning) { DeleteObject(m_brushWarning); m_brushWarning = nullptr; }
    if (m_brushInfo) { DeleteObject(m_brushInfo); m_brushInfo = nullptr; }
    if (m_brushHint) { DeleteObject(m_brushHint); m_brushHint = nullptr; }
    
    m_annotations.clear();
    m_initialized = false;
    m_visible = false;
    m_isMouseOverAnnotation = false;
    
    LOG_INFO("AnnotationOverlay shutdown complete");
}

// ============================================================================
// LAYERED WINDOW CREATION
// ============================================================================

bool AnnotationOverlay::CreateLayeredWindow()
{
    // Register window class
    WNDCLASSEXW wc = {};
    wc.cbSize = sizeof(wc);
    wc.lpfnWndProc = WindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = OVERLAY_CLASS_NAME;
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    
    if (!RegisterClassExW(&wc)) {
        if (GetLastError() != ERROR_CLASS_ALREADY_EXISTS) {
            LOG_ERROR("AnnotationOverlay: Failed to register window class");
            return false;
        }
    }
    
    // Get editor rect for initial position
    RECT editorRect;
    GetWindowRect(m_hwndEditor, &editorRect);
    
    // Create layered window
    // WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE
    // - Layered: For per-pixel alpha blending
    // - Transparent: Mouse events pass through to editor
    // - NoActivate: Don't steal focus
    m_hwndOverlay = CreateWindowExW(
        WS_EX_LAYERED | WS_EX_TRANSPARENT | WS_EX_NOACTIVATE,
        OVERLAY_CLASS_NAME,
        L"RawrXD Annotation Overlay",
        WS_POPUP,  // No border, not a child window
        editorRect.left,
        editorRect.top,
        editorRect.right - editorRect.left,
        editorRect.bottom - editorRect.top,
        m_hwndEditor,  // Owner window
        nullptr,
        GetModuleHandle(nullptr),
        this  // Pass this pointer for WM_CREATE
    );
    
    if (!m_hwndOverlay) {
        LOG_ERROR("AnnotationOverlay: Failed to create overlay window");
        return false;
    }
    
    OutputDebugStringA("[RawrXD] AnnotationOverlay: Layered window created successfully\n");
    
    // Set initial opacity
    UpdateLayeredWindow();
    
    OutputDebugStringA("[RawrXD] AnnotationOverlay: Layered window initialized\n");
    
    // Create tooltip window for hit-testing feedback
    m_hwndTooltip = CreateWindowExW(
        WS_EX_TOPMOST | WS_EX_TOOLWINDOW,
        TOOLTIPS_CLASSW,
        nullptr,
        WS_POPUP | TTS_NOPREFIX | TTS_ALWAYSTIP,
        CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT, CW_USEDEFAULT,
        m_hwndOverlay,
        nullptr,
        GetModuleHandle(nullptr),
        nullptr
    );
    
    if (m_hwndTooltip) {
        // Set tooltip to follow mouse
        SendMessage(m_hwndTooltip, TTM_SETMAXTIPWIDTH, 0, 300);
        SendMessage(m_hwndTooltip, TTM_SETDELAYTIME, TTDT_INITIAL, 100);
        SendMessage(m_hwndTooltip, TTM_SETDELAYTIME, TTDT_AUTOPOP, 5000);
    }
    
    LOG_INFO("AnnotationOverlay: Layered window created");
    return true;
}

void AnnotationOverlay::DestroyLayeredWindow()
{
    // Hide and destroy tooltip first
    HideTooltip();
    if (m_hwndTooltip && IsWindow(m_hwndTooltip)) {
        DestroyWindow(m_hwndTooltip);
        m_hwndTooltip = nullptr;
    }
    
    if (m_hwndOverlay && IsWindow(m_hwndOverlay)) {
        DestroyWindow(m_hwndOverlay);
        m_hwndOverlay = nullptr;
    }
}

// ============================================================================
// AGENTBRIDGE AWARENESS
// ============================================================================

void AnnotationOverlay::OnAgentBridgeReady()
{
    if (!m_initialized) {
        return;
    }
    
    // Check if AgentBridge is healthy via FeatureRegistry or direct check
    if (IsAgentBridgeHealthy()) {
        m_agentBridgeReady = true;
        SetVisible(true);
        Invalidate();
        LOG_INFO("AnnotationOverlay: AgentBridge ready, overlay activated");
    } else {
        LOG_WARNING("AnnotationOverlay: AgentBridge not healthy, overlay remains hidden");
    }
}

void AnnotationOverlay::OnAgentBridgeDisconnected()
{
    m_agentBridgeReady = false;
    SetVisible(false);
    LOG_INFO("AnnotationOverlay: AgentBridge disconnected, overlay hidden");
}

bool AnnotationOverlay::IsAgentBridgeHealthy() const
{
    if (!m_ide) {
        return false;
    }
    
    // Check via Win32IDE atomic flag
    return m_ide->m_agentBridgeReady.load();
}

// ============================================================================
// VISIBILITY
// ============================================================================

void AnnotationOverlay::SetVisible(bool visible)
{
    if (!m_initialized || !m_hwndOverlay) {
        return;
    }
    
    m_visible = visible && m_agentBridgeReady;
    
    if (m_visible) {
        UpdateWindowPosition();
        ShowWindow(m_hwndOverlay, SW_SHOWNA);  // Show without activating
        Invalidate();
    } else {
        ShowWindow(m_hwndOverlay, SW_HIDE);
    }
    
    LOG_INFO("AnnotationOverlay visibility: " + std::string(m_visible ? "visible" : "hidden"));
}

void AnnotationOverlay::Invalidate()
{
    if (!m_initialized || !m_visible) {
        return;
    }
    
    // Force redraw
    InvalidateRect(m_hwndOverlay, nullptr, FALSE);
    UpdateWindow(m_hwndOverlay);
}

// ============================================================================
// ANNOTATION MANAGEMENT
// ============================================================================

void AnnotationOverlay::ClearAnnotations()
{
    m_annotations.clear();
    Invalidate();
}

void AnnotationOverlay::AddAnnotation(const AnnotationItem& annotation)
{
    m_annotations.push_back(annotation);
    
    // Calculate screen rect
    auto& newItem = m_annotations.back();
    CalculateAnnotationRect(newItem, newItem.screenRect);
    newItem.isActive = true;
    
    Invalidate();
}

void AnnotationOverlay::RemoveAnnotation(int line, int startColumn)
{
    auto it = std::remove_if(m_annotations.begin(), m_annotations.end(),
        [line, startColumn](const AnnotationItem& item) {
            return item.line == line && item.startColumn == startColumn;
        });
    
    if (it != m_annotations.end()) {
        m_annotations.erase(it, m_annotations.end());
        Invalidate();
    }
}

void AnnotationOverlay::UpdateAnnotation(const AnnotationItem& annotation)
{
    for (auto& item : m_annotations) {
        if (item.line == annotation.line && 
            item.startColumn == annotation.startColumn) {
            item = annotation;
            CalculateAnnotationRect(item, item.screenRect);
            Invalidate();
            return;
        }
    }
    
    // Not found, add as new
    AddAnnotation(annotation);
}

// ============================================================================
// MOCK DIAGNOSTIC INJECTION (Phase II Testing)
// ============================================================================

void AnnotationOverlay::InjectMockDiagnostic(int line, const char* message)
{
    if (!m_initialized) {
        LOG_WARNING("AnnotationOverlay: Cannot inject mock - not initialized");
        return;
    }
    
    AnnotationItem mock;
    mock.line = line;
    mock.startColumn = 0;
    mock.endColumn = 20;  // Arbitrary width for testing
    mock.severity = DiagnosticSeverity::Information;
    mock.message = message;
    mock.code = "MOCK";
    mock.isActive = true;
    
    AddAnnotation(mock);
    
    LOG_INFO("AnnotationOverlay: Mock diagnostic injected at line " + 
             std::to_string(line) + ": " + message);
}

void AnnotationOverlay::InjectMockDiagnostics()
{
    // HARD DIAGNOSTIC: Function entry
    OutputDebugStringA("[AnnotationOverlay] InjectMockDiagnostics() ENTER\n");
    
    if (!m_initialized) {
        LOG_WARNING("AnnotationOverlay: Cannot inject mocks - not initialized");
        OutputDebugStringA("[AnnotationOverlay] ERROR: Not initialized\n");
        return;
    }
    
    // HARD DIAGNOSTIC: Initialization state
    OutputDebugStringA("[AnnotationOverlay] State: initialized=true\n");
    
    // Clear existing annotations first
    ClearAnnotations();
    OutputDebugStringA("[AnnotationOverlay] Cleared existing annotations\n");
    
    // Inject multiple test annotations at different lines
    struct MockData {
        int line;
        DiagnosticSeverity severity;
        const char* code;
        const char* message;
    };
    
    MockData mocks[] = {
        {5,  DiagnosticSeverity::Error,       "E0001", "[Mock] Variable 'foo' is undefined"},
        {12, DiagnosticSeverity::Warning,     "W0023", "[Mock] Unused import detected"},
        {18, DiagnosticSeverity::Information, "I0100", "[Mock] AgentBridge initialized successfully"},
        {25, DiagnosticSeverity::Hint,        "H0001", "[Mock] Consider using const reference"},
        {30, DiagnosticSeverity::Error,       "E0002", "[Mock] Type mismatch in function call"},
    };
    
    const size_t mockCount = sizeof(mocks) / sizeof(mocks[0]);
    
    // HARD DIAGNOSTIC: About to inject
    char injectBuffer[256];
    sprintf_s(injectBuffer, "[AnnotationOverlay] Injecting %zu mock diagnostics...\n", mockCount);
    OutputDebugStringA(injectBuffer);
    
    for (size_t i = 0; i < mockCount; ++i) {
        const auto& data = mocks[i];
        AnnotationItem mock;
        mock.line = data.line;
        mock.startColumn = 10;  // Start at column 10
        mock.endColumn = 30;    // End at column 30
        mock.severity = data.severity;
        mock.message = data.message;
        mock.code = data.code;
        mock.isActive = true;
        
        AddAnnotation(mock);
        
        // HARD DIAGNOSTIC: Each injection
        sprintf_s(injectBuffer, "[AnnotationOverlay] Added diagnostic line %d (%s)\n", 
                 data.line, data.code);
        OutputDebugStringA(injectBuffer);
    }
    
    // Force visibility for testing
    SetVisible(true);
    
    // HARD DIAGNOSTIC: Final count
    sprintf_s(injectBuffer, "[AnnotationOverlay] Total annotations: %zu\n", m_annotations.size());
    OutputDebugStringA(injectBuffer);
    
    LOG_INFO("AnnotationOverlay: " + std::to_string(m_annotations.size()) + 
             " mock diagnostics injected for testing");
    
    // Log instructions for tester
    OutputDebugStringA(
        "\n========================================\n"
        "ANNOTATION OVERLAY TEST MODE ACTIVATED\n"
        "========================================\n"
        "5 mock diagnostics injected at lines: 5, 12, 18, 25, 30\n"
        "\nTest Instructions:\n"
        "1. Hover over squiggles - cursor should change to hand\n"
        "2. Wait for tooltip - should show diagnostic message\n"
        "3. Click squiggle - should navigate to that line\n"
        "4. Scroll editor - squiggles should stay synced\n"
        "========================================\n\n"
    );
}

// ============================================================================
// SCINTILLA SYNC EVENTS
// ============================================================================

void AnnotationOverlay::OnEditorScroll(int scrollPos)
{
    m_editorScrollPos = scrollPos;
    
    // Recalculate all annotation positions
    for (auto& item : m_annotations) {
        CalculateAnnotationRect(item, item.screenRect);
    }
    
    UpdateWindowPosition();
    Invalidate();
}

void AnnotationOverlay::OnEditorResize()
{
    if (!m_hwndEditor || !m_hwndOverlay) {
        return;
    }
    
    // Get CLIENT rect (not window rect) to match actual editor content area
    RECT clientRect;
    GetClientRect(m_hwndEditor, &clientRect);
    
    // Convert client rect to screen coordinates for the overlay
    POINT ptClient = { clientRect.left, clientRect.top };
    ClientToScreen(m_hwndEditor, &ptClient);
    
    int width = clientRect.right - clientRect.left;
    int height = clientRect.bottom - clientRect.top;
    
    // Ensure minimum dimensions to prevent clipping
    width = (std::max)(width, 100);
    height = (std::max)(height, 50);
    
    // Resize overlay to match editor client area exactly
    SetWindowPos(m_hwndOverlay, HWND_TOP,
        ptClient.x, ptClient.y,
        width, height,
        SWP_NOACTIVATE);
    
    // Recalculate annotation positions with new dimensions
    for (auto& item : m_annotations) {
        CalculateAnnotationRect(item, item.screenRect);
    }
    
    // Force immediate repaint
    Invalidate();
    
    // DEBUG: Log resize operation
    char resizeBuf[256];
    sprintf_s(resizeBuf, "[AnnotationOverlay] Resized to %dx%d at (%d,%d)\n",
             width, height, ptClient.x, ptClient.y);
    OutputDebugStringA(resizeBuf);
}

void AnnotationOverlay::OnEditorZoomChanged()
{
    // Update cached metrics
    m_lineHeight = GetLineHeight();
    m_charWidth = GetCharWidth();
    
    // Recalculate all positions
    for (auto& item : m_annotations) {
        CalculateAnnotationRect(item, item.screenRect);
    }
    
    Invalidate();
}

void AnnotationOverlay::OnCursorPositionChanged(int line, int column)
{
    // Could highlight annotations near cursor
    // For now, just invalidate to ensure fresh render
    Invalidate();
}

// ============================================================================
// COORDINATE MAPPING
// ============================================================================

void AnnotationOverlay::MapEditorToScreen(const AnnotationItem& item, RECT& screenRect)
{
    CalculateAnnotationRect(item, screenRect);
}

bool AnnotationOverlay::ScreenToEditor(POINT screenPt, int& line, int& column)
{
    if (!m_hwndEditor) {
        return false;
    }
    
    // Convert screen point to client coordinates
    POINT clientPt = screenPt;
    ScreenToClient(m_hwndEditor, &clientPt);
    
    // Calculate line from Y position
    line = clientPt.y / m_lineHeight + m_editorScrollPos;
    
    // Calculate column from X position
    column = clientPt.x / m_charWidth;
    
    return true;
}

void AnnotationOverlay::CalculateAnnotationRect(const AnnotationItem& item, RECT& rect)
{
    if (!m_hwndEditor) {
        SetRectEmpty(&rect);
        return;
    }
    
    // Get editor client rect
    RECT editorRect;
    GetClientRect(m_hwndEditor, &editorRect);
    
    // Calculate Y position (line-based)
    int visibleLine = item.line - m_editorScrollPos;
    int y = visibleLine * m_lineHeight;
    
    // Check if line is visible
    if (visibleLine < 0 || y > editorRect.bottom - editorRect.top) {
        SetRectEmpty(&rect);
        return;
    }
    
    // Calculate X positions
    int xStart = item.startColumn * m_charWidth;
    int xEnd = item.endColumn * m_charWidth;
    
    // Build rect for squiggle area (below text)
    rect.left = xStart;
    rect.top = y + m_lineHeight - m_squiggleHeight - 2;
    rect.right = xEnd;
    rect.bottom = y + m_lineHeight - 2;
    
    // Convert to screen coordinates
    MapWindowPoints(m_hwndEditor, nullptr, (LPPOINT)&rect, 2);
}

// ============================================================================
// RENDERING (Phase III Preview)
// ============================================================================

void AnnotationOverlay::Render()
{
    OutputDebugStringA("[RawrXD] AnnotationOverlay: Render() called\n");
    
    // PAINT DIAGNOSTIC: Log annotation count at render time
    char paintBuffer[256];
    sprintf_s(paintBuffer, "[AnnotationOverlay] Paint annotations=%zu visible=%d\n", 
             m_annotations.size(), m_visible ? 1 : 0);
    OutputDebugStringA(paintBuffer);
    fprintf(stderr, "%s", paintBuffer);
    
    // FILE-BASED PAINT DIAGNOSTIC
    FILE* paintFile = nullptr;
    errno_t err = fopen_s(&paintFile, "annotation_overlay_diag.log", "a");
    if (err == 0 && paintFile) {
        fprintf(paintFile, "[AnnotationOverlay] Paint annotations=%zu visible=%d\n", 
                m_annotations.size(), m_visible ? 1 : 0);
        fclose(paintFile);
    }
    
    if (!m_hwndOverlay || !m_visible) {
        return;
    }
    
    // Get overlay DC
    HDC hdcScreen = GetDC(nullptr);
    HDC hdcOverlay = GetDC(m_hwndOverlay);
    
    if (!hdcScreen || !hdcOverlay) {
        return;
    }
    
    // Get overlay size
    RECT overlayRect;
    GetClientRect(m_hwndOverlay, &overlayRect);
    int width = overlayRect.right - overlayRect.left;
    int height = overlayRect.bottom - overlayRect.top;
    
    // Create memory DC for double-buffering
    HDC hdcMem = CreateCompatibleDC(hdcScreen);
    HBITMAP hbmMem = CreateCompatibleBitmap(hdcScreen, width, height);
    HBITMAP hbmOld = (HBITMAP)SelectObject(hdcMem, hbmMem);
    
    // Clear to transparent
    RECT clearRect = {0, 0, width, height};
    FillRect(hdcMem, &clearRect, (HBRUSH)GetStockObject(NULL_BRUSH));
    
    // Render each annotation
    for (const auto& item : m_annotations) {
        if (!item.isActive || IsRectEmpty(&item.screenRect)) {
            continue;
        }
        
        // Convert screen rect to overlay client rect
        RECT localRect = item.screenRect;
        ScreenToClient(m_hwndOverlay, (LPPOINT)&localRect);
        ScreenToClient(m_hwndOverlay, ((LPPOINT)&localRect) + 1);
        
        // Render squiggle
        RenderSquiggle(hdcMem, localRect, item.severity);
    }
    
    // Update layered window using Windows API
    POINT ptSrc = {0, 0};
    POINT ptDst = {overlayRect.left, overlayRect.top};
    SIZE size = {width, height};
    BLENDFUNCTION blend = {AC_SRC_OVER, 0, m_opacity, AC_SRC_ALPHA};
    
    ::UpdateLayeredWindow(m_hwndOverlay, hdcScreen, &ptDst, &size, 
                      hdcMem, &ptSrc, 0, &blend, ULW_ALPHA);
    
    // Cleanup
    SelectObject(hdcMem, hbmOld);
    DeleteObject(hbmMem);
    DeleteDC(hdcMem);
    
    ReleaseDC(nullptr, hdcScreen);
    ReleaseDC(m_hwndOverlay, hdcOverlay);
}

void AnnotationOverlay::RenderSquiggle(HDC hdc, const RECT& rect, DiagnosticSeverity severity)
{
    // Severity colors matching VS Code diagnostic theme
    COLORREF color;
    switch (severity) {
        case DiagnosticSeverity::Error:       color = RGB(255, 65, 54);   break;  // Red
        case DiagnosticSeverity::Warning:     color = RGB(255, 165, 0);   break;  // Orange
        case DiagnosticSeverity::Information: color = RGB(0, 150, 255);   break;  // Blue
        case DiagnosticSeverity::Hint:         color = RGB(128, 128, 128); break;  // Gray
        default:                               color = RGB(255, 65, 54);     break;  // Default red
    }
    
    // Draw squiggle line with wavy pattern (VS Code style)
    int baselineY = rect.bottom - 2;  // 2px from bottom
    int x = rect.left;
    int width = rect.right - rect.left;
    
    // Wavy underline pattern: ~ ~ ~ ~
    // Amplitude: 2px, Period: 6px (3px up, 3px down)
    const int amplitude = 2;
    const int period = 6;
    const int halfPeriod = period / 2;
    
    // Create pen with severity color
    HPEN pen = CreatePen(PS_SOLID, 2, color);  // 2px thickness
    HPEN oldPen = (HPEN)SelectObject(hdc, pen);
    
    // Build wavy path
    POINT points[512];  // Generous buffer for wavy line
    int pointCount = 0;
    
    while (x < rect.right && pointCount < 512) {
        int phase = (x - rect.left) % period;
        int yOffset;
        
        if (phase < halfPeriod) {
            // Rising phase: 0 -> +amplitude
            yOffset = -(phase * amplitude / halfPeriod);
        } else {
            // Falling phase: +amplitude -> 0
            yOffset = -((period - phase) * amplitude / halfPeriod);
        }
        
        points[pointCount].x = x;
        points[pointCount].y = baselineY + yOffset;
        pointCount++;
        x++;
    }
    
    // Draw the wavy line
    if (pointCount > 1) {
        Polyline(hdc, points, pointCount);
    }
    
    // Add subtle glow effect for errors (draw again with lighter color, offset)
    if (severity == DiagnosticSeverity::Error && pointCount > 1) {
        COLORREF glowColor = RGB(255, 100, 100);  // Lighter red
        HPEN glowPen = CreatePen(PS_SOLID, 1, glowColor);
        HPEN oldGlowPen = (HPEN)SelectObject(hdc, glowPen);
        
        // Offset points slightly for glow
        for (int i = 0; i < pointCount; i++) {
            points[i].y -= 1;
        }
        Polyline(hdc, points, pointCount);
        
        SelectObject(hdc, oldGlowPen);
        DeleteObject(glowPen);
    }
    
    SelectObject(hdc, oldPen);
    DeleteObject(pen);
    
    LOG_INFO("AnnotationOverlay: Rendered squiggle at (" + 
             std::to_string(rect.left) + "," + std::to_string(rect.top) + 
             ") size " + std::to_string(width) + "x" + 
             std::to_string(rect.bottom - rect.top));
}

void AnnotationOverlay::RenderTooltip(HDC hdc, const AnnotationItem& item)
{
    // Phase III: Implement tooltip rendering
    // For now, placeholder
}

// ============================================================================
// LAYERED WINDOW UPDATE
// ============================================================================

void AnnotationOverlay::UpdateLayeredWindow()
{
    if (!m_hwndOverlay) {
        return;
    }
    
    // Force redraw with new opacity
    Invalidate();
}

void AnnotationOverlay::UpdateWindowPosition()
{
    if (!m_hwndEditor || !m_hwndOverlay) {
        return;
    }
    
    // Keep overlay positioned over editor
    RECT editorRect;
    GetWindowRect(m_hwndEditor, &editorRect);
    
    SetWindowPos(m_hwndOverlay, nullptr,
        editorRect.left, editorRect.top,
        editorRect.right - editorRect.left,
        editorRect.bottom - editorRect.top,
        SWP_NOZORDER | SWP_NOACTIVATE | SWP_NOREDRAW);
}

// ============================================================================
// METRICS
// ============================================================================

int AnnotationOverlay::GetLineHeight()
{
    // Query Scintilla for line height
    if (m_hwndEditor) {
        // Send SCI_TEXTHEIGHT message
        LRESULT height = SendMessage(m_hwndEditor, SCI_TEXTHEIGHT, 0, 0);
        if (height > 0) {
            return static_cast<int>(height);
        }
    }
    return 20;  // Default fallback
}

int AnnotationOverlay::GetCharWidth()
{
    // Query Scintilla for character width
    if (m_hwndEditor) {
        // Send SCI_TEXTWIDTH for a sample character
        LRESULT width = SendMessage(m_hwndEditor, SCI_TEXTWIDTH, 0, 
                                   reinterpret_cast<LPARAM>(" "));
        if (width > 0) {
            return static_cast<int>(width);
        }
    }
    return 8;  // Default fallback
}

// ============================================================================
// HIT TESTING (Phase II)
// ============================================================================

bool AnnotationOverlay::HitTest(POINT screenPt, AnnotationItem& outAnnotation)
{
    if (!m_visible) {
        return false;
    }
    
    for (const auto& item : m_annotations) {
        if (!item.isActive) {
            continue;
        }
        
        // Check if point is within annotation rect
        // Add some padding for easier hit testing
        RECT hitRect = item.screenRect;
        InflateRect(&hitRect, 5, 5);  // 5px padding
        
        if (PtInRect(&hitRect, screenPt)) {
            outAnnotation = item;
            return true;
        }
    }
    
    return false;
}

void AnnotationOverlay::OnMouseMove(POINT screenPt)
{
    if (!m_initialized || !m_visible) {
        return;
    }
    
    AnnotationItem hitItem;
    bool hit = HitTest(screenPt, hitItem);
    
    if (hit) {
        // Mouse is over an annotation
        if (!m_isMouseOverAnnotation || m_lastHoveredLine != hitItem.line) {
            // New annotation hovered
            m_isMouseOverAnnotation = true;
            m_lastHoveredLine = hitItem.line;
            
            // Change cursor to hand
            SetCursor(LoadCursor(nullptr, IDC_HAND));
            
            // Show tooltip
            ShowTooltip(hitItem);
            
            LOG_INFO("AnnotationOverlay: Hovering annotation on line " + 
                     std::to_string(hitItem.line) + ": " + hitItem.message);
        }
    } else {
        // Mouse left annotation area
        if (m_isMouseOverAnnotation) {
            OnMouseLeave();
        }
    }
}

void AnnotationOverlay::OnMouseLeave()
{
    if (m_isMouseOverAnnotation) {
        m_isMouseOverAnnotation = false;
        m_lastHoveredLine = -1;
        
        // Restore default cursor
        SetCursor(LoadCursor(nullptr, IDC_ARROW));
        
        // Hide tooltip
        HideTooltip();
        
        LOG_INFO("AnnotationOverlay: Mouse left annotation area");
    }
}

// ============================================================================
// TOOLTIP MANAGEMENT
// ============================================================================

void AnnotationOverlay::ShowTooltip(const AnnotationItem& item)
{
    if (!m_hwndTooltip) {
        return;
    }
    
    // Build tooltip text with severity prefix
    std::wstring prefix;
    switch (item.severity) {
        case DiagnosticSeverity::Error: prefix = L"[Error] "; break;
        case DiagnosticSeverity::Warning: prefix = L"[Warning] "; break;
        case DiagnosticSeverity::Information: prefix = L"[Info] "; break;
        case DiagnosticSeverity::Hint: prefix = L"[Hint] "; break;
    }
    
    std::wstring tooltipText = prefix;
    if (!item.code.empty()) {
        tooltipText += std::wstring(item.code.begin(), item.code.end()) + L": ";
    }
    tooltipText += std::wstring(item.message.begin(), item.message.end());
    
    // Truncate if too long
    if (tooltipText.length() > 256) {
        tooltipText = tooltipText.substr(0, 253) + L"...";
    }
    
    // Get cursor position for tooltip placement
    POINT pt;
    GetCursorPos(&pt);
    
    // Setup tooltip info
    TOOLINFOW ti = {};
    ti.cbSize = sizeof(ti);
    ti.uFlags = TTF_TRACK | TTF_ABSOLUTE;
    ti.hwnd = m_hwndOverlay;
    ti.lpszText = const_cast<LPWSTR>(tooltipText.c_str());
    
    // Add or update the tool
    SendMessage(m_hwndTooltip, TTM_ADDTOOLW, 0, reinterpret_cast<LPARAM>(&ti));
    
    // Position tooltip near cursor
    SendMessage(m_hwndTooltip, TTM_TRACKPOSITION, 0, MAKELPARAM(pt.x + 10, pt.y + 20));
    
    // Show tooltip
    SendMessage(m_hwndTooltip, TTM_TRACKACTIVATE, TRUE, reinterpret_cast<LPARAM>(&ti));
    
    LOG_INFO("AnnotationOverlay: Tooltip shown for line " + std::to_string(item.line));
}

void AnnotationOverlay::HideTooltip()
{
    if (!m_hwndTooltip) {
        return;
    }
    
    // Deactivate tooltip
    TOOLINFOW ti = {};
    ti.cbSize = sizeof(ti);
    ti.hwnd = m_hwndOverlay;
    ti.uId = 0;
    
    SendMessage(m_hwndTooltip, TTM_TRACKACTIVATE, FALSE, reinterpret_cast<LPARAM>(&ti));
}

void AnnotationOverlay::UpdateTooltipPosition()
{
    if (!m_isMouseOverAnnotation || !m_hwndTooltip) {
        return;
    }
    
    POINT pt;
    GetCursorPos(&pt);
    
    // Update tooltip position to follow cursor
    SendMessage(m_hwndTooltip, TTM_TRACKPOSITION, 0, MAKELPARAM(pt.x + 10, pt.y + 20));
}

// ============================================================================
// WINDOW PROCEDURE
// ============================================================================

LRESULT CALLBACK AnnotationOverlay::WindowProc(HWND hwnd, UINT uMsg, 
                                                WPARAM wParam, LPARAM lParam)
{
    // Get this pointer from window data on first message
    AnnotationOverlay* pThis = nullptr;
    
    if (uMsg == WM_CREATE) {
        auto* pCreate = reinterpret_cast<LPCREATESTRUCT>(lParam);
        pThis = static_cast<AnnotationOverlay*>(pCreate->lpCreateParams);
        SetWindowLongPtr(hwnd, GWLP_USERDATA, reinterpret_cast<LONG_PTR>(pThis));
    } else {
        pThis = reinterpret_cast<AnnotationOverlay*>(
            GetWindowLongPtr(hwnd, GWLP_USERDATA));
    }
    
    if (pThis) {
        return pThis->HandleMessage(uMsg, wParam, lParam);
    }
    
    return DefWindowProc(hwnd, uMsg, wParam, lParam);
}

LRESULT AnnotationOverlay::HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam)
{
    switch (uMsg) {
        case WM_PAINT: {
            OutputDebugStringA("[RawrXD] AnnotationOverlay: WM_PAINT received\n");
            PAINTSTRUCT ps;
            BeginPaint(m_hwndOverlay, &ps);
            Render();
            EndPaint(m_hwndOverlay, &ps);
            return 0;
        }
        
        case WM_ERASEBKGND:
            // Prevent flicker by not erasing background
            return 1;
            
        case WM_SIZE:
            OutputDebugStringA("[RawrXD] AnnotationOverlay: WM_SIZE received\n");
            // Recalculate positions on size change
            OnEditorResize();
            return 0;
            
        case WM_DESTROY:
            OutputDebugStringA("[RawrXD] AnnotationOverlay: WM_DESTROY received\n");
            m_hwndOverlay = nullptr;
            return 0;
            
        case WM_MOUSEMOVE: {
            // Handle mouse movement for hit-testing
            POINT pt;
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
            
            // Convert from client to screen coordinates
            ClientToScreen(m_hwndOverlay, &pt);
            
            // Process hit-testing
            OnMouseMove(pt);
            
            // Track mouse leave events
            TRACKMOUSEEVENT tme = {};
            tme.cbSize = sizeof(tme);
            tme.dwFlags = TME_LEAVE;
            tme.hwndTrack = m_hwndOverlay;
            TrackMouseEvent(&tme);
            
            return 0;
        }
        
        case WM_MOUSELEAVE:
            // Mouse left the overlay window
            OnMouseLeave();
            return 0;
            
        case WM_LBUTTONDOWN: {
            // Handle click on annotation
            POINT pt;
            pt.x = GET_X_LPARAM(lParam);
            pt.y = GET_Y_LPARAM(lParam);
            ClientToScreen(m_hwndOverlay, &pt);
            
            AnnotationItem hitItem;
            if (HitTest(pt, hitItem)) {
                LOG_INFO("AnnotationOverlay: Clicked annotation on line " + 
                         std::to_string(hitItem.line));
                
                // Navigate to the annotation line in editor
                if (m_hwndEditor) {
                    // Send SCI_GOTOLINE message to Scintilla
                    SendMessage(m_hwndEditor, SCI_GOTOLINE, hitItem.line, 0);
                    
                    // Set focus to editor
                    SetFocus(m_hwndEditor);
                }
            }
            return 0;
        }
            
        default:
            return DefWindowProc(m_hwndOverlay, uMsg, wParam, lParam);
    }
}

} // namespace UI
} // namespace RawrXD
