// AnnotationOverlay.h - Native Feel Diagnostic Overlay
// Phase I: Foundation - Layered window with Scintilla sync
// Author: RawrXD Engineering
// Date: 2026-06-23

#pragma once

// WindowsX macros for mouse coordinates - define before windows.h
#ifndef GET_X_LPARAM
#define GET_X_LPARAM(lp) ((int)(short)LOWORD(lp))
#define GET_Y_LPARAM(lp) ((int)(short)HIWORD(lp))
#endif

#include <windows.h>
#include <memory>
#include <vector>
#include <functional>
#include <string>

// Forward declarations
class Win32IDE;

namespace RawrXD {
namespace UI {

// Diagnostic severity levels matching VS Code
enum class DiagnosticSeverity {
    Error = 0,
    Warning = 1,
    Information = 2,
    Hint = 3
};

// Annotation item representing a diagnostic marker
struct AnnotationItem {
    int line;           // 0-based line number
    int startColumn;    // 0-based start column
    int endColumn;      // 0-based end column
    DiagnosticSeverity severity;
    std::string message;
    std::string code;   // Error code (e.g., "E1234")
    bool isActive;      // Is this annotation currently visible
    
    // Cached screen coordinates (updated on scroll/resize)
    RECT screenRect;    // Calculated screen coordinates
    
    AnnotationItem() : line(0), startColumn(0), endColumn(0), 
                       severity(DiagnosticSeverity::Error), isActive(false) {}
};

// Layered window overlay for diagnostic annotations
// Provides "Native Feel" by rendering directly over the editor with GDI
class AnnotationOverlay {
public:
    AnnotationOverlay(Win32IDE* ide);
    ~AnnotationOverlay();
    
    // Lifecycle
    bool Initialize(HWND hwndEditor);
    void Shutdown();
    bool IsInitialized() const { return m_initialized; }
    
    // AgentBridge awareness
    void OnAgentBridgeReady();
    void OnAgentBridgeDisconnected();
    bool IsAgentBridgeHealthy() const;
    
    // Visibility
    void SetVisible(bool visible);
    bool IsVisible() const { return m_visible; }
    void Invalidate();  // Force redraw
    
    // Annotation management
    void ClearAnnotations();
    void AddAnnotation(const AnnotationItem& annotation);
    void RemoveAnnotation(int line, int startColumn);
    void UpdateAnnotation(const AnnotationItem& annotation);
    
    // Mock injection for testing (Phase II verification)
    void InjectMockDiagnostic(int line = 5, const char* message = "[Mock] AgentBridge Initialization Successful");
    void InjectMockDiagnostics();  // Inject multiple test annotations
    
    // Coordinate mapping (Editor -> Screen)
    void MapEditorToScreen(const AnnotationItem& item, RECT& screenRect);
    bool ScreenToEditor(POINT screenPt, int& line, int& column);
    
    // Scintilla sync events
    void OnEditorScroll(int scrollPos);
    void OnEditorResize();
    void OnEditorZoomChanged();
    void OnCursorPositionChanged(int line, int column);
    
    // Hit testing for Phase II
    bool HitTest(POINT screenPt, AnnotationItem& outAnnotation);
    void OnMouseMove(POINT screenPt);
    void OnMouseLeave();
    
    // Tooltip management
    void ShowTooltip(const AnnotationItem& item);
    void HideTooltip();
    void UpdateTooltipPosition();
    
    // Render configuration
    void SetSquiggleHeight(int height) { m_squiggleHeight = height; }
    void SetOpacity(BYTE opacity) { m_opacity = opacity; UpdateLayeredWindow(); }
    
private:
    // Window creation
    bool CreateLayeredWindow();
    void DestroyLayeredWindow();
    
    // Rendering (Phase III)
    void Render();
    void RenderSquiggle(HDC hdc, const RECT& rect, DiagnosticSeverity severity);
    void RenderTooltip(HDC hdc, const AnnotationItem& item);
    
    // Layered window update
    void UpdateLayeredWindow();
    void UpdateWindowPosition();
    
    // Coordinate calculations
    void CalculateAnnotationRect(const AnnotationItem& item, RECT& rect);
    int GetLineHeight();
    int GetCharWidth();
    
    // Static window procedure
    static LRESULT CALLBACK WindowProc(HWND hwnd, UINT uMsg, WPARAM wParam, LPARAM lParam);
    LRESULT HandleMessage(UINT uMsg, WPARAM wParam, LPARAM lParam);
    
private:
    // Parent IDE reference
    Win32IDE* m_ide;
    
    // Window handles
    HWND m_hwndEditor;      // Scintilla editor window
    HWND m_hwndOverlay;     // Our layered overlay window
    
    // State
    bool m_initialized;
    bool m_visible;
    bool m_agentBridgeReady;
    
    // Render configuration
    int m_squiggleHeight;
    BYTE m_opacity;
    
    // Annotations
    std::vector<AnnotationItem> m_annotations;
    
    // Cached editor metrics
    int m_lineHeight;
    int m_charWidth;
    int m_editorScrollPos;
    
    // GDI resources
    HDC m_memDC;
    HBITMAP m_memBitmap;
    HBRUSH m_brushError;
    HBRUSH m_brushWarning;
    HBRUSH m_brushInfo;
    HBRUSH m_brushHint;
    
    // Tooltip window handle
    HWND m_hwndTooltip;
    
    // Hit testing state
    bool m_isMouseOverAnnotation;
    int m_lastHoveredLine;
    
    // Constants
    static constexpr int DEFAULT_SQUIGGLE_HEIGHT = 3;
    static constexpr BYTE DEFAULT_OPACITY = 255;
    static constexpr const wchar_t* OVERLAY_CLASS_NAME = L"RawrXD_AnnotationOverlay";
};

} // namespace UI
} // namespace RawrXD

// Convenience typedef for IDE integration
using AnnotationOverlay = RawrXD::UI::AnnotationOverlay;
