// ProblemsPanel.h
// Phase 24: The Cockpit - Diagnostics/Problems Panel
// ============================================================================
// Displays LSP diagnostics (errors, warnings, info) with filtering
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>

namespace RawrXD {
namespace LSP { struct Diagnostic; enum class DiagnosticSeverity : int; }

namespace UI {

// ============================================================================
// Problem Item Display
// ============================================================================
struct ProblemDisplayItem {
    std::wstring filePath;
    uint32_t lineNumber;
    uint32_t column;
    std::wstring message;
    std::wstring code;          // Error code if available
    LSP::DiagnosticSeverity severity;
    bool isSelected = false;
};

// ============================================================================
// Problems Panel Configuration
// ============================================================================
struct ProblemsPanelConfig {
    int rowHeight = 22;
    int iconWidth = 20;
    COLORREF backgroundColor = RGB(255, 255, 255);
    COLORREF errorColor = RGB(255, 0, 0);
    COLORREF warningColor = RGB(255, 165, 0);
    COLORREF infoColor = RGB(0, 120, 215);
    COLORREF hintColor = RGB(100, 100, 100);
    COLORREF selectedBackground = RGB(0, 120, 215);
    COLORREF selectedText = RGB(255, 255, 255);
    wchar_t fontName[32] = L"Segoe UI";
    int fontSize = 9;
    bool showErrors = true;
    bool showWarnings = true;
    bool showInfo = true;
    bool showHints = true;
};

// ============================================================================
// Problems Panel
// ============================================================================
class ProblemsPanel {
public:
    using ProblemSelectedCallback = std::function<void(const std::wstring& filePath, uint32_t line, uint32_t column)>;

    ProblemsPanel();
    ~ProblemsPanel();

    // Initialization
    bool Initialize(HWND parentWindow);
    void Shutdown();

    // Configuration
    void SetConfig(const ProblemsPanelConfig& config);
    void SetFilter(bool errors, bool warnings, bool info, bool hints);

    // Data updates
    void AddDiagnostic(const std::wstring& filePath, const LSP::Diagnostic& diagnostic);
    void ClearDiagnostics(const std::wstring& filePath);
    void ClearAllDiagnostics();
    void RefreshDisplay();

    // Rendering
    void Render(HDC hdc, const RECT& panelRect);
    void Invalidate();

    // Event handling
    void SetProblemSelectedCallback(ProblemSelectedCallback callback);
    bool OnMouseClick(int x, int y);
    bool OnMouseDoubleClick(int x, int y);
    bool OnKeyDown(WPARAM keyCode);

    // Statistics
    size_t GetErrorCount() const;
    size_t GetWarningCount() const;
    size_t GetInfoCount() const;
    size_t GetTotalCount() const;

    // Sizing
    SIZE GetPreferredSize() const;
    void SetSize(int width, int height);

private:
    class Impl;
    std::unique_ptr<Impl> pImpl_;
};

} // namespace UI
} // namespace RawrXD
