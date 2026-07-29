/*===========================================================================
 * LSPDiagnosticsDisplay.hpp
 * 
 * Bridges LSP diagnostics to Scintilla editor indicators.
 * Displays red/yellow squiggles under code errors and warnings.
 * 
 * Integration: Called from IDE when LSP publishes diagnostics
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <vector>
#include <string>
#include <memory>
#include "../agentic/lsp/LSPClient.hpp"

// Forward declaration - avoid including full Scintilla headers
struct ScintillaEditor;

namespace RawrXD {
namespace IDE {

// ============================================================================
// Diagnostic Display Configuration
// ============================================================================
struct DiagnosticsDisplayConfig {
    // Indicator numbers (must match ScintillaEditor setup)
    static constexpr int INDICATOR_ERROR = 0;
    static constexpr int INDICATOR_WARNING = 1;
    static constexpr int INDICATOR_INFO = 2;
    static constexpr int INDICATOR_HINT = 3;
    
    // Colors
    COLORREF colorError = RGB(255, 65, 54);    // Red
    COLORREF colorWarning = RGB(255, 165, 0); // Orange
    COLOReref colorInfo = RGB(0, 150, 200);    // Blue
    COLORREF colorHint = RGB(150, 150, 150);   // Gray
    
    // Behavior
    bool showTooltips = true;
    bool underlineText = true;
    int tooltipDelayMs = 500;
};

// ============================================================================
// Displayed Diagnostic
// ============================================================================
struct DisplayedDiagnostic {
    Agentic::LSPDiagnostic lspDiag;
    std::string filePath;
    int scintillaStartPos = 0;
    int scintillaEndPos = 0;
    bool visible = false;
};

// ============================================================================
// LSP Diagnostics Display Manager
// ============================================================================
class LSPDiagnosticsDisplay {
public:
    LSPDiagnosticsDisplay();
    ~LSPDiagnosticsDisplay();
    
    // Initialize with editor handle
    bool Initialize(HWND hEditor);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Core API: Display diagnostics from LSP
    void ClearAllDiagnostics();
    void DisplayDiagnostics(const std::string& filePath, 
                           const std::vector<Agentic::LSPDiagnostic>& diagnostics);
    void RemoveFileDiagnostics(const std::string& filePath);
    
    // Update display for current file
    void UpdateForFile(const std::string& filePath);
    
    // Tooltip handling
    std::string GetDiagnosticAtPosition(int line, int character) const;
    bool HasDiagnosticAtPosition(int line, int character) const;
    
    // Configuration
    void SetConfig(const DiagnosticsDisplayConfig& config) { config_ = config; }
    const DiagnosticsDisplayConfig& GetConfig() const { return config_; }
    
    // Statistics
    size_t GetTotalDiagnosticCount() const;
    size_t GetErrorCount() const;
    size_t GetWarningCount() const;
    
private:
    // Internal helpers
    void SetupScintillaIndicators();
    void ClearIndicatorsInRange(int startPos, int endPos);
    void FillIndicatorRange(int indicator, int startPos, int endPos);
    int LineCharacterToPosition(int line, int character);
    
    // Scintilla wrapper
    LRESULT SendScintilla(UINT msg, WPARAM wParam = 0, LPARAM lParam = 0);
    
private:
    bool initialized_ = false;
    HWND hEditor_ = nullptr;
    DiagnosticsDisplayConfig config_;
    
    // Active diagnostics by file
    std::unordered_map<std::string, std::vector<DisplayedDiagnostic>> fileDiagnostics_;
    mutable std::mutex diagnosticsMutex_;
    
    // Current file being displayed
    std::string currentFilePath_;
};

// ============================================================================
// C-style API for C integration
// ============================================================================
extern "C" {
    typedef void* LSPDiagnosticsDisplayHandle;
    
    LSPDiagnosticsDisplayHandle LSPDiagnosticsDisplay_Create(void);
    void LSPDiagnosticsDisplay_Destroy(LSPDiagnosticsDisplayHandle handle);
    int LSPDiagnosticsDisplay_Initialize(LSPDiagnosticsDisplayHandle handle, HWND hEditor);
    void LSPDiagnosticsDisplay_ClearAll(LSPDiagnosticsDisplayHandle handle);
    void LSPDiagnosticsDisplay_ShowDiagnostics(LSPDiagnosticsDisplayHandle handle,
                                                  const char* filePath,
                                                  const Agentic::LSPDiagnostic* diagnostics,
                                                  size_t count);
    int LSPDiagnosticsDisplay_GetErrorCount(LSPDiagnosticsDisplayHandle handle);
    int LSPDiagnosticsDisplay_GetWarningCount(LSPDiagnosticsDisplayHandle handle);
}

} // namespace IDE
} // namespace RawrXD
