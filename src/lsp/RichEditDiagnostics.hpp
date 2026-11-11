/*===========================================================================
 * RichEditDiagnostics.hpp
 * 
 * LSP Diagnostics display for RichEdit control.
 * Uses character formatting (CFM_UNDERLINE, CFM_BACKCOLOR) to highlight errors.
 * 
 * Note: RichEdit doesn't support custom indicators like Scintilla.
 * We use underline styles and background colors instead.
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <richedit.h>
#include <vector>
#include <string>
#include <mutex>
#include "../agentic/lsp/LSPClient.hpp"

namespace RawrXD {
namespace IDE {

// ============================================================================
// RichEdit Diagnostic Display
// ============================================================================
struct RichEditDiagnostic {
    Agentic::LSPDiagnostic lspDiag;
    std::string filePath;
    CHARRANGE charRange;        // RichEdit character range
    BOOL visible = FALSE;
};

class RichEditDiagnosticsDisplay {
public:
    RichEditDiagnosticsDisplay();
    ~RichEditDiagnosticsDisplay();
    
    // Initialize with RichEdit window handle
    bool Initialize(HWND hRichEdit);
    void Shutdown();
    bool IsInitialized() const { return initialized_; }
    
    // Core API
    void ClearAllDiagnostics();
    void DisplayDiagnostics(const std::string& filePath,
                           const std::vector<Agentic::LSPDiagnostic>& diagnostics);
    void RemoveFileDiagnostics(const std::string& filePath);
    void UpdateForFile(const std::string& filePath);
    
    // Tooltip / hover info
    std::string GetDiagnosticAtPosition(int line, int character) const;
    bool HasDiagnosticAtPosition(int line, int character) const;
    
    // Statistics
    size_t GetErrorCount() const;
    size_t GetWarningCount() const;
    size_t GetTotalCount() const;
    
    // Status bar update
    void UpdateStatusBar();
    
private:
    // RichEdit helpers
    int LineCharacterToCharPos(int line, int character);
    void ApplyDiagnosticFormatting(const RichEditDiagnostic& diag);
    void ClearFormattingInRange(const CHARRANGE& range);
    int GetLineCount() const;
    int GetLineStart(int line) const;
    
    // Formatting helpers
    void SetErrorFormat(const CHARRANGE& range);
    void SetWarningFormat(const CHARRANGE& range);
    void SetInfoFormat(const CHARRANGE& range);
    void SetHintFormat(const CHARRANGE& range);
    void ClearFormat(const CHARRANGE& range);
    
private:
    bool initialized_ = false;
    HWND hRichEdit_ = nullptr;
    std::string currentFilePath_;
    
    std::unordered_map<std::string, std::vector<RichEditDiagnostic>> fileDiagnostics_;
    mutable std::mutex diagnosticsMutex_;
};

// ============================================================================
// C API for IDE integration
// ============================================================================
extern "C" {
    typedef void* RichEditDiagnosticsHandle;
    
    RichEditDiagnosticsHandle RichEditDiagnostics_Create(void);
    void RichEditDiagnostics_Destroy(RichEditDiagnosticsHandle handle);
    int RichEditDiagnostics_Initialize(RichEditDiagnosticsHandle handle, HWND hRichEdit);
    void RichEditDiagnostics_ClearAll(RichEditDiagnosticsHandle handle);
    void RichEditDiagnostics_ShowDiagnostics(RichEditDiagnosticsHandle handle,
                                               const char* filePath,
                                               const Agentic::LSPDiagnostic* diagnostics,
                                               size_t count);
    int RichEditDiagnostics_GetErrorCount(RichEditDiagnosticsHandle handle);
    int RichEditDiagnostics_GetWarningCount(RichEditDiagnosticsHandle handle);
}

} // namespace IDE
} // namespace RawrXD
