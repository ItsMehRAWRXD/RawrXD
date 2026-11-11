/*===========================================================================
 * LSPDiagnosticsDisplay.cpp
 * 
 * Implementation of LSP diagnostics display for Scintilla editor.
 * Maps LSP diagnostics to Scintilla squiggle indicators.
 *===========================================================================*/

#include "LSPDiagnosticsDisplay.hpp"
#include <windows.h>
#include <algorithm>
#include <string>

// Scintilla messages (from Scintilla.h)
#define SCI_INDICSETSTYLE 2080
#define SCI_INDICSETFORE 2081
#define SCI_INDICSETUNDER 2513
#define SCI_INDICSETALPHA 2523
#define SCI_INDICSETOUTLINEALPHA 2558
#define SCI_SETINDICATORCURRENT 2500
#define SCI_SETINDICATORVALUE 2501
#define SCI_INDICFILLRANGE 2086
#define SCI_INDICCLEARRANGE 2085
#define SCI_POSITIONFROMLINE 2166
#define SCI_LINELENGTH 2350
#define SCI_GETLENGTH 2006

// Indicator styles
#define INDIC_SQUIGGLE 13
#define INDIC_STRAIGHTBOX 14

namespace RawrXD {
namespace IDE {

// ============================================================================
// Construction / Destruction
// ============================================================================
LSPDiagnosticsDisplay::LSPDiagnosticsDisplay() = default;

LSPDiagnosticsDisplay::~LSPDiagnosticsDisplay() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool LSPDiagnosticsDisplay::Initialize(HWND hEditor) {
    if (!hEditor || !IsWindow(hEditor)) {
        return false;
    }
    
    hEditor_ = hEditor;
    SetupScintillaIndicators();
    initialized_ = true;
    
    return true;
}

void LSPDiagnosticsDisplay::Shutdown() {
    if (!initialized_) return;
    
    ClearAllDiagnostics();
    hEditor_ = nullptr;
    initialized_ = false;
}

// ============================================================================
// Scintilla Indicator Setup
// ============================================================================
void LSPDiagnosticsDisplay::SetupScintillaIndicators() {
    if (!hEditor_) return;
    
    // Error indicator (0) - Red squiggles
    SendScintilla(SCI_INDICSETSTYLE, config_.INDICATOR_ERROR, INDIC_SQUIGGLE);
    SendScintilla(SCI_INDICSETFORE, config_.INDICATOR_ERROR, config_.colorError);
    SendScintilla(SCI_INDICSETUNDER, config_.INDICATOR_ERROR, 1);
    
    // Warning indicator (1) - Orange squiggles
    SendScintilla(SCI_INDICSETSTYLE, config_.INDICATOR_WARNING, INDIC_SQUIGGLE);
    SendScintilla(SCI_INDICSETFORE, config_.INDICATOR_WARNING, config_.colorWarning);
    SendScintilla(SCI_INDICSETUNDER, config_.INDICATOR_WARNING, 1);
    
    // Info indicator (2) - Blue straight box
    SendScintilla(SCI_INDICSETSTYLE, config_.INDICATOR_INFO, INDIC_STRAIGHTBOX);
    SendScintilla(SCI_INDICSETFORE, config_.INDICATOR_INFO, config_.colorInfo);
    SendScintilla(SCI_INDICSETUNDER, config_.INDICATOR_INFO, 1);
    
    // Hint indicator (3) - Gray straight box
    SendScintilla(SCI_INDICSETSTYLE, config_.INDICATOR_HINT, INDIC_STRAIGHTBOX);
    SendScintilla(SCI_INDICSETFORE, config_.INDICATOR_HINT, config_.colorHint);
    SendScintilla(SCI_INDICSETUNDER, config_.INDICATOR_HINT, 1);
}

// ============================================================================
// Core Diagnostic Display
// ============================================================================
void LSPDiagnosticsDisplay::ClearAllDiagnostics() {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    
    if (!hEditor_) return;
    
    // Clear all indicators
    int docLength = (int)SendScintilla(SCI_GETLENGTH);
    for (int i = 0; i <= 3; ++i) {
        SendScintilla(SCI_SETINDICATORCURRENT, i);
        SendScintilla(SCI_INDICCLEARRANGE, 0, docLength);
    }
    
    fileDiagnostics_.clear();
}

void LSPDiagnosticsDisplay::DisplayDiagnostics(
    const std::string& filePath,
    const std::vector<Agentic::LSPDiagnostic>& diagnostics) {
    
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    
    if (!hEditor_ || !initialized_) return;
    
    // Remove existing diagnostics for this file
    RemoveFileDiagnosticsInternal(filePath);
    
    // Convert and store new diagnostics
    std::vector<DisplayedDiagnostic> displayed;
    displayed.reserve(diagnostics.size());
    
    for (const auto& diag : diagnostics) {
        DisplayedDiagnostic dd;
        dd.lspDiag = diag;
        dd.filePath = filePath;
        dd.visible = (filePath == currentFilePath_);
        
        // Convert LSP line/character to Scintilla positions
        dd.scintillaStartPos = LineCharacterToPosition(diag.range.start.line, 
                                                         diag.range.start.character);
        dd.scintillaEndPos = LineCharacterToPosition(diag.range.end.line, 
                                                      diag.range.end.character);
        
        // Ensure valid range
        if (dd.scintillaStartPos < 0) dd.scintillaStartPos = 0;
        if (dd.scintillaEndPos < dd.scintillaStartPos) dd.scintillaEndPos = dd.scintillaStartPos;
        
        displayed.push_back(dd);
        
        // Apply indicator if this is the current file
        if (dd.visible) {
            int indicator = config_.INDICATOR_ERROR;
            switch (diag.severity) {
                case 2: indicator = config_.INDICATOR_WARNING; break;
                case 3: indicator = config_.INDICATOR_INFO; break;
                case 4: indicator = config_.INDICATOR_HINT; break;
                default: indicator = config_.INDICATOR_ERROR; break;
            }
            
            FillIndicatorRange(indicator, dd.scintillaStartPos, dd.scintillaEndPos);
        }
    }
    
    fileDiagnostics_[filePath] = std::move(displayed);
}

void LSPDiagnosticsDisplay::RemoveFileDiagnostics(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    RemoveFileDiagnosticsInternal(filePath);
}

void LSPDiagnosticsDisplay::RemoveFileDiagnosticsInternal(const std::string& filePath) {
    auto it = fileDiagnostics_.find(filePath);
    if (it == fileDiagnostics_.end()) return;
    
    // Clear indicators if this was the current file
    if (filePath == currentFilePath_ && hEditor_) {
        for (const auto& dd : it->second) {
            ClearIndicatorsInRange(dd.scintillaStartPos, dd.scintillaEndPos);
        }
    }
    
    fileDiagnostics_.erase(it);
}

// ============================================================================
// File Switching
// ============================================================================
void LSPDiagnosticsDisplay::UpdateForFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    
    if (!hEditor_) return;
    
    // Clear current indicators
    int docLength = (int)SendScintilla(SCI_GETLENGTH);
    for (int i = 0; i <= 3; ++i) {
        SendScintilla(SCI_SETINDICATORCURRENT, i);
        SendScintilla(SCI_INDICCLEARRANGE, 0, docLength);
    }
    
    currentFilePath_ = filePath;
    
    // Apply diagnostics for new file
    auto it = fileDiagnostics_.find(filePath);
    if (it == fileDiagnostics_.end()) return;
    
    for (auto& dd : it->second) {
        dd.visible = true;
        
        int indicator = config_.INDICATOR_ERROR;
        switch (dd.lspDiag.severity) {
            case 2: indicator = config_.INDICATOR_WARNING; break;
            case 3: indicator = config_.INDICATOR_INFO; break;
            case 4: indicator = config_.INDICATOR_HINT; break;
        }
        
        FillIndicatorRange(indicator, dd.scintillaStartPos, dd.scintillaEndPos);
    }
}

// ============================================================================
// Tooltip / Hover Information
// ============================================================================
std::string LSPDiagnosticsDisplay::GetDiagnosticAtPosition(int line, int character) const {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    
    auto it = fileDiagnostics_.find(currentFilePath_);
    if (it == fileDiagnostics_.end()) return "";
    
    for (const auto& dd : it->second) {
        if (!dd.visible) continue;
        
        // Check if position is within diagnostic range
        if (line >= dd.lspDiag.range.start.line && 
            line <= dd.lspDiag.range.end.line) {
            
            // For same line, check character range
            if (line == dd.lspDiag.range.start.line && 
                character < dd.lspDiag.range.start.character) {
                continue;
            }
            if (line == dd.lspDiag.range.end.line && 
                character > dd.lspDiag.range.end.character) {
                continue;
            }
            
            // Build tooltip text
            std::string result;
            switch (dd.lspDiag.severity) {
                case 1: result = "[Error] "; break;
                case 2: result = "[Warning] "; break;
                case 3: result = "[Info] "; break;
                case 4: result = "[Hint] "; break;
            }
            result += dd.lspDiag.message;
            if (!dd.lspDiag.code.empty()) {
                result += " (" + dd.lspDiag.code + ")";
            }
            return result;
        }
    }
    
    return "";
}

bool LSPDiagnosticsDisplay::HasDiagnosticAtPosition(int line, int character) const {
    return !GetDiagnosticAtPosition(line, character).empty();
}

// ============================================================================
// Statistics
// ============================================================================
size_t LSPDiagnosticsDisplay::GetTotalDiagnosticCount() const {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    size_t count = 0;
    for (const auto& [path, diags] : fileDiagnostics_) {
        count += diags.size();
    }
    return count;
}

size_t LSPDiagnosticsDisplay::GetErrorCount() const {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    size_t count = 0;
    for (const auto& [path, diags] : fileDiagnostics_) {
        for (const auto& dd : diags) {
            if (dd.lspDiag.severity == 1) ++count;
        }
    }
    return count;
}

size_t LSPDiagnosticsDisplay::GetWarningCount() const {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    size_t count = 0;
    for (const auto& [path, diags] : fileDiagnostics_) {
        for (const auto& dd : diags) {
            if (dd.lspDiag.severity == 2) ++count;
        }
    }
    return count;
}

// ============================================================================
// Scintilla Helpers
// ============================================================================
LRESULT LSPDiagnosticsDisplay::SendScintilla(UINT msg, WPARAM wParam, LPARAM lParam) {
    if (!hEditor_) return 0;
    return SendMessage(hEditor_, msg, wParam, lParam);
}

int LSPDiagnosticsDisplay::LineCharacterToPosition(int line, int character) {
    // Get position at start of line
    int lineStart = (int)SendScintilla(SCI_POSITIONFROMLINE, line);
    if (lineStart < 0) return 0;
    
    // Get line length
    int lineLen = (int)SendScintilla(SCI_LINELENGTH, line);
    
    // Clamp character to line length
    if (character > lineLen) character = lineLen;
    
    return lineStart + character;
}

void LSPDiagnosticsDisplay::ClearIndicatorsInRange(int startPos, int endPos) {
    for (int i = 0; i <= 3; ++i) {
        SendScintilla(SCI_SETINDICATORCURRENT, i);
        SendScintilla(SCI_INDICCLEARRANGE, startPos, endPos - startPos);
    }
}

void LSPDiagnosticsDisplay::FillIndicatorRange(int indicator, int startPos, int endPos) {
    SendScintilla(SCI_SETINDICATORCURRENT, indicator);
    SendScintilla(SCI_INDICFILLRANGE, startPos, endPos - startPos);
}

// ============================================================================
// C API Implementation
// ============================================================================
extern "C" {

LSPDiagnosticsDisplayHandle LSPDiagnosticsDisplay_Create(void) {
    return new LSPDiagnosticsDisplay();
}

void LSPDiagnosticsDisplay_Destroy(LSPDiagnosticsDisplayHandle handle) {
    delete static_cast<LSPDiagnosticsDisplay*>(handle);
}

int LSPDiagnosticsDisplay_Initialize(LSPDiagnosticsDisplayHandle handle, HWND hEditor) {
    auto* display = static_cast<LSPDiagnosticsDisplay*>(handle);
    if (!display) return 0;
    return display->Initialize(hEditor) ? 1 : 0;
}

void LSPDiagnosticsDisplay_ClearAll(LSPDiagnosticsDisplayHandle handle) {
    auto* display = static_cast<LSPDiagnosticsDisplay*>(handle);
    if (display) display->ClearAllDiagnostics();
}

void LSPDiagnosticsDisplay_ShowDiagnostics(LSPDiagnosticsDisplayHandle handle,
                                              const char* filePath,
                                              const Agentic::LSPDiagnostic* diagnostics,
                                              size_t count) {
    auto* display = static_cast<LSPDiagnosticsDisplay*>(handle);
    if (!display || !filePath) return;
    
    std::vector<Agentic::LSPDiagnostic> diags;
    diags.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        diags.push_back(diagnostics[i]);
    }
    
    display->DisplayDiagnostics(filePath, diags);
}

int LSPDiagnosticsDisplay_GetErrorCount(LSPDiagnosticsDisplayHandle handle) {
    auto* display = static_cast<LSPDiagnosticsDisplay*>(handle);
    if (!display) return 0;
    return (int)display->GetErrorCount();
}

int LSPDiagnosticsDisplay_GetWarningCount(LSPDiagnosticsDisplayHandle handle) {
    auto* display = static_cast<LSPDiagnosticsDisplay*>(handle);
    if (!display) return 0;
    return (int)display->GetWarningCount();
}

} // extern "C"

} // namespace IDE
} // namespace RawrXD
