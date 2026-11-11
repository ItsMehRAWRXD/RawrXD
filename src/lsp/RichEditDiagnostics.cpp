/*===========================================================================
 * RichEditDiagnostics.cpp
 * 
 * LSP Diagnostics display implementation for RichEdit control.
 * Uses character formatting to highlight errors with underlines and colors.
 *===========================================================================*/

#include "RichEditDiagnostics.hpp"
#include <algorithm>
#include <sstream>

namespace RawrXD {
namespace IDE {

// ============================================================================
// Construction / Destruction
// ============================================================================
RichEditDiagnosticsDisplay::RichEditDiagnosticsDisplay() = default;

RichEditDiagnosticsDisplay::~RichEditDiagnosticsDisplay() {
    Shutdown();
}

// ============================================================================
// Initialization
// ============================================================================
bool RichEditDiagnosticsDisplay::Initialize(HWND hRichEdit) {
    if (!hRichEdit || !IsWindow(hRichEdit)) {
        return false;
    }
    
    hRichEdit_ = hRichEdit;
    initialized_ = true;
    return true;
}

void RichEditDiagnosticsDisplay::Shutdown() {
    if (!initialized_) return;
    
    ClearAllDiagnostics();
    hRichEdit_ = nullptr;
    initialized_ = false;
}

// ============================================================================
// Core Diagnostic Display
// ============================================================================
void RichEditDiagnosticsDisplay::ClearAllDiagnostics() {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    
    if (!hRichEdit_) return;
    
    // Clear all formatting by selecting all and resetting
    CHARRANGE all;
    all.cpMin = 0;
    all.cpMax = -1;  // Select all
    
    SendMessage(hRichEdit_, EM_EXSETSEL, 0, (LPARAM)&all);
    
    CHARFORMAT2 cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_UNDERLINE | CFM_UNDERLINETYPE | CFM_BACKCOLOR;
    cf.bUnderline = FALSE;
    cf.bUnderlineType = 0;
    cf.crBackColor = 0xFFFFFF;  // White background
    
    SendMessage(hRichEdit_, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    
    fileDiagnostics_.clear();
}

void RichEditDiagnosticsDisplay::DisplayDiagnostics(
    const std::string& filePath,
    const std::vector<Agentic::LSPDiagnostic>& diagnostics) {
    
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    
    if (!hRichEdit_ || !initialized_) return;
    
    // Remove existing diagnostics for this file
    RemoveFileDiagnosticsInternal(filePath);
    
    // Convert and store new diagnostics
    std::vector<RichEditDiagnostic> displayed;
    displayed.reserve(diagnostics.size());
    
    for (const auto& diag : diagnostics) {
        RichEditDiagnostic rd;
        rd.lspDiag = diag;
        rd.filePath = filePath;
        rd.visible = (filePath == currentFilePath_);
        
        // Convert LSP line/character to RichEdit character positions
        int startPos = LineCharacterToCharPos(diag.range.start.line, 
                                               diag.range.start.character);
        int endPos = LineCharacterToCharPos(diag.range.end.line, 
                                           diag.range.end.character);
        
        rd.charRange.cpMin = startPos;
        rd.charRange.cpMax = endPos;
        
        displayed.push_back(rd);
        
        // Apply formatting if this is the current file
        if (rd.visible) {
            ApplyDiagnosticFormatting(rd);
        }
    }
    
    fileDiagnostics_[filePath] = std::move(displayed);
}

void RichEditDiagnosticsDisplay::RemoveFileDiagnostics(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    RemoveFileDiagnosticsInternal(filePath);
}

void RichEditDiagnosticsDisplay::RemoveFileDiagnosticsInternal(const std::string& filePath) {
    auto it = fileDiagnostics_.find(filePath);
    if (it == fileDiagnostics_.end()) return;
    
    // Clear formatting if this was the current file
    if (filePath == currentFilePath_ && hRichEdit_) {
        for (const auto& rd : it->second) {
            ClearFormattingInRange(rd.charRange);
        }
    }
    
    fileDiagnostics_.erase(it);
}

// ============================================================================
// File Switching
// ============================================================================
void RichEditDiagnosticsDisplay::UpdateForFile(const std::string& filePath) {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    
    if (!hRichEdit_) return;
    
    // Clear current formatting
    CHARRANGE all;
    all.cpMin = 0;
    all.cpMax = -1;
    SendMessage(hRichEdit_, EM_EXSETSEL, 0, (LPARAM)&all);
    
    CHARFORMAT2 cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_UNDERLINE | CFM_UNDERLINETYPE | CFM_BACKCOLOR;
    cf.bUnderline = FALSE;
    cf.bUnderlineType = 0;
    cf.crBackColor = 0xFFFFFF;
    SendMessage(hRichEdit_, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
    
    currentFilePath_ = filePath;
    
    // Apply diagnostics for new file
    auto it = fileDiagnostics_.find(filePath);
    if (it == fileDiagnostics_.end()) return;
    
    for (auto& rd : it->second) {
        rd.visible = true;
        ApplyDiagnosticFormatting(rd);
    }
}

// ============================================================================
// Formatting Application
// ============================================================================
void RichEditDiagnosticsDisplay::ApplyDiagnosticFormatting(const RichEditDiagnostic& diag) {
    switch (diag.lspDiag.severity) {
        case 1: SetErrorFormat(diag.charRange); break;
        case 2: SetWarningFormat(diag.charRange); break;
        case 3: SetInfoFormat(diag.charRange); break;
        case 4: SetHintFormat(diag.charRange); break;
        default: SetErrorFormat(diag.charRange); break;
    }
}

void RichEditDiagnosticsDisplay::SetErrorFormat(const CHARRANGE& range) {
    SendMessage(hRichEdit_, EM_EXSETSEL, 0, (LPARAM)&range);
    
    CHARFORMAT2 cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_UNDERLINE | CFM_UNDERLINETYPE | CFM_BACKCOLOR;
    cf.bUnderline = TRUE;
    cf.bUnderlineType = CFU_UNDERLINEWAVE;  // Wavy underline
    cf.crBackColor = RGB(255, 200, 200);    // Light red background
    
    SendMessage(hRichEdit_, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

void RichEditDiagnosticsDisplay::SetWarningFormat(const CHARRANGE& range) {
    SendMessage(hRichEdit_, EM_EXSETSEL, 0, (LPARAM)&range);
    
    CHARFORMAT2 cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_UNDERLINE | CFM_UNDERLINETYPE | CFM_BACKCOLOR;
    cf.bUnderline = TRUE;
    cf.bUnderlineType = CFU_UNDERLINEWAVE;
    cf.crBackColor = RGB(255, 240, 200);    // Light orange background
    
    SendMessage(hRichEdit_, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

void RichEditDiagnosticsDisplay::SetInfoFormat(const CHARRANGE& range) {
    SendMessage(hRichEdit_, EM_EXSETSEL, 0, (LPARAM)&range);
    
    CHARFORMAT2 cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_UNDERLINE | CFM_UNDERLINETYPE | CFM_BACKCOLOR;
    cf.bUnderline = TRUE;
    cf.bUnderlineType = CFU_UNDERLINEDOTTED;
    cf.crBackColor = RGB(200, 230, 255);    // Light blue background
    
    SendMessage(hRichEdit_, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

void RichEditDiagnosticsDisplay::SetHintFormat(const CHARRANGE& range) {
    SendMessage(hRichEdit_, EM_EXSETSEL, 0, (LPARAM)&range);
    
    CHARFORMAT2 cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_UNDERLINE | CFM_UNDERLINETYPE | CFM_BACKCOLOR;
    cf.bUnderline = TRUE;
    cf.bUnderlineType = CFU_UNDERLINEDOTTED;
    cf.crBackColor = RGB(240, 240, 240);    // Light gray background
    
    SendMessage(hRichEdit_, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

void RichEditDiagnosticsDisplay::ClearFormattingInRange(const CHARRANGE& range) {
    SendMessage(hRichEdit_, EM_EXSETSEL, 0, (LPARAM)&range);
    
    CHARFORMAT2 cf = {};
    cf.cbSize = sizeof(cf);
    cf.dwMask = CFM_UNDERLINE | CFM_UNDERLINETYPE | CFM_BACKCOLOR;
    cf.bUnderline = FALSE;
    cf.bUnderlineType = 0;
    cf.crBackColor = 0xFFFFFF;
    
    SendMessage(hRichEdit_, EM_SETCHARFORMAT, SCF_SELECTION, (LPARAM)&cf);
}

// ============================================================================
// Position Conversion
// ============================================================================
int RichEditDiagnosticsDisplay::LineCharacterToCharPos(int line, int character) {
    if (!hRichEdit_) return 0;
    
    // Get character index at start of line
    int lineStart = (int)SendMessage(hRichEdit_, EM_LINEINDEX, line, 0);
    if (lineStart < 0) lineStart = 0;
    
    // Get line length
    int lineLen = (int)SendMessage(hRichEdit_, EM_LINELENGTH, lineStart, 0);
    
    // Clamp character to line length
    if (character > lineLen) character = lineLen;
    
    return lineStart + character;
}

// ============================================================================
// Tooltip / Hover Information
// ============================================================================
std::string RichEditDiagnosticsDisplay::GetDiagnosticAtPosition(int line, int character) const {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    
    auto it = fileDiagnostics_.find(currentFilePath_);
    if (it == fileDiagnostics_.end()) return "";
    
    for (const auto& rd : it->second) {
        if (!rd.visible) continue;
        
        // Check if position is within range
        if (line >= rd.lspDiag.range.start.line && 
            line <= rd.lspDiag.range.end.line) {
            
            if (line == rd.lspDiag.range.start.line && 
                character < rd.lspDiag.range.start.character) continue;
            if (line == rd.lspDiag.range.end.line && 
                character > rd.lspDiag.range.end.character) continue;
            
            std::string result;
            switch (rd.lspDiag.severity) {
                case 1: result = "[Error] "; break;
                case 2: result = "[Warning] "; break;
                case 3: result = "[Info] "; break;
                case 4: result = "[Hint] "; break;
            }
            result += rd.lspDiag.message;
            return result;
        }
    }
    
    return "";
}

bool RichEditDiagnosticsDisplay::HasDiagnosticAtPosition(int line, int character) const {
    return !GetDiagnosticAtPosition(line, character).empty();
}

// ============================================================================
// Statistics
// ============================================================================
size_t RichEditDiagnosticsDisplay::GetErrorCount() const {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    size_t count = 0;
    for (const auto& [path, diags] : fileDiagnostics_) {
        for (const auto& rd : diags) {
            if (rd.lspDiag.severity == 1) ++count;
        }
    }
    return count;
}

size_t RichEditDiagnosticsDisplay::GetWarningCount() const {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    size_t count = 0;
    for (const auto& [path, diags] : fileDiagnostics_) {
        for (const auto& rd : diags) {
            if (rd.lspDiag.severity == 2) ++count;
        }
    }
    return count;
}

size_t RichEditDiagnosticsDisplay::GetTotalCount() const {
    std::lock_guard<std::mutex> lock(diagnosticsMutex_);
    size_t count = 0;
    for (const auto& [path, diags] : fileDiagnostics_) {
        count += diags.size();
    }
    return count;
}

// ============================================================================
// C API Implementation
// ============================================================================
extern "C" {

RichEditDiagnosticsHandle RichEditDiagnostics_Create(void) {
    return new RichEditDiagnosticsDisplay();
}

void RichEditDiagnostics_Destroy(RichEditDiagnosticsHandle handle) {
    delete static_cast<RichEditDiagnosticsDisplay*>(handle);
}

int RichEditDiagnostics_Initialize(RichEditDiagnosticsHandle handle, HWND hRichEdit) {
    auto* display = static_cast<RichEditDiagnosticsDisplay*>(handle);
    if (!display) return 0;
    return display->Initialize(hRichEdit) ? 1 : 0;
}

void RichEditDiagnostics_ClearAll(RichEditDiagnosticsHandle handle) {
    auto* display = static_cast<RichEditDiagnosticsDisplay*>(handle);
    if (display) display->ClearAllDiagnostics();
}

void RichEditDiagnostics_ShowDiagnostics(RichEditDiagnosticsHandle handle,
                                           const char* filePath,
                                           const Agentic::LSPDiagnostic* diagnostics,
                                           size_t count) {
    auto* display = static_cast<RichEditDiagnosticsDisplay*>(handle);
    if (!display || !filePath) return;
    
    std::vector<Agentic::LSPDiagnostic> diags;
    diags.reserve(count);
    for (size_t i = 0; i < count; ++i) {
        diags.push_back(diagnostics[i]);
    }
    
    display->DisplayDiagnostics(filePath, diags);
}

int RichEditDiagnostics_GetErrorCount(RichEditDiagnosticsHandle handle) {
    auto* display = static_cast<RichEditDiagnosticsDisplay*>(handle);
    if (!display) return 0;
    return (int)display->GetErrorCount();
}

int RichEditDiagnostics_GetWarningCount(RichEditDiagnosticsHandle handle) {
    auto* display = static_cast<RichEditDiagnosticsDisplay*>(handle);
    if (!display) return 0;
    return (int)display->GetWarningCount();
}

} // extern "C"

} // namespace IDE
} // namespace RawrXD
