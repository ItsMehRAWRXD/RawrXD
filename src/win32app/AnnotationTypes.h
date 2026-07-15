// AnnotationTypes.h - Bridge data structures for AgentBridge integration
// Phase II: AgentBridge Integration
// Author: RawrXD Engineering
// Date: 2026-06-23

#pragma once

#include <string>
#include <vector>
#include <cstdint>
#include <memory>

namespace RawrXD {
namespace UI {

// Severity levels matching LSP specification
enum class AnnotationSeverity {
    Error = 1,       // LSP Error
    Warning = 2,     // LSP Warning
    Information = 3, // LSP Information
    Hint = 4         // LSP Hint
};

// Actions available on annotation interaction
enum class AnnotationAction {
    None = 0,
    GoToLine = 1,
    ShowQuickFix = 2,
    OpenUrl = 3
};

// Core annotation data structure
// Bridges LSP diagnostics to overlay rendering
struct AnnotationData {
    int lineNumber;              // 1-based line number
    int columnStart;             // 1-based start column
    int columnEnd;               // 1-based end column
    std::wstring message;        // Short message for tooltip
    std::wstring tooltip;        // Full tooltip text
    AnnotationSeverity severity;
    AnnotationAction action;
    std::wstring actionData;     // e.g., "25" for GoToLine, URL for OpenUrl
    std::wstring source;         // "lsp", "compiler", "agent"
    
    // Rendering hints (ARGB format)
    uint32_t squiggleColor;      // Underline color
    uint32_t marginColor;        // Gutter indicator color
    bool showInMargin;           // Show indicator in gutter
    
    AnnotationData()
        : lineNumber(0)
        , columnStart(0)
        , columnEnd(0)
        , severity(AnnotationSeverity::Error)
        , action(AnnotationAction::None)
        , squiggleColor(0xFF0000FF)  // Default red
        , marginColor(0xFFFF0000)
        , showInMargin(true)
    {}
};

// Bridge interface for annotation sources
class IAnnotationSource {
public:
    virtual ~IAnnotationSource() = default;
    
    // Called when diagnostics are updated
    virtual void OnDiagnosticsUpdated(
        const std::vector<AnnotationData>& diagnostics
    ) = 0;
    
    // Called when annotations should be cleared
    virtual void OnAnnotationsCleared(
        const std::wstring& source
    ) = 0;
};

// Convenience typedefs
using AnnotationDataPtr = std::shared_ptr<AnnotationData>;
using AnnotationDataVector = std::vector<AnnotationData>;

} // namespace UI
} // namespace RawrXD

// Global message IDs for annotation updates
// Using WM_USER range (0x0400-0x7FFF)
#define WM_USER_UPDATE_ANNOTATIONS  (WM_USER + 0x100)
#define WM_USER_CLEAR_ANNOTATIONS   (WM_USER + 0x101)
