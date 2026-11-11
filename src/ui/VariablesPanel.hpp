// ============================================================================
// Phase 26: Variables Panel - Debug Variable Inspection
// ============================================================================
// Displays local variables, arguments, and globals during debugging.
// Tree-view style with expandable objects/arrays.
//
// Design Principles:
//   - Tree structure: Variables can have children (objects, arrays)
//   - Lazy loading: Children fetched on-demand via DAP
//   - Frame-aware: Updates when selected stack frame changes
//   - Type visualization: Colors/icons based on variable type
//
// Integration Points:
//   - CallStackPanel: Frame selection triggers variable refresh
//   - DapService: Variable retrieval via scopesRequest + variablesRequest
//   - BreakpointIntegration: Clear variables when execution resumes
//
// Author: RawrXD Engineering
// Phase: 26 - Variable Inspection
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <unordered_map>

namespace RawrXD {
namespace Debug { struct Variable; }

namespace UI {

// ============================================================================
// Variable Display Types
// ============================================================================
enum class VariableType {
    Local,          // Local variables
    Argument,       // Function arguments
    Global,         // Global/static variables
    Register,       // CPU registers
    Static,         // Static locals
    Unknown
};

// ============================================================================
// Variable Display Node (Tree Structure)
// ============================================================================
struct VariableDisplayNode {
    // Core data
    std::wstring name;
    std::wstring value;
    std::wstring type;
    VariableType varType;
    
    // Tree structure
    uint32_t variablesReference;  // DAP reference for fetching children
    std::vector<std::shared_ptr<VariableDisplayNode>> children;
    bool isExpanded;
    bool isExpandable;
    int depth;                    // Nesting level for indentation
    
    // Display state
    bool isModified;              // Changed since last stop
    bool isHighlighted;           // Search/filter match
    uint64_t lastModifiedTick;    // For change tracking
    
    // Layout (computed during render)
    mutable int rowIndex;         // Visual row index
    mutable bool isVisible;       // Currently visible (parent expanded)
    
    VariableDisplayNode() 
        : variablesReference(0)
        , isExpanded(false)
        , isExpandable(false)
        , depth(0)
        , isModified(false)
        , isHighlighted(false)
        , lastModifiedTick(0)
        , rowIndex(-1)
        , isVisible(true) {}
};

// ============================================================================
// Variables Panel Configuration
// ============================================================================
struct VariablesPanelConfig {
    int rowHeight = 20;
    int indentWidth = 16;         // Per-depth indentation
    int iconWidth = 16;
    int nameColumnWidth = 150;
    int typeColumnWidth = 100;
    
    // Colors
    COLORREF backgroundColor = RGB(30, 30, 30);
    COLORREF textColor = RGB(220, 220, 220);
    COLORREF nameColor = RGB(156, 220, 254);      // Light blue
    COLORREF valueColor = RGB(206, 145, 120);    // Orange-ish
    COLORREF typeColor = RGB(78, 201, 176);      // Teal
    COLORREF modifiedColor = RGB(255, 200, 0);   // Yellow for changed
    COLORREF selectedColor = RGB(0, 120, 215);
    COLORREF selectedTextColor = RGB(255, 255, 255);
    
    // Type-specific colors
    COLORREF stringColor = RGB(206, 145, 120);   // Orange
    COLORREF numberColor = RGB(181, 206, 168);  // Green
    COLORREF boolColor = RGB(86, 156, 214);      // Blue
    COLORREF nullColor = RGB(128, 128, 128);     // Gray
    
    wchar_t fontName[32] = L"Consolas";
    int fontSize = 10;
    bool showTypes = true;
    bool highlightModified = true;
};

// ============================================================================
// Variables Panel
// ============================================================================
class VariablesPanel {
public:
    using VariableSelectedCallback = std::function<void(const VariableDisplayNode&)>;
    using ExpandVariableCallback = std::function<void(uint32_t variablesReference)>;

    VariablesPanel();
    ~VariablesPanel();

    // Initialization
    bool Initialize(HWND parentWindow);
    void Shutdown();

    // Configuration
    void SetConfig(const VariablesPanelConfig& config);

    // Data updates (called when stack frame changes)
    void UpdateVariables(const std::vector<Debug::Variable>& variables, VariableType type);
    void ClearVariables();
    void SetCurrentFrame(uint32_t frameId);

    // Tree operations
    void ExpandNode(const std::shared_ptr<VariableDisplayNode>& node);
    void CollapseNode(const std::shared_ptr<VariableDisplayNode>& node);
    void ToggleNode(const std::shared_ptr<VariableDisplayNode>& node);
    void ExpandAll();
    void CollapseAll();

    // Child variable updates (async from DAP)
    void UpdateChildVariables(uint32_t parentReference, 
                              const std::vector<Debug::Variable>& children);

    // Rendering
    void Render(HDC hdc, const RECT& panelRect);
    void Invalidate();

    // Event handling
    void SetVariableSelectedCallback(VariableSelectedCallback callback);
    void SetExpandVariableCallback(ExpandVariableCallback callback);
    bool OnMouseClick(int x, int y);
    bool OnMouseDoubleClick(int x, int y);
    bool OnKeyDown(WPARAM keyCode);

    // Search/Filter
    void SetFilter(const std::wstring& filter);
    void ClearFilter();

    // Sizing
    void SetSize(int width, int height);
    SIZE GetPreferredSize() const;

    // Change tracking
    void MarkAllUnmodified();
    void TrackChanges();  // Call before update to detect modifications

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Variables Integration Bridge
// ============================================================================
// Connects VariablesPanel to DapService for automatic updates
class VariablesIntegration {
public:
    VariablesIntegration();
    ~VariablesIntegration();

    // Initialize with panel and DAP service
    bool Initialize(VariablesPanel* panel, void* dapService);  // DapService*
    void Shutdown();

    // Frame selection from CallStackPanel
    void OnFrameSelected(uint32_t frameId);

    // DAP event handlers
    void OnVariablesReceived(uint32_t frameId, 
                            const std::vector<Debug::Variable>& variables);
    void OnChildVariablesReceived(uint32_t parentReference,
                                 const std::vector<Debug::Variable>& children);
    void OnExecutionResumed();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace UI
} // namespace RawrXD
