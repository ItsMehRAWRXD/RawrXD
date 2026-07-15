// ============================================================================
// Phase 27: Watch Expressions Panel - Debug Watch Management
// ============================================================================
// Allows users to monitor custom expressions and variables during debugging.
// Supports persistence across sessions and automatic re-evaluation on stops.
//
// Design Principles:
//   - Persistent: Watch expressions saved across debugging sessions
//   - Auto-evaluate: Re-evaluated automatically when execution stops
//   - Error tolerant: Invalid expressions show error state, don't crash
//   - Quick-add: Add from VariablesPanel via context menu
//
// Integration Points:
//   - DapService: evaluateRequest for expression evaluation
//   - VariablesPanel: Context menu "Add to Watch"
//   - Settings: Persistence across IDE sessions
//
// Author: RawrXD Engineering
// Phase: 27 - Watch Expressions
// ============================================================================

#pragma once

#include <windows.h>
#include <string>
#include <vector>
#include <memory>
#include <functional>
#include <chrono>

namespace RawrXD {
namespace UI {

// ============================================================================
// Watch Expression State
// ============================================================================
enum class WatchState {
    Valid,          // Successfully evaluated
    Error,          // Evaluation failed (syntax, scope, etc.)
    Pending,        // Waiting for evaluation
    Stale           // Value from previous stop, may be outdated
};

// ============================================================================
// Watch Expression Entry
// ============================================================================
struct WatchExpression {
    uint32_t id;                    // Unique identifier
    std::wstring expression;        // The expression to evaluate
    std::wstring value;             // Last evaluated value
    std::wstring type;              // Type of result
    WatchState state;               // Current evaluation state
    std::wstring errorMessage;      // Error details if state == Error
    
    // Metadata
    std::chrono::system_clock::time_point lastEvaluated;
    uint32_t evaluationCount;       // How many times evaluated
    bool isPinned;                  // Persist across sessions
    int sortOrder;                  // Display order
    
    WatchExpression() 
        : id(0)
        , state(WatchState::Pending)
        , evaluationCount(0)
        , isPinned(true)
        , sortOrder(0) {}
};

// ============================================================================
// Watch Expressions Panel Configuration
// ============================================================================
struct WatchPanelConfig {
    int rowHeight = 20;
    int expressionColumnWidth = 200;
    int valueColumnWidth = 150;
    int typeColumnWidth = 100;
    
    // Colors
    COLORREF backgroundColor = RGB(30, 30, 30);
    COLORREF textColor = RGB(220, 220, 220);
    COLORREF expressionColor = RGB(156, 220, 254);   // Light blue
    COLORREF valueColor = RGB(206, 145, 120);        // Orange-ish
    COLORREF typeColor = RGB(78, 201, 176);          // Teal
    COLORREF errorColor = RGB(255, 100, 100);        // Red for errors
    COLORREF pendingColor = RGB(128, 128, 128);      // Gray for pending
    COLORREF selectedColor = RGB(0, 120, 215);
    COLORREF selectedTextColor = RGB(255, 255, 255);
    
    wchar_t fontName[32] = L"Consolas";
    int fontSize = 10;
    bool autoEvaluate = true;        // Auto-evaluate on stops
    bool showTypes = true;
    int maxHistory = 100;            // Max expressions to keep
};

// ============================================================================
// Watch Expressions Panel
// ============================================================================
class WatchExpressionsPanel {
public:
    using ExpressionSelectedCallback = std::function<void(const WatchExpression&)>;
    using EvaluateExpressionCallback = std::function<void(const std::wstring& expression, uint32_t watchId)>;
    using ExpressionAddedCallback = std::function<void(const WatchExpression&)>;
    using ExpressionRemovedCallback = std::function<void(uint32_t watchId)>;

    WatchExpressionsPanel();
    ~WatchExpressionsPanel();

    // Initialization
    bool Initialize(HWND parentWindow);
    void Shutdown();

    // Configuration
    void SetConfig(const WatchPanelConfig& config);

    // Expression management
    uint32_t AddExpression(const std::wstring& expression);
    void RemoveExpression(uint32_t watchId);
    void RemoveAllExpressions();
    void UpdateExpression(uint32_t watchId, const std::wstring& value, 
                          const std::wstring& type);
    void SetExpressionError(uint32_t watchId, const std::wstring& errorMessage);
    
    // Evaluation
    void EvaluateAll();              // Trigger evaluation of all expressions
    void MarkAllStale();             // Mark all as potentially outdated
    void ClearValues();              // Clear all values (execution resumed)
    
    // Persistence
    void LoadFromSettings();         // Load saved expressions
    void SaveToSettings();           // Save pinned expressions
    
    // Accessors
    std::vector<WatchExpression> GetExpressions() const;
    std::shared_ptr<WatchExpression> GetExpression(uint32_t watchId);
    size_t GetExpressionCount() const;
    
    // Rendering
    void Render(HDC hdc, const RECT& panelRect);
    void Invalidate();

    // Event handling
    void SetExpressionSelectedCallback(ExpressionSelectedCallback callback);
    void SetEvaluateExpressionCallback(EvaluateExpressionCallback callback);
    void SetExpressionAddedCallback(ExpressionAddedCallback callback);
    void SetExpressionRemovedCallback(ExpressionRemovedCallback callback);
    
    bool OnMouseClick(int x, int y);
    bool OnMouseDoubleClick(int x, int y);
    bool OnKeyDown(WPARAM keyCode);
    bool OnChar(wchar_t ch);         // For inline editing
    
    // Editing
    void StartEdit(uint32_t watchId);
    void CommitEdit(const std::wstring& newExpression);
    void CancelEdit();
    bool IsEditing() const;
    
    // Quick add from other panels
    void QuickAddFromVariable(const std::wstring& variableName);
    void QuickAddFromSelection(const std::wstring& selectedText);

    // Sizing
    void SetSize(int width, int height);
    SIZE GetPreferredSize() const;

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

// ============================================================================
// Watch Expressions Integration
// ============================================================================
// Connects WatchExpressionsPanel to DapService for automatic evaluation
class WatchExpressionsIntegration {
public:
    WatchExpressionsIntegration();
    ~WatchExpressionsIntegration();

    // Initialize with panel and DAP service
    bool Initialize(WatchExpressionsPanel* panel, void* dapService);
    void Shutdown();

    // DAP event handlers
    void OnExecutionStopped(uint32_t threadId, uint32_t frameId);
    void OnExecutionResumed();
    void OnEvaluationComplete(uint32_t watchId, const std::wstring& value,
                              const std::wstring& type);
    void OnEvaluationError(uint32_t watchId, const std::wstring& error);

    // Settings persistence
    void LoadWatches();
    void SaveWatches();

private:
    class Impl;
    std::unique_ptr<Impl> m_impl;
};

} // namespace UI
} // namespace RawrXD
