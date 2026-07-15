// ============================================================================
// Phase 25: BreakpointGutter-Debugger Integration
// ============================================================================
// Connects the BreakpointsGutter UI to the DapService backend
// Handles the full breakpoint lifecycle: Set → Verify → Hit → Clear
//
// Author: RawrXD Engineering
// Phase: 25 - Breakpoint Lifecycle Completion
// ============================================================================

#pragma once

#include "ui/BreakpointsGutter.h"
#include "win32app/Win32IDE_DebuggerIntegration.hpp"
#include <windows.h>
#include <string>
#include <map>
#include <set>

namespace RawrXD {
namespace UI {

// ============================================================================
// Breakpoint Lifecycle State
// ============================================================================
enum class BreakpointLifecycleState {
    None,           // No breakpoint at this location
    Pending,        // Set in UI, waiting for debugger confirmation
    Verified,       // Confirmed by debugger (symbols resolved)
    Failed,         // Failed to set (no symbols, invalid line)
    Hit,            // Currently stopped at this breakpoint
    Disabled        // Temporarily disabled
};

// ============================================================================
// Breakpoint Metadata
// ============================================================================
struct BreakpointMetadata {
    uint32_t id;                           // DAP breakpoint ID
    std::wstring filePath;
    uint32_t lineNumber;
    BreakpointLifecycleState state;
    std::string condition;               // Optional condition expression
    bool isEnabled;
    std::string errorMessage;            // If Failed
};

// ============================================================================
// Breakpoint Integration
// ============================================================================
class BreakpointIntegration {
public:
    /// @brief Initialize breakpoint integration
    /// @param gutter Pointer to BreakpointsGutter instance
    /// @return true on success
    static bool Initialize(BreakpointsGutter* gutter);
    
    /// @brief Shutdown and cleanup
    static void Shutdown();
    
    /// @brief Check if initialized
    static bool IsInitialized();
    
    /// @brief Set current file being edited
    /// @param filePath Full path to current source file
    static void SetCurrentFile(const std::wstring& filePath);
    
    /// @brief Get current file
    static std::wstring GetCurrentFile();
    
    /// @brief Toggle breakpoint at line
    /// @param lineNumber 1-based line number
    /// @return true if breakpoint was set, false if cleared
    static bool ToggleBreakpoint(uint32_t lineNumber);
    
    /// @brief Set breakpoint at line
    /// @param lineNumber 1-based line number
    /// @param condition Optional condition expression
    /// @return true on success
    static bool SetBreakpoint(uint32_t lineNumber, const std::string& condition = "");
    
    /// @brief Clear breakpoint at line
    /// @param lineNumber 1-based line number
    /// @return true if breakpoint existed and was cleared
    static bool ClearBreakpoint(uint32_t lineNumber);
    
    /// @brief Clear all breakpoints in current file
    static void ClearAllBreakpointsInCurrentFile();
    
    /// @brief Clear all breakpoints everywhere
    static void ClearAllBreakpoints();
    
    /// @brief Enable/disable breakpoint
    /// @param lineNumber 1-based line number
    /// @param enabled true to enable, false to disable
    static void SetBreakpointEnabled(uint32_t lineNumber, bool enabled);
    
    /// @brief Check if breakpoint exists at line
    static bool HasBreakpoint(uint32_t lineNumber);
    
    /// @brief Get breakpoint state at line
    static BreakpointLifecycleState GetBreakpointState(uint32_t lineNumber);
    
    /// @brief Update breakpoint from DAP verification
    /// @param lineNumber Original line number requested
    /// @param actualLine Actual line where breakpoint was set (may differ)
    /// @param verified true if debugger confirmed the breakpoint
    /// @param breakpointId DAP breakpoint ID
    static void OnBreakpointVerified(uint32_t lineNumber, uint32_t actualLine, 
                                      bool verified, uint32_t breakpointId);
    
    /// @brief Mark breakpoint as hit
    /// @param lineNumber Line where execution stopped
    static void OnBreakpointHit(uint32_t lineNumber);
    
    /// @brief Clear hit indicator (when continuing)
    static void ClearHitIndicator();
    
    /// @brief Get all breakpoints in current file
    static std::vector<BreakpointMetadata> GetBreakpointsInCurrentFile();
    
    /// @brief Save breakpoints to session
    static void SaveBreakpoints();
    
    /// @brief Load breakpoints from session
    static void LoadBreakpoints();

private:
    static BreakpointsGutter* s_gutter;
    static std::wstring s_currentFile;
    static std::map<std::wstring, std::map<uint32_t, BreakpointMetadata>> s_breakpoints;
    static uint32_t s_nextBreakpointId;
    static bool s_initialized;
    
    // Internal helpers
    static void UpdateGutterVisuals(uint32_t lineNumber, BreakpointLifecycleState state);
    static BreakpointVisualState LifecycleToVisual(BreakpointLifecycleState state);
    static void OnGutterToggle(const std::wstring& filePath, uint32_t lineNumber);
};

// ============================================================================
// Integration Macros
// ============================================================================

/// @brief Initialize breakpoint integration with gutter
#define WIN32IDE_INIT_BREAKPOINTS(gutter) \
    RawrXD::UI::BreakpointIntegration::Initialize(gutter)

/// @brief Set current file for breakpoint tracking
#define WIN32IDE_SET_BREAKPOINT_FILE(filePath) \
    RawrXD::UI::BreakpointIntegration::SetCurrentFile(filePath)

/// @brief Toggle breakpoint at current line
#define WIN32IDE_TOGGLE_BREAKPOINT_AT_LINE(line) \
    RawrXD::UI::BreakpointIntegration::ToggleBreakpoint(line)

} // namespace UI
} // namespace RawrXD

// ============================================================================
// Usage Example (for documentation)
// ============================================================================
/*
 
 // In Win32IDE.cpp initialization:
 void Win32IDE::InitializeEditor() {
     // ... existing editor setup ...
     
     // Initialize breakpoint gutter
     m_breakpointGutter = std::make_unique<BreakpointsGutter>();
     m_breakpointGutter->Initialize(m_hwndEditor);
     
     // Wire to debugger
     WIN32IDE_INIT_BREAKPOINTS(m_breakpointGutter.get());
 }
 
 // When file changes:
 void Win32IDE::OnFileOpen(const std::wstring& filePath) {
     WIN32IDE_SET_BREAKPOINT_FILE(filePath);
     BreakpointIntegration::LoadBreakpoints();  // Restore saved breakpoints
 }
 
 // In editor WndProc for gutter clicks:
 LRESULT EditorWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
     switch (msg) {
         case WM_LBUTTONDOWN: {
             int x = GET_X_LPARAM(lParam);
             int y = GET_Y_LPARAM(lParam);
             
             // Check if click is in gutter
             if (x < BREAKPOINT_GUTTER_WIDTH) {
                 int line = LineFromY(y);
                 WIN32IDE_TOGGLE_BREAKPOINT_AT_LINE(line);
                 return 0;
             }
             break;
         }
     }
 }
 
 // In DapService callbacks:
 void OnBreakpointVerified(uint32_t line, bool verified, uint32_t id) {
     BreakpointIntegration::OnBreakpointVerified(line, line, verified, id);
 }
 
 void OnStopped(const std::string& reason, uint32_t threadId) {
     if (reason == "breakpoint") {
         // Get current IP from stack trace
         auto& service = DapService::instance();
         service.requestStackTrace(threadId, 0, 1);  // Just top frame
         
         // The stack trace callback will give us the line
         // Then call: BreakpointIntegration::OnBreakpointHit(line);
     }
 }
 
 */
