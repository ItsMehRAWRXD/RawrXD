// ============================================================================
// Phase 24: Win32IDE Debugger Integration Module
// ============================================================================
// Standalone integration point for DapService into Win32IDE
// 
// Usage:
//   1. Include this header in Win32IDE.h or Win32IDE.cpp
//   2. Call Win32IDE_DebuggerIntegration::Initialize() in Win32IDE::onCreate()
//   3. Call Win32IDE_DebuggerIntegration::HandleMessages() in WndProc
//
// Author: RawrXD Engineering
// Phase: 24 - Final Mile
// ============================================================================

#pragma once

#include "../ui/CallStackIntegration.hpp"
#include "../ui/CallStackPanel.h"
#include "../debug/DapService.hpp"
#include <windows.h>
#include <string>

namespace RawrXD {

// ============================================================================
// Win32IDE Debugger Integration
// ============================================================================
class Win32IDE_DebuggerIntegration {
public:
    /// @brief Initialize debugger integration
    /// @param hwndMain Main IDE window handle
    /// @param callStackPanel Pointer to CallStackPanel instance
    /// @return true on success
    static bool Initialize(HWND hwndMain, UI::CallStackPanel* callStackPanel);
    
    /// @brief Shutdown debugger integration
    static void Shutdown();
    
    /// @brief Handle DAP messages in WndProc
    /// @return true if message was handled
    static bool HandleMessages(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam);
    
    /// @brief Start debugging session
    /// @param program Path to executable
    /// @param workingDir Working directory
    /// @param stopOnEntry Break at entry point
    /// @return true on success
    static bool StartDebugging(const std::string& program, 
                                const std::string& workingDir,
                                bool stopOnEntry = true);
    
    /// @brief Stop debugging session
    static void StopDebugging();
    
    /// @brief Continue execution
    static void Continue();
    
    /// @brief Step over
    static void StepOver();
    
    /// @brief Step into
    static void StepInto();
    
    /// @brief Step out
    static void StepOut();
    
    /// @brief Pause execution
    static void Pause();
    
    /// @brief Set breakpoint
    /// @param file Source file path
    /// @param line Line number (1-based)
    static void SetBreakpoint(const std::string& file, uint32_t line);
    
    /// @brief Check if debugging
    static bool IsDebugging();
    
    /// @brief Get current debugger state
    static Debug::DapState GetState();
    
    /// @brief Show error message
    static void ShowError(HWND hwnd, const std::string& error);

private:
    static HWND s_hwndMain;
    static UI::CallStackPanel* s_callStackPanel;
    static bool s_initialized;
};

// ============================================================================
// Integration Macros for Easy WndProc Integration
// ============================================================================

/// @brief Place this at the start of your WndProc switch statement
#define WIN32IDE_HANDLE_DAP_MESSAGES(hwnd, msg, wParam, lParam) \
    if (RawrXD::Win32IDE_DebuggerIntegration::HandleMessages(hwnd, msg, wParam, lParam)) { \
        return 0; \
    }

/// @brief Place this in your initialization code
#define WIN32IDE_INIT_DEBUGGER(hwnd, callStackPanel) \
    RawrXD::Win32IDE_DebuggerIntegration::Initialize(hwnd, callStackPanel)

/// @brief Place this in your shutdown code
#define WIN32IDE_SHUTDOWN_DEBUGGER() \
    RawrXD::Win32IDE_DebuggerIntegration::Shutdown()

} // namespace RawrXD

// ============================================================================
// Example Integration (for documentation)
// ============================================================================
/*
 
 // In Win32IDE.h, add:
 #include "win32app/Win32IDE_DebuggerIntegration.hpp"
 
 // In Win32IDE::onCreate(), add:
 void Win32IDE::onCreate(HWND hwnd) {
     // ... existing code ...
     
     // Initialize debugger integration
     WIN32IDE_INIT_DEBUGGER(hwnd, m_callStackPanel);
     
     // ... rest of initialization ...
 }
 
 // In your WndProc or message handler, add at the top:
 LRESULT Win32IDE::handleMessage(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
     // Handle DAP messages first
     WIN32IDE_HANDLE_DAP_MESSAGES(hwnd, msg, wParam, lParam);
     
     switch (msg) {
         // ... existing cases ...
     }
 }
 
 // In your Debug menu handlers:
 void Win32IDE::OnDebugStart() {
     std::string exePath = GetCurrentProjectExecutable();
     std::string workDir = GetCurrentProjectDirectory();
     
     if (Win32IDE_DebuggerIntegration::StartDebugging(exePath, workDir, true)) {
         UpdateStatusBar("Debugging started");
     } else {
         MessageBoxA(m_hwndMain, "Failed to start debugger", "Error", MB_OK);
     }
 }
 
 void Win32IDE::OnDebugStop() {
     Win32IDE_DebuggerIntegration::StopDebugging();
     UpdateStatusBar("Debugging stopped");
 }
 
 void Win32IDE::OnDebugContinue() {
     Win32IDE_DebuggerIntegration::Continue();
 }
 
 void Win32IDE::OnDebugStepOver() {
     Win32IDE_DebuggerIntegration::StepOver();
 }
 
 void Win32IDE::OnDebugStepInto() {
     Win32IDE_DebuggerIntegration::StepInto();
 }
 
 void Win32IDE::OnDebugStepOut() {
     Win32IDE_DebuggerIntegration::StepOut();
 }
 
 void Win32IDE::OnDebugPause() {
     Win32IDE_DebuggerIntegration::Pause();
 }
 
 void Win32IDE::OnToggleBreakpoint() {
     std::string file = GetCurrentFilePath();
     uint32_t line = GetCurrentLineNumber();
     Win32IDE_DebuggerIntegration::SetBreakpoint(file, line);
 }
 
 */
