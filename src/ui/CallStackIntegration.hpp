// ============================================================================
// Phase 24: CallStackPanel-DapService Integration
// ============================================================================
// Bridges the DapService backend with the CallStackPanel UI
// Handles thread marshaling from debugger reader thread to UI thread
//
// Usage:
//   CallStackIntegration::Initialize(hwndMain, callStackPanel);
//   CallStackIntegration::RegisterWithDapService();
//
// Author: RawrXD Engineering
// Phase: 24 - UI Bridge
// ============================================================================

#pragma once

#include "debug/DapService.hpp"
#include "ui/CallStackPanel.h"
#include <windows.h>
#include <functional>
#include <vector>

namespace RawrXD {
namespace UI {

// ============================================================================
// Thread Marshaling Message
// ============================================================================
// Custom window message for cross-thread UI updates
constexpr UINT WM_DAP_STACKTRACE = WM_USER + 0x1000;
constexpr UINT WM_DAP_STATE_CHANGED = WM_USER + 0x1001;
constexpr UINT WM_DAP_OUTPUT = WM_USER + 0x1002;

// ============================================================================
// Stack Trace Data for Marshaling
// ============================================================================
struct StackTraceData {
    uint32_t threadId;
    std::vector<Debug::StackFrame> frames;
};

// ============================================================================
// CallStack Integration
// ============================================================================
class CallStackIntegration {
public:
    /// @brief Initialize the integration layer
    /// @param mainWindow Handle to main IDE window for message posting
    /// @param panel Pointer to CallStackPanel instance
    static void Initialize(HWND mainWindow, CallStackPanel* panel);
    
    /// @brief Shutdown and cleanup
    static void Shutdown();
    
    /// @brief Register callbacks with DapService
    static void RegisterWithDapService();
    
    /// @brief Unregister callbacks
    static void UnregisterFromDapService();
    
    /// @brief Check if initialized
    static bool IsInitialized();
    
    /// @brief Handle WM_DAP_STACKTRACE message (called from WndProc)
    static void HandleStackTraceMessage(WPARAM wParam, LPARAM lParam);
    
    /// @brief Handle state change message
    static void HandleStateChangeMessage(WPARAM wParam, LPARAM lParam);

private:
    // Internal state
    static HWND s_mainWindow;
    static CallStackPanel* s_panel;
    static bool s_registered;
    
    // DapService callbacks
    static void OnStackTraceReceived(uint32_t threadId, const std::vector<Debug::StackFrame>& frames);
    static void OnStateChanged(Debug::DapState oldState, Debug::DapState newState);
    static void OnStopped(const std::string& reason, uint32_t threadId, const std::string& description);
    static void OnContinued(uint32_t threadId);
    static void OnTerminated();
    static void OnOutput(Debug::OutputChannel channel, const std::string& data);
    static void OnError(const std::string& error, bool fatal);
    
    // Thread-safe data marshaling
    static void MarshalStackTraceToUI(uint32_t threadId, const std::vector<Debug::StackFrame>& frames);
    static void MarshalStateChangeToUI(Debug::DapState oldState, Debug::DapState newState);
};

// ============================================================================
// Win32 Message Handler Helpers
// ============================================================================

/// @brief Call from your main WndProc to handle DAP messages
/// @return true if message was handled
inline bool HandleDapMessages(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_DAP_STACKTRACE:
            CallStackIntegration::HandleStackTraceMessage(wParam, lParam);
            return true;
            
        case WM_DAP_STATE_CHANGED:
            CallStackIntegration::HandleStateChangeMessage(wParam, lParam);
            return true;
            
        default:
            return false;
    }
}

} // namespace UI
} // namespace RawrXD

// ============================================================================
// Integration Example (for documentation)
// ============================================================================
/*
 
 // In Win32IDE.cpp initialization:
 void Win32IDE::InitializeDebugger() {
     // Get CallStackPanel instance
     auto* callStackPanel = GetCallStackPanel();
     
     // Initialize integration
     RawrXD::UI::CallStackIntegration::Initialize(m_hWnd, callStackPanel);
     RawrXD::UI::CallStackIntegration::RegisterWithDapService();
 }
 
 // In Win32IDE WndProc:
 LRESULT CALLBACK Win32IDE::WndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
     // Handle DAP messages first
     if (RawrXD::UI::HandleDapMessages(hwnd, msg, wParam, lParam)) {
         return 0;
     }
     
     // ... rest of message handling
 }
 
 // In Debug menu handler:
 void Win32IDE::OnDebugStart() {
     auto& service = RawrXD::Debug::DapService::instance();
     
     RawrXD::Debug::LaunchConfig config;
     config.program = GetCurrentProjectExecutable();
     config.workingDirectory = GetCurrentProjectDirectory();
     config.stopOnEntry = true;
     
     auto result = service.initialize(config);
     if (result) {
         service.launch();
     } else {
         MessageBoxA(m_hWnd, result.error.c_str(), "Debug Error", MB_OK);
     }
 }
 
 */
