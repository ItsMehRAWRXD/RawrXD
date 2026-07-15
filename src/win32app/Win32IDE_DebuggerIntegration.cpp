// ============================================================================
// Phase 24: Win32IDE Debugger Integration Implementation
// ============================================================================

#include "Win32IDE_DebuggerIntegration.hpp"
#include <windows.h>
#include <string>

namespace RawrXD {

// ============================================================================
// Static Member Definitions
// ============================================================================

HWND Win32IDE_DebuggerIntegration::s_hwndMain = nullptr;
UI::CallStackPanel* Win32IDE_DebuggerIntegration::s_callStackPanel = nullptr;
bool Win32IDE_DebuggerIntegration::s_initialized = false;

// ============================================================================
// Public Interface
// ============================================================================

bool Win32IDE_DebuggerIntegration::Initialize(HWND hwndMain, UI::CallStackPanel* callStackPanel) {
    if (s_initialized) {
        return true;  // Already initialized
    }
    
    if (!hwndMain || !callStackPanel) {
        return false;
    }
    
    s_hwndMain = hwndMain;
    s_callStackPanel = callStackPanel;
    
    // Initialize the CallStackIntegration bridge
    UI::CallStackIntegration::Initialize(hwndMain, callStackPanel);
    UI::CallStackIntegration::RegisterWithDapService();
    
    s_initialized = true;
    return true;
}

void Win32IDE_DebuggerIntegration::Shutdown() {
    if (!s_initialized) {
        return;
    }
    
    // Stop any active debugging
    StopDebugging();
    
    // Unregister from DapService
    UI::CallStackIntegration::UnregisterFromDapService();
    UI::CallStackIntegration::Shutdown();
    
    s_hwndMain = nullptr;
    s_callStackPanel = nullptr;
    s_initialized = false;
}

bool Win32IDE_DebuggerIntegration::HandleMessages(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Delegate to CallStackIntegration
    return UI::HandleDapMessages(hwnd, msg, wParam, lParam);
}

bool Win32IDE_DebuggerIntegration::StartDebugging(const std::string& program,
                                                   const std::string& workingDir,
                                                   bool stopOnEntry) {
    if (!s_initialized) {
        return false;
    }
    
    auto& service = Debug::DapService::instance();
    
    // Configure launch
    Debug::LaunchConfig config;
    config.program = program;
    config.workingDirectory = workingDir;
    config.stopOnEntry = stopOnEntry;
    config.debuggerType = "cppvsdbg";  // Use VS Code's C++ debugger
    
    // Initialize DAP service
    auto result = service.initialize(config);
    if (!result) {
        ShowError(s_hwndMain, "Failed to initialize debugger: " + result.error);
        return false;
    }
    
    // Launch the target
    result = service.launch();
    if (!result) {
        ShowError(s_hwndMain, "Failed to launch target: " + result.error);
        service.shutdown();
        return false;
    }
    
    return true;
}

void Win32IDE_DebuggerIntegration::StopDebugging() {
    if (!s_initialized) {
        return;
    }
    
    auto& service = Debug::DapService::instance();
    
    // Terminate the target
    service.terminate();
    
    // Shutdown the service
    service.shutdown();
}

void Win32IDE_DebuggerIntegration::Continue() {
    if (!s_initialized) {
        return;
    }
    
    auto& service = Debug::DapService::instance();
    service.continueExecution(0);  // 0 = all threads
}

void Win32IDE_DebuggerIntegration::StepOver() {
    if (!s_initialized) {
        return;
    }
    
    auto& service = Debug::DapService::instance();
    // Get current thread ID from service or use 1 as default
    service.stepOver(1);
}

void Win32IDE_DebuggerIntegration::StepInto() {
    if (!s_initialized) {
        return;
    }
    
    auto& service = Debug::DapService::instance();
    service.stepInto(1);
}

void Win32IDE_DebuggerIntegration::StepOut() {
    if (!s_initialized) {
        return;
    }
    
    auto& service = Debug::DapService::instance();
    service.stepOut(1);
}

void Win32IDE_DebuggerIntegration::Pause() {
    if (!s_initialized) {
        return;
    }
    
    auto& service = Debug::DapService::instance();
    service.pause();
}

void Win32IDE_DebuggerIntegration::SetBreakpoint(const std::string& file, uint32_t line) {
    if (!s_initialized) {
        return;
    }
    
    auto& service = Debug::DapService::instance();
    service.setBreakpoint(file, line, "");
}

bool Win32IDE_DebuggerIntegration::IsDebugging() {
    if (!s_initialized) {
        return false;
    }
    
    auto& service = Debug::DapService::instance();
    auto state = service.state();
    return state == Debug::DapState::Running || 
           state == Debug::DapState::Paused ||
           state == Debug::DapState::Initializing;
}

Debug::DapState Win32IDE_DebuggerIntegration::GetState() {
    if (!s_initialized) {
        return Debug::DapState::Disconnected;
    }
    
    auto& service = Debug::DapService::instance();
    return service.state();
}

void Win32IDE_DebuggerIntegration::ShowError(HWND hwnd, const std::string& error) {
    MessageBoxA(hwnd, error.c_str(), "Debugger Error", MB_OK | MB_ICONERROR);
}

} // namespace RawrXD
