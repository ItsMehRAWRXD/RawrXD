//=============================================================================
// RawrXD Debug Integration Example
// Shows how to wire Debug Backend, Bridge, and UI in your main window
//=============================================================================

/*
 * INSTRUCTIONS:
 * 
 * 1. Include this in your main window procedure or IDE initialization
 * 2. Call DebugIntegration_Init() during IDE startup
 * 3. Call DebugIntegration_Shutdown() during IDE cleanup
 * 4. Add WM_APP_DEBUG_EVENT handler to your main window proc
 * 5. Call DebugIntegration_OnResize() in your WM_SIZE handler
 */

#include "DebugBackend.h"
#include "DebugBridge.hpp"
#include "DebugUI.hpp"
#include <windows.h>

using namespace RawrXD::Debug;
using namespace RawrXD::DebugUI;

// Global state for integration
static HWND g_hMainWindow = nullptr;
static std::shared_ptr<DebugSession> g_session = nullptr;

//=============================================================================
// Initialization
//=============================================================================

void DebugIntegration_Init(HWND hMainWindow) {
    g_hMainWindow = hMainWindow;
    
    // Initialize UI Manager
    DebugUIManager::Instance().Initialize(hMainWindow);
    
    // Initialize Bridge (for thread-safe communication)
    DebugBridge::Instance().Initialize(hMainWindow);
    
    // Wire toolbar callbacks to bridge
    DebugUIManager::Instance().GetToolbar().SetCallbacks(
        [](void* user) { 
            // Go / Continue
            DebugBridge::Instance().Continue();
            DebugUIManager::Instance().GetToolbar().SetRunning(true);
        },
        [](void* user) { 
            // Step Into
            DebugBridge::Instance().StepInto();
            DebugUIManager::Instance().GetToolbar().SetRunning(true);
        },
        [](void* user) { 
            // Step Over
            DebugBridge::Instance().StepOver();
            DebugUIManager::Instance().GetToolbar().SetRunning(true);
        },
        [](void* user) { 
            // Stop / Break
            DebugBridge::Instance().Break();
        },
        nullptr
    );
    
    // Initially hide debug panels
    DebugUIManager::Instance().ShowPanels(false);
}

void DebugIntegration_Shutdown() {
    if (g_session) {
        g_session->DetachProcess();
        DebugBackend::Instance().DestroySession(g_session);
        g_session = nullptr;
    }
    
    DebugBridge::Instance().Shutdown();
    DebugUIManager::Instance().Shutdown();
}

//=============================================================================
// Session Management
//=============================================================================

bool DebugIntegration_LaunchProcess(const wchar_t* exePath, const wchar_t* args) {
    // Create new debug session
    g_session = DebugBackend::Instance().CreateSession();
    
    // Set up event callback that marshals to UI thread via bridge
    g_session->SetEventCallback([](const DebugEvent& event) {
        // This runs on BACKEND THREAD - must use bridge to marshal to UI
        auto* bridgeEvent = new DebugBridgeEvent();
        
        switch (event.type) {
            case DebugEventType::BreakpointHit:
                bridgeEvent->type = DebugBridgeEventType::BreakpointHit;
                bridgeEvent->breakpoint.address = event.exceptionAddress;
                break;
            case DebugEventType::SingleStep:
                bridgeEvent->type = DebugBridgeEventType::SingleStep;
                break;
            case DebugEventType::Exception:
                bridgeEvent->type = DebugBridgeEventType::Exception;
                bridgeEvent->exception.code = (uint32_t)event.exceptionCode;
                bridgeEvent->exception.address = event.exceptionAddress;
                break;
            case DebugEventType::ProcessExited:
                bridgeEvent->type = DebugBridgeEventType::ProcessExited;
                bridgeEvent->processExit.exitCode = event.exitCode;
                break;
            case DebugEventType::LoadDll:
                bridgeEvent->type = DebugBridgeEventType::DllLoaded;
                bridgeEvent->dllLoad.baseAddress = event.dllBaseAddress;
                wcsncpy(bridgeEvent->dllLoad.path, event.dllPath.c_str(), 259);
                break;
            default:
                delete bridgeEvent;
                return;
        }
        
        // Copy context if available
        if (event.registers.rip != 0) {
            bridgeEvent->registers = new RegisterContext(event.registers);
        }
        
        // Marshal to UI thread
        DebugBridge::Instance().PostEvent(bridgeEvent);
    });
    
    // Launch the process
    if (!g_session->LaunchProcess(exePath, args)) {
        DebugBackend::Instance().DestroySession(g_session);
        g_session = nullptr;
        return false;
    }
    
    // Attach bridge and UI to session
    DebugBridge::Instance().AttachSession(g_session.get());
    DebugUIManager::Instance().AttachSession(g_session.get());
    DebugUIManager::Instance().ShowPanels(true);
    
    return true;
}

bool DebugIntegration_AttachToProcess(uint32_t pid) {
    g_session = DebugBackend::Instance().CreateSession();
    
    g_session->SetEventCallback([](const DebugEvent& event) {
        auto* bridgeEvent = new DebugBridgeEvent();
        
        switch (event.type) {
            case DebugEventType::BreakpointHit:
                bridgeEvent->type = DebugBridgeEventType::BreakpointHit;
                bridgeEvent->breakpoint.address = event.exceptionAddress;
                break;
            case DebugEventType::SingleStep:
                bridgeEvent->type = DebugBridgeEventType::SingleStep;
                break;
            case DebugEventType::Exception:
                bridgeEvent->type = DebugBridgeEventType::Exception;
                bridgeEvent->exception.code = (uint32_t)event.exceptionCode;
                bridgeEvent->exception.address = event.exceptionAddress;
                break;
            case DebugEventType::ProcessExited:
                bridgeEvent->type = DebugBridgeEventType::ProcessExited;
                bridgeEvent->processExit.exitCode = event.exitCode;
                break;
            default:
                delete bridgeEvent;
                return;
        }
        
        if (event.registers.rip != 0) {
            bridgeEvent->registers = new RegisterContext(event.registers);
        }
        
        DebugBridge::Instance().PostEvent(bridgeEvent);
    });
    
    if (!g_session->AttachProcess(pid)) {
        DebugBackend::Instance().DestroySession(g_session);
        g_session = nullptr;
        return false;
    }
    
    DebugBridge::Instance().AttachSession(g_session.get());
    DebugUIManager::Instance().AttachSession(g_session.get());
    DebugUIManager::Instance().ShowPanels(true);
    
    return true;
}

void DebugIntegration_Detach() {
    if (g_session) {
        g_session->DetachProcess();
        DebugBackend::Instance().DestroySession(g_session);
        g_session = nullptr;
    }
    
    DebugBridge::Instance().DetachSession();
    DebugUIManager::Instance().DetachSession();
    DebugUIManager::Instance().ShowPanels(false);
}

//=============================================================================
// Window Message Handlers
//=============================================================================

void DebugIntegration_OnResize(int width, int height) {
    DebugUIManager::Instance().OnMainResize(width, height);
}

// Add this to your main window procedure:
/*
LRESULT CALLBACK MainWndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        // ... other cases ...
        
        case WM_SIZE:
            DebugIntegration_OnResize(LOWORD(lParam), HIWORD(lParam));
            break;
            
        case WM_APP_DEBUG_EVENT: {
            // This runs on the UI THREAD - safe to touch UI
            DebugBridgeEvent* event = (DebugBridgeEvent*)lParam;
            DebugBridge::Instance().ProcessEvent(event);
            // Note: ProcessEvent deletes the event
            return 0;
        }
        
        // ... other cases ...
    }
    return DefWindowProc(hWnd, msg, wParam, lParam);
}
*/

//=============================================================================
// Keyboard Shortcuts
//=============================================================================

// Add this to your accelerator table or key handler:
/*
void OnKeyDown(WPARAM key) {
    bool ctrl = (GetKeyState(VK_CONTROL) & 0x8000) != 0;
    bool shift = (GetKeyState(VK_SHIFT) & 0x8000) != 0;
    
    switch (key) {
        case VK_F5:
            if (shift) {
                DebugIntegration_Detach();  // Shift+F5 = Stop
            } else {
                DebugBridge::Instance().Continue();  // F5 = Go
            }
            break;
        case VK_F10:
            DebugBridge::Instance().StepOver();  // F10 = Step Over
            break;
        case VK_F11:
            DebugBridge::Instance().StepInto();  // F11 = Step Into
            break;
    }
}
*/

//=============================================================================
// Example Usage
//=============================================================================

/*
// In your IDE's "Debug" menu:
void OnDebugLaunch() {
    const wchar_t* exePath = L"C:\\Path\\To\\MyApp.exe";
    if (DebugIntegration_LaunchProcess(exePath, nullptr)) {
        // Debug session started
    } else {
        MessageBox(nullptr, "Failed to launch process", "Debug Error", MB_OK);
    }
}

void OnDebugAttach() {
    // Show dialog to enter PID
    uint32_t pid = ShowAttachDialog();
    if (DebugIntegration_AttachToProcess(pid)) {
        // Attached successfully
    } else {
        MessageBox(nullptr, "Failed to attach to process", "Debug Error", MB_OK);
    }
}

void OnDebugToggleBreakpoint() {
    int currentLine = GetCurrentEditorLine();
    DebugUIManager::Instance().GetGutter().ToggleBreakpoint(currentLine);
    
    // Also set in backend if session active
    if (g_session) {
        uint64_t addr = GetAddressForLine(currentLine);  // Your symbol resolution
        g_session->SetBreakpoint(addr);
    }
}
*/
