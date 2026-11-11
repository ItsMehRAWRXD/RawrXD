// DebugIntegrationExample.cpp
// Phase 24: RawrXD IDE - Complete Debug Integration Example
// ============================================================================
// Shows how to integrate DapService and DebugUIController into the IDE
// ============================================================================

#include "debug/DapService.hpp"
#include "debug/DebugUIPanel.hpp"
#include <windows.h>
#include <string>

using namespace RawrXD::Debug;

// ============================================================================
// Example: Adding Debug Support to Your IDE Window
// ============================================================================

class IDEWindow {
public:
    bool Initialize() {
        // Create main window
        hwnd_ = CreateWindowExW(0, L"IDEWindow", L"RawrXD IDE",
                               WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT,
                               1280, 800,
                               nullptr, nullptr, GetModuleHandle(nullptr), this);
        
        if (!hwnd_) return false;
        
        // Initialize debug UI
        if (!UI::DebugUIController::instance().Initialize(hwnd_)) {
            return false;
        }
        
        return true;
    }
    
    void Shutdown() {
        // Stop debugging if active
        if (dapService_) {
            dapService_>shutdown();
        }
        
        UI::DebugUIController::instance().Shutdown();
    }
    
    // Start debugging session
    void StartDebugging(const std::wstring& programPath) {
        // Create DAP service
        dapService_ = std::make_unique<DapService>();
        
        // Configure
        LaunchConfig config;
        config.program = std::string(programPath.begin(), programPath.end());
        config.workingDirectory = ".";
        config.stopOnEntry = true;
        config.debuggerPath = "d:\\rawrxd\\bin\\BeaconDebugger.exe";
        
        // Initialize
        auto result = dapService_>initialize(config);
        if (!result.success) {
            MessageBoxA(hwnd_, result.error.c_str(), "Debug Error", MB_OK | MB_ICONERROR);
            return;
        }
        
        // Connect UI to service
        UI::DebugUIController::instance().AttachToDapService(dapService_.get());
        
        // Launch the program
        dapService_>launch();
        
        // Show debug panels
        UI::DebugUIController::instance().ShowDebugToolbar(true);
        UI::DebugUIController::instance().ShowDebugOutputPanel(true);
    }
    
    // Stop debugging
    void StopDebugging() {
        if (dapService_) {
            dapService_>terminate();
            dapService_>shutdown();
            dapService_.reset();
        }
        
        UI::DebugUIController::instance().DetachFromDapService();
    }
    
    // Handle menu commands
    void OnCommand(int cmd) {
        switch (cmd) {
            case ID_DEBUG_START:
                StartDebugging(L"d:\\rawrxd\\Victim.exe");
                break;
                
            case ID_DEBUG_STOP:
                StopDebugging();
                break;
                
            case ID_DEBUG_TOGGLE_BREAKPOINT:
                ToggleBreakpointAtCurrentLine();
                break;
        }
    }
    
    void ToggleBreakpointAtCurrentLine() {
        // Get current file and line from editor
        std::string file = GetCurrentFile();
        uint32_t line = GetCurrentLine();
        
        if (dapService_) {
            dapService_>setBreakpoint(file, line);
        }
    }
    
private:
    HWND hwnd_ = nullptr;
    std::unique_ptr<DapService> dapService_;
    
    std::string GetCurrentFile() { return "Victim.asm"; }
    uint32_t GetCurrentLine() { return 25; }
    
    static const int ID_DEBUG_START = 2001;
    static const int ID_DEBUG_STOP = 2002;
    static const int ID_DEBUG_TOGGLE_BREAKPOINT = 2003;
};

// ============================================================================
// Integration Checklist
// ============================================================================
/*

To integrate debugging into your IDE:

1. BUILD DEPENDENCIES
   - Compile DapService.cpp with nlohmann/json.hpp
   - Compile DebugUIPanel.cpp
   - Link with comctl32.lib

2. INITIALIZATION (in your main window creation)
   
   // After creating main window
   UI::DebugUIController::instance().Initialize(hwnd);
   
3. MENU ITEMS (add to your menu)
   
   - Debug > Start Debugging (F5)
   - Debug > Stop Debugging (Shift+F5)
   - Debug > Toggle Breakpoint (F9)
   - Debug > Step Over (F10)
   - Debug > Step Into (F11)
   - Debug > Step Out (Shift+F11)

4. COMMAND HANDLING (in your WndProc)
   
   case WM_COMMAND:
       switch (LOWORD(wParam)) {
           case ID_DEBUG_START:
               StartDebugging();
               break;
           case ID_DEBUG_TOGGLE_BREAKPOINT:
               ToggleBreakpoint();
               break;
           // ... etc
       }
       break;

5. EDITOR INTEGRATION
   
   - When user presses F9, call:
     dapService_>setBreakpoint(file, line);
   
   - When stopped event received:
     - Highlight line in editor
     - Show call stack panel
     - Show variables panel

6. CLEANUP (in WM_DESTROY)
   
   UI::DebugUIController::instance().Shutdown();

*/

// ============================================================================
// Quick Reference: DapService Methods
// ============================================================================
/*

// Lifecycle
DapService::instance().initialize(config);  // Start debugger process
DapService::instance().shutdown();          // Stop debugger

// Execution Control
DapService::instance().launch();                    // Start program
DapService::instance().continueExecution(threadId); // Resume
DapService::instance().pause();                     // Break
DapService::instance().stepOver(threadId);          // Step over
DapService::instance().stepInto(threadId);          // Step into
DapService::instance().stepOut(threadId);           // Step out
DapService::instance().terminate();                 // Kill program

// Breakpoints
DapService::instance().setBreakpoint(file, line, condition);
DapService::instance().removeBreakpoint(breakpointId);

// Data Inspection
DapService::instance().requestStackTrace(threadId, startFrame, levels);
DapService::instance().requestVariables(variablesReference);
DapService::instance().evaluate(expression, frameId);

// Callbacks
DapService::instance().onStopped([](const std::string& reason, uint32_t threadId, ...) {
    // Update UI
});

DapService::instance().onStackTrace([](uint32_t threadId, const std::vector<StackFrame>& frames) {
    // Update call stack panel
});

*/

// ============================================================================
// Build Command
// ============================================================================
/*

cl /EHsc /O2 /MD /W4 /I. DebugIntegrationExample.cpp ^
    debug\DapService.cpp ^
    debug\DebugUIPanel.cpp ^
    /link comctl32.lib user32.lib gdi32.lib

*/
