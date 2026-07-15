// DebugIntegrationTest.cpp
// Phase 24D: System Integration Test Protocol
// ============================================================================
// Comprehensive test of the complete debugger stack
// Run this to verify: Breakpoints → Stepping → State Management → Error Recovery
// ============================================================================

#include "debug/DapService.hpp"
#include "debug/DebugUIPanel.hpp"
#include "debug/BreakpointGutter.hpp"
#include "debug/StepController.hpp"
#include <windows.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <syncstream>

using namespace RawrXD::Debug;
using namespace RawrXD::Debug::UI;

// ============================================================================
// Test Framework
// ============================================================================

struct TestResult {
    std::string name;
    bool passed;
    std::string error;
    std::chrono::milliseconds duration;
};

class IntegrationTest {
public:
    std::vector<TestResult> results;
    std::ofstream logFile;
    
    IntegrationTest() {
        logFile.open("debug_integration_test.log");
        Log("=== RawrXD Debugger Integration Test ===");
        Log("Started: " + GetTimestamp());
        Log("");
    }
    
    ~IntegrationTest() {
        Log("");
        Log("=== Test Complete ===");
        PrintSummary();
        logFile.close();
    }
    
    void Log(const std::string& msg) {
        std::osyncstream(std::cout) << msg << std::endl;
        logFile << msg << std::endl;
    }
    
    std::string GetTimestamp() {
        auto now = std::chrono::system_clock::now();
        auto time = std::chrono::system_clock::to_time_t(now);
        char buf[64];
        ctime_s(buf, sizeof(buf), &time);
        return std::string(buf);
    }
    
    bool RunTest(const std::string& name, std::function<bool(std::string&)> testFn) {
        Log("[TEST] " + name);
        Log("  Running...");
        
        auto start = std::chrono::steady_clock::now();
        std::string error;
        bool passed = testFn(error);
        auto end = std::chrono::steady_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
        
        TestResult result{name, passed, error, duration};
        results.push_back(result);
        
        if (passed) {
            Log("  ✓ PASSED (" + std::to_string(duration.count()) + "ms)");
        } else {
            Log("  ✗ FAILED: " + error);
        }
        Log("");
        
        return passed;
    }
    
    void PrintSummary() {
        int passed = 0, failed = 0;
        for (const auto& r : results) {
            if (r.passed) passed++;
            else failed++;
        }
        
        Log("=== SUMMARY ===");
        Log("Total: " + std::to_string(results.size()));
        Log("Passed: " + std::to_string(passed));
        Log("Failed: " + std::to_string(failed));
        
        if (failed > 0) {
            Log("");
            Log("Failed tests:");
            for (const auto& r : results) {
                if (!r.passed) {
                    Log("  - " + r.name + ": " + r.error);
                }
            }
        }
    }
    
    bool AllPassed() const {
        for (const auto& r : results) {
            if (!r.passed) return false;
        }
        return true;
    }
};

// ============================================================================
// Test 1: DapService Initialization
// ============================================================================
bool Test_DapService_Init(std::string& error) {
    LaunchConfig config;
    config.program = "d:\\rawrxd\\Victim.exe";
    config.workingDirectory = "d:\\rawrxd";
    config.stopOnEntry = true;
    config.debuggerPath = "d:\\rawrxd\\bin\\BeaconDebugger.exe";
    
    auto result = DapService::instance().initialize(config);
    if (!result.success) {
        error = result.error;
        return false;
    }
    
    // Verify state
    if (DapService::instance().state() != DapState::Initializing) {
        error = "Expected Initializing state, got " + 
                std::to_string(static_cast<int>(DapService::instance().state()));
        DapService::instance().shutdown();
        return false;
    }
    
    DapService::instance().shutdown();
    return true;
}

// ============================================================================
// Test 2: Breakpoint Gutter Handshake
// ============================================================================
bool Test_BreakpointGutter_Handshake(std::string& error) {
    // Create mock window
    HWND hwnd = CreateWindowExW(0, L"STATIC", L"Test",
                                 WS_OVERLAPPED, 0, 0, 100, 100,
                                 nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!hwnd) {
        error = "Failed to create test window";
        return false;
    }
    
    // Create gutter
    BreakpointGutter gutter;
    if (!gutter.Create(hwnd, 40)) {
        error = "Failed to create breakpoint gutter";
        DestroyWindow(hwnd);
        return false;
    }
    
    // Track if callback fired
    bool callbackFired = false;
    uint32_t callbackLine = 0;
    
    gutter.onBreakpointToggled = [&](uint32_t line, bool added) {
        callbackFired = true;
        callbackLine = line;
    };
    
    // Toggle breakpoint
    gutter.ToggleBreakpoint(25);
    
    // Verify callback fired
    if (!callbackFired) {
        error = "Breakpoint toggle callback did not fire";
        gutter.Destroy();
        DestroyWindow(hwnd);
        return false;
    }
    
    if (callbackLine != 25) {
        error = "Callback reported wrong line: " + std::to_string(callbackLine);
        gutter.Destroy();
        DestroyWindow(hwnd);
        return false;
    }
    
    // Verify breakpoint exists
    if (!gutter.HasBreakpoint(25)) {
        error = "Breakpoint not found after toggle";
        gutter.Destroy();
        DestroyWindow(hwnd);
        return false;
    }
    
    gutter.Destroy();
    DestroyWindow(hwnd);
    return true;
}

// ============================================================================
// Test 3: Step Controller State Machine
// ============================================================================
bool Test_StepController_StateMachine(std::string& error) {
    StepController controller;
    
    // Initial state should be Idle
    if (controller.GetState() != StepState::Idle) {
        error = "Initial state should be Idle";
        return false;
    }
    
    // Without DAP service, step should not change state
    controller.StepOver();
    if (controller.GetState() != StepState::Idle) {
        error = "Step without DAP service should remain Idle";
        return false;
    }
    
    return true;
}

// ============================================================================
// Test 4: DebugUIController Event Marshalling
// ============================================================================
bool Test_DebugUIController_Marshalling(std::string& error) {
    HWND hwnd = CreateWindowExW(0, L"STATIC", L"Test",
                                 WS_OVERLAPPED, 0, 0, 100, 100,
                                 nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!hwnd) {
        error = "Failed to create test window";
        return false;
    }
    
    // Initialize UI controller
    if (!DebugUIController::instance().Initialize(hwnd)) {
        error = "Failed to initialize DebugUIController";
        DestroyWindow(hwnd);
        return false;
    }
    
    // Test state change callback
    bool stateChanged = false;
    DapState newState = DapState::Disconnected;
    
    // Simulate state change
    DebugUIController::instance().OnStateChanged(DapState::Disconnected, DapState::Paused);
    
    // Verify UI state updated
    if (DebugUIController::instance().GetState() != DapState::Paused) {
        error = "UI state not updated after OnStateChanged";
        DebugUIController::instance().Shutdown();
        DestroyWindow(hwnd);
        return false;
    }
    
    DebugUIController::instance().Shutdown();
    DestroyWindow(hwnd);
    return true;
}

// ============================================================================
// Test 5: Breakpoint Persistence
// ============================================================================
bool Test_Breakpoint_Persistence(std::string& error) {
    // Create temp directory
    std::string tempDir = "d:\\rawrxd\\.test_breakpoints";
    CreateDirectoryA(tempDir.c_str(), nullptr);
    
    // Add breakpoints
    BreakpointInfo bp1, bp2;
    bp1.id = 1;
    bp1.filePath = "test.cpp";
    bp1.line = 10;
    bp1.verified = true;
    bp1.enabled = true;
    
    bp2.id = 2;
    bp2.filePath = "test.cpp";
    bp2.line = 25;
    bp2.verified = false;
    bp2.enabled = true;
    bp2.condition = "x > 0";
    
    std::vector<BreakpointInfo> bps = {bp1, bp2};
    BreakpointManager::instance().SetBreakpointsForFile("test.cpp", bps);
    
    // Save
    if (!BreakpointManager::instance().SaveBreakpoints(tempDir)) {
        error = "Failed to save breakpoints";
        return false;
    }
    
    // Clear
    BreakpointManager::instance().ClearAllBreakpoints();
    
    // Load
    if (!BreakpointManager::instance().LoadBreakpoints(tempDir)) {
        error = "Failed to load breakpoints";
        return false;
    }
    
    // Verify
    auto loaded = BreakpointManager::instance().GetBreakpointsForFile("test.cpp");
    if (loaded.size() != 2) {
        error = "Expected 2 breakpoints, got " + std::to_string(loaded.size());
        return false;
    }
    
    if (loaded[0].line != 10 || loaded[1].line != 25) {
        error = "Breakpoint lines don't match after load";
        return false;
    }
    
    // Cleanup
    DeleteFileA((tempDir + "\\.rawrxd\\breakpoints.json").c_str());
    RemoveDirectoryA((tempDir + "\\.rawrxd").c_str());
    RemoveDirectoryA(tempDir.c_str());
    
    return true;
}

// ============================================================================
// Test 6: Keyboard Shortcuts
// ============================================================================
bool Test_Keyboard_Shortcuts(std::string& error) {
    StepController controller;
    
    // Test F10 (Step Over) - should not crash without DAP
    MSG msg = {};
    msg.hwnd = nullptr;
    msg.message = WM_KEYDOWN;
    msg.wParam = VK_F10;
    
    // This should return false (not handled) since no DAP attached
    bool handled = HandleDebugKeyDown(nullptr, VK_F10, 0, &controller);
    if (handled) {
        error = "F10 should not be handled without DAP service";
        return false;
    }
    
    // Test F11 (Step Into)
    handled = HandleDebugKeyDown(nullptr, VK_F11, 0, &controller);
    if (handled) {
        error = "F11 should not be handled without DAP service";
        return false;
    }
    
    // Test Shift+F11 (Step Out)
    keybd_event(VK_SHIFT, 0, 0, 0);
    handled = HandleDebugKeyDown(nullptr, VK_F11, 0, &controller);
    keybd_event(VK_SHIFT, 0, KEYEVENTF_KEYUP, 0);
    
    if (handled) {
        error = "Shift+F11 should not be handled without DAP service";
        return false;
    }
    
    return true;
}

// ============================================================================
// Test 7: Error Recovery (Simulated)
// ============================================================================
bool Test_Error_Recovery(std::string& error) {
    // Test that components handle null/invalid states gracefully
    
    StepController controller;
    
    // Step without DAP should not crash
    controller.StepOver();
    controller.StepInto();
    controller.StepOut();
    
    // State should remain Idle
    if (controller.GetState() != StepState::Idle) {
        error = "State should remain Idle after failed steps";
        return false;
    }
    
    return true;
}

// ============================================================================
// Test 8: Component Integration
// ============================================================================
bool Test_Component_Integration(std::string& error) {
    // This test verifies all components can be instantiated together
    
    HWND hwnd = CreateWindowExW(0, L"STATIC", L"Test",
                                 WS_OVERLAPPED, 0, 0, 800, 600,
                                 nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!hwnd) {
        error = "Failed to create test window";
        return false;
    }
    
    // Initialize all components
    if (!DebugUIController::instance().Initialize(hwnd)) {
        error = "Failed to initialize DebugUIController";
        DestroyWindow(hwnd);
        return false;
    }
    
    // Create gutter
    BreakpointGutter gutter;
    if (!gutter.Create(hwnd, 40)) {
        error = "Failed to create BreakpointGutter";
        DebugUIController::instance().Shutdown();
        DestroyWindow(hwnd);
        return false;
    }
    
    // Create step controller
    StepController stepController;
    
    // Wire them together
    gutter.onBreakpointToggled = [&](uint32_t line, bool added) {
        // This would normally call DapService
        std::osyncstream(std::cout) << "  Breakpoint " << (added ? "added" : "removed") 
                  << " at line " << line << std::endl;
    };
    
    // Test interaction
    gutter.ToggleBreakpoint(10);
    
    // Cleanup
    gutter.Destroy();
    DebugUIController::instance().Shutdown();
    DestroyWindow(hwnd);
    
    return true;
}

// ============================================================================
// Main Test Runner
// ============================================================================
int main() {
    std::cout << "╔════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║  RawrXD Debugger Integration Test Suite                    ║" << std::endl;
    std::cout << "╚════════════════════════════════════════════════════════════╝" << std::endl;
    std::cout << std::endl;
    
    IntegrationTest test;
    
    // Run all tests
    test.RunTest("DapService Initialization", Test_DapService_Init);
    test.RunTest("Breakpoint Gutter Handshake", Test_BreakpointGutter_Handshake);
    test.RunTest("Step Controller State Machine", Test_StepController_StateMachine);
    test.RunTest("DebugUIController Event Marshalling", Test_DebugUIController_Marshalling);
    test.RunTest("Breakpoint Persistence", Test_Breakpoint_Persistence);
    test.RunTest("Keyboard Shortcuts", Test_Keyboard_Shortcuts);
    test.RunTest("Error Recovery", Test_Error_Recovery);
    test.RunTest("Component Integration", Test_Component_Integration);
    
    std::cout << std::endl;
    
    if (test.AllPassed()) {
        std::cout << "🎉 ALL TESTS PASSED!" << std::endl;
        std::cout << "The debugger stack is ready for live testing with Victim.exe" << std::endl;
        return 0;
    } else {
        std::cout << "⚠️  Some tests failed. Review debug_integration_test.log" << std::endl;
        return 1;
    }
}

// ============================================================================
// Build Command
// ============================================================================
/*
cl /EHsc /O2 /MD /W4 /std:c++20 /I. DebugIntegrationTest.cpp ^
    debug\DapService.cpp ^
    debug\DebugUIPanel.cpp ^
    debug\BreakpointGutter.cpp ^
    debug\StepController.cpp ^
    /link user32.lib gdi32.lib comctl32.lib
*/
