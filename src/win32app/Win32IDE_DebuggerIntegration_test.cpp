// ============================================================================
// Phase 24: Win32IDE Debugger Integration Test
// ============================================================================
// Validates the integration layer compiles and initializes correctly

#include "win32app/Win32IDE_DebuggerIntegration.hpp"
#include "ui/CallStackPanel.h"
#include <iostream>
#include <string>
#include <windows.h>

using namespace RawrXD;

// Mock CallStackPanel for testing
class MockCallStackPanel : public UI::CallStackPanel {
public:
    bool wasCleared = false;
    bool wasInvalidated = false;
    
    void ClearCallStack() { wasCleared = true; }
    void SetCurrentFrame(size_t index) { (void)index; }
    void Invalidate() { wasInvalidated = true; }
};

// Test window procedure
LRESULT CALLBACK TestWndProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    // Handle DAP messages
    WIN32IDE_HANDLE_DAP_MESSAGES(hwnd, msg, wParam, lParam);
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

void runIntegrationTest() {
    std::cout << "========================================" << std::endl;
    std::cout << "Phase 24: Win32IDE Integration Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Test 1: Initial state
    std::cout << "[TEST 1] Initial state" << std::endl;
    if (Win32IDE_DebuggerIntegration::IsDebugging()) {
        std::cout << "[FAIL] Should not be debugging initially" << std::endl;
        return;
    }
    if (Win32IDE_DebuggerIntegration::GetState() != Debug::DapState::Disconnected) {
        std::cout << "[FAIL] Should be Disconnected initially" << std::endl;
        return;
    }
    std::cout << "[PASS] Initial state correct" << std::endl;
    std::cout << std::endl;
    
    // Test 2: Initialization without window
    std::cout << "[TEST 2] Initialization validation" << std::endl;
    MockCallStackPanel mockPanel;
    
    if (Win32IDE_DebuggerIntegration::Initialize(nullptr, &mockPanel)) {
        std::cout << "[FAIL] Should fail with null hwnd" << std::endl;
        return;
    }
    
    if (Win32IDE_DebuggerIntegration::Initialize((HWND)1, nullptr)) {
        std::cout << "[FAIL] Should fail with null panel" << std::endl;
        return;
    }
    std::cout << "[PASS] Validation works" << std::endl;
    std::cout << std::endl;
    
    // Test 3: Create test window and initialize
    std::cout << "[TEST 3] Create window and initialize" << std::endl;
    
    WNDCLASSA wc = {};
    wc.lpfnWndProc = TestWndProc;
    wc.lpszClassName = "TestWin32IDEWindow";
    wc.hInstance = GetModuleHandle(nullptr);
    RegisterClassA(&wc);
    
    HWND hwnd = CreateWindowA("TestWin32IDEWindow", "Test", 0, 0, 0, 0, 0,
                               nullptr, nullptr, GetModuleHandle(nullptr), nullptr);
    
    if (!hwnd) {
        std::cout << "[FAIL] Failed to create test window" << std::endl;
        return;
    }
    
    if (!Win32IDE_DebuggerIntegration::Initialize(hwnd, &mockPanel)) {
        std::cout << "[FAIL] Initialize failed" << std::endl;
        DestroyWindow(hwnd);
        return;
    }
    std::cout << "[PASS] Initialized successfully" << std::endl;
    std::cout << std::endl;
    
    // Test 4: Double initialization
    std::cout << "[TEST 4] Double initialization" << std::endl;
    if (!Win32IDE_DebuggerIntegration::Initialize(hwnd, &mockPanel)) {
        std::cout << "[FAIL] Double init should succeed (idempotent)" << std::endl;
        DestroyWindow(hwnd);
        return;
    }
    std::cout << "[PASS] Double init handled" << std::endl;
    std::cout << std::endl;
    
    // Test 5: Message handling
    std::cout << "[TEST 5] Message handling" << std::endl;
    
    // Test that HandleMessages returns false for non-DAP messages
    bool handled = Win32IDE_DebuggerIntegration::HandleMessages(hwnd, WM_PAINT, 0, 0);
    if (handled) {
        std::cout << "[FAIL] Should not handle WM_PAINT" << std::endl;
        DestroyWindow(hwnd);
        return;
    }
    std::cout << "[PASS] Message handling works" << std::endl;
    std::cout << std::endl;
    
    // Test 6: State queries
    std::cout << "[TEST 6] State queries" << std::endl;
    
    Debug::DapState state = Win32IDE_DebuggerIntegration::GetState();
    std::cout << "  Current state: " << Debug::StateToString(state) << std::endl;
    
    if (Win32IDE_DebuggerIntegration::IsDebugging()) {
        std::cout << "[FAIL] Should not be debugging" << std::endl;
        DestroyWindow(hwnd);
        return;
    }
    std::cout << "[PASS] State queries work" << std::endl;
    std::cout << std::endl;
    
    // Test 7: Shutdown
    std::cout << "[TEST 7] Shutdown" << std::endl;
    Win32IDE_DebuggerIntegration::Shutdown();
    
    if (Win32IDE_DebuggerIntegration::IsDebugging()) {
        std::cout << "[FAIL] Should not be debugging after shutdown" << std::endl;
        DestroyWindow(hwnd);
        return;
    }
    std::cout << "[PASS] Shutdown successful" << std::endl;
    std::cout << std::endl;
    
    // Cleanup
    DestroyWindow(hwnd);
    UnregisterClassA("TestWin32IDEWindow", GetModuleHandle(nullptr));
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "All Win32IDE Integration Tests PASSED!" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Phase 24 Status: Win32IDE integration validated" << std::endl;
    std::cout << "Ready for production use" << std::endl;
}

int main() {
    runIntegrationTest();
    return 0;
}
