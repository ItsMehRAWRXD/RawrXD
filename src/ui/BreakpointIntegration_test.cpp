// ============================================================================
// Phase 25: Breakpoint Integration Test
// ============================================================================
// Validates the breakpoint lifecycle without requiring an actual debugger

#include "ui/BreakpointIntegration.hpp"
#include "ui/BreakpointsGutter.h"
#include <iostream>
#include <string>
#include <windows.h>
#include <set>

using namespace RawrXD;

// Mock BreakpointsGutter for testing
class MockBreakpointsGutter : public UI::BreakpointsGutter {
public:
    std::set<uint32_t> enabledBreakpoints;
    std::set<uint32_t> disabledBreakpoints;
    std::set<uint32_t> hitBreakpoints;
    uint32_t currentLine = 0;
    bool wasCleared = false;
    
    void SetBreakpointState(uint32_t lineNumber, UI::BreakpointVisualState state) {
        switch (state) {
            case UI::BreakpointVisualState::Enabled:
                enabledBreakpoints.insert(lineNumber);
                disabledBreakpoints.erase(lineNumber);
                hitBreakpoints.erase(lineNumber);
                break;
            case UI::BreakpointVisualState::Disabled:
                disabledBreakpoints.insert(lineNumber);
                enabledBreakpoints.erase(lineNumber);
                hitBreakpoints.erase(lineNumber);
                break;
            case UI::BreakpointVisualState::Hit:
                hitBreakpoints.insert(lineNumber);
                break;
            default:
                enabledBreakpoints.erase(lineNumber);
                disabledBreakpoints.erase(lineNumber);
                hitBreakpoints.erase(lineNumber);
                break;
        }
    }
    
    void ClearBreakpointState(uint32_t lineNumber) {
        enabledBreakpoints.erase(lineNumber);
        disabledBreakpoints.erase(lineNumber);
        hitBreakpoints.erase(lineNumber);
    }
    
    void ClearAllBreakpoints() {
        enabledBreakpoints.clear();
        disabledBreakpoints.clear();
        hitBreakpoints.clear();
        wasCleared = true;
    }
    
    void SetCurrentLine(uint32_t lineNumber) {
        currentLine = lineNumber;
    }
    
    void ClearCurrentLine() {
        currentLine = 0;
    }
};

void runBreakpointTest() {
    std::cout << "========================================" << std::endl;
    std::cout << "Phase 25: Breakpoint Integration Test" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Test 1: Initial state
    std::cout << "[TEST 1] Initial state" << std::endl;
    if (UI::BreakpointIntegration::IsInitialized()) {
        std::cout << "[FAIL] Should not be initialized" << std::endl;
        return;
    }
    std::cout << "[PASS] Initial state correct" << std::endl;
    std::cout << std::endl;
    
    // Test 2: Initialization
    std::cout << "[TEST 2] Initialization" << std::endl;
    MockBreakpointsGutter mockGutter;
    
    if (!UI::BreakpointIntegration::Initialize(&mockGutter)) {
        std::cout << "[FAIL] Initialize failed" << std::endl;
        return;
    }
    
    if (!UI::BreakpointIntegration::IsInitialized()) {
        std::cout << "[FAIL] Should be initialized" << std::endl;
        return;
    }
    std::cout << "[PASS] Initialized successfully" << std::endl;
    std::cout << std::endl;
    
    // Test 3: Set current file
    std::cout << "[TEST 3] Set current file" << std::endl;
    UI::BreakpointIntegration::SetCurrentFile(L"C:\\test\\main.cpp");
    
    if (UI::BreakpointIntegration::GetCurrentFile() != L"C:\\test\\main.cpp") {
        std::cout << "[FAIL] File not set correctly" << std::endl;
        return;
    }
    std::cout << "[PASS] Current file set" << std::endl;
    std::cout << std::endl;
    
    // Test 4: Set breakpoint
    std::cout << "[TEST 4] Set breakpoint" << std::endl;
    if (!UI::BreakpointIntegration::SetBreakpoint(42)) {
        std::cout << "[FAIL] SetBreakpoint failed" << std::endl;
        return;
    }
    
    if (!UI::BreakpointIntegration::HasBreakpoint(42)) {
        std::cout << "[FAIL] Breakpoint not recorded" << std::endl;
        return;
    }
    
    if (mockGutter.enabledBreakpoints.find(42) == mockGutter.enabledBreakpoints.end()) {
        std::cout << "[FAIL] Gutter not updated" << std::endl;
        return;
    }
    std::cout << "[PASS] Breakpoint set at line 42" << std::endl;
    std::cout << std::endl;
    
    // Test 5: Toggle breakpoint (clear)
    std::cout << "[TEST 5] Toggle breakpoint (clear)" << std::endl;
    bool wasSet = UI::BreakpointIntegration::ToggleBreakpoint(42);
    if (wasSet) {
        std::cout << "[FAIL] Toggle should have cleared breakpoint" << std::endl;
        return;
    }
    
    if (UI::BreakpointIntegration::HasBreakpoint(42)) {
        std::cout << "[FAIL] Breakpoint should be cleared" << std::endl;
        return;
    }
    std::cout << "[PASS] Breakpoint cleared" << std::endl;
    std::cout << std::endl;
    
    // Test 6: Toggle breakpoint (set)
    std::cout << "[TEST 6] Toggle breakpoint (set)" << std::endl;
    wasSet = UI::BreakpointIntegration::ToggleBreakpoint(100);
    if (!wasSet) {
        std::cout << "[FAIL] Toggle should have set breakpoint" << std::endl;
        return;
    }
    
    if (!UI::BreakpointIntegration::HasBreakpoint(100)) {
        std::cout << "[FAIL] Breakpoint should exist" << std::endl;
        return;
    }
    std::cout << "[PASS] Breakpoint set at line 100" << std::endl;
    std::cout << std::endl;
    
    // Test 7: Breakpoint verification
    std::cout << "[TEST 7] Breakpoint verification" << std::endl;
    UI::BreakpointIntegration::SetBreakpoint(50);
    UI::BreakpointIntegration::OnBreakpointVerified(50, 50, true, 123);
    
    auto state = UI::BreakpointIntegration::GetBreakpointState(50);
    if (state != UI::BreakpointLifecycleState::Verified) {
        std::cout << "[FAIL] State should be Verified" << std::endl;
        return;
    }
    std::cout << "[PASS] Breakpoint verified" << std::endl;
    std::cout << std::endl;
    
    // Test 8: Breakpoint hit
    std::cout << "[TEST 8] Breakpoint hit" << std::endl;
    UI::BreakpointIntegration::OnBreakpointHit(50);
    
    if (mockGutter.currentLine != 50) {
        std::cout << "[FAIL] Current line not set" << std::endl;
        return;
    }
    std::cout << "[PASS] Breakpoint hit indicator shown" << std::endl;
    std::cout << std::endl;
    
    // Test 9: Clear hit indicator
    std::cout << "[TEST 9] Clear hit indicator" << std::endl;
    UI::BreakpointIntegration::ClearHitIndicator();
    
    if (mockGutter.currentLine != 0) {
        std::cout << "[FAIL] Current line should be cleared" << std::endl;
        return;
    }
    std::cout << "[PASS] Hit indicator cleared" << std::endl;
    std::cout << std::endl;
    
    // Test 10: Get breakpoints in file
    std::cout << "[TEST 10] Get breakpoints in file" << std::endl;
    auto bps = UI::BreakpointIntegration::GetBreakpointsInCurrentFile();
    if (bps.size() != 2) {
        std::cout << "[FAIL] Expected 2 breakpoints, got " << bps.size() << std::endl;
        return;
    }
    std::cout << "[PASS] Retrieved " << bps.size() << " breakpoints" << std::endl;
    std::cout << std::endl;
    
    // Test 11: Clear all breakpoints
    std::cout << "[TEST 11] Clear all breakpoints" << std::endl;
    UI::BreakpointIntegration::ClearAllBreakpoints();
    
    bps = UI::BreakpointIntegration::GetBreakpointsInCurrentFile();
    if (!bps.empty()) {
        std::cout << "[FAIL] Expected 0 breakpoints" << std::endl;
        return;
    }
    
    if (!mockGutter.wasCleared) {
        std::cout << "[FAIL] Gutter should be cleared" << std::endl;
        return;
    }
    std::cout << "[PASS] All breakpoints cleared" << std::endl;
    std::cout << std::endl;
    
    // Test 12: Shutdown
    std::cout << "[TEST 12] Shutdown" << std::endl;
    UI::BreakpointIntegration::Shutdown();
    
    if (UI::BreakpointIntegration::IsInitialized()) {
        std::cout << "[FAIL] Should not be initialized after shutdown" << std::endl;
        return;
    }
    std::cout << "[PASS] Shutdown successful" << std::endl;
    std::cout << std::endl;
    
    // Summary
    std::cout << "========================================" << std::endl;
    std::cout << "All Breakpoint Tests PASSED!" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    std::cout << "Phase 25 Status: Breakpoint lifecycle validated" << std::endl;
    std::cout << "Ready for production use" << std::endl;
}

int main() {
    runBreakpointTest();
    return 0;
}
