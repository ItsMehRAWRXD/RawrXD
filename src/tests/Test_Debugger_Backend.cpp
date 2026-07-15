// Test_Debugger_Backend.cpp
// Phase 23: Unit tests for Debugger Backend
// ============================================================================

#include "debugger/Debugger_Backend.h"
#include <iostream>
#include <assert>
#include <windows.h>

using namespace RawrXD::Debugger;

// Simple test debuggee that hits a breakpoint
const wchar_t* TEST_DEBUGGEE_CODE = LR"(
#include <windows.h>
int main() {
    DebugBreak();  // Will trigger breakpoint
    return 0;
}
)";

void TestDebuggerInitialization() {
    DebugSession session;
    assert(session.Initialize());
    assert(!session.IsActive());  // Not attached yet
    std::wcout << L"✓ Debugger initialization test passed\n";
}

void TestFormatAddress() {
    std::wstring formatted = FormatAddress(0x140001000);
    assert(formatted == L"0x0000000140001000");
    std::wcout << L"✓ Format address test passed\n";
}

void TestFormatBytes() {
    std::vector<uint8_t> bytes = {0x48, 0x89, 0x5C, 0x24};
    std::wstring formatted = FormatBytes(bytes);
    assert(formatted == L"48 89 5C 24");
    std::wcout << L"✓ Format bytes test passed\n";
}

void TestBreakpointStructure() {
    Breakpoint bp;
    bp.id = 1;
    bp.address = 0x140001000;
    bp.filePath = L"test.cpp";
    bp.lineNumber = 42;
    bp.enabled = true;
    
    assert(bp.id == 1);
    assert(bp.address == 0x140001000);
    assert(bp.lineNumber == 42);
    assert(bp.enabled);
    
    std::wcout << L"✓ Breakpoint structure test passed\n";
}

void TestStackFrameStructure() {
    StackFrame frame;
    frame.frameNumber = 0;
    frame.instructionPointer = 0x140001000;
    frame.functionName = L"main";
    frame.filePath = L"test.cpp";
    frame.lineNumber = 10;
    
    assert(frame.frameNumber == 0);
    assert(frame.instructionPointer == 0x140001000);
    assert(frame.functionName == L"main");
    
    std::wcout << L"✓ Stack frame structure test passed\n";
}

void TestRegisterValueStructure() {
    RegisterValue reg;
    reg.name = L"rax";
    reg.value = 0xDEADBEEF;
    reg.size = 8;
    reg.formatted = L"0x00000000DEADBEEF";
    
    assert(reg.name == L"rax");
    assert(reg.value == 0xDEADBEEF);
    assert(reg.size == 8);
    
    std::wcout << L"✓ Register value structure test passed\n";
}

// Note: This test requires a compiled debuggee
// For now, we just test the API surface
void TestDebugSessionAPI() {
    DebugSession session;
    assert(session.Initialize());
    
    // Test that we can create breakpoints (but not set them without process)
    auto bp = session.SetBreakpointAtAddress(0x140001000);
    // This will fail because no process is active, but shouldn't crash
    
    std::wcout << L"✓ Debug session API test passed\n";
}

int wmain() {
    std::wcout << L"=== Phase 23: Debugger Backend Tests ===\n\n";
    
    try {
        TestDebuggerInitialization();
        TestFormatAddress();
        TestFormatBytes();
        TestBreakpointStructure();
        TestStackFrameStructure();
        TestRegisterValueStructure();
        TestDebugSessionAPI();
        
        std::wcout << L"\n=== All tests passed! ===\n";
        std::wcout << L"\nNote: Full integration tests require:\n";
        std::wcout << L"  1. A compiled test debuggee executable\n";
        std::wcout << L"  2. Running with appropriate privileges\n";
        std::wcout << L"  3. Debug symbols available\n";
        
        return 0;
    } catch (const std::exception& e) {
        std::wcerr << L"\n✗ Test failed: " << e.what() << L"\n";
        return 1;
    }
}
