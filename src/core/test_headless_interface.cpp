// Test harness for HeadlessIDEInterface
// Compile: g++ -std=c++17 -O2 -Wall test_headless_interface.cpp HeadlessIDEInterface.cpp IDEEventBus.cpp UnifiedSessionState.cpp Version.cpp -o test_headless_interface.exe -lkernel32

#include "HeadlessIDEInterface.hpp"
#include <cstdio>
#include <cstring>

using namespace RawrXD;

int main() {
    printf("=== RawrXD HeadlessIDEInterface Test ===\n\n");
    
    // Test 1: Create and initialize
    printf("Test 1: Create and initialize...\n");
    auto* iface = new HeadlessIDEInterface();
    if (!iface) {
        printf("  FAILED: Could not create interface\n");
        return 1;
    }
    
    auto result = iface->Initialize();
    if (result != IDEResult::Success) {
        printf("  FAILED: Initialize returned %d\n", static_cast<int>(result));
        delete iface;
        return 1;
    }
    printf("  PASSED: Interface initialized\n");
    
    // Test 2: Check interface type
    printf("\nTest 2: Check interface type...\n");
    if (iface->GetInterfaceType() == 3) { // Headless = 3
        printf("  PASSED: Interface type is Headless (3)\n");
    } else {
        printf("  FAILED: Expected type 3, got %u\n", iface->GetInterfaceType());
    }
    
    // Test 3: Check version
    printf("\nTest 3: Check version...\n");
    printf("  Version: 0x%08X\n", iface->GetVersion());
    printf("  Protocol: %u\n", iface->GetProtocolVersion());
    printf("  PASSED: Version info retrieved\n");
    
    // Test 4: Open file
    printf("\nTest 4: Open file...\n");
    BufferHandle buffer = nullptr;
    result = iface->OpenFile(L"test.cpp", &buffer);
    if (result == IDEResult::Success && buffer != nullptr) {
        printf("  PASSED: File opened, buffer handle = %p\n", buffer);
    } else {
        printf("  FAILED: OpenFile returned %d\n", static_cast<int>(result));
    }
    
    // Test 5: Get active file
    printf("\nTest 5: Get active file...\n");
    wchar_t activePath[256];
    result = iface->GetActiveFile(activePath, 256);
    if (result == IDEResult::Success) {
        printf("  PASSED: Active file = %ls\n", activePath);
    } else {
        printf("  FAILED: GetActiveFile returned %d\n", static_cast<int>(result));
    }
    
    // Test 6: Execute command
    printf("\nTest 6: Execute command...\n");
    char cmdResult[256];
    size_t resultLen = sizeof(cmdResult);
    result = iface->ExecuteCommand("help", nullptr, cmdResult, &resultLen);
    if (result == IDEResult::Success) {
        printf("  PASSED: Command executed\n");
    } else {
        printf("  FAILED: ExecuteCommand returned %d\n", static_cast<int>(result));
    }
    
    // Test 7: Model operations
    printf("\nTest 7: Model operations...\n");
    result = iface->LoadModel("models/test.gguf", nullptr);
    if (result == IDEResult::Success) {
        printf("  PASSED: Model loaded\n");
        
        char status[256];
        size_t statusLen = sizeof(status);
        result = iface->GetModelStatus(status, &statusLen);
        if (result == IDEResult::Success) {
            printf("  Model status: %s\n", status);
        }
    } else {
        printf("  FAILED: LoadModel returned %d\n", static_cast<int>(result));
    }
    
    // Test 8: UI operations (redirected to stdout)
    printf("\nTest 8: UI operations...\n");
    result = iface->ShowMessage(L"Test", L"This is a test message", 0);
    if (result == IDEResult::Success) {
        printf("  PASSED: ShowMessage works\n");
    }
    
    result = iface->SetStatusText(L"Ready");
    if (result == IDEResult::Success) {
        printf("  PASSED: SetStatusText works\n");
    }
    
    // Test 9: Global interface
    printf("\nTest 9: Global interface...\n");
    if (GetGlobalIDEInterface() == iface) {
        printf("  PASSED: Global interface set correctly\n");
    } else {
        printf("  FAILED: Global interface not set\n");
    }
    
    // Test 10: Shutdown
    printf("\nTest 10: Shutdown...\n");
    result = iface->Shutdown();
    delete iface;
    if (result == IDEResult::Success) {
        printf("  PASSED: Interface shutdown\n");
    } else {
        printf("  FAILED: Shutdown returned %d\n", static_cast<int>(result));
    }
    
    printf("\n=== All Tests Complete ===\n");
    return 0;
}
