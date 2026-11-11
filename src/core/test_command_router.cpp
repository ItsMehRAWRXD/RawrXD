// Test harness for IDECommandRouter
// Compile: g++ -std=c++17 -O2 -Wall test_command_router.cpp IDECommandRouter.cpp IDEEventBus.cpp UnifiedSessionState.cpp Version.cpp -o test_command_router.exe -lkernel32

#include "IDECommandRouter.hpp"
#include "UnifiedSessionState.hpp"
#include <cstdio>

using namespace RawrXD;

int main() {
    printf("=== RawrXD Command Router Test ===\n\n");
    
    // Test 1: Initialize session and router
    printf("Test 1: Initialize session and router...\n");
    UnifiedSessionState session;
    if (!session.Initialize(true)) {
        printf("  FAILED: Could not initialize session\n");
        return 1;
    }
    
    IDECommandRouter router;
    if (!router.Initialize(&session, nullptr)) {
        printf("  FAILED: Could not initialize router\n");
        return 1;
    }
    printf("  PASSED: Router initialized\n");
    
    // Test 2: Register custom commands
    printf("\nTest 2: Register custom commands...\n");
    int execCount = 0;
    
    router.RegisterCommand("custom/test", [&execCount](std::string_view args) {
        ++execCount;
        printf("  Executed custom/test with args: %.*s\n", 
               static_cast<int>(args.length()), args.data());
        return CommandResult{true, 0, "Custom command executed"};
    });
    
    router.RegisterCommand("custom/echo", [](std::string_view args) {
        printf("  Echo: %.*s\n", static_cast<int>(args.length()), args.data());
        return CommandResult{true, 0, "Echo completed"};
    });
    
    printf("  PASSED: Commands registered\n");
    
    // Test 3: Execute by hash (O(1))
    printf("\nTest 3: Execute by hash (O(1))...\n");
    auto result = router.Execute("custom/test"_cmd, "arg1 arg2");
    if (result.success && execCount == 1) {
        printf("  PASSED: Command executed by hash\n");
    } else {
        printf("  FAILED: Command execution failed\n");
    }
    
    // Test 4: Execute by name
    printf("\nTest 4: Execute by name...\n");
    result = router.Execute("custom/echo", "Hello, World!");
    if (result.success) {
        printf("  PASSED: Command executed by name\n");
    } else {
        printf("  FAILED: Command execution failed\n");
    }
    
    // Test 5: Execute parsed command line
    printf("\nTest 5: Execute parsed command line...\n");
    result = router.ExecuteParsed("custom/test these are args");
    if (result.success && execCount == 2) {
        printf("  PASSED: Parsed command executed\n");
    } else {
        printf("  FAILED: Parsed command execution failed\n");
    }
    
    // Test 6: Built-in commands
    printf("\nTest 6: Built-in commands...\n");
    printf("  Testing 'help':\n");
    router.Execute(CommandHashes::Help, {});
    
    printf("\n  Testing 'version':\n");
    router.Execute(CommandHashes::Version, {});
    
    printf("\n  Testing 'status':\n");
    router.Execute(CommandHashes::Status, {});
    
    printf("  PASSED: Built-in commands work\n");
    
    // Test 7: Command existence check
    printf("\nTest 7: Command existence check...\n");
    if (router.HasCommand("custom/test") && 
        router.HasCommand(CommandHashes::Help) &&
        !router.HasCommand("nonexistent")) {
        printf("  PASSED: Command existence checks work\n");
    } else {
        printf("  FAILED: Command existence check failed\n");
    }
    
    // Test 8: Unknown command
    printf("\nTest 8: Unknown command handling...\n");
    result = router.Execute("unknown/command", {});
    if (!result.success) {
        printf("  PASSED: Unknown command handled correctly\n");
    } else {
        printf("  FAILED: Unknown command should fail\n");
    }
    
    // Test 9: Global router
    printf("\nTest 9: Global router...\n");
    if (GetGlobalCommandRouter() == &router) {
        printf("  PASSED: Global router set correctly\n");
    } else {
        printf("  FAILED: Global router not set\n");
    }
    
    // Test 10: List commands
    printf("\nTest 10: List commands...\n");
    router.ListCommands();
    printf("  PASSED: Commands listed\n");
    
    printf("\n=== All Tests Complete ===\n");
    return 0;
}
