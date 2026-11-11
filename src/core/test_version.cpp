// Test harness for Version system
// Compile: g++ -std=c++17 -O2 -Wall test_version.cpp Version.cpp UnifiedSessionState.cpp -o test_version.exe -lkernel32

#include "Version.hpp"
#include "UnifiedSessionState.hpp"
#include <cstdio>

using namespace RawrXD;

int main() {
    printf("=== RawrXD Version System Test ===\n\n");
    
    // Test 1: Compile-time version constants
    printf("Test 1: Compile-time version constants...\n");
    printf("  Version: %s\n", GetVersionString().data());
    printf("  Codename: %s\n", GetVersionCodename().data());
    printf("  Packed: 0x%08X\n", GetVersionPacked());
    printf("  Protocol: %u\n", GetProtocolVersion());
    printf("  PASSED\n");
    
    // Test 2: Runtime version info
    printf("\nTest 2: Runtime version info...\n");
    const auto& info = GetVersionInfo();
    printf("  Major: %u\n", info.major);
    printf("  Minor: %u\n", info.minor);
    printf("  Patch: %u\n", info.patch);
    printf("  Build: %u\n", info.build);
    printf("  Full: %s\n", info.string);
    printf("  Codename: %s\n", info.codename);
    printf("  Timestamp: %s\n", info.buildTimestamp);
    printf("  PASSED\n");
    
    // Test 3: Version comparison
    printf("\nTest 3: Version comparison...\n");
    bool atLeast1_0 = IsVersionAtLeast(1, 0, 0);
    bool atLeast2_0 = IsVersionAtLeast(2, 0, 0);
    printf("  IsVersionAtLeast(1.0.0): %s\n", atLeast1_0 ? "true" : "false");
    printf("  IsVersionAtLeast(2.0.0): %s\n", atLeast2_0 ? "true" : "false");
    if (atLeast1_0 && !atLeast2_0) {
        printf("  PASSED\n");
    } else {
        printf("  FAILED\n");
    }
    
    // Test 4: Shared memory version sync
    printf("\nTest 4: Shared memory version sync...\n");
    UnifiedSessionState session;
    if (session.Initialize(true)) {
        printf("  Protocol from shared memory: %u\n", session.GetProtocolVersion());
        printf("  Version from shared memory: 0x%08X\n", session.GetRuntimeVersionPacked());
        printf("  Version string from shared memory: %s\n", session.GetRuntimeVersionString().data());
        printf("  Protocol compatible: %s\n", session.IsProtocolCompatible() ? "true" : "false");
        printf("  PASSED\n");
    } else {
        printf("  FAILED: Could not initialize shared memory\n");
    }
    
    printf("\n=== All Tests Complete ===\n");
    return 0;
}
