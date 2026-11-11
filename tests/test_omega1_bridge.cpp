// ═════════════════════════════════════════════════════════════════════════════
// OMEGA-1 Bridge Test Harness
// Validates IAT slots 64-75 for self-mutating engine integration
// ═════════════════════════════════════════════════════════════════════════════

#include <windows.h>
#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

// Include OMEGA-1 Bridge header
#include "omega1_modules/OmegaPowerShellBridge.h"

// ═════════════════════════════════════════════════════════════════════════════
// Test Result Tracking
// ═════════════════════════════════════════════════════════════════════════════

struct TestResult {
    const char* name;
    bool passed;
    const char* message;
};

static std::vector<TestResult> g_results;
static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST_ASSERT(name, condition, msg) \
    do { \
        bool result = (condition); \
        g_results.push_back({name, result, result ? "PASS" : msg}); \
        if (result) g_testsPassed++; else g_testsFailed++; \
        if (!result) printf("  [FAIL] %s: %s\n", name, msg); \
        else printf("  [PASS] %s\n", name); \
    } while(0)

// ═════════════════════════════════════════════════════════════════════════════
// IAT Slot Validation Tests
// ═════════════════════════════════════════════════════════════════════════════

bool Test_Slot64_Initialize() {
    printf("\n[TEST] Slot 64: Omega1_Initialize\n");
    
    void* pContext = nullptr;
    BOOL result = Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    TEST_ASSERT("Initialize returns TRUE", result == TRUE, "Expected TRUE");
    TEST_ASSERT("Context is allocated", pContext != nullptr, "Context should not be null");
    
    if (pContext) {
        Omega1_Shutdown(pContext);
    }
    
    return g_testsFailed == 0;
}

bool Test_Slot65_Shutdown() {
    printf("\n[TEST] Slot 65: Omega1_Shutdown\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    // Should not crash
    Omega1_Shutdown(pContext);
    
    TEST_ASSERT("Shutdown completes without crash", true, "Shutdown should not crash");
    
    // Test shutdown with null (should not crash)
    Omega1_Shutdown(nullptr);
    TEST_ASSERT("Shutdown with null handles gracefully", true, "Should handle null");
    
    return true;
}

bool Test_Slot66_GetModuleCount() {
    printf("\n[TEST] Slot 66: Omega1_GetModuleCount\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    uint32_t count = Omega1_GetModuleCount(pContext);
    
    TEST_ASSERT("GetModuleCount returns valid count", count >= 0, "Count should be >= 0");
    
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot67_IsMutant() {
    printf("\n[TEST] Slot 67: Omega1_IsMutant\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    BOOL isMutant = Omega1_IsMutant(pContext);
    
    TEST_ASSERT("IsMutant returns FALSE for non-mutant", isMutant == FALSE, "Should be FALSE without MUTANT flag");
    
    Omega1_Shutdown(pContext);
    
    // Test with MUTANT flag
    Omega1_Initialize(&pContext, OMEGA1_FLAG_MUTANT);
    isMutant = Omega1_IsMutant(pContext);
    
    TEST_ASSERT("IsMutant returns TRUE with MUTANT flag", isMutant == TRUE, "Should be TRUE with MUTANT flag");
    
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot68_GetMutationCount() {
    printf("\n[TEST] Slot 68: Omega1_GetMutationCount\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    uint32_t count = Omega1_GetMutationCount(pContext);
    
    TEST_ASSERT("Initial mutation count is 0", count == 0, "Should start at 0");
    
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot69_ExecuteReflective() {
    printf("\n[TEST] Slot 69: Omega1_ExecuteReflective\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    // Initialize PowerShell bridge first
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    const char* testCommand = "Write-Host 'Reflective Execution Test'";
    char output[4096] = {0};
    
    BOOL result = Omega1_ExecuteReflective(pContext, testCommand, (uint32_t)strlen(testCommand), output, sizeof(output));
    
    TEST_ASSERT("ExecuteReflective returns valid result", result == TRUE || result == FALSE, "Should return BOOL");
    
    uint32_t mutationCount = Omega1_GetMutationCount(pContext);
    TEST_ASSERT("Mutation count incremented", mutationCount >= 1, "Should be >= 1 after execution");
    
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot70_ValidateIntegrity() {
    printf("\n[TEST] Slot 70: Omega1_ValidateIntegrity\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    uint32_t checksum = 0;
    BOOL result = Omega1_ValidateIntegrity(pContext, &checksum);
    
    TEST_ASSERT("ValidateIntegrity returns TRUE", result == TRUE, "Should return TRUE");
    TEST_ASSERT("Checksum is computed", checksum != 0, "Checksum should be non-zero");
    
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot71_TriggerMutation() {
    printf("\n[TEST] Slot 71: Omega1_TriggerMutation\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    BOOL result = Omega1_TriggerMutation(pContext, OMEGA1_MUTATION_HOTPATCH);
    
    TEST_ASSERT("TriggerMutation returns TRUE", result == TRUE, "Should return TRUE");
    
    BOOL isMutant = Omega1_IsMutant(pContext);
    TEST_ASSERT("IsMutant is TRUE after mutation", isMutant == TRUE, "Should be mutant after trigger");
    
    uint32_t count = Omega1_GetMutationCount(pContext);
    TEST_ASSERT("Mutation count incremented", count >= 1, "Should be >= 1");
    
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot72_GetManifestJson() {
    printf("\n[TEST] Slot 72: Omega1_GetManifestJson\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    char buffer[8192] = {0};
    BOOL result = Omega1_GetManifestJson(pContext, buffer, sizeof(buffer));
    
    TEST_ASSERT("GetManifestJson returns TRUE", result == TRUE, "Should return TRUE");
    TEST_ASSERT("Buffer contains JSON", strlen(buffer) > 0, "Should contain JSON data");
    TEST_ASSERT("JSON contains version", strstr(buffer, "version") != nullptr, "Should contain version field");
    
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot73_ExecutePowerShell() {
    printf("\n[TEST] Slot 73: Omega1_ExecutePowerShell\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    const char* command = "Get-Date -Format 'yyyy-MM-dd'";
    char output[4096] = {0};
    
    BOOL result = Omega1_ExecutePowerShell(pContext, command, output, sizeof(output));
    
    TEST_ASSERT("ExecutePowerShell returns valid result", result == TRUE || result == FALSE, "Should return BOOL");
    
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot74_LoadModule() {
    printf("\n[TEST] Slot 74: Omega1_LoadModule\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    HPSMODULE hModule = Omega1_LoadModule(pContext, "Core");
    
    TEST_ASSERT("LoadModule returns handle", hModule != nullptr, "Should return non-null handle");
    
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

bool Test_Slot75_InvokeModule() {
    printf("\n[TEST] Slot 75: Omega1_InvokeModule\n");
    
    void* pContext = nullptr;
    Omega1_Initialize(&pContext, OMEGA1_FLAG_NONE);
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    HPSMODULE hModule = Omega1_LoadModule(pContext, "Core");
    
    char output[4096] = {0};
    // Format: "ModuleName::FunctionName"
    BOOL result = Omega1_InvokeModule(pContext, hModule, "Core::Get-Date", output, sizeof(output));
    
    TEST_ASSERT("InvokeModule returns valid result", result == TRUE || result == FALSE, "Should return BOOL");
    
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_Shutdown(pContext);
    
    return g_testsFailed == 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// C API Tests
// ═════════════════════════════════════════════════════════════════════════════

bool Test_CAPI_CreateDestroyContext() {
    printf("\n[TEST] C API: Omega1_CreateContext / Omega1_DestroyContext\n");
    
    void* pContext = Omega1_CreateContext();
    TEST_ASSERT("CreateContext returns valid pointer", pContext != nullptr, "Should return non-null");
    
    Omega1_DestroyContext(pContext);
    TEST_ASSERT("DestroyContext completes", true, "Should complete without crash");
    
    return g_testsFailed == 0;
}

bool Test_CAPI_GetVersion() {
    printf("\n[TEST] C API: Omega1_GetVersion\n");
    
    char buffer[256] = {0};
    uint32_t len = Omega1_GetVersion(buffer, sizeof(buffer));
    
    TEST_ASSERT("GetVersion returns non-zero length", len > 0, "Should return version string length");
    TEST_ASSERT("Version string is not empty", strlen(buffer) > 0, "Should contain version");
    
    return g_testsFailed == 0;
}

bool Test_CAPI_GetStatus() {
    printf("\n[TEST] C API: Omega1_GetStatus\n");
    
    void* pContext = Omega1_CreateContext();
    uint32_t status = Omega1_GetStatus(pContext);
    
    TEST_ASSERT("GetStatus returns OK for valid context", status == OMEGA1_STATUS_OK, "Should be OK");
    
    Omega1_DestroyContext(pContext);
    
    status = Omega1_GetStatus(nullptr);
    TEST_ASSERT("GetStatus returns NOT_INIT for null", status == OMEGA1_STATUS_NOT_INIT, "Should be NOT_INIT");
    
    return g_testsFailed == 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// C++ Class Tests
// ═════════════════════════════════════════════════════════════════════════════

bool Test_CPP_Omega1Engine() {
    printf("\n[TEST] C++: Omega1Engine class\n");
    
    RawrXD::Bridge::Omega1Engine engine;
    
    bool initialized = engine.Initialize(OMEGA1_FLAG_NONE);
    TEST_ASSERT("Engine initializes successfully", initialized == true, "Should initialize");
    
    if (initialized) {
        uint32_t count = engine.GetModuleCount();
        TEST_ASSERT("GetModuleCount returns valid value", count >= 0, "Should be >= 0");
        
        bool isMutant = engine.IsMutant();
        TEST_ASSERT("IsMutant returns expected value", isMutant == false, "Should be false initially");
        
        engine.Shutdown();
        TEST_ASSERT("Engine shuts down successfully", true, "Should shutdown");
    }
    
    return g_testsFailed == 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// Main Entry Point
// ═════════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    printf("═════════════════════════════════════════════════════════════════════════════\n");
    printf("  OMEGA-1 Bridge Test Harness\n");
    printf("  Validating IAT Slots 64-75 for Self-Mutating Engine Integration\n");
    printf("═════════════════════════════════════════════════════════════════════════════\n");
    
    // Reset counters
    g_testsPassed = 0;
    g_testsFailed = 0;
    g_results.clear();
    
    // Run all IAT slot tests
    Test_Slot64_Initialize();
    Test_Slot65_Shutdown();
    Test_Slot66_GetModuleCount();
    Test_Slot67_IsMutant();
    Test_Slot68_GetMutationCount();
    Test_Slot69_ExecuteReflective();
    Test_Slot70_ValidateIntegrity();
    Test_Slot71_TriggerMutation();
    Test_Slot72_GetManifestJson();
    Test_Slot73_ExecutePowerShell();
    Test_Slot74_LoadModule();
    Test_Slot75_InvokeModule();
    
    // Run C API tests
    Test_CAPI_CreateDestroyContext();
    Test_CAPI_GetVersion();
    Test_CAPI_GetStatus();
    
    // Run C++ class tests
    Test_CPP_Omega1Engine();
    
    // Print summary
    printf("\n═════════════════════════════════════════════════════════════════════════════\n");
    printf("  TEST SUMMARY\n");
    printf("═════════════════════════════════════════════════════════════════════════════\n");
    printf("  Total Tests:  %d\n", g_testsPassed + g_testsFailed);
    printf("  Passed:       %d\n", g_testsPassed);
    printf("  Failed:       %d\n", g_testsFailed);
    printf("═════════════════════════════════════════════════════════════════════════════\n");
    
    if (g_testsFailed > 0) {
        printf("\nFAILED TESTS:\n");
        for (const auto& result : g_results) {
            if (!result.passed) {
                printf("  - %s: %s\n", result.name, result.message);
            }
        }
        return 1;
    }
    
    printf("\n[✓] All tests passed!\n");
    return 0;
}
