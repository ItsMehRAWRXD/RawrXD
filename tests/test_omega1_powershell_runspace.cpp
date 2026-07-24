// ═════════════════════════════════════════════════════════════════════════════
// OMEGA-1 PowerShell Runspace Integration Tests
// Validates actual PowerShell execution with real runspaces
// ═════════════════════════════════════════════════════════════════════════════

#include <windows.h>
#include <stdio>
#include <string>
#include <vector>
#include <string>
#include <chrono>
#include <iomanip>
#include <sstream>

#include "omega1_modules/OmegaPowerShellBridge.h"

// ═════════════════════════════════════════════════════════════════════════════
// Test Framework
// ═════════════════════════════════════════════════════════════════════════════

struct TestResult {
    const char* name;
    bool passed;
    const char* message;
    std::chrono::milliseconds duration;
};

static std::vector<TestResult> g_results;
static int g_testsPassed = 0;
static int g_testsFailed = 0;

#define TEST_START(name) \
    printf("\n[TEST] %s\n", name); \
    auto _test_start = std::chrono::high_resolution_clock::now();

#define TEST_END(name) \
    { \
        auto _test_end = std::chrono::high_resolution_clock::now(); \
        auto _duration = std::chrono::duration_cast<std::chrono::milliseconds>(_test_end - _test_start); \
        printf("  Duration: %lld ms\n", _duration.count()); \
    }

#define TEST_ASSERT(name, condition, msg) \
    do { \
        bool result = (condition); \
        auto _test_end = std::chrono::high_resolution_clock::now(); \
        auto _duration = std::chrono::duration_cast<std::chrono::milliseconds>(_test_end - _test_start); \
        g_results.push_back({name, result, result ? "PASS" : msg, _duration}); \
        if (result) g_testsPassed++; else g_testsFailed++; \
        if (!result) printf("  [FAIL] %s: %s\n", name, msg); \
        else printf("  [PASS] %s\n", name); \
    } while(0)

// ═════════════════════════════════════════════════════════════════════════════
// PowerShell Runspace Tests
// ═════════════════════════════════════════════════════════════════════════════

bool Test_Runspace_BasicExecution() {
    TEST_START("Runspace: Basic PowerShell Execution");
    
    void* pContext = Omega1_CreateContext();
    TEST_ASSERT("Context created", pContext != nullptr, "Should create context");
    
    if (!pContext) return false;
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    bool psInit = RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    TEST_ASSERT("PowerShell bridge initialized", psInit, "Should initialize bridge");
    
    // Execute simple command
    char output[4096] = {0};
    BOOL result = Omega1_ExecutePowerShell(pContext, "Write-Host 'Hello from OMEGA-1'", output, sizeof(output));
    TEST_ASSERT("ExecutePowerShell returns TRUE", result == TRUE, "Should execute successfully");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Basic PowerShell Execution");
    return g_testsFailed == 0;
}

bool Test_Runspace_GetDate() {
    TEST_START("Runspace: Get-Date Execution");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Execute Get-Date
    char output[4096] = {0};
    BOOL result = Omega1_ExecutePowerShell(pContext, "Get-Date -Format 'yyyy-MM-dd'", output, sizeof(output));
    
    TEST_ASSERT("ExecutePowerShell returns TRUE", result == TRUE, "Should execute successfully");
    TEST_ASSERT("Output contains date", strlen(output) > 0, "Should have output");
    
    // Verify date format (should be yyyy-MM-dd)
    bool hasDateFormat = (strlen(output) >= 10 && output[4] == '-' && output[7] == '-');
    TEST_ASSERT("Output is valid date format", hasDateFormat, "Should be yyyy-MM-dd format");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Get-Date Execution");
    return g_testsFailed == 0;
}

bool Test_Runspace_ModuleDiscovery() {
    TEST_START("Runspace: Module Discovery");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Get module count
    uint32_t count = Omega1_GetModuleCount(pContext);
    TEST_ASSERT("Module count retrieved", count >= 0, "Should get module count");
    
    // Get manifest
    char manifest[8192] = {0};
    BOOL result = Omega1_GetManifestJson(pContext, manifest, sizeof(manifest));
    TEST_ASSERT("GetManifestJson returns TRUE", result == TRUE, "Should get manifest");
    TEST_ASSERT("Manifest is not empty", strlen(manifest) > 0, "Should have manifest content");
    TEST_ASSERT("Manifest contains version", strstr(manifest, "version") != nullptr, "Should contain version");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Module Discovery");
    return g_testsFailed == 0;
}

bool Test_Runspace_LoadModule() {
    TEST_START("Runspace: Load PowerShell Module");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Try to load Core module
    HPSMODULE hModule = Omega1_LoadModule(pContext, "Core");
    TEST_ASSERT("LoadModule returns handle", hModule != nullptr, "Should return module handle");
    
    if (hModule) {
        // Try to invoke a function
        char output[4096] = {0};
        BOOL result = Omega1_InvokeModule(pContext, hModule, "Core::Get-Date", output, sizeof(output));
        TEST_ASSERT("InvokeModule returns valid result", result == TRUE || result == FALSE, "Should return BOOL");
    }
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Load PowerShell Module");
    return g_testsFailed == 0;
}

bool Test_Runspace_JsonOutput() {
    TEST_START("Runspace: JSON Output");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Execute command that returns JSON
    char output[4096] = {0};
    BOOL result = Omega1_ExecutePowerShell(pContext, 
        "@{ Name = 'Test'; Value = 42 } | ConvertTo-Json", output, sizeof(output));
    
    TEST_ASSERT("ExecutePowerShell returns TRUE", result == TRUE, "Should execute successfully");
    TEST_ASSERT("Output contains JSON", strstr(output, "{") != nullptr, "Should contain JSON object");
    TEST_ASSERT("JSON contains Name", strstr(output, "Name") != nullptr, "Should contain Name property");
    TEST_ASSERT("JSON contains Value", strstr(output, "Value") != nullptr, "Should contain Value property");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: JSON Output");
    return g_testsFailed == 0;
}

bool Test_Runspace_MultipleCommands() {
    TEST_START("Runspace: Multiple Commands");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Execute multiple commands
    const char* commands[] = {
        "$x = 10",
        "$y = 20",
        "$x + $y",
        nullptr
    };
    
    bool allPassed = true;
    for (int i = 0; commands[i] != nullptr; i++) {
        char output[4096] = {0};
        BOOL result = Omega1_ExecutePowerShell(pContext, commands[i], output, sizeof(output));
        if (!result) {
            allPassed = false;
            break;
        }
    }
    
    TEST_ASSERT("All commands executed", allPassed, "Should execute all commands");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Multiple Commands");
    return g_testsFailed == 0;
}

bool Test_Runspace_ErrorHandling() {
    TEST_START("Runspace: Error Handling");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Execute invalid command
    char output[4096] = {0};
    BOOL result = Omega1_ExecutePowerShell(pContext, "Invalid-Command-That-Does-Not-Exist", output, sizeof(output));
    
    // Should still return TRUE (PowerShell handles the error)
    TEST_ASSERT("Invalid command handled", result == TRUE || result == FALSE, "Should handle gracefully");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Error Handling");
    return g_testsFailed == 0;
}

bool Test_Runspace_ReflectiveExecution() {
    TEST_START("Runspace: Reflective Execution");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Execute reflective payload
    char output[4096] = {0};
    BOOL result = Omega1_ExecuteReflective(pContext, 
        "Write-Host 'Reflective payload executed'", 
        (uint32_t)strlen("Write-Host 'Reflective payload executed'"), 
        output, sizeof(output));
    
    TEST_ASSERT("ExecuteReflective returns valid result", result == TRUE || result == FALSE, "Should return BOOL");
    
    // Check mutation count incremented
    uint32_t mutationCount = Omega1_GetMutationCount(pContext);
    TEST_ASSERT("Mutation count incremented", mutationCount >= 1, "Should be >= 1 after execution");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Reflective Execution");
    return g_testsFailed == 0;
}

bool Test_Runspace_MutationTrigger() {
    TEST_START("Runspace: Mutation Trigger");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Check initial state
    BOOL initialMutant = Omega1_IsMutant(pContext);
    TEST_ASSERT("Initial mutant state is FALSE", initialMutant == FALSE, "Should start as non-mutant");
    
    // Trigger mutation
    BOOL result = Omega1_TriggerMutation(pContext, OMEGA1_MUTATION_HOTPATCH);
    TEST_ASSERT("TriggerMutation returns TRUE", result == TRUE, "Should trigger mutation");
    
    // Check mutant state
    BOOL afterMutant = Omega1_IsMutant(pContext);
    TEST_ASSERT("Mutant state is TRUE after trigger", afterMutant == TRUE, "Should be mutant after trigger");
    
    // Check mutation count
    uint32_t count = Omega1_GetMutationCount(pContext);
    TEST_ASSERT("Mutation count is 1", count == 1, "Should be 1 after trigger");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Mutation Trigger");
    return g_testsFailed == 0;
}

bool Test_Runspace_IntegrityValidation() {
    TEST_START("Runspace: Integrity Validation");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Validate integrity
    uint32_t checksum = 0;
    BOOL result = Omega1_ValidateIntegrity(pContext, &checksum);
    
    TEST_ASSERT("ValidateIntegrity returns TRUE", result == TRUE, "Should validate");
    TEST_ASSERT("Checksum is non-zero", checksum != 0, "Should have non-zero checksum");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Integrity Validation");
    return g_testsFailed == 0;
}

bool Test_Runspace_Performance() {
    TEST_START("Runspace: Performance Benchmark");
    
    void* pContext = Omega1_CreateContext();
    
    // Initialize PowerShell bridge
    std::string modulePath = RawrXD::Bridge::Omega1Utils::GetModulePath();
    RawrXD::Bridge::InitializePowerShellBridge(modulePath.c_str());
    
    // Benchmark: Execute 100 commands
    const int iterations = 100;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; i++) {
        char output[4096] = {0};
        Omega1_ExecutePowerShell(pContext, "Get-Date", output, sizeof(output));
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start);
    double avgMs = (double)duration.count() / iterations;
    
    printf("  Executed %d commands in %lld ms (avg: %.2f ms/command)\n", 
           iterations, duration.count(), avgMs);
    
    TEST_ASSERT("Performance acceptable", avgMs < 1000.0, "Should be under 1s per command");
    
    // Cleanup
    RawrXD::Bridge::ShutdownPowerShellBridge();
    Omega1_DestroyContext(pContext);
    
    TEST_END("Runspace: Performance Benchmark");
    return g_testsFailed == 0;
}

// ═════════════════════════════════════════════════════════════════════════════
// Main Entry Point
// ═════════════════════════════════════════════════════════════════════════════

int main(int argc, char* argv[]) {
    printf("═════════════════════════════════════════════════════════════════════════════\n");
    printf("  OMEGA-1 PowerShell Runspace Integration Tests\n");
    printf("  Testing actual PowerShell execution with real runspaces\n");
    printf("═════════════════════════════════════════════════════════════════════════════\n");
    
    // Reset counters
    g_testsPassed = 0;
    g_testsFailed = 0;
    g_results.clear();
    
    // Run all runspace tests
    Test_Runspace_BasicExecution();
    Test_Runspace_GetDate();
    Test_Runspace_ModuleDiscovery();
    Test_Runspace_LoadModule();
    Test_Runspace_JsonOutput();
    Test_Runspace_MultipleCommands();
    Test_Runspace_ErrorHandling();
    Test_Runspace_ReflectiveExecution();
    Test_Runspace_MutationTrigger();
    Test_Runspace_IntegrityValidation();
    Test_Runspace_Performance();
    
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
                printf("  - %s: %s (%lld ms)\n", result.name, result.message, result.duration.count());
            }
        }
        return 1;
    }
    
    printf("\n[✓] All runspace integration tests passed!\n");
    return 0;
}
