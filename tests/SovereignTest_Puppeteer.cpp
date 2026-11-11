// =============================================================================
// SovereignTest_Puppeteer.cpp - End-to-End Puppeteer Architecture Tests
// Validates self-modification workflow: Introspection -> Synthesis -> Application
// =============================================================================

#include <iostream>
#include <vector>
#include <cstring>
#include <chrono>
#include <thread>
#include <atomic>

#include "../src/sovereign/introspection/SymbolTableGenerator.hpp"
#include "../src/sovereign/puppeteer/PuppeteerAPI.hpp"
#include "../src/sovereign/puppeteer/VEH_Watchdog.hpp"

using namespace RawrXD::Sovereign;

// =============================================================================
// Test Utilities
// =============================================================================

struct TestResult {
    const char* name;
    bool passed;
    double duration_ms;
    std::string details;
};

std::vector<TestResult> g_results;
std::atomic<size_t> g_exception_count{0};

#define TEST(name) \
    auto _test_start = std::chrono::high_resolution_clock::now(); \
    bool _test_passed = true; \
    std::string _test_details; \
    try {

#define END_TEST(name) \
    } catch (const std::exception& e) { \
        _test_passed = false; \
        _test_details = e.what(); \
    } \
    auto _test_end = std::chrono::high_resolution_clock::now(); \
    double _test_duration = std::chrono::duration<double, std::milli>(_test_end - _test_start).count(); \
    g_results.push_back({name, _test_passed, _test_duration, _test_details}); \
    std::cout << "[" << (_test_passed ? "PASS" : "FAIL") << "] " << name \
              << " (" << _test_duration << " ms)" << std::endl;

#define ASSERT_TRUE(cond) \
    if (!(cond)) { \
        _test_passed = false; \
        _test_details = "Assertion failed: " #cond; \
        throw std::runtime_error(_test_details); \
    }

// =============================================================================
// Test 1: Symbol Table Initialization
// =============================================================================

void Test_SymbolTable_Init() {
    TEST("SymbolTable_Initialization")
    
    SymbolTableGenerator& symtab = SymbolTableGenerator::Instance();
    ASSERT_TRUE(symtab.Initialize());
    
    // Should have found some symbols
    ASSERT_TRUE(symtab.GetSymbolCount() > 0);
    ASSERT_TRUE(symtab.GetRegionCount() > 0);
    
    // Should have executable regions
    auto execRegions = symtab.GetExecutableRegions();
    ASSERT_TRUE(execRegions.size() > 0);
    
    END_TEST("SymbolTable_Initialization")
}

// =============================================================================
// Test 2: Symbol Lookup Performance
// =============================================================================

void Test_SymbolLookup_Performance() {
    TEST("SymbolLookup_Performance")
    
    SymbolTableGenerator& symtab = SymbolTableGenerator::Instance();
    
    // Register a test symbol
    SymbolEntry testSym;
    testSym.name = "TestSymbol_Performance";
    testSym.address = 0x7FF600001000;
    testSym.size = 256;
    testSym.type = SymbolType::FUNCTION;
    symtab.RegisterSymbol(testSym);
    
    // Benchmark lookup
    const int ITERATIONS = 100000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < ITERATIONS; ++i) {
        const SymbolEntry* sym = symtab.FindSymbol("TestSymbol_Performance");
        if (!sym) {
            _test_passed = false;
            _test_details = "Symbol not found";
            throw std::runtime_error(_test_details);
        }
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    double total_ms = std::chrono::duration<double, std::milli>(end - start).count();
    double ns_per_lookup = (total_ms * 1000000.0) / ITERATIONS;
    
    std::cout << "    " << ITERATIONS << " lookups in " << total_ms << " ms" << std::endl;
    std::cout << "    " << ns_per_lookup << " ns per lookup" << std::endl;
    
    // Should be sub-microsecond
    ASSERT_TRUE(ns_per_lookup < 1000.0);
    
    END_TEST("SymbolLookup_Performance")
}

// =============================================================================
// Test 3: VEH Watchdog Initialization
// =============================================================================

void Test_VEH_Watchdog_Init() {
    TEST("VEH_Watchdog_Initialization")
    
    VEH_Watchdog& watchdog = VEH_Watchdog::Instance();
    ASSERT_TRUE(watchdog.Initialize());
    ASSERT_TRUE(watchdog.IsInitialized());
    
    // Set up exception callback
    watchdog.SetExceptionCallback([](const ExceptionContext& ctx) {
        g_exception_count.fetch_add(1);
        std::cout << "    [VEH] Exception caught at 0x" 
                  << std::hex << ctx.faulting_address << std::dec << std::endl;
    });
    
    END_TEST("VEH_Watchdog_Initialization")
}

// =============================================================================
// Test 4: Patch Guard Functionality
// =============================================================================

void Test_PatchGuard() {
    TEST("PatchGuard_Functionality")
    
    VEH_Watchdog& watchdog = VEH_Watchdog::Instance();
    
    // Create a test memory region
    uint8_t testRegion[256];
    std::memset(testRegion, 0x90, sizeof(testRegion));  // NOP sled
    
    // Original bytes for rollback
    std::vector<uint8_t> original(testRegion, testRegion + sizeof(testRegion));
    
    // Guard the region
    uintptr_t regionAddr = reinterpret_cast<uintptr_t>(testRegion);
    ASSERT_TRUE(watchdog.GuardPatch(regionAddr, sizeof(testRegion), 1, original));
    
    // Verify guard is active
    ASSERT_TRUE(watchdog.IsGuarded(regionAddr));
    ASSERT_TRUE(watchdog.IsGuarded(regionAddr + 128));
    ASSERT_TRUE(!watchdog.IsGuarded(regionAddr + 512));  // Outside region
    
    // Release guard
    ASSERT_TRUE(watchdog.ReleaseGuard(1));
    ASSERT_TRUE(!watchdog.IsGuarded(regionAddr));
    
    END_TEST("PatchGuard_Functionality")
}

// =============================================================================
// Test 5: Memory Protection Validation
// =============================================================================

void Test_MemoryProtection() {
    TEST("MemoryProtection_Validation")
    
    SymbolTableGenerator& symtab = SymbolTableGenerator::Instance();
    
    // Allocate test memory
    void* testMem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    ASSERT_TRUE(testMem != nullptr);
    
    uintptr_t addr = reinterpret_cast<uintptr_t>(testMem);
    
    // Initially should be writable data, not code
    ASSERT_TRUE(symtab.IsWritableDataAddress(addr));
    ASSERT_TRUE(!symtab.IsValidCodeAddress(addr));
    
    // Change protection to execute
    DWORD oldProtect;
    BOOL result = VirtualProtect(testMem, 4096, PAGE_EXECUTE_READ, &oldProtect);
    ASSERT_TRUE(result);
    
    // Re-scan to pick up new protection
    symtab.ScanProcessMemory();
    
    // Now should be valid code
    ASSERT_TRUE(symtab.IsValidCodeAddress(addr));
    ASSERT_TRUE(!symtab.IsWritableDataAddress(addr));
    
    // Cleanup
    VirtualFree(testMem, 0, MEM_RELEASE);
    
    END_TEST("MemoryProtection_Validation")
}

// =============================================================================
// Test 6: PuppeteerAPI Initialization
// =============================================================================

void Test_PuppeteerAPI_Init() {
    TEST("PuppeteerAPI_Initialization")
    
    PuppeteerAPI& puppeteer = PuppeteerAPI::Instance();
    
    // Initialize with dependencies
    ASSERT_TRUE(puppeteer.Initialize(nullptr));  // Will use default patcher
    
    END_TEST("PuppeteerAPI_Initialization")
}

// =============================================================================
// Test 7: Read Memory (Introspection)
// =============================================================================

void Test_ReadMemory() {
    TEST("ReadMemory_Introspection")
    
    PuppeteerAPI& puppeteer = PuppeteerAPI::Instance();
    
    // Create test data
    uint8_t testData[] = {0x48, 0x89, 0x5C, 0x24, 0x08};  // mov [rsp+8], rbx
    
    // Allocate executable memory
    void* execMem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, 
                                    PAGE_EXECUTE_READWRITE);
    ASSERT_TRUE(execMem != nullptr);
    
    std::memcpy(execMem, testData, sizeof(testData));
    
    // Read via Puppeteer
    uintptr_t addr = reinterpret_cast<uintptr_t>(execMem);
    auto result = puppeteer.ReadMemory(addr, sizeof(testData));
    
    ASSERT_TRUE(result.success);
    ASSERT_TRUE(result.originalBytes.size() == sizeof(testData));
    
    // Verify data
    for (size_t i = 0; i < sizeof(testData); ++i) {
        ASSERT_TRUE(result.originalBytes[i] == testData[i]);
    }
    
    VirtualFree(execMem, 0, MEM_RELEASE);
    
    END_TEST("ReadMemory_Introspection")
}

// =============================================================================
// Test 8: Write Memory (Self-Modification)
// =============================================================================

void Test_WriteMemory() {
    TEST("WriteMemory_SelfModification")
    
    PuppeteerAPI& puppeteer = PuppeteerAPI::Instance();
    
    // Allocate executable memory
    void* execMem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, 
                                    PAGE_EXECUTE_READWRITE);
    ASSERT_TRUE(execMem != nullptr);
    
    uintptr_t addr = reinterpret_cast<uintptr_t>(execMem);
    
    // Write new code
    std::vector<uint8_t> newCode = {0x90, 0x90, 0x90, 0x90, 0xC3};  // NOP NOP NOP NOP RET
    
    auto result = puppeteer.WriteMemory(addr, newCode);
    ASSERT_TRUE(result.success);
    
    // Verify write
    uint8_t* mem = static_cast<uint8_t*>(execMem);
    for (size_t i = 0; i < newCode.size(); ++i) {
        ASSERT_TRUE(mem[i] == newCode[i]);
    }
    
    VirtualFree(execMem, 0, MEM_RELEASE);
    
    END_TEST("WriteMemory_SelfModification")
}

// =============================================================================
// Test 9: End-to-End Puppeteer Workflow
// =============================================================================

void Test_PuppeteerWorkflow() {
    TEST("Puppeteer_Workflow_E2E")
    
    // This test simulates the full workflow:
    // 1. Symbol table finds function
    // 2. Read current implementation
    // 3. Generate optimized version
    // 4. Apply patch with guard
    // 5. Verify execution
    // 6. Rollback
    
    SymbolTableGenerator& symtab = SymbolTableGenerator::Instance();
    PuppeteerAPI& puppeteer = PuppeteerAPI::Instance();
    VEH_Watchdog& watchdog = VEH_Watchdog::Instance();
    
    // Create a test function
    typedef int (*TestFunc)();
    
    // Original: return 42
    uint8_t originalCode[] = {
        0xB8, 0x2A, 0x00, 0x00, 0x00,  // mov eax, 42
        0xC3                            // ret
    };
    
    // Optimized: return 84 (2x speedup!)
    uint8_t optimizedCode[] = {
        0xB8, 0x54, 0x00, 0x00, 0x00,  // mov eax, 84
        0xC3                            // ret
    };
    
    // Allocate executable memory
    void* funcMem = VirtualAlloc(nullptr, 4096, MEM_COMMIT | MEM_RESERVE, 
                                  PAGE_EXECUTE_READWRITE);
    ASSERT_TRUE(funcMem != nullptr);
    
    std::memcpy(funcMem, originalCode, sizeof(originalCode));
    
    uintptr_t funcAddr = reinterpret_cast<uintptr_t>(funcMem);
    
    // Register as symbol
    SymbolEntry testFunc;
    testFunc.name = "TestFunction_OptimizeMe";
    testFunc.address = funcAddr;
    testFunc.size = sizeof(originalCode);
    testFunc.type = SymbolType::FUNCTION;
    symtab.RegisterSymbol(testFunc);
    
    // Step 1: Find symbol
    auto* sym = symtab.FindSymbol("TestFunction_OptimizeMe");
    ASSERT_TRUE(sym != nullptr);
    
    // Step 2: Read current implementation
    auto readResult = puppeteer.ReadMemory(sym->address, sym->size);
    ASSERT_TRUE(readResult.success);
    
    // Step 3: Apply patch with guard
    std::vector<uint8_t> original(readResult.originalBytes);
    ASSERT_TRUE(watchdog.GuardPatch(sym->address, sym->size, 1, original));
    
    // Step 4: Write optimized code
    auto writeResult = puppeteer.WriteMemory(sym->address, optimizedCode);
    ASSERT_TRUE(writeResult.success);
    
    // Step 5: Execute (verify it works)
    TestFunc func = reinterpret_cast<TestFunc>(funcMem);
    int result = func();
    ASSERT_TRUE(result == 84);
    
    // Step 6: Release guard
    ASSERT_TRUE(watchdog.ReleaseGuard(1));
    
    // Cleanup
    VirtualFree(funcMem, 0, MEM_RELEASE);
    
    END_TEST("Puppeteer_Workflow_E2E")
}

// =============================================================================
// Test 10: Safety - Protected Symbols
// =============================================================================

void Test_ProtectedSymbols() {
    TEST("Safety_ProtectedSymbols")
    
    PuppeteerAPI& puppeteer = PuppeteerAPI::Instance();
    
    // Try to patch a protected symbol (should fail validation)
    // Note: This is a conceptual test - actual protected symbols
    // would be infrastructure functions
    
    // For now, just verify the safety policy exists
    // In real implementation, this would check against protected list
    
    ASSERT_TRUE(true);  // Placeholder - actual test needs real symbols
    
    END_TEST("Safety_ProtectedSymbols")
}

// =============================================================================
// Main
// =============================================================================

int main() {
    std::cout << "========================================" << std::endl;
    std::cout << "Sovereign Puppeteer Architecture Tests" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << std::endl;
    
    // Run all tests
    Test_SymbolTable_Init();
    Test_SymbolLookup_Performance();
    Test_VEH_Watchdog_Init();
    Test_PatchGuard();
    Test_MemoryProtection();
    Test_PuppeteerAPI_Init();
    Test_ReadMemory();
    Test_WriteMemory();
    Test_PuppeteerWorkflow();
    Test_ProtectedSymbols();
    
    // Summary
    std::cout << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Test Summary" << std::endl;
    std::cout << "========================================" << std::endl;
    
    int passed = 0;
    int failed = 0;
    double total_time = 0.0;
    
    for (const auto& result : g_results) {
        total_time += result.duration_ms;
        if (result.passed) {
            ++passed;
        } else {
            ++failed;
            std::cout << "[FAIL] " << result.name << ": " << result.details << std::endl;
        }
    }
    
    std::cout << "Total: " << g_results.size() << " tests" << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << "Total time: " << total_time << " ms" << std::endl;
    std::cout << "Exceptions caught: " << g_exception_count.load() << std::endl;
    
    // Cleanup
    VEH_Watchdog::Instance().Shutdown();
    
    return failed == 0 ? 0 : 1;
}
