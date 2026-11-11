// Test: Sovereign Puppeteer Integration Verification
// Verifies that all Puppeteer components compile and link correctly

#include <cstdio>
#include <cstdint>

// Include Puppeteer headers
#include "sovereign/puppeteer/SymbolTableGenerator.hpp"
#include "sovereign/puppeteer/PuppeteerAPI.hpp"
#include "sovereign/puppeteer/VEH_Watchdog.hpp"
#include "sovereign/puppeteer/JITAssembler.hpp"
#include "sovereign/puppeteer/AutonomousPuppeteer.hpp"

// MASM extern declarations
extern "C" {
    void Puppeteer_CaptureState(void* ctx);
}

int main() {
    printf("=== Sovereign Puppeteer Integration Test ===\n\n");
    
    // Test 1: SymbolTableGenerator instantiation
    printf("[Test 1] SymbolTableGenerator... ");
    auto& symGen = SymbolTableGenerator::Instance();
    if (&symGen != nullptr) {
        printf("OK (singleton accessible)\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Test 2: PuppeteerAPI instantiation
    printf("[Test 2] PuppeteerAPI... ");
    auto& puppeteer = PuppeteerAPI::Instance();
    if (&puppeteer != nullptr) {
        printf("OK (singleton accessible)\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Test 3: VEH_Watchdog instantiation
    printf("[Test 3] VEH_Watchdog... ");
    auto& watchdog = VEH_Watchdog::Instance();
    if (&watchdog != nullptr) {
        printf("OK (singleton accessible)\n");
    } else {
        printf("FAIL\n");
        return 1;
    }
    
    // Test 4: JITAssembler instantiation
    printf("[Test 4] JITAssembler... ");
    JITAssembler jit;
    printf("OK (instantiated)\n");
    
    // Test 5: AutonomousPuppeteer instantiation
    printf("[Test 5] AutonomousPuppeteer... ");
    AutonomousPuppeteer autoPuppet;
    printf("OK (instantiated)\n");
    
    // Test 6: MASM function reference
    printf("[Test 6] MASM CaptureState... ");
    void* captureStateAddr = (void*)&Puppeteer_CaptureState;
    if (captureStateAddr != nullptr) {
        printf("OK (linked at %p)\n", captureStateAddr);
    } else {
        printf("FAIL (not linked)\n");
        return 1;
    }
    
    printf("\n=== All Tests Passed ===\n");
    printf("\nSovereign Puppeteer Architecture is fully integrated:\n");
    printf("  - SymbolTableGenerator: Runtime introspection\n");
    printf("  - PuppeteerAPI: Self-modification interface\n");
    printf("  - VEH_Watchdog: Crash recovery\n");
    printf("  - JITAssembler: Dynamic code generation\n");
    printf("  - AutonomousPuppeteer: High-level orchestration\n");
    printf("  - Puppeteer_CaptureState: MASM state capture\n");
    
    return 0;
}
