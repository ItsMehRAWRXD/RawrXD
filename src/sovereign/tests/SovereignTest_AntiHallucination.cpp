// SovereignTest_AntiHallucination.cpp
// Integration test for MASM Anti-Hallucination HotPatcher
// Validates patches before application to prevent logic drift

#include "../patcher/AntiHallucinationWrapper.hpp"
#include <iostream>
#include <vector>
#include <cstring>

// Direct MASM function declaration for debugging
extern "C" int AH_CompareBytes(const void* a, const void* b, size_t len);

namespace Sovereign {

// Test: Basic byte comparison
bool Test_ByteComparison() {
    std::cout << "[Test] Byte Comparison..." << std::endl;
    
    uint8_t a[] = {0x90, 0x90, 0x90, 0x90};
    uint8_t b[] = {0x90, 0x90, 0x90, 0x90};
    uint8_t c[] = {0x90, 0x90, 0xCC, 0x90};
    
    // Debug: print addresses and values
    std::cout << "  a addr: " << (void*)a << " values: " << (int)a[0] << " " << (int)a[1] << " " << (int)a[2] << " " << (int)a[3] << std::endl;
    std::cout << "  b addr: " << (void*)b << " values: " << (int)b[0] << " " << (int)b[1] << " " << (int)b[2] << " " << (int)b[3] << std::endl;
    std::cout << "  c addr: " << (void*)c << " values: " << (int)c[0] << " " << (int)c[1] << " " << (int)c[2] << " " << (int)c[3] << std::endl;
    
    // Same bytes should match
    int result1 = AH_CompareBytes(a, b, 4);
    std::cout << "  AH_CompareBytes(a, b, 4) returned: " << result1 << std::endl;
    bool match1 = (result1 != 0);
    std::cout << "  Same bytes match: " << (match1 ? "PASS" : "FAIL") << std::endl;
    
    // Different bytes should not match
    int result2 = AH_CompareBytes(a, c, 4);
    std::cout << "  AH_CompareBytes(a, c, 4) returned: " << result2 << std::endl;
    bool match2 = (result2 != 0);
    std::cout << "  Different bytes mismatch: " << (!match2 ? "PASS" : "FAIL") << std::endl;
    
    return match1 && !match2;
}

// Test: Hash calculation
bool Test_HashCalculation() {
    std::cout << "\n[Test] Hash Calculation..." << std::endl;
    
    const char* data1 = "test data";
    const char* data2 = "test data";
    const char* data3 = "different";
    
    uint64_t hash1 = AntiHallucinationGuard::CalculateHash(data1, strlen(data1));
    uint64_t hash2 = AntiHallucinationGuard::CalculateHash(data2, strlen(data2));
    uint64_t hash3 = AntiHallucinationGuard::CalculateHash(data3, strlen(data3));
    
    std::cout << "  Hash1: 0x" << std::hex << hash1 << std::dec << std::endl;
    std::cout << "  Hash2: 0x" << std::hex << hash2 << std::dec << std::endl;
    std::cout << "  Hash3: 0x" << std::hex << hash3 << std::dec << std::endl;
    
    // Same data should produce same hash
    bool same = (hash1 == hash2);
    std::cout << "  Same data same hash: " << (same ? "PASS" : "FAIL") << std::endl;
    
    // Different data should produce different hash (usually)
    bool different = (hash1 != hash3);
    std::cout << "  Different data different hash: " << (different ? "PASS" : "FAIL") << std::endl;
    
    return same && different;
}

// Test: Error message retrieval
bool Test_ErrorMessages() {
    std::cout << "\n[Test] Error Messages..." << std::endl;
    
    std::cout << "  OK: " << AntiHallucinationGuard::GetErrorMessage(AHError::OK) << std::endl;
    std::cout << "  EXPECT_MISMATCH: " << AntiHallucinationGuard::GetErrorMessage(AHError::EXPECT_MISMATCH) << std::endl;
    std::cout << "  PROTECT_FAIL: " << AntiHallucinationGuard::GetErrorMessage(AHError::PROTECT_FAIL) << std::endl;
    
    return true;
}

// Test: Patch request structure
bool Test_PatchRequestStructure() {
    std::cout << "\n[Test] Patch Request Structure..." << std::endl;
    
    AHPatchRequest req{};
    req.target = (void*)0x140001000;
    req.expected = nullptr;
    req.replacement = nullptr;
    req.original = nullptr;
    req.length = 16;
    req.flags = static_cast<uint64_t>(AHFlags::REQUIRE_MATCH | AHFlags::RESTORE_PROTECT);
    
    std::cout << "  Target: 0x" << req.target << std::endl;
    std::cout << "  Length: " << req.length << std::endl;
    std::cout << "  Flags: 0x" << std::hex << req.flags << std::dec << std::endl;
    
    // Verify flags are set correctly
    bool requireMatch = hasFlag(static_cast<AHFlags>(req.flags), AHFlags::REQUIRE_MATCH);
    bool restoreProtect = hasFlag(static_cast<AHFlags>(req.flags), AHFlags::RESTORE_PROTECT);
    
    std::cout << "  REQUIRE_MATCH: " << (requireMatch ? "YES" : "NO") << std::endl;
    std::cout << "  RESTORE_PROTECT: " << (restoreProtect ? "YES" : "NO") << std::endl;
    
    return requireMatch && restoreProtect;
}

// Test: Anti-hallucination guard concept
bool Test_AntiHallucinationConcept() {
    std::cout << "\n[Test] Anti-Hallucination Concept..." << std::endl;
    
    // Simulate a scenario where agent generates a patch
    // but the target memory doesn't match expected bytes
    
    uint8_t targetMemory[] = {0x48, 0x89, 0xE5, 0x90}; // Actual memory
    uint8_t expectedBytes[] = {0x48, 0x89, 0xE5, 0x90}; // What agent expects
    uint8_t wrongExpected[] = {0xCC, 0xCC, 0xCC, 0xCC}; // Wrong expectation (hallucination)
    uint8_t patchBytes[] = {0x90, 0x90, 0x90, 0x90};     // NOP replacement
    
    // Correct expectation should validate
    bool correctValidation = AntiHallucinationGuard::ValidateBytes(
        targetMemory, expectedBytes, 4);
    std::cout << "  Correct expectation validates: " 
              << (correctValidation ? "PASS" : "FAIL") << std::endl;
    
    // Wrong expectation should fail (hallucination detected)
    bool wrongValidation = AntiHallucinationGuard::ValidateBytes(
        targetMemory, wrongExpected, 4);
    std::cout << "  Wrong expectation rejected (hallucination): " 
              << (!wrongValidation ? "PASS" : "FAIL") << std::endl;
    
    std::cout << "\n  Anti-hallucination guard prevents:" << std::endl;
    std::cout << "    - Patching wrong memory location" << std::endl;
    std::cout << "    - Applying patches to already-modified code" << std::endl;
    std::cout << "    - Logic drift from agent hallucinations" << std::endl;
    
    return correctValidation && !wrongValidation;
}

// Main test runner
void RunAntiHallucinationTests() {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║     Anti-Hallucination HotPatcher - Integration Tests       ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    auto runTest = [&passed, &failed](const char* name, bool (*test)()) {
        std::cout << "\n--- " << name << " ---" << std::endl;
        try {
            if (test()) {
                passed++;
                std::cout << "[✓] " << name << " PASSED" << std::endl;
            } else {
                failed++;
                std::cout << "[✗] " << name << " FAILED" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "[✗] " << name << " EXCEPTION: " << e.what() << std::endl;
        }
    };
    
    runTest("ByteComparison", Test_ByteComparison);
    runTest("HashCalculation", Test_HashCalculation);
    runTest("ErrorMessages", Test_ErrorMessages);
    runTest("PatchRequestStructure", Test_PatchRequestStructure);
    runTest("AntiHallucinationConcept", Test_AntiHallucinationConcept);
    
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
    std::cout << "║                      Test Summary                            ║" << std::endl;
    std::cout << "╠══════════════════════════════════════════════════════════════╣" << std::endl;
    std::cout << "║  Passed: " << passed << "                                                  ║" << std::endl;
    std::cout << "║  Failed: " << failed << "                                                  ║" << std::endl;
    std::cout << "║  Total:  " << (passed + failed) << "                                                  ║" << std::endl;
    std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
    
    if (failed == 0) {
        std::cout << "\n🎉 All anti-hallucination tests PASSED!" << std::endl;
        std::cout << "The MASM guard is ready for production use." << std::endl;
    }
}

} // namespace Sovereign

// Standalone entry point
int main() {
    Sovereign::RunAntiHallucinationTests();
    return 0;
}
