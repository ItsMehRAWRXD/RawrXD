// RawrXD-Script Golden Master Sealing Test
// Seals the 25-test corpus as golden masters and demonstrates regression detection

#include "golden_master.hpp"
#include "trace_collector_masm.hpp"
#include <cstdio>
#include <vector>
#include <string>
#include <functional>

using namespace RawrXD::Script;

// Simulated test functions that generate different execution traces
// In production, these would be actual JavaScript test cases

void Test_Arithmetic_Add() {
    // Simulates: 10 + 20
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 10
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 20
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);    // ADD r0, r1
    MASMTraceCollector::RecordRegister(0, 30);
}

void Test_Arithmetic_Sub() {
    // Simulates: 50 - 20
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 50
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 20
    MASMTraceCollector::RecordOpcode(0x21, 0, 1);    // SUB r0, r1
    MASMTraceCollector::RecordRegister(0, 30);
}

void Test_Arithmetic_Mul() {
    // Simulates: 5 * 6
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 5
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 6
    MASMTraceCollector::RecordOpcode(0x22, 0, 1);    // MUL r0, r1
    MASMTraceCollector::RecordRegister(0, 30);
}

void Test_ControlFlow_If() {
    // Simulates: if (true) { x = 1 }
    MASMTraceCollector::RecordOpcode(0x06, 0, 0);  // LOAD_TRUE r0
    MASMTraceCollector::RecordOpcode(0x51, 0, 0);    // JMP_COND r0, label
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 1
    MASMTraceCollector::RecordRegister(1, 1);
}

void Test_ControlFlow_Loop() {
    // Simulates: for (i = 0; i < 3; i++)
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 0 (i)
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 3
    MASMTraceCollector::RecordOpcode(0x42, 0, 1);    // LT r0, r1
    MASMTraceCollector::RecordOpcode(0x51, 0, 0);    // JMP_COND
    MASMTraceCollector::RecordOpcode(0x26, 0, 0);    // INC r0
    MASMTraceCollector::RecordRegister(0, 3);
}

void Test_Memory_LoadStore() {
    // Simulates: x = arr[0]
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, arr
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 0
    MASMTraceCollector::RecordMemoryAccess(0x1000, 8, false);  // Read
    MASMTraceCollector::RecordRegister(0, 42);
}

void Test_Function_Call() {
    // Simulates: foo()
    MASMTraceCollector::RecordOpcode(0x56, 0, 0);  // CALL
    MASMTraceCollector::RecordOpcode(0x58, 0, 0);    // RETURN
    MASMTraceCollector::RecordRegister(0, 0);
}

void Test_String_Concat() {
    // Simulates: "Hello" + "World"
    MASMTraceCollector::RecordOpcode(0x03, 0, 0);  // LOAD_STRING r0, "Hello"
    MASMTraceCollector::RecordOpcode(0x03, 1, 1);  // LOAD_STRING r1, "World"
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);    // ADD (concat)
    MASMTraceCollector::RecordRegister(0, 0xDEADBEEF);  // String pointer
}

void Test_Boolean_Logic() {
    // Simulates: true && false
    MASMTraceCollector::RecordOpcode(0x06, 0, 0);  // LOAD_TRUE r0
    MASMTraceCollector::RecordOpcode(0x07, 1, 0);  // LOAD_FALSE r1
    MASMTraceCollector::RecordOpcode(0x30, 0, 1);    // AND r0, r1
    MASMTraceCollector::RecordRegister(0, 0);
}

void Test_Comparison_Eq() {
    // Simulates: 5 == 5
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 5
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 5
    MASMTraceCollector::RecordOpcode(0x40, 0, 1);    // EQ r0, r1
    MASMTraceCollector::RecordRegister(0, 1);  // true
}

// Test registry
struct TestCase {
    std::string name;
    std::string category;
    std::function<void()> func;
};

std::vector<TestCase> g_testCases = {
    {"arithmetic_add", "arithmetic", Test_Arithmetic_Add},
    {"arithmetic_sub", "arithmetic", Test_Arithmetic_Sub},
    {"arithmetic_mul", "arithmetic", Test_Arithmetic_Mul},
    {"control_if", "control_flow", Test_ControlFlow_If},
    {"control_loop", "control_flow", Test_ControlFlow_Loop},
    {"memory_loadstore", "memory", Test_Memory_LoadStore},
    {"function_call", "function", Test_Function_Call},
    {"string_concat", "string", Test_String_Concat},
    {"boolean_logic", "boolean", Test_Boolean_Logic},
    {"comparison_eq", "comparison", Test_Comparison_Eq},
};

// Run a test and capture its fingerprint
ExecutionFingerprint RunTestAndCapture(const std::string& testName, 
                                        std::function<void()> testFunc,
                                        uint32_t& outEventCount) {
    MASMTraceCollector::Reset();
    MASMTraceCollector::Start();
    
    testFunc();
    
    MASMTraceCollector::Stop();
    
    outEventCount = MASMTraceCollector::GetEventCount();
    return MASMTraceCollector::GetFingerprint();
}

// Phase 1: Seal all tests as golden masters
bool Phase1_SealGoldenMasters() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 1: SEALING GOLDEN MASTERS                               ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    GoldenMasterDB::Initialize("test_golden_masters.db");
    
    printf("Sealing %zu test cases as golden masters...\n\n", g_testCases.size());
    
    for (const auto& test : g_testCases) {
        uint32_t eventCount = 0;
        auto fingerprint = RunTestAndCapture(test.name, test.func, eventCount);
        
        bool sealed = GoldenMasterDB::SealMaster(
            test.name,
            test.category,
            fingerprint,
            eventCount,
            "Auto-sealed from test corpus",
            0  // 0% tolerance - exact match required
        );
        
        char fpStr[33];
        fingerprint.ToString(fpStr, sizeof(fpStr));
        
        printf("  [%s] %s\n", sealed ? "✓" : "✗", test.name.c_str());
        printf("       Category: %s\n", test.category.c_str());
        printf("       Events: %u\n", eventCount);
        printf("       Fingerprint: %s\n", fpStr);
        printf("\n");
    }
    
    // Save database
    if (GoldenMasterDB::SaveToDisk()) {
        printf("✓ Golden master database saved to: test_golden_masters.db\n");
    } else {
        printf("✗ Failed to save golden master database\n");
        return false;
    }
    
    // Export to JSON for inspection
    if (GoldenMasterDB::ExportToJSON("test_golden_masters.json")) {
        printf("✓ Golden masters exported to: test_golden_masters.json\n");
    }
    
    printf("\n");
    printf("Database Statistics:\n");
    printf("  Total masters: %zu\n", GoldenMasterDB::GetMasterCount());
    printf("  Categories: %zu\n", GoldenMasterDB::GetCategoryCount());
    
    return true;
}

// Phase 2: Run regression detection
bool Phase2_RegressionDetection() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 2: REGRESSION DETECTION                                 ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    int passed = 0;
    int failed = 0;
    int newTests = 0;
    
    // Test 1: Run all tests - should match exactly
    printf("Test Set 1: Exact execution replay\n");
    printf("-----------------------------------\n");
    for (const auto& test : g_testCases) {
        uint32_t eventCount = 0;
        auto fingerprint = RunTestAndCapture(test.name, test.func, eventCount);
        
        auto comparison = GoldenMasterDB::CompareAgainstMaster(
            test.name, fingerprint, eventCount);
        
        if (comparison.IsPass()) {
            printf("  ✓ %s: %s\n", test.name.c_str(), comparison.diagnosticMessage.c_str());
            passed++;
        } else {
            printf("  ✗ %s: %s\n", test.name.c_str(), comparison.diagnosticMessage.c_str());
            failed++;
        }
    }
    
    // Test 2: Simulate a regression (modified execution)
    printf("\n");
    printf("Test Set 2: Simulated regression detection\n");
    printf("--------------------------------------------\n");
    
    // Create a "regressed" version of arithmetic_add
    auto Regressed_Arithmetic_Add = []() {
        // Bug: Wrong opcode sequence (SUB instead of ADD)
        MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 10
        MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 20
        MASMTraceCollector::RecordOpcode(0x21, 0, 1);    // SUB r0, r1 (BUG!)
        MASMTraceCollector::RecordRegister(0, -10);     // Wrong result
    };
    
    uint32_t eventCount = 0;
    auto fingerprint = RunTestAndCapture("arithmetic_add", Regressed_Arithmetic_Add, eventCount);
    
    auto comparison = GoldenMasterDB::CompareAgainstMaster(
        "arithmetic_add", fingerprint, eventCount);
    
    printf("  Test: arithmetic_add (with simulated bug)\n");
    printf("  Expected: ADD operation\n");
    printf("  Actual:   SUB operation (regression!)\n");
    printf("  Result:   %s\n", comparison.IsFail() ? "✗ REGRESSION DETECTED" : "✓ (unexpected)");
    printf("  Details:  %s\n", comparison.diagnosticMessage.c_str());
    printf("  Similarity: %.2f%%\n", comparison.similarityScore * 100);
    printf("  Hamming Distance: %u bits\n", comparison.hammingDistance);
    
    if (comparison.IsFail()) {
        printf("\n  ✓ Regression detection working correctly!\n");
        passed++;
    } else {
        printf("\n  ✗ Regression detection failed to catch the bug\n");
        failed++;
    }
    
    // Test 3: New test without master
    printf("\n");
    printf("Test Set 3: New test without golden master\n");
    printf("-------------------------------------------\n");
    
    auto New_Test_Unknown = []() {
        MASMTraceCollector::RecordOpcode(0x99, 0, 0);  // Unknown opcode
        MASMTraceCollector::RecordRegister(0, 0);
    };
    
    eventCount = 0;
    fingerprint = RunTestAndCapture("new_unknown_test", New_Test_Unknown, eventCount);
    
    comparison = GoldenMasterDB::CompareAgainstMaster(
        "new_unknown_test", fingerprint, eventCount);
    
    printf("  Test: new_unknown_test\n");
    printf("  Result: %s\n", 
        comparison.status == FingerprintComparison::Status::MissingMaster 
            ? "⚠ NEW TEST (no master exists)" : "?");
    printf("  Action: Seal as new golden master\n");
    
    // Seal the new test
    GoldenMasterDB::SealMaster(
        "new_unknown_test",
        "unknown",
        fingerprint,
        eventCount,
        "Auto-sealed new test"
    );
    newTests++;
    
    // Summary
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  REGRESSION DETECTION SUMMARY                                  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  Tests passed:      %d\n", passed);
    printf("  Tests failed:      %d\n", failed);
    printf("  New tests sealed:  %d\n", newTests);
    printf("  Total masters:     %zu\n", GoldenMasterDB::GetMasterCount());
    printf("\n");
    
    return failed == 0;
}

// Phase 3: Export final database
bool Phase3_ExportResults() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  PHASE 3: EXPORT RESULTS                                     ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    // Export to JSON
    if (GoldenMasterDB::ExportToJSON("golden_masters_final.json")) {
        printf("✓ Final database exported to: golden_masters_final.json\n");
        
        // Print summary of all masters
        auto masters = GoldenMasterDB::ListMasters();
        
        printf("\nGolden Master Registry:\n");
        printf("%-30s %-15s %s\n", "Test Name", "Category", "Fingerprint (first 16 chars)");
        printf("%-30s %-15s %s\n", std::string(30, '-').c_str(), std::string(15, '-').c_str(), 
                std::string(16, '-').c_str());
        
        for (const auto& master : masters) {
            char fpStr[33];
            master.fingerprint.ToString(fpStr, sizeof(fpStr));
            fpStr[16] = '\0';  // Truncate for display
            
            printf("%-30s %-15s %s...\n", 
                   master.testName.c_str(), 
                   master.testCategory.c_str(),
                   fpStr);
        }
        
        return true;
    }
    
    return false;
}

int main() {
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD-Script Golden Master System                            ║\n");
    printf("║  Self-Diagnosing Engine - Baseline Generation                  ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("This test demonstrates:\n");
    printf("  1. Sealing execution traces as golden masters\n");
    printf("  2. Detecting regressions through fingerprint comparison\n");
    printf("  3. Automatic classification of execution deviations\n");
    printf("\n");
    
    bool success = true;
    
    success &= Phase1_SealGoldenMasters();
    success &= Phase2_RegressionDetection();
    success &= Phase3_ExportResults();
    
    printf("\n");
    printf("╔════════════════════════════════════════════════════════════════╗\n");
    if (success) {
        printf("║  ✓ ALL PHASES COMPLETED SUCCESSFULLY                         ║\n");
    } else {
        printf("║  ✗ SOME PHASES FAILED                                        ║\n");
    }
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    return success ? 0 : 1;
}
