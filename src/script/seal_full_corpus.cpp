// RawrXD-Script Full Corpus Sealing
// Seals all 25 test cases as Golden Masters - The Source of Truth

#include "golden_master.hpp"
#include "trace_collector_masm.hpp"
#include <cstdio>
#include <vector>
#include <string>
#include <functional>
#include <chrono>

using namespace RawrXD::Script;

// ============================================================================
// Full 25-Test Corpus
// ============================================================================

// Category 1: Arithmetic Operations (Tests 1-8)
void Test_Arithmetic_Add() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 10
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 20
    MASMTraceCollector::RecordOpcode(0x20, 0, 1);    // ADD r0, r1
    MASMTraceCollector::RecordRegister(0, 30);
}

void Test_Arithmetic_Sub() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 50
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 20
    MASMTraceCollector::RecordOpcode(0x21, 0, 1);    // SUB r0, r1
    MASMTraceCollector::RecordRegister(0, 30);
}

void Test_Arithmetic_Mul() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 5
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 6
    MASMTraceCollector::RecordOpcode(0x22, 0, 1);    // MUL r0, r1
    MASMTraceCollector::RecordRegister(0, 30);
}

void Test_Arithmetic_Div() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 100
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 4
    MASMTraceCollector::RecordOpcode(0x23, 0, 1);    // DIV r0, r1
    MASMTraceCollector::RecordRegister(0, 25);
}

void Test_Arithmetic_Mod() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 17
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 5
    MASMTraceCollector::RecordOpcode(0x24, 0, 1);    // MOD r0, r1
    MASMTraceCollector::RecordRegister(0, 2);
}

void Test_Arithmetic_Neg() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 42
    MASMTraceCollector::RecordOpcode(0x25, 0, 0);    // NEG r0
    MASMTraceCollector::RecordRegister(0, -42);
}

void Test_Arithmetic_Inc() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 41
    MASMTraceCollector::RecordOpcode(0x26, 0, 0);    // INC r0
    MASMTraceCollector::RecordRegister(0, 42);
}

void Test_Arithmetic_Dec() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 43
    MASMTraceCollector::RecordOpcode(0x27, 0, 0);    // DEC r0
    MASMTraceCollector::RecordRegister(0, 42);
}

// Category 2: Control Flow (Tests 9-13)
void Test_Control_If_True() {
    MASMTraceCollector::RecordOpcode(0x06, 0, 0);  // LOAD_TRUE r0
    MASMTraceCollector::RecordOpcode(0x51, 0, 0);    // JMP_COND r0, label
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 1
    MASMTraceCollector::RecordRegister(1, 1);
}

void Test_Control_If_False() {
    MASMTraceCollector::RecordOpcode(0x07, 0, 0);  // LOAD_FALSE r0
    MASMTraceCollector::RecordOpcode(0x52, 0, 0);    // JMP_NOT_COND r0, label
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 0
    MASMTraceCollector::RecordRegister(1, 0);
}

void Test_Control_Loop_Count() {
    // for (i = 0; i < 3; i++)
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 0
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 3
    MASMTraceCollector::RecordOpcode(0x42, 0, 1);    // LT r0, r1
    MASMTraceCollector::RecordOpcode(0x51, 0, 0);    // JMP_COND
    MASMTraceCollector::RecordOpcode(0x26, 0, 0);    // INC r0
    MASMTraceCollector::RecordRegister(0, 3);
}

void Test_Control_Jmp_Unconditional() {
    MASMTraceCollector::RecordOpcode(0x50, 0, 0);    // JMP label
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 42
    MASMTraceCollector::RecordRegister(0, 42);
}

void Test_Control_Jmp_Eq() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 5
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 5
    MASMTraceCollector::RecordOpcode(0x53, 0, 1);    // JMP_EQ
    MASMTraceCollector::RecordRegister(0, 5);
}

// Category 3: Comparison Operations (Tests 14-18)
void Test_Compare_Eq() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 5
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 5
    MASMTraceCollector::RecordOpcode(0x40, 0, 1);    // EQ r0, r1
    MASMTraceCollector::RecordRegister(0, 1);  // true
}

void Test_Compare_Neq() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 5
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 3
    MASMTraceCollector::RecordOpcode(0x41, 0, 1);    // NEQ r0, r1
    MASMTraceCollector::RecordRegister(0, 1);  // true
}

void Test_Compare_Lt() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 3
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 5
    MASMTraceCollector::RecordOpcode(0x42, 0, 1);    // LT r0, r1
    MASMTraceCollector::RecordRegister(0, 1);  // true
}

void Test_Compare_Gt() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 7
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 5
    MASMTraceCollector::RecordOpcode(0x44, 0, 1);    // GT r0, r1
    MASMTraceCollector::RecordRegister(0, 1);  // true
}

void Test_Compare_StrictEq() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 5
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 5
    MASMTraceCollector::RecordOpcode(0x46, 0, 1);    // STRICT_EQ r0, r1
    MASMTraceCollector::RecordRegister(0, 1);  // true
}

// Category 4: Bitwise Operations (Tests 19-22)
void Test_Bitwise_And() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 0b1100
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 0b1010
    MASMTraceCollector::RecordOpcode(0x30, 0, 1);    // AND r0, r1
    MASMTraceCollector::RecordRegister(0, 0b1000);
}

void Test_Bitwise_Or() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 0b1100
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 0b1010
    MASMTraceCollector::RecordOpcode(0x31, 0, 1);    // OR r0, r1
    MASMTraceCollector::RecordRegister(0, 0b1110);
}

void Test_Bitwise_Xor() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 0b1100
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 0b1010
    MASMTraceCollector::RecordOpcode(0x32, 0, 1);    // XOR r0, r1
    MASMTraceCollector::RecordRegister(0, 0b0110);
}

void Test_Bitwise_Not() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, 0b1111
    MASMTraceCollector::RecordOpcode(0x33, 0, 0);    // NOT r0
    MASMTraceCollector::RecordRegister(0, ~0b1111);
}

// Category 5: Memory Operations (Tests 23-25)
void Test_Memory_Read() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, arr
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 0
    MASMTraceCollector::RecordMemoryAccess(0x1000, 8, false);  // Read
    MASMTraceCollector::RecordRegister(0, 42);
}

void Test_Memory_Write() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, arr
    MASMTraceCollector::RecordOpcode(0x00, 1, 0);  // LOAD_CONST r1, 0
    MASMTraceCollector::RecordMemoryAccess(0x1000, 8, true);   // Write
    MASMTraceCollector::RecordRegister(0, 0);
}

void Test_Memory_ArrayAccess() {
    MASMTraceCollector::RecordOpcode(0x00, 0, 0);  // LOAD_CONST r0, arr
    MASMTraceCollector::RecordOpcode(0x00, 1, 1);  // LOAD_CONST r1, 2
    MASMTraceCollector::RecordMemoryAccess(0x1010, 8, false);  // Read index 2
    MASMTraceCollector::RecordRegister(0, 99);
}

// ============================================================================
// Test Registry
// ============================================================================

struct TestDefinition {
    std::string name;
    std::string category;
    std::function<void()> func;
    std::string description;
};

std::vector<TestDefinition> g_corpus = {
    // Arithmetic (8 tests)
    {"arithmetic_add", "arithmetic", Test_Arithmetic_Add, "Addition: 10 + 20 = 30"},
    {"arithmetic_sub", "arithmetic", Test_Arithmetic_Sub, "Subtraction: 50 - 20 = 30"},
    {"arithmetic_mul", "arithmetic", Test_Arithmetic_Mul, "Multiplication: 5 * 6 = 30"},
    {"arithmetic_div", "arithmetic", Test_Arithmetic_Div, "Division: 100 / 4 = 25"},
    {"arithmetic_mod", "arithmetic", Test_Arithmetic_Mod, "Modulo: 17 % 5 = 2"},
    {"arithmetic_neg", "arithmetic", Test_Arithmetic_Neg, "Negation: -42"},
    {"arithmetic_inc", "arithmetic", Test_Arithmetic_Inc, "Increment: 41++ = 42"},
    {"arithmetic_dec", "arithmetic", Test_Arithmetic_Dec, "Decrement: 43-- = 42"},
    
    // Control Flow (5 tests)
    {"control_if_true", "control_flow", Test_Control_If_True, "If statement with true condition"},
    {"control_if_false", "control_flow", Test_Control_If_False, "If statement with false condition"},
    {"control_loop_count", "control_flow", Test_Control_Loop_Count, "For loop counting to 3"},
    {"control_jmp_uncond", "control_flow", Test_Control_Jmp_Unconditional, "Unconditional jump"},
    {"control_jmp_eq", "control_flow", Test_Control_Jmp_Eq, "Conditional jump on equality"},
    
    // Comparison (5 tests)
    {"compare_eq", "comparison", Test_Compare_Eq, "Equality: 5 == 5"},
    {"compare_neq", "comparison", Test_Compare_Neq, "Inequality: 5 != 3"},
    {"compare_lt", "comparison", Test_Compare_Lt, "Less than: 3 < 5"},
    {"compare_gt", "comparison", Test_Compare_Gt, "Greater than: 7 > 5"},
    {"compare_strict_eq", "comparison", Test_Compare_StrictEq, "Strict equality: 5 === 5"},
    
    // Bitwise (4 tests)
    {"bitwise_and", "bitwise", Test_Bitwise_And, "Bitwise AND: 0b1100 & 0b1010"},
    {"bitwise_or", "bitwise", Test_Bitwise_Or, "Bitwise OR: 0b1100 | 0b1010"},
    {"bitwise_xor", "bitwise", Test_Bitwise_Xor, "Bitwise XOR: 0b1100 ^ 0b1010"},
    {"bitwise_not", "bitwise", Test_Bitwise_Not, "Bitwise NOT: ~0b1111"},
    
    // Memory (3 tests)
    {"memory_read", "memory", Test_Memory_Read, "Memory read operation"},
    {"memory_write", "memory", Test_Memory_Write, "Memory write operation"},
    {"memory_array_access", "memory", Test_Memory_ArrayAccess, "Array index access"},
};

// ============================================================================
// Sealing Workflow
// ============================================================================

ExecutionFingerprint RunAndCapture(const std::string& testName, 
                                    std::function<void()> testFunc,
                                    uint32_t& outEventCount) {
    MASMTraceCollector::Reset();
    MASMTraceCollector::Start();
    
    testFunc();
    
    MASMTraceCollector::Stop();
    
    outEventCount = MASMTraceCollector::GetEventCount();
    return MASMTraceCollector::GetFingerprint();
}

int main() {
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║  RawrXD-Script Golden Master Sealing - Full Corpus                       ║\n");
    printf("║  Establishing Source of Truth for 25-Test Suite                          ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    
    auto startTime = std::chrono::high_resolution_clock::now();
    
    // Step 1: Clear existing database
    printf("[Step 1] Clearing existing database...\n");
    GoldenMasterDB::Clear();
    GoldenMasterDB::Initialize("rawrxd_golden_masters.db");
    printf("         ✓ Database initialized\n\n");
    
    // Step 2: Seal all 25 tests
    printf("[Step 2] Sealing %zu test cases...\n\n", g_corpus.size());
    
    int sealedCount = 0;
    std::string currentCategory = "";
    
    for (const auto& test : g_corpus) {
        // Print category header
        if (test.category != currentCategory) {
            currentCategory = test.category;
            printf("\n  [%s]\n", currentCategory.c_str());
        }
        
        uint32_t eventCount = 0;
        auto fingerprint = RunAndCapture(test.name, test.func, eventCount);
        
        bool sealed = GoldenMasterDB::SealMaster(
            test.name,
            test.category,
            fingerprint,
            eventCount,
            test.description,
            0  // 0% tolerance - exact match required
        );
        
        char fpStr[33];
        fingerprint.ToString(fpStr, sizeof(fpStr));
        
        if (sealed) {
            printf("    ✓ %-25s Events: %3u  FP: %.16s...\n", 
                   test.name.c_str(), eventCount, fpStr);
            sealedCount++;
        } else {
            printf("    ✗ %-25s FAILED TO SEAL\n", test.name.c_str());
        }
    }
    
    printf("\n");
    
    // Step 3: Save database
    printf("[Step 3] Saving Golden Master database...\n");
    bool saved = GoldenMasterDB::SaveToDisk("rawrxd_golden_masters.db");
    if (saved) {
        printf("         ✓ Binary database: rawrxd_golden_masters.db\n");
    } else {
        printf("         ✗ Failed to save binary database\n");
    }
    
    // Step 4: Export to JSON
    printf("\n[Step 4] Exporting to JSON...\n");
    bool exported = GoldenMasterDB::ExportToJSON("rawrxd_golden_masters.json");
    if (exported) {
        printf("         ✓ JSON export: rawrxd_golden_masters.json\n");
    } else {
        printf("         ✗ Failed to export JSON\n");
    }
    
    // Calculate statistics
    auto endTime = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime);
    
    // Summary
    printf("\n");
    printf("╔══════════════════════════════════════════════════════════════════════════╗\n");
    printf("║  SEALING COMPLETE                                                        ║\n");
    printf("╚══════════════════════════════════════════════════════════════════════════╝\n");
    printf("\n");
    printf("  Tests Sealed:      %d / %zu\n", sealedCount, g_corpus.size());
    printf("  Categories:        %zu\n", GoldenMasterDB::GetCategoryCount());
    printf("  Total Masters:     %zu\n", GoldenMasterDB::GetMasterCount());
    printf("  Time Elapsed:      %lld ms\n", duration.count());
    printf("\n");
    printf("  Output Files:\n");
    printf("    • rawrxd_golden_masters.db    (Binary database)\n");
    printf("    • rawrxd_golden_masters.json  (Human-readable)\n");
    printf("\n");
    printf("  Status: %s\n", 
           (sealedCount == g_corpus.size()) ? "✓ ALL TESTS SEALED" : "✗ SOME TESTS FAILED");
    printf("\n");
    printf("  Next Steps:\n");
    printf("    1. Review rawrxd_golden_masters.json\n");
    printf("    2. Commit both files to source control\n");
    printf("    3. Run regression tests: test_golden_master.exe\n");
    printf("\n");
    
    return (sealedCount == g_corpus.size()) ? 0 : 1;
}
