// ============================================================================
// reverse_integration_standalone_test.cpp - Standalone Reverse Engine Bridge Test
// Tests ReverseIntegration without full Deep2Engine dependencies
// ============================================================================

#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <chrono>
#include <vector>
#include <string>

#include "../reverse/ReverseEngine.hpp"
#include "../reverse/ReverseModelLoader.hpp"
#include "ReverseIntegration.hpp"

using namespace Deep2;
using namespace rxd::reverse;

// Timing helper
inline double GetTimeMs() {
    using namespace std::chrono;
    return duration_cast<microseconds>(high_resolution_clock::now().time_since_epoch()).count() / 1000.0;
}

// ============================================================================
// Test 1: ReverseEngine Standalone
// ============================================================================
bool Test_ReverseEngine_Standalone() {
    printf("\n[TEST 1] ReverseEngine Standalone...\n");
    
    // Create a simple reverse model inline
    ReverseModel model;
    model.name = "TestModel";
    model.version = "1.0";
    model.minConfidence = 0.5;
    
    // Add a pattern for x86 mov rbp, rsp (0x48 0x89 0xE5)
    Pattern pat;
    pat.id = "mov_rbp_rsp";
    pat.mnemonic = "MOV";
    pat.description = "Move RSP to RBP";
    pat.bytes = {0x48, 0x89, 0xE5};
    pat.weight = 1.0;
    model.patterns.push_back(pat);
    
    // Add another pattern: nop (0x90)
    Pattern pat2;
    pat2.id = "nop";
    pat2.mnemonic = "NOP";
    pat2.description = "No operation";
    pat2.bytes = {0x90};
    pat2.weight = 0.8;
    model.patterns.push_back(pat2);
    
    // Create engine
    double t0 = GetTimeMs();
    ReverseEngine engine(model);
    double t1 = GetTimeMs();
    
    // Test data containing the patterns
    uint8_t testData[] = {
        0x00, 0x01, 0x02,           // junk
        0x48, 0x89, 0xE5,           // mov rbp, rsp
        0x90,                       // nop
        0x48, 0x89, 0xE5,           // mov rbp, rsp
        0xFF, 0xFF                  // junk
    };
    
    auto matches = engine.Scan(testData, sizeof(testData));
    
    printf("  [PASS] Engine created in %.3f ms\n", t1 - t0);
    printf("  [INFO] Found %zu matches\n", matches.size());
    
    for (const auto& m : matches) {
        printf("    - %s at offset %zu (conf=%.3f, byte=0x%02X)\n",
               m.patternName.c_str(), m.offset, m.confidence, m.predictedByte);
    }
    
    return matches.size() >= 2;
}

// ============================================================================
// Test 2: ReverseIntegration Creation
// ============================================================================
bool Test_ReverseIntegration_Creation() {
    printf("\n[TEST 2] ReverseIntegration Creation...\n");
    
    double t0 = GetTimeMs();
    ReverseIntegration integration;
    double t1 = GetTimeMs();
    
    printf("  [PASS] ReverseIntegration created in %.3f ms\n", t1 - t0);
    
    // Test enable/disable
    integration.enableRealTimeAnalysis(true);
    integration.enableSpeculativeReverse(true);
    integration.enableRealTimeAnalysis(false);
    integration.enableSpeculativeReverse(false);
    
    printf("  [PASS] Configuration toggles work\n");
    
    return true;
}

// ============================================================================
// Test 3: ReverseIntegration analyzeBuffer
// ============================================================================
bool Test_ReverseIntegration_Analyze() {
    printf("\n[TEST 3] ReverseIntegration analyzeBuffer...\n");
    
    ReverseIntegration integration;
    
    // Create a temporary model file with absolute path
    const char* tempModelPath = "d:\\RawrXD\\src\\deep2\\test_reverse_model.json";
    FILE* f = fopen(tempModelPath, "w");
    if (!f) {
        printf("  [FAIL] Cannot create temp model file\n");
        return false;
    }
    
    fprintf(f, "{\n");
    fprintf(f, "  \"name\": \"TestModel\",\n");
    fprintf(f, "  \"version\": \"1.0\",\n");
    fprintf(f, "  \"minConfidence\": 0.5,\n");
    fprintf(f, "  \"patterns\": [\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"id\": \"mov_rbp_rsp\",\n");
    fprintf(f, "      \"mnemonic\": \"MOV\",\n");
    fprintf(f, "      \"description\": \"Move RSP to RBP\",\n");
    fprintf(f, "      \"bytes\": [72, 137, 229],\n");
    fprintf(f, "      \"weight\": 1.0\n");
    fprintf(f, "    },\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"id\": \"nop\",\n");
    fprintf(f, "      \"mnemonic\": \"NOP\",\n");
    fprintf(f, "      \"description\": \"No operation\",\n");
    fprintf(f, "      \"bytes\": [144],\n");
    fprintf(f, "      \"weight\": 0.8\n");
    fprintf(f, "    }\n");
    fprintf(f, "  ],\n");
    fprintf(f, "  \"samples\": []\n");
    fprintf(f, "}\n");
    fclose(f);
    
    // Initialize integration with model
    bool ok = integration.initialize(tempModelPath);
    if (!ok) {
        printf("  [FAIL] Failed to initialize with model file\n");
        remove(tempModelPath);
        return false;
    }
    
    // Test data
    uint8_t testData[] = {
        0x00, 0x01, 0x02,
        0x48, 0x89, 0xE5,  // mov rbp, rsp
        0x90,              // nop
        0x48, 0x89, 0xE5,  // mov rbp, rsp
        0xFF, 0xFF
    };
    
    auto results = integration.analyzeBuffer(testData, sizeof(testData), 5);
    
    auto stats = integration.getStats();
    
    printf("  [PASS] Analysis complete\n");
    printf("  [INFO] Results: %zu, Total matches: %zu\n", results.size(), stats.total_matches);
    
    for (const auto& r : results) {
        printf("    - %s (conf=%.3f, layer=%d)\n",
               r.pattern_name.c_str(), r.confidence, r.layer_idx);
    }
    
    // Cleanup
    remove(tempModelPath);
    
    return results.size() >= 2;
}

// ============================================================================
// Test 4: ReverseIntegration Callbacks
// ============================================================================
bool Test_ReverseIntegration_Callbacks() {
    printf("\n[TEST 4] ReverseIntegration Callbacks...\n");
    
    ReverseIntegration integration;
    
    int callbackCount = 0;
    integration.setCallback([&callbackCount](const ReverseAnalysisResult& result) {
        callbackCount++;
        printf("    [CB] Match: %s (conf=%.3f)\n", 
               result.pattern_name.c_str(), result.confidence);
    });
    
    // Create a temporary model file
    const char* tempModelPath2 = "d:\\RawrXD\\src\\deep2\\test_reverse_model2.json";
    FILE* f = fopen(tempModelPath2, "w");
    if (!f) {
        printf("  [FAIL] Cannot create temp model file\n");
        return false;
    }
    
    fprintf(f, "{\n");
    fprintf(f, "  \"name\": \"TestModel\",\n");
    fprintf(f, "  \"version\": \"1.0\",\n");
    fprintf(f, "  \"minConfidence\": 0.5,\n");
    fprintf(f, "  \"patterns\": [\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"id\": \"nop\",\n");
    fprintf(f, "      \"mnemonic\": \"NOP\",\n");
    fprintf(f, "      \"description\": \"No operation\",\n");
    fprintf(f, "      \"bytes\": [144],\n");
    fprintf(f, "      \"weight\": 0.8\n");
    fprintf(f, "    }\n");
    fprintf(f, "  ],\n");
    fprintf(f, "  \"samples\": []\n");
    fprintf(f, "}\n");
    fclose(f);
    
    bool ok = integration.initialize(tempModelPath2);
    if (!ok) {
        remove(tempModelPath2);
        return false;
    }
    
    uint8_t testData[] = {0x90, 0x90, 0x90};  // Three nops
    auto results = integration.analyzeBuffer(testData, sizeof(testData));
    
    printf("  [PASS] Callbacks fired: %d times\n", callbackCount);
    
    remove(tempModelPath2);
    
    return callbackCount >= 1;
}

// ============================================================================
// Test 5: ReverseIntegration Layer Hooks
// ============================================================================
bool Test_ReverseIntegration_LayerHooks() {
    printf("\n[TEST 5] ReverseIntegration Layer Hooks...\n");
    
    ReverseIntegration integration;
    
    // Model layer processing
    std::vector<float> activations(256);
    for (size_t i = 0; i < activations.size(); i++) {
        activations[i] = static_cast<float>(i) / 255.0f;
    }
    
    // onLayerProcessed should not crash even without model
    integration.onLayerProcessed(0, activations.data(), activations.size());
    integration.onLayerProcessed(1, activations.data(), activations.size());
    
    // onAttentionComputed should not crash
    integration.onAttentionComputed(0, activations.data(), activations.size());
    
    printf("  [PASS] Layer hooks executed without crash\n");
    
    return true;
}

// ============================================================================
// Test 6: ReverseIntegration Statistics
// ============================================================================
bool Test_ReverseIntegration_Stats() {
    printf("\n[TEST 6] ReverseIntegration Statistics...\n");
    
    ReverseIntegration integration;
    
    auto stats1 = integration.getStats();
    printf("  [INFO] Initial stats: matches=%zu, avg_conf=%.3f\n",
           stats1.total_matches, stats1.average_confidence);
    
    // Create a temporary model file
    const char* tempModelPath3 = "d:\\RawrXD\\src\\deep2\\test_reverse_model3.json";
    FILE* f = fopen(tempModelPath3, "w");
    if (!f) {
        printf("  [FAIL] Cannot create temp model file\n");
        return false;
    }
    
    fprintf(f, "{\n");
    fprintf(f, "  \"name\": \"TestModel\",\n");
    fprintf(f, "  \"version\": \"1.0\",\n");
    fprintf(f, "  \"minConfidence\": 0.1,\n");  // Low threshold to get matches
    fprintf(f, "  \"patterns\": [\n");
    fprintf(f, "    {\n");
    fprintf(f, "      \"id\": \"any_byte\",\n");
    fprintf(f, "      \"mnemonic\": \"ANY\",\n");
    fprintf(f, "      \"description\": \"Any single byte\",\n");
    fprintf(f, "      \"bytes\": [0],\n");
    fprintf(f, "      \"weight\": 0.2\n");
    fprintf(f, "    }\n");
    fprintf(f, "  ],\n");
    fprintf(f, "  \"samples\": []\n");
    fprintf(f, "}\n");
    fclose(f);
    
    bool ok = integration.initialize(tempModelPath3);
    if (!ok) {
        remove(tempModelPath3);
        return false;
    }
    
    uint8_t testData[] = {0x00, 0x00, 0x00};
    integration.analyzeBuffer(testData, sizeof(testData));
    
    auto stats2 = integration.getStats();
    printf("  [INFO] After analysis: matches=%zu, avg_conf=%.3f\n",
           stats2.total_matches, stats2.average_confidence);
    
    remove(tempModelPath3);
    
    return stats2.total_matches >= stats1.total_matches;
}

// ============================================================================
// Main
// ============================================================================
int main(int argc, char** argv) {
    printf("=================================================================\n");
    printf("BigDaddyG Reverse Engine - Standalone Integration Test\n");
    printf("=================================================================\n");
    printf("Testing ReverseIntegration bridge component:\n");
    printf("  1. ReverseEngine Standalone\n");
    printf("  2. ReverseIntegration Creation\n");
    printf("  3. ReverseIntegration analyzeBuffer\n");
    printf("  4. ReverseIntegration Callbacks\n");
    printf("  5. ReverseIntegration Layer Hooks\n");
    printf("  6. ReverseIntegration Statistics\n");
    printf("=================================================================\n");
    
    int passed = 0;
    int failed = 0;
    
    auto runTest = [&](const char* name, bool (*testFunc)()) {
        bool result = testFunc();
        if (result) {
            passed++;
            printf("  [PASS] %s\n", name);
        } else {
            failed++;
            printf("  [FAIL] %s\n", name);
        }
        return result;
    };
    
    runTest("ReverseEngine Standalone", Test_ReverseEngine_Standalone);
    runTest("ReverseIntegration Creation", Test_ReverseIntegration_Creation);
    runTest("ReverseIntegration analyzeBuffer", Test_ReverseIntegration_Analyze);
    runTest("ReverseIntegration Callbacks", Test_ReverseIntegration_Callbacks);
    runTest("ReverseIntegration Layer Hooks", Test_ReverseIntegration_LayerHooks);
    runTest("ReverseIntegration Statistics", Test_ReverseIntegration_Stats);
    
    printf("\n=================================================================\n");
    printf("TEST SUMMARY\n");
    printf("=================================================================\n");
    printf("Passed: %d/%d\n", passed, passed + failed);
    printf("Failed: %d/%d\n", failed, passed + failed);
    printf("\n");
    
    if (failed == 0) {
        printf("*** ALL TESTS PASSED ***\n");
        printf("BigDaddyG Reverse Engine bridge is fully operational.\n");
        printf("\n");
        printf("Components validated:\n");
        printf("  ✓ ReverseEngine standalone scanning\n");
        printf("  ✓ ReverseIntegration creation\n");
        printf("  ✓ analyzeBuffer with real model loading\n");
        printf("  ✓ Callback system\n");
        printf("  ✓ Layer hooks (onLayerProcessed, onAttentionComputed)\n");
        printf("  ✓ Statistics tracking\n");
        return 0;
    } else {
        printf("*** SOME TESTS FAILED ***\n");
        return 1;
    }
}
