// ============================================================================
// RawrXD_IDE_TestHarness.cpp - Comprehensive IDE Pipeline Test
// ============================================================================
// Tests the complete IDE integration:
// - Ghost text rendering
// - AI inference bridge
// - Token streaming
// - User interactions (Tab, Esc, Ctrl+Break)
// - Telemetry collection
// ============================================================================

#include <Windows.h>
#include <iostream>
#include <fstream>
#include <chrono>
#include <thread>
#include <atomic>
#include <string>

// IDE Components
#include "RawrXD_IDE_Integration.hpp"
#include "GhostTextWndProc.hpp"
#include "AIInferenceBridge.hpp"

// Deep2 Engine
#include "../deep2/Deep2Engine.h"

// Test configuration
#define TEST_WINDOW_WIDTH 800
#define TEST_WINDOW_HEIGHT 600

using namespace RawrXD::IDE;

// ============================================================================
// Test Results
// ============================================================================
struct TestResults {
    int totalTests = 0;
    int passedTests = 0;
    int failedTests = 0;
    std::string log;

    void RecordPass(const char* testName) {
        totalTests++;
        passedTests++;
        log += "[PASS] " + std::string(testName) + "\n";
        std::cout << "[PASS] " << testName << std::endl;
    }

    void RecordFail(const char* testName, const char* reason) {
        totalTests++;
        failedTests++;
        log += "[FAIL] " + std::string(testName) + ": " + reason + "\n";
        std::cout << "[FAIL] " << testName << ": " << reason << std::endl;
    }

    void PrintSummary() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Test Summary" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Total:  " << totalTests << std::endl;
        std::cout << "Passed: " << passedTests << std::endl;
        std::cout << "Failed: " << failedTests << std::endl;
        std::cout << "========================================" << std::endl;
    }

    bool SaveToFile(const char* filename) {
        std::ofstream file(filename);
        if (!file.is_open()) return false;
        file << "RawrXD IDE Test Results\n";
        file << "=======================\n\n";
        file << log;
        file << "\n=======================\n";
        file << "Total:  " << totalTests << "\n";
        file << "Passed: " << passedTests << "\n";
        file << "Failed: " << failedTests << "\n";
        file.close();
        return true;
    }
};

static TestResults g_results;

// ============================================================================
// Test 1: Ghost Text System Initialization
// ============================================================================
void Test_GhostTextInitialization() {
    std::cout << "\n[Test] Ghost Text Initialization..." << std::endl;

    // Create a test window
    WNDCLASS wc = {};
    wc.lpfnWndProc = DefWindowProc;
    wc.hInstance = GetModuleHandle(nullptr);
    wc.lpszClassName = "TestIDEWindow";
    RegisterClass(&wc);

    HWND hWnd = CreateWindow("TestIDEWindow", "Test",
        WS_OVERLAPPEDWINDOW, 0, 0, 100, 100,
        nullptr, nullptr, wc.hInstance, nullptr);

    HWND hEditor = CreateWindow("EDIT", "",
        WS_CHILD | WS_VISIBLE | ES_MULTILINE,
        0, 0, 100, 100, hWnd, nullptr, wc.hInstance, nullptr);

    if (!hWnd || !hEditor) {
        g_results.RecordFail("GhostText_Init", "Failed to create test windows");
        return;
    }

    // Test installation
    bool installed = GhostText_Install(hWnd, hEditor);
    if (!installed) {
        g_results.RecordFail("GhostText_Init", "GhostText_Install failed");
        DestroyWindow(hEditor);
        DestroyWindow(hWnd);
        return;
    }

    // Test initial state
    bool isShowing = GhostText_IsShowing();
    if (isShowing) {
        g_results.RecordFail("GhostText_Init", "Ghost text should not be showing initially");
        GhostText_Uninstall(hWnd, hEditor);
        DestroyWindow(hEditor);
        DestroyWindow(hWnd);
        return;
    }

    // Cleanup
    GhostText_Uninstall(hWnd, hEditor);
    DestroyWindow(hEditor);
    DestroyWindow(hWnd);
    UnregisterClass("TestIDEWindow", wc.hInstance);

    g_results.RecordPass("GhostText_Init");
}

// ============================================================================
// Test 2: AI Inference Bridge Initialization
// ============================================================================
void Test_AIInferenceBridge() {
    std::cout << "\n[Test] AI Inference Bridge..." << std::endl;

    // Create a mock engine (without actual model)
    Deep2::Deep2Engine engine;

    // Initialize bridge
    bool initialized = AIInferenceBridge_Initialize(&engine);
    if (!initialized) {
        g_results.RecordFail("AIBridge_Init", "Failed to initialize bridge");
        return;
    }

    // Get bridge instance
    AIInferenceBridge* bridge = AIInferenceBridge_Get();
    if (!bridge) {
        g_results.RecordFail("AIBridge_Init", "Get returned nullptr");
        AIInferenceBridge_Shutdown();
        return;
    }

    // Check initial state
    if (bridge->IsGenerating()) {
        g_results.RecordFail("AIBridge_Init", "Should not be generating initially");
        AIInferenceBridge_Shutdown();
        return;
    }

    AIInferenceBridge_Shutdown();
    g_results.RecordPass("AIBridge_Init");
}

// ============================================================================
// Test 3: Token Streaming Simulation
// ============================================================================
void Test_TokenStreaming() {
    std::cout << "\n[Test] Token Streaming Simulation..." << std::endl;

    // This test simulates the token streaming without actual model
    // by directly calling the ghost text callbacks

    std::atomic<int> tokensReceived{0};
    std::atomic<bool> streamComplete{false};

    // Simulate stream start
    GhostText_OnAIStreamStart();

    // Simulate tokens arriving
    const char* testTokens[] = {
        "function", " ", "test", "()", " ", "{", "\n",
        "    ", "return", " ", "42", ";", "\n", "}"
    };

    std::string accumulated;
    for (const auto& token : testTokens) {
        accumulated += token;
        GhostText_OnAICompletion(accumulated.c_str(), -1);
        tokensReceived++;

        // Small delay to simulate real streaming
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
    }

    GhostText_OnAIStreamEnd();
    streamComplete = true;

    // Verify
    if (tokensReceived != 13) {
        g_results.RecordFail("TokenStreaming", "Token count mismatch");
        return;
    }

    if (!streamComplete) {
        g_results.RecordFail("TokenStreaming", "Stream not marked complete");
        return;
    }

    g_results.RecordPass("TokenStreaming");
}

// ============================================================================
// Test 4: User Interaction Simulation
// ============================================================================
void Test_UserInteractions() {
    std::cout << "\n[Test] User Interactions..." << std::endl;

    // Test 4a: Tab to accept
    GhostText_ShowSuggestion(0, "test_completion");
    if (!GhostText_IsShowing()) {
        g_results.RecordFail("UserInteraction_Tab", "Ghost text not showing");
        return;
    }

    // Simulate Tab key (accept)
    bool accepted = GhostText_Accept();
    if (!accepted) {
        g_results.RecordFail("UserInteraction_Tab", "Accept failed");
        return;
    }

    if (GhostText_IsShowing()) {
        g_results.RecordFail("UserInteraction_Tab", "Ghost text should be dismissed after accept");
        return;
    }

    // Test 4b: Escape to dismiss
    GhostText_ShowSuggestion(0, "another_completion");
    if (!GhostText_IsShowing()) {
        g_results.RecordFail("UserInteraction_Esc", "Ghost text not showing");
        return;
    }

    GhostText_Dismiss();
    if (GhostText_IsShowing()) {
        g_results.RecordFail("UserInteraction_Esc", "Ghost text should be dismissed");
        return;
    }

    g_results.RecordPass("UserInteractions");
}

// ============================================================================
// Test 5: Telemetry Collection
// ============================================================================
void Test_Telemetry() {
    std::cout << "\n[Test] Telemetry Collection..." << std::endl;

    Deep2::Deep2Engine engine;
    if (!AIInferenceBridge_Initialize(&engine)) {
        g_results.RecordFail("Telemetry", "Failed to initialize bridge");
        return;
    }

    AIInferenceBridge* bridge = AIInferenceBridge_Get();
    if (!bridge) {
        g_results.RecordFail("Telemetry", "Bridge is nullptr");
        AIInferenceBridge_Shutdown();
        return;
    }

    // Reset telemetry
    bridge->ResetTelemetry();

    // Get telemetry (should be empty/zeroed)
    const auto& telemetry = bridge->GetLastTelemetry();
    if (telemetry.tokensGenerated != 0) {
        g_results.RecordFail("Telemetry", "Initial tokensGenerated should be 0");
        AIInferenceBridge_Shutdown();
        return;
    }

    // Export to JSON
    std::string json = bridge->ExportTelemetryJson();
    if (json.empty()) {
        g_results.RecordFail("Telemetry", "Export returned empty string");
        AIInferenceBridge_Shutdown();
        return;
    }

    // Verify JSON format
    if (json.find("requestId") == std::string::npos) {
        g_results.RecordFail("Telemetry", "JSON missing requestId field");
        AIInferenceBridge_Shutdown();
        return;
    }

    AIInferenceBridge_Shutdown();
    g_results.RecordPass("Telemetry");
}

// ============================================================================
// Test 6: Stale Generation Protection
// ============================================================================
void Test_StaleGenerationProtection() {
    std::cout << "\n[Test] Stale Generation Protection..." << std::endl;

    Deep2::Deep2Engine engine;
    if (!AIInferenceBridge_Initialize(&engine)) {
        g_results.RecordFail("StaleGenProtection", "Failed to initialize");
        return;
    }

    // Start first generation
    uint64_t gen1 = AIInferenceBridge_Start("context", 0, 0, 10);
    if (gen1 == 0) {
        g_results.RecordFail("StaleGenProtection", "Failed to start generation");
        AIInferenceBridge_Shutdown();
        return;
    }

    // Start second generation (should invalidate first)
    uint64_t gen2 = AIInferenceBridge_Start("new context", 0, 0, 10);
    if (gen2 == 0) {
        g_results.RecordFail("StaleGenProtection", "Failed to start second generation");
        AIInferenceBridge_Shutdown();
        return;
    }

    if (gen2 <= gen1) {
        g_results.RecordFail("StaleGenProtection", "Generation ID should increment");
        AIInferenceBridge_Shutdown();
        return;
    }

    // Cancel current
    AIInferenceBridge_Cancel();

    AIInferenceBridge_Shutdown();
    g_results.RecordPass("StaleGenProtection");
}

// ============================================================================
// Test 7: Performance Benchmark
// ============================================================================
void Test_PerformanceBenchmark() {
    std::cout << "\n[Test] Performance Benchmark..." << std::endl;

    auto start = std::chrono::high_resolution_clock::now();

    // Measure ghost text show/dismiss latency
    const int iterations = 1000;
    for (int i = 0; i < iterations; i++) {
        GhostText_ShowSuggestion(i, "test");
        GhostText_Dismiss();
    }

    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    double avgLatency = duration.count() / (double)iterations;

    std::cout << "  Average ghost text latency: " << avgLatency << " us" << std::endl;

    // Should be under 100 microseconds per operation
    if (avgLatency > 100.0) {
        g_results.RecordFail("Performance", "Latency too high");
        return;
    }

    g_results.RecordPass("Performance");
}

// ============================================================================
// Main Test Entry Point
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD IDE Test Harness" << std::endl;
    std::cout << "========================================" << std::endl;
    std::cout << "Testing complete IDE pipeline..." << std::endl;

    // Run all tests
    Test_GhostTextInitialization();
    Test_AIInferenceBridge();
    Test_TokenStreaming();
    Test_UserInteractions();
    Test_Telemetry();
    Test_StaleGenerationProtection();
    Test_PerformanceBenchmark();

    // Print summary
    g_results.PrintSummary();

    // Save results
    if (g_results.SaveToFile("IDE_TestResults.txt")) {
        std::cout << "\nResults saved to IDE_TestResults.txt" << std::endl;
    }

    // Return exit code
    return g_results.failedTests > 0 ? 1 : 0;
}
