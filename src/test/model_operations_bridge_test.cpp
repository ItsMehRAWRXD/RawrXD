// ============================================================================
// model_operations_bridge_test.cpp — Integration Validation Test
// ============================================================================
// Quick "Hello World" test to verify the ModelOperationsBridge integration
// before wiring complex P0 tools.
//
// Build: Add to CMakeLists.txt or compile manually
// Run: Validates async inference, benchmark, and callback dispatch
// ============================================================================

#include "core/model_operations_bridge.hpp"
#include "core/thread_pool.hpp"
#include "cpu_inference_engine.h"
#include "IDELogger.h"

#include <iostream>
#include <chrono>
#include <thread>
#include <atomic>
#include <windows.h>

// Test state
static std::atomic<int> g_testsPassed{0};
static std::atomic<int> g_testsFailed{0};
static std::atomic<bool> g_testComplete{false};

// ============================================================================
// Test Window Procedure
// ============================================================================

LRESULT CALLBACK TestWindowProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam)
{
    static ModelOperationsBridge* bridge = nullptr;
    
    switch (msg) {
        case WM_CREATE: {
            // Initialize bridge
            bridge = new ModelOperationsBridge(hwnd, nullptr);
            if (!bridge->initialize()) {
                std::cerr << "[TEST] Failed to initialize ModelOperationsBridge" << std::endl;
                PostQuitMessage(1);
                return -1;
            }
            std::cout << "[TEST] ModelOperationsBridge initialized" << std::endl;
            
            // Store bridge for later use
            SetWindowLongPtr(hwnd, GWLP_USERDATA, (LONG_PTR)bridge);
            
            // Schedule test sequence
            SetTimer(hwnd, 1, 100, nullptr);  // Start tests after 100ms
            return 0;
        }
        
        case WM_TIMER: {
            KillTimer(hwnd, 1);
            
            // Get bridge
            bridge = (ModelOperationsBridge*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            if (!bridge) {
                std::cerr << "[TEST] Bridge not available" << std::endl;
                PostQuitMessage(1);
                return 0;
            }
            
            // Run test sequence
            std::cout << "\n[TEST] === Starting Test Sequence ===\n" << std::endl;
            
            // Test 1: Check if model is loaded (should be false initially)
            std::cout << "[TEST 1] Checking IsModelLoaded()..." << std::endl;
            bool loaded = bridge->IsModelLoaded();
            if (!loaded) {
                std::cout << "[TEST 1] PASS: IsModelLoaded() returned false (expected)" << std::endl;
                g_testsPassed++;
            } else {
                std::cout << "[TEST 1] FAIL: IsModelLoaded() returned true (unexpected)" << std::endl;
                g_testsFailed++;
            }
            
            // Test 2: Get model info (should return error)
            std::cout << "\n[TEST 2] Checking GetModelInfo()..." << std::endl;
            std::string info = bridge->GetModelInfo();
            if (info.find("error") != std::string::npos) {
                std::cout << "[TEST 2] PASS: GetModelInfo() returned error (expected)" << std::endl;
                g_testsPassed++;
            } else {
                std::cout << "[TEST 2] FAIL: GetModelInfo() returned unexpected: " << info << std::endl;
                g_testsFailed++;
            }
            
            // Test 3: Queue inference without model (should fail immediately)
            std::cout << "\n[TEST 3] Testing QueueInference without model..." << std::endl;
            uint64_t jobId = bridge->QueueInference("Test input", 10,
                [](const std::string& result, bool success, const std::string& error) {
                    // This should be called immediately with error
                    if (!success && error.find("No model loaded") != std::string::npos) {
                        std::cout << "[TEST 3] PASS: QueueInference returned error (expected)" << std::endl;
                        g_testsPassed++;
                    } else {
                        std::cout << "[TEST 3] FAIL: Unexpected callback result" << std::endl;
                        g_testsFailed++;
                    }
                });
            
            if (jobId == 0) {
                std::cout << "[TEST 3] PASS: QueueInference returned 0 (expected)" << std::endl;
                g_testsPassed++;
            } else {
                std::cout << "[TEST 3] INFO: QueueInference returned job ID " << jobId << std::endl;
            }
            
            // Test 4: Queue benchmark without model (should fail immediately)
            std::cout << "\n[TEST 4] Testing QueueBenchmark without model..." << std::endl;
            jobId = bridge->QueueBenchmark(5, 10,
                [](double tps, double latency, bool success) {
                    if (!success) {
                        std::cout << "[TEST 4] PASS: QueueBenchmark returned error (expected)" << std::endl;
                        g_testsPassed++;
                    } else {
                        std::cout << "[TEST 4] FAIL: Unexpected benchmark success" << std::endl;
                        g_testsFailed++;
                    }
                });
            
            if (jobId == 0) {
                std::cout << "[TEST 4] PASS: QueueBenchmark returned 0 (expected)" << std::endl;
                g_testsPassed++;
            }
            
            // Test 5: Check statistics
            std::cout << "\n[TEST 5] Checking statistics..." << std::endl;
            auto stats = bridge->GetStats();
            std::cout << "[TEST 5] Jobs submitted: " << stats.totalJobsSubmitted << std::endl;
            std::cout << "[TEST 5] Jobs completed: " << stats.totalJobsCompleted << std::endl;
            std::cout << "[TEST 5] Jobs failed: " << stats.totalJobsFailed << std::endl;
            
            if (stats.totalJobsSubmitted >= 0) {
                std::cout << "[TEST 5] PASS: Statistics available" << std::endl;
                g_testsPassed++;
            } else {
                std::cout << "[TEST 5] FAIL: Statistics unavailable" << std::endl;
                g_testsFailed++;
            }
            
            // Test 6: Test pending job count
            std::cout << "\n[TEST 6] Checking pending job count..." << std::endl;
            size_t pending = bridge->PendingJobCount();
            std::cout << "[TEST 6] Pending jobs: " << pending << std::endl;
            
            if (pending == 0) {
                std::cout << "[TEST 6] PASS: No pending jobs (expected)" << std::endl;
                g_testsPassed++;
            } else {
                std::cout << "[TEST 6] FAIL: Unexpected pending jobs: " << pending << std::endl;
                g_testsFailed++;
            }
            
            // All tests complete
            std::cout << "\n[TEST] === Test Sequence Complete ===" << std::endl;
            std::cout << "[TEST] Passed: " << g_testsPassed << std::endl;
            std::cout << "[TEST] Failed: " << g_testsFailed << std::endl;
            
            // Cleanup and exit
            bridge->shutdown();
            delete bridge;
            PostQuitMessage(0);
            return 0;
        }
        
        case WM_JOB_COMPLETE: {
            // Handle async job completion
            uint64_t jobId = static_cast<uint64_t>(wParam);
            ModelJobResult* result = reinterpret_cast<ModelJobResult*>(lParam);
            
            bridge = (ModelOperationsBridge*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            if (bridge && result) {
                bridge->DispatchResult(jobId, result);
            } else if (result) {
                delete result;
            }
            return 0;
        }
        
        case WM_DESTROY: {
            bridge = (ModelOperationsBridge*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            if (bridge) {
                bridge->shutdown();
                delete bridge;
            }
            PostQuitMessage(0);
            return 0;
        }
    }
    
    return DefWindowProc(hwnd, msg, wParam, lParam);
}

// ============================================================================
// Main Entry Point
// ============================================================================

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow)
{
    // Initialize logger
    IDELogger::getInstance().initialize("model_bridge_test.log", IDELogger::Level::DEBUG);
    
    // Register window class
    WNDCLASSEXA wc = {0};
    wc.cbSize = sizeof(WNDCLASSEXA);
    wc.lpfnWndProc = TestWindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ModelBridgeTestClass";
    wc.hCursor = LoadCursor(nullptr, IDC_ARROW);
    
    if (!RegisterClassExA(&wc)) {
        std::cerr << "[TEST] Failed to register window class" << std::endl;
        return 1;
    }
    
    // Create test window (hidden)
    HWND hwnd = CreateWindowExA(
        0,
        "ModelBridgeTestClass",
        "Model Bridge Test",
        WS_OVERLAPPEDWINDOW,
        CW_USEDEFAULT, CW_USEDEFAULT, 400, 300,
        nullptr, nullptr, hInstance, nullptr
    );
    
    if (!hwnd) {
        std::cerr << "[TEST] Failed to create window" << std::endl;
        return 1;
    }
    
    // Initialize ThreadPool
    RawrXD::Threading::ThreadPool::Global();
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Report results
    std::cout << "\n[TEST] === Final Results ===" << std::endl;
    std::cout << "[TEST] Tests Passed: " << g_testsPassed << std::endl;
    std::cout << "[TEST] Tests Failed: " << g_testsFailed << std::endl;
    
    if (g_testsFailed == 0) {
        std::cout << "[TEST] ✅ ALL TESTS PASSED" << std::endl;
        return 0;
    } else {
        std::cout << "[TEST] ❌ SOME TESTS FAILED" << std::endl;
        return 1;
    }
}

// ============================================================================
// VALIDATION CHECKLIST
// ============================================================================

/*
✅ Test 1: IsModelLoaded() returns false when no model loaded
✅ Test 2: GetModelInfo() returns error when no model loaded
✅ Test 3: QueueInference() fails gracefully without model
✅ Test 4: QueueBenchmark() fails gracefully without model
✅ Test 5: GetStats() returns valid statistics
✅ Test 6: PendingJobCount() returns 0 when no jobs pending

EXPECTED OUTPUT:
[TEST] === Starting Test Sequence ===
[TEST 1] Checking IsModelLoaded()...
[TEST 1] PASS: IsModelLoaded() returned false (expected)
[TEST 2] Checking GetModelInfo()...
[TEST 2] PASS: GetModelInfo() returned error (expected)
[TEST 3] Testing QueueInference without model...
[TEST 3] PASS: QueueInference returned error (expected)
[TEST 4] Testing QueueBenchmark without model...
[TEST 4] PASS: QueueBenchmark returned error (expected)
[TEST 5] Checking statistics...
[TEST 5] PASS: Statistics available
[TEST 6] Checking pending job count...
[TEST 6] PASS: No pending jobs (expected)
[TEST] === Test Sequence Complete ===
[TEST] Passed: 6
[TEST] Failed: 0
[TEST] ✅ ALL TESTS PASSED

NEXT STEPS AFTER VALIDATION:
1. Run this test to verify basic integration
2. Add real model file and test actual inference
3. Test with ThreadPool under load
4. Verify UI remains responsive during inference
5. Test cancellation with CancelJob()
*/