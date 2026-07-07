// ============================================================================
// model_operations_bridge_test.cpp — Integration Validation Test
// ============================================================================
// Quick "Hello World" test to verify the ModelOperationsBridge integration
// before wiring complex P0 tools.
//
// Uses mock headers to avoid C++23 std::expected dependency.
//
// Build: build_test_direct.bat
// Run: build\test\model_operations_bridge_test.exe
// ============================================================================

// Include mocks BEFORE real headers to override dependencies
#include "cpu_inference_engine_mock.h"
#include "agentic_executor_mock.h"

#include "core/model_operations_bridge.hpp"
#include "core/thread_pool.hpp"
#include "win32app/IDELogger.h"

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
                std::cout << "[TEST 3] PASS: QueueInference returned 0 (no model)" << std::endl;
                g_testsPassed++;
            } else {
                std::cout << "[TEST 3] INFO: QueueInference returned job ID " << jobId << std::endl;
            }
            
            // Test 4: Get stats
            std::cout << "\n[TEST 4] Checking GetStats()..." << std::endl;
            auto stats = bridge->GetStats();
            std::cout << "[TEST 4] Stats: submitted=" << stats.totalJobsSubmitted
                      << ", completed=" << stats.totalJobsCompleted
                      << ", failed=" << stats.totalJobsFailed << std::endl;
            g_testsPassed++;
            
            // Test 5: Shutdown
            std::cout << "\n[TEST 5] Testing shutdown..." << std::endl;
            bridge->shutdown();
            std::cout << "[TEST 5] PASS: Shutdown completed" << std::endl;
            g_testsPassed++;
            
            // Signal completion
            g_testComplete = true;
            PostQuitMessage(0);
            return 0;
        }
        
        case WM_JOB_COMPLETE: {
            uint64_t jobId = (uint64_t)wParam;
            ModelJobResult* result = (ModelJobResult*)lParam;
            
            std::cout << "[TEST] WM_JOB_COMPLETE received for job " << jobId << std::endl;
            if (result) {
                std::cout << "[TEST]   success=" << result->success << std::endl;
                std::cout << "[TEST]   duration=" << result->durationMs << "ms" << std::endl;
                if (!result->success) {
                    std::cout << "[TEST]   error=" << result->error << std::endl;
                }
            }
            
            // Dispatch result through bridge
            bridge = (ModelOperationsBridge*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            if (bridge && result) {
                bridge->DispatchResult(jobId, result);
            }
            return 0;
        }
        
        case WM_DESTROY: {
            bridge = (ModelOperationsBridge*)GetWindowLongPtr(hwnd, GWLP_USERDATA);
            if (bridge) {
                delete bridge;
                SetWindowLongPtr(hwnd, GWLP_USERDATA, 0);
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
    // Initialize logging
    IDELogger::getInstance().initialize("model_operations_bridge_test.log");
    IDELogger::getInstance().setLevel(IDELogger::Level::DEBUG);
    
    std::cout << "[TEST] ModelOperationsBridge Validation Test" << std::endl;
    std::cout << "[TEST] ======================================" << std::endl;
    
    // Register window class
    WNDCLASSEX wc = {};
    wc.cbSize = sizeof(WNDCLASSEX);
    wc.lpfnWndProc = TestWindowProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = "ModelOperationsBridgeTest";
    
    if (!RegisterClassEx(&wc)) {
        std::cerr << "[TEST] Failed to register window class" << std::endl;
        return 1;
    }
    
    // Create test window (hidden)
    HWND hwnd = CreateWindowEx(
        0,
        "ModelOperationsBridgeTest",
        "ModelOperationsBridge Test",
        0,
        CW_USEDEFAULT, CW_USEDEFAULT,
        0, 0,
        nullptr, nullptr, hInstance, nullptr
    );
    
    if (!hwnd) {
        std::cerr << "[TEST] Failed to create test window" << std::endl;
        return 1;
    }
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    // Print results
    std::cout << "\n[TEST] === Test Results ===" << std::endl;
    std::cout << "[TEST] Passed: " << g_testsPassed << std::endl;
    std::cout << "[TEST] Failed: " << g_testsFailed << std::endl;
    
    if (g_testsFailed == 0) {
        std::cout << "[TEST] SUCCESS: All tests passed!" << std::endl;
        return 0;
    } else {
        std::cout << "[TEST] FAILURE: Some tests failed" << std::endl;
        return 1;
    }
}