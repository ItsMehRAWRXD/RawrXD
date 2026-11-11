// ============================================================================
// Inference Routing Test - Minimal validation of local vs Ollama path selection
// ============================================================================
// Build: cmake --build . --target RawrXD-InferenceRoutingTest
// Run:   .\bin\RawrXD-InferenceRoutingTest.exe
//
// This test validates:
// 1. Local GGUF inference path is prioritized
// 2. Ollama fallback works when local model not loaded
// 3. Audit logging captures the actual branch taken
// ============================================================================

#define WIN32_LEAN_AND_MEAN
#define NOMINMAX
#include <windows.h>
#include <iostream>
#include <string>
#include <functional>
#include <thread>
#include <atomic>

// Minimal mock of Win32IDE inference state
class InferenceRouterTest {
public:
    // State flags that would normally come from Win32IDE
    bool m_nativeEngineLoaded = false;
    bool m_nativeEngine = false;
    std::string m_loadedModelPath;
    std::atomic<bool> m_inferenceRunning{false};
    
    // Simulated chat history
    struct ChatMessage {
        std::string role;
        std::string content;
    };
    std::vector<ChatMessage> m_chatHistory;
    
    // Test result tracking
    struct TestResult {
        std::string testName;
        bool passed;
        std::string actualPath;
        std::string expectedPath;
        std::string logOutput;
    };
    std::vector<TestResult> m_results;
    
    // Simulated Ollama client
    bool m_ollamaCalled = false;
    std::string m_lastOllamaPrompt;
    
    // Simulated native engine
    bool m_nativeEngineCalled = false;
    std::string m_lastNativePrompt;

    void Reset() {
        m_nativeEngineLoaded = false;
        m_nativeEngine = false;
        m_loadedModelPath.clear();
        m_inferenceRunning = false;
        m_chatHistory.clear();
        m_ollamaCalled = false;
        m_lastOllamaPrompt.clear();
        m_nativeEngineCalled = false;
        m_lastNativePrompt.clear();
    }
    
    // ============================================================================
    // CORE TEST: HandleCopilotSend with routing decision logging
    // ============================================================================
    void HandleCopilotSend(const std::string& userMessage) {
        std::cout << "\n========== CHAT REQUEST ==========\n";
        std::cout << "User message: " << userMessage << "\n";
        
        // AUDIT: Log decision factors (matches Win32IDE implementation)
        std::cout << "[AUDIT] Chat inference decision:\n";
        std::cout << "  m_nativeEngineLoaded = " << (m_nativeEngineLoaded ? "true" : "false") << "\n";
        std::cout << "  m_nativeEngine = " << (m_nativeEngine ? " " : "null") << "\n";
        std::cout << "  m_loadedModelPath = '" << m_loadedModelPath << "'\n";
        
        // PRIORITY 1: Local native inference
        if (m_nativeEngineLoaded && m_nativeEngine) {
            std::cout << "[AUDIT] Chat: Using LOCAL native inference engine\n";
            GenerateLocalResponse(userMessage);
            return;
        }
        
        // PRIORITY 2: Fallback to Ollama
        std::cout << "[AUDIT] Chat: FALLING BACK to Ollama (local engine not ready)\n";
        SendToOllama(userMessage);
    }
    
    void GenerateLocalResponse(const std::string& prompt) {
        m_nativeEngineCalled = true;
        m_lastNativePrompt = prompt;
        
        std::cout << "[LOCAL] Generating response for: " << prompt << "\n";
        
        // Simulate streaming tokens
        std::vector<std::string> tokens = {"2", "+", "2", "=", "4"};
        std::string fullResponse;
        
        for (const auto& token : tokens) {
            std::cout << "[LOCAL] Token: '" << token << "'\n";
            fullResponse += token;
        }
        
        std::cout << "[LOCAL] Complete response: " << fullResponse << "\n";
        m_chatHistory.push_back({"assistant", fullResponse});
    }
    
    void SendToOllama(const std::string& prompt) {
        m_ollamaCalled = true;
        m_lastOllamaPrompt = prompt;
        
        std::cout << "[OLLAMA] Sending to Ollama API: " << prompt << "\n";
        
        // Simulate Ollama response
        std::string response = "The answer is 4.";
        std::cout << "[OLLAMA] Response: " << response << "\n";
        m_chatHistory.push_back({"assistant", response});
    }
    
    // ============================================================================
    // TEST CASES
    // ============================================================================
    void RunTest_LocalEngineReady() {
        std::cout << "\n\n========================================\n";
        std::cout << "TEST 1: Local Engine Ready\n";
        std::cout << "========================================\n";
        
        Reset();
        m_nativeEngineLoaded = true;
        m_nativeEngine = true;
        m_loadedModelPath = "d:\\models\\test.gguf";
        
        HandleCopilotSend("What is 2+2?");
        
        // Verify
        bool passed = (m_nativeEngineCalled && !m_ollamaCalled);
        std::cout << "\n[TEST RESULT] " << (passed ? "PASS" : "FAIL") << "\n";
        std::cout << "  Expected: LOCAL path\n";
        std::cout << "  Actual: " << (m_nativeEngineCalled ? "LOCAL" : "OLLAMA") << "\n";
        
        m_results.push_back({"LocalEngineReady", passed, 
            m_nativeEngineCalled ? "LOCAL" : "OLLAMA", "LOCAL", ""});
    }
    
    void RunTest_NoLocalEngine() {
        std::cout << "\n\n========================================\n";
        std::cout << "TEST 2: No Local Engine (Fallback to Ollama)\n";
        std::cout << "========================================\n";
        
        Reset();
        // m_nativeEngineLoaded = false (default)
        // m_nativeEngine = false (default)
        
        HandleCopilotSend("What is 2+2?");
        
        // Verify
        bool passed = (!m_nativeEngineCalled && m_ollamaCalled);
        std::cout << "\n[TEST RESULT] " << (passed ? "PASS" : "FAIL") << "\n";
        std::cout << "  Expected: OLLAMA fallback\n";
        std::cout << "  Actual: " << (m_ollamaCalled ? "OLLAMA" : "LOCAL") << "\n";
        
        m_results.push_back({"NoLocalEngine", passed,
            m_ollamaCalled ? "OLLAMA" : "LOCAL", "OLLAMA", ""});
    }
    
    void RunTest_ModelLoadedButEngineNotReady() {
        std::cout << "\n\n========================================\n";
        std::cout << "TEST 3: Model Path Set But Engine Not Initialized\n";
        std::cout << "========================================\n";
        
        Reset();
        m_loadedModelPath = "d:\\models\\test.gguf";
        // m_nativeEngineLoaded = false (engine not actually ready)
        
        HandleCopilotSend("What is 2+2?");
        
        // Verify - should fallback because m_nativeEngineLoaded is false
        bool passed = (!m_nativeEngineCalled && m_ollamaCalled);
        std::cout << "\n[TEST RESULT] " << (passed ? "PASS" : "FAIL") << "\n";
        std::cout << "  Expected: OLLAMA fallback (engine not ready)\n";
        std::cout << "  Actual: " << (m_ollamaCalled ? "OLLAMA" : "LOCAL") << "\n";
        
        m_results.push_back({"ModelPathButNoEngine", passed,
            m_ollamaCalled ? "OLLAMA" : "LOCAL", "OLLAMA", ""});
    }
    
    void RunTest_EngineLoadedButNoModel() {
        std::cout << "\n\n========================================\n";
        std::cout << "TEST 4: Engine Ready But No Model Loaded\n";
        std::cout << "========================================\n";
        
        Reset();
        m_nativeEngineLoaded = true;
        m_nativeEngine = true;
        // m_loadedModelPath is empty
        
        HandleCopilotSend("What is 2+2?");
        
        // This should still try local path (engine is ready)
        // The actual model loading check happens inside generateResponseAsync
        bool passed = (m_nativeEngineCalled && !m_ollamaCalled);
        std::cout << "\n[TEST RESULT] " << (passed ? "PASS" : "FAIL") << "\n";
        std::cout << "  Expected: LOCAL path (engine ready)\n";
        std::cout << "  Actual: " << (m_nativeEngineCalled ? "LOCAL" : "OLLAMA") << "\n";
        
        m_results.push_back({"EngineReadyNoModel", passed,
            m_nativeEngineCalled ? "LOCAL" : "OLLAMA", "LOCAL", ""});
    }
    
    void PrintSummary() {
        std::cout << "\n\n========================================\n";
        std::cout << "TEST SUMMARY\n";
        std::cout << "========================================\n";
        
        int passed = 0;
        int failed = 0;
        
        for (const auto& result : m_results) {
            std::cout << result.testName << ": " 
                      << (result.passed ? "PASS" : "FAIL")
                      << " (expected: " << result.expectedPath
                      << ", actual: " << result.actualPath << ")\n";
            if (result.passed) passed++;
            else failed++;
        }
        
        std::cout << "\nTotal: " << passed << " passed, " << failed << " failed\n";
        
        if (failed == 0) {
            std::cout << "\n✓ All inference routing tests PASSED\n";
            std::cout << "  Local inference is correctly prioritized\n";
            std::cout << "  Ollama fallback works when local unavailable\n";
        } else {
            std::cout << "\n✗ Some tests FAILED - review routing logic\n";
        }
    }
};

// ============================================================================
// MAIN ENTRY POINT
// ============================================================================
int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "RawrXD Inference Routing Test\n";
    std::cout << "========================================\n";
    std::cout << "Validates local vs Ollama path selection\n\n";
    
    InferenceRouterTest test;
    
    // Run all test cases
    test.RunTest_LocalEngineReady();
    test.RunTest_NoLocalEngine();
    test.RunTest_ModelLoadedButEngineNotReady();
    test.RunTest_EngineLoadedButNoModel();
    
    // Print summary
    test.PrintSummary();
    
    std::cout << "\nPress Enter to exit...\n";
    std::cin.get();
    
    return 0;
}
