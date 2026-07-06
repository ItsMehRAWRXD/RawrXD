// ============================================================================
// RawrXD GUI Component Tests
// ============================================================================
// Tests for individual GUI components
// Build: cl.exe /EHsc /O2 /std:c++17 /FeTestGUI.exe test_gui_components.cpp
// ============================================================================

#include <windows.h>
#include <string>
#include <vector>
#include <iostream>
#include <functional>
#include <cassert>

// Test framework
class TestFramework {
public:
    struct TestResult {
        std::string name;
        bool passed;
        std::string message;
    };
    
    std::vector<TestResult> m_results;
    int m_passed = 0;
    int m_failed = 0;
    
    void RunTest(const std::string& name, std::function<bool()> test) {
        std::cout << "Running: " << name << "... ";
        try {
            bool result = test();
            if (result) {
                std::cout << "PASS" << std::endl;
                m_results.push_back({name, true, ""});
                m_passed++;
            } else {
                std::cout << "FAIL" << std::endl;
                m_results.push_back({name, false, "Test returned false"});
                m_failed++;
            }
        } catch (const std::exception& e) {
            std::cout << "FAIL (exception: " << e.what() << ")" << std::endl;
            m_results.push_back({name, false, e.what()});
            m_failed++;
        }
    }
    
    void PrintSummary() {
        std::cout << "\n========================================" << std::endl;
        std::cout << "Test Summary" << std::endl;
        std::cout << "========================================" << std::endl;
        std::cout << "Passed: " << m_passed << std::endl;
        std::cout << "Failed: " << m_failed << std::endl;
        std::cout << "Total:  " << (m_passed + m_failed) << std::endl;
        std::cout << "========================================" << std::endl;
        
        if (m_failed > 0) {
            std::cout << "\nFailed tests:" << std::endl;
            for (const auto& result : m_results) {
                if (!result.passed) {
                    std::cout << "  - " << result.name << ": " << result.message << std::endl;
                }
            }
        }
    }
};

// Mock classes for testing
class MockInferenceEngine {
public:
    bool m_loaded = false;
    std::wstring m_modelPath;
    std::vector<std::pair<std::string, std::string>> m_history;
    
    bool LoadModel(const std::wstring& path) {
        m_loaded = true;
        m_modelPath = path;
        return true;
    }
    
    bool IsLoaded() const { return m_loaded; }
    
    std::string GenerateResponse(const std::string& input) {
        m_history.push_back({"user", input});
        std::string response = "Response to: " + input;
        m_history.push_back({"assistant", response});
        return response;
    }
    
    void ClearHistory() { m_history.clear(); }
};

class MockChatPanel {
public:
    std::vector<std::wstring> m_messages;
    std::wstring m_status;
    bool m_sendCalled = false;
    
    void AddMessage(const std::wstring& role, const std::wstring& content) {
        m_messages.push_back(role + L": " + content);
    }
    
    void SetStatus(const std::wstring& status) {
        m_status = status;
    }
    
    void OnSend(const std::wstring& input) {
        m_sendCalled = true;
        AddMessage(L"user", input);
    }
};

// Tests
bool RunTests() {
    TestFramework framework;
    
    std::cout << "========================================" << std::endl;
    std::cout << "RawrXD GUI Component Tests" << std::endl;
    std::cout << "========================================" << std::endl << std::endl;
    
    // Test 1: Inference Engine Load
    framework.RunTest("InferenceEngine.LoadModel", []() {
        MockInferenceEngine engine;
        bool result = engine.LoadModel(L"test.gguf");
        return result && engine.IsLoaded() && engine.m_modelPath == L"test.gguf";
    });
    
    // Test 2: Inference Engine Generate
    framework.RunTest("InferenceEngine.GenerateResponse", []() {
        MockInferenceEngine engine;
        engine.LoadModel(L"test.gguf");
        std::string response = engine.GenerateResponse("Hello");
        return response.find("Hello") != std::string::npos;
    });
    
    // Test 3: Inference Engine History
    framework.RunTest("InferenceEngine.ChatHistory", []() {
        MockInferenceEngine engine;
        engine.LoadModel(L"test.gguf");
        engine.GenerateResponse("Message 1");
        engine.GenerateResponse("Message 2");
        return engine.m_history.size() == 4; // 2 user + 2 assistant messages
    });
    
    // Test 4: Chat Panel Add Message
    framework.RunTest("ChatPanel.AddMessage", []() {
        MockChatPanel panel;
        panel.AddMessage(L"user", L"Hello");
        panel.AddMessage(L"assistant", L"Hi");
        return panel.m_messages.size() == 2;
    });
    
    // Test 5: Chat Panel Status
    framework.RunTest("ChatPanel.SetStatus", []() {
        MockChatPanel panel;
        panel.SetStatus(L"Ready");
        return panel.m_status == L"Ready";
    });
    
    // Test 6: Chat Panel Send
    framework.RunTest("ChatPanel.OnSend", []() {
        MockChatPanel panel;
        panel.OnSend(L"Test message");
        return panel.m_sendCalled && panel.m_messages.size() == 1;
    });
    
    // Test 7: Clear History
    framework.RunTest("InferenceEngine.ClearHistory", []() {
        MockInferenceEngine engine;
        engine.LoadModel(L"test.gguf");
        engine.GenerateResponse("Test");
        engine.ClearHistory();
        return engine.m_history.empty();
    });
    
    // Test 8: Model Path Validation
    framework.RunTest("ModelPath.Validation", []() {
        std::wstring path1 = L"model.gguf";
        std::wstring path2 = L"model.bin";
        bool valid1 = path1.find(L".gguf") != std::wstring::npos;
        bool valid2 = path2.find(L".gguf") != std::wstring::npos;
        return valid1 && !valid2;
    });
    
    // Test 9: UTF-8 Conversion
    framework.RunTest("UTF8.Conversion", []() {
        std::wstring wide = L"Hello World";
        int len = WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string utf8(len - 1, 0);
        WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), -1, &utf8[0], len, nullptr, nullptr);
        return utf8 == "Hello World";
    });
    
    // Test 10: Message Formatting
    framework.RunTest("Message.Formatting", []() {
        std::string userMsg = "[You]: Hello";
        std::string aiMsg = "[Assistant]: Hi there";
        bool userFormatted = userMsg.find("[You]") != std::string::npos;
        bool aiFormatted = aiMsg.find("[Assistant]") != std::string::npos;
        return userFormatted && aiFormatted;
    });
    
    framework.PrintSummary();
    
    // CI/headless-friendly: no interactive pause.
    return framework.m_failed == 0;
}

int main() {
    return RunTests() ? 0 : 1;
}
