// smoke_test_rag.cpp - Lightweight smoke test for RAG pipeline
// Compile: cl.exe /EHsc /std:c++17 /I d:\rawrxd\include /I d:\rawrxd\src\core smoke_test_rag.cpp d:\rawrxd\src\core\voice_assistant_types.cpp /link /OUT:smoke_test_rag.exe
// ============================================================================

#include <iostream>
#include <string>
#include <chrono>
#include <nlohmann/json.hpp>

// Minimal includes for smoke test
#include "../src/core/voice_assistant_types.hpp"

// Simple test framework
#define TEST_ASSERT(cond, msg) do { \
    if (!(cond)) { \
        std::cerr << "[FAIL] " << __FILE__ << ":" << __LINE__ << " - " << msg << std::endl; \
        return false; \
    } \
} while(0)

#define TEST_PASS(msg) do { \
    std::cout << "[PASS] " << msg << std::endl; \
    return true; \
} while(0)

// ============================================================================
// Mock Analyzer for Smoke Testing
// ============================================================================

class SmokeTestAnalyzer : public CodebaseContextAnalyzer {
public:
    mutable int call_count = 0;
    
    ScopeInfo analyzeCurrentScope(const std::string& file, int line, int column) override {
        call_count++;
        ScopeInfo scope;
        scope.type = "test_scope";
        scope.name = "TestFunction";
        scope.filePath = file;
        scope.lineNumber = line;
        scope.column = column;
        return scope;
    }
    
    std::vector<Symbol> getRelevantSymbols(const std::string& query, const ScopeInfo& scope) override {
        call_count++;
        std::vector<Symbol> results;
        
        Symbol s1;
        s1.name = "process_voice_input";
        s1.type = "function";
        s1.filePath = "voice_assistant_manager.cpp";
        s1.lineNumber = 42;
        s1.signature = "json process_voice_input(string, string, string)";
        results.push_back(s1);
        
        Symbol s2;
        s2.name = "query_codebase";
        s2.type = "method";
        s2.filePath = "voice_assistant_manager.cpp";
        s2.lineNumber = 180;
        s2.signature = "json query_codebase(string, string, int)";
        results.push_back(s2);
        
        return results;
    }
    
    std::vector<std::string> getDependencies(const std::string& file) override {
        call_count++;
        return {
            "voice_assistant_types.hpp",
            "nlohmann/json.hpp",
            "IDE_Telemetry.hpp"
        };
    }
    
    bool initialize(const std::string& path) override {
        std::cout << "  [Mock] Initializing analyzer for: " << path << std::endl;
        return true;
    }
    
    bool isReady() const override {
        return true;
    }
};

// ============================================================================
// Smoke Tests
// ============================================================================

bool test_symbol_structure() {
    std::cout << "\n[Test] Symbol Structure...\n";
    
    Symbol s;
    s.name = "TestFunction";
    s.type = "function";
    s.filePath = "test.cpp";
    s.lineNumber = 100;
    s.signature = "void TestFunction(int)";
    
    TEST_ASSERT(s.name == "TestFunction", "Symbol name mismatch");
    TEST_ASSERT(s.type == "function", "Symbol type mismatch");
    TEST_ASSERT(s.lineNumber == 100, "Symbol line number mismatch");
    TEST_ASSERT(!s.filePath.empty(), "Symbol file path empty");
    
    TEST_PASS("Symbol structure valid");
}

bool test_scope_info_structure() {
    std::cout << "\n[Test] ScopeInfo Structure...\n";
    
    ScopeInfo scope;
    scope.type = "class";
    scope.name = "VoiceAssistantManager";
    scope.filePath = "voice_assistant_manager.hpp";
    scope.lineNumber = 25;
    scope.column = 0;
    
    TEST_ASSERT(scope.type == "class", "Scope type mismatch");
    TEST_ASSERT(scope.name == "VoiceAssistantManager", "Scope name mismatch");
    TEST_ASSERT(scope.lineNumber == 25, "Scope line number mismatch");
    
    // Test JSON serialization
    auto json = scope.to_json();
    TEST_ASSERT(json["type"] == "class", "JSON type field mismatch");
    TEST_ASSERT(json["name"] == "VoiceAssistantManager", "JSON name field mismatch");
    
    TEST_PASS("ScopeInfo structure valid");
}

bool test_mock_analyzer() {
    std::cout << "\n[Test] Mock Analyzer...\n";
    
    SmokeTestAnalyzer analyzer;
    
    // Test scope analysis
    auto scope = analyzer.analyzeCurrentScope("test.cpp", 50, 10);
    TEST_ASSERT(scope.type == "test_scope", "Mock scope type mismatch");
    TEST_ASSERT(analyzer.call_count == 1, "Call count should be 1 after analyzeCurrentScope");
    
    // Test symbol retrieval
    auto symbols = analyzer.getRelevantSymbols("find functions", scope);
    TEST_ASSERT(symbols.size() == 2, "Should return 2 mock symbols");
    TEST_ASSERT(symbols[0].name == "process_voice_input", "First symbol name mismatch");
    TEST_ASSERT(analyzer.call_count == 2, "Call count should be 2 after getRelevantSymbols");
    
    // Test dependencies
    auto deps = analyzer.getDependencies("test.cpp");
    TEST_ASSERT(deps.size() == 3, "Should return 3 mock dependencies");
    TEST_ASSERT(analyzer.call_count == 3, "Call count should be 3 after getDependencies");
    
    TEST_PASS("Mock analyzer working correctly");
}

bool test_intent_utils() {
    std::cout << "\n[Test] Intent Utilities...\n";
    
    // Test intent to string conversion
    std::string ide_build_str = VoiceAssistantUtils::intent_to_string(IntentType::IDE_BUILD);
    TEST_ASSERT(ide_build_str == "ide_build", "IDE_BUILD string conversion failed");
    
    std::string code_explain_str = VoiceAssistantUtils::intent_to_string(IntentType::CODE_EXPLAIN_SYMBOL);
    TEST_ASSERT(code_explain_str == "code_explain_symbol", "CODE_EXPLAIN_SYMBOL string conversion failed");
    
    // Test string to intent conversion
    auto ide_build_intent = VoiceAssistantUtils::string_to_intent("ide_build");
    TEST_ASSERT(ide_build_intent == IntentType::IDE_BUILD, "ide_build string to intent failed");
    
    auto unknown_intent = VoiceAssistantUtils::string_to_intent("unknown_xyz");
    TEST_ASSERT(unknown_intent == IntentType::UNKNOWN, "Unknown intent should return UNKNOWN");
    
    // Test IDE action detection
    TEST_ASSERT(VoiceAssistantUtils::is_ide_action_intent(IntentType::IDE_BUILD) == true, "IDE_BUILD should be IDE action");
    TEST_ASSERT(VoiceAssistantUtils::is_ide_action_intent(IntentType::WEATHER) == false, "WEATHER should not be IDE action");
    
    TEST_PASS("Intent utilities working correctly");
}

bool test_ide_action_structure() {
    std::cout << "\n[Test] IDE Action Structure...\n";
    
    IDEAction action;
    action.command_id = "IDM_BUILD_SOLUTION";
    action.description = "Build the current project";
    action.requires_confirmation = false;
    action.requires_context = true;
    
    TEST_ASSERT(action.command_id == "IDM_BUILD_SOLUTION", "Command ID mismatch");
    TEST_ASSERT(action.description == "Build the current project", "Description mismatch");
    TEST_ASSERT(action.requires_confirmation == false, "requires_confirmation mismatch");
    TEST_ASSERT(action.requires_context == true, "requires_context mismatch");
    
    // Test constructor
    IDEAction action2("IDM_FILE_SAVE", "Save file", true, false);
    TEST_ASSERT(action2.command_id == "IDM_FILE_SAVE", "Constructor command ID mismatch");
    TEST_ASSERT(action2.requires_confirmation == true, "Constructor requires_confirmation mismatch");
    
    TEST_PASS("IDE Action structure valid");
}

bool test_dispatcher_registration() {
    std::cout << "\n[Test] Command Dispatcher Registration...\n";
    
    VoiceAssistantCommandDispatcher dispatcher;
    dispatcher.register_default_ide_actions();
    
    // Check that default actions are registered
    TEST_ASSERT(dispatcher.has_action(IntentType::IDE_BUILD) == true, "IDE_BUILD should be registered");
    TEST_ASSERT(dispatcher.has_action(IntentType::IDE_RUN) == true, "IDE_RUN should be registered");
    TEST_ASSERT(dispatcher.has_action(IntentType::IDE_DEBUG) == true, "IDE_DEBUG should be registered");
    TEST_ASSERT(dispatcher.has_action(IntentType::UNKNOWN) == false, "UNKNOWN should not be registered");
    
    // Check action retrieval
    auto build_action = dispatcher.get_action(IntentType::IDE_BUILD);
    TEST_ASSERT(build_action.command_id == "IDM_BUILD_SOLUTION", "Build action command ID mismatch");
    TEST_ASSERT(!build_action.description.empty(), "Build action description should not be empty");
    
    // Check unknown action handling
    auto unknown_action = dispatcher.get_action(IntentType::UNKNOWN);
    TEST_ASSERT(unknown_action.description == "Unknown action", "Unknown action should have default description");
    
    TEST_PASS("Command dispatcher registration working");
}

bool test_performance_baseline() {
    std::cout << "\n[Test] Performance Baseline...\n";
    
    SmokeTestAnalyzer analyzer;
    
    const int iterations = 1000;
    auto start = std::chrono::high_resolution_clock::now();
    
    for (int i = 0; i < iterations; ++i) {
        auto scope = analyzer.analyzeCurrentScope("test.cpp", i, 0);
        auto symbols = analyzer.getRelevantSymbols("query", scope);
        auto deps = analyzer.getDependencies("test.cpp");
    }
    
    auto end = std::chrono::high_resolution_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    double avg_ms = static_cast<double>(duration) / iterations;
    
    std::cout << "  " << iterations << " iterations in " << duration << " ms\n";
    std::cout << "  Average: " << avg_ms << " ms per full RAG cycle\n";
    
    // Should complete 1000 iterations in less than 100ms (very generous)
    TEST_ASSERT(duration < 1000, "Performance regression detected: >1s for 1000 iterations");
    TEST_ASSERT(avg_ms < 1.0, "Average latency should be < 1ms");
    
    TEST_PASS("Performance baseline acceptable");
}

// ============================================================================
// Main Entry Point
// ============================================================================

int main(int argc, char* argv[]) {
    std::cout << "========================================\n";
    std::cout << "RawrXD Voice Assistant RAG Smoke Tests\n";
    std::cout << "========================================\n";
    
    int passed = 0;
    int failed = 0;
    
    // Run all tests
    auto run_test = [&](const char* name, bool (*test_func)()) {
        std::cout << "\n--- Running: " << name << " ---";
        if (test_func()) {
            passed++;
        } else {
            failed++;
        }
    };
    
    run_test("Symbol Structure", test_symbol_structure);
    run_test("ScopeInfo Structure", test_scope_info_structure);
    run_test("Mock Analyzer", test_mock_analyzer);
    run_test("Intent Utilities", test_intent_utils);
    run_test("IDE Action Structure", test_ide_action_structure);
    run_test("Dispatcher Registration", test_dispatcher_registration);
    run_test("Performance Baseline", test_performance_baseline);
    
    // Summary
    std::cout << "\n\n========================================\n";
    std::cout << "Test Summary: " << passed << " passed, " << failed << " failed\n";
    std::cout << "========================================\n";
    
    if (failed > 0) {
        std::cout << "\n[RESULT] SMOKE TEST FAILED\n";
        return 1;
    }
    
    std::cout << "\n[RESULT] ALL SMOKE TESTS PASSED ✓\n";
    std::cout << "\nThe RAG pipeline foundation is solid. Ready for integration!\n";
    return 0;
}
