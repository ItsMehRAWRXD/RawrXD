// test_voice_assistant_rag.cpp - Unit tests for Voice Assistant RAG pipeline
// ============================================================================

#include <catch2/catch_test_macros.hpp>
#include <catch2/matchers/catch_matchers_string.hpp>
#include "../src/core/voice_assistant_manager.hpp"
#include "../src/core/voice_assistant_types.hpp"
#include <nlohmann/json.hpp>
#include <chrono>
#include <thread>

using namespace Catch::Matchers;

// ============================================================================
// Mock CodebaseContextAnalyzer for Testing
// ============================================================================

class MockCodebaseContextAnalyzer : public CodebaseContextAnalyzer {
public:
    MockCodebaseContextAnalyzer() = default;
    
    // Track call counts for verification
    mutable int analyze_scope_calls = 0;
    mutable int get_symbols_calls = 0;
    mutable int get_dependencies_calls = 0;
    
    // Configurable mock responses
    std::string mock_scope_type = "function";
    std::string mock_scope_name = "TestFunction";
    std::vector<Symbol> mock_symbols;
    std::vector<std::string> mock_dependencies;
    bool should_throw = false;
    
    ScopeInfo analyzeCurrentScope(const std::string& file, int line, int column) override {
        analyze_scope_calls++;
        
        if (should_throw) {
            throw std::runtime_error("Mock scope analysis failure");
        }
        
        ScopeInfo scope;
        scope.type = mock_scope_type;
        scope.name = mock_scope_name;
        scope.filePath = file;
        scope.lineNumber = line;
        scope.column = column;
        return scope;
    }
    
    std::vector<Symbol> getRelevantSymbols(const std::string& query, const ScopeInfo& scope) override {
        get_symbols_calls++;
        
        if (should_throw) {
            throw std::runtime_error("Mock symbol retrieval failure");
        }
        
        // Return mock symbols or generate based on query
        if (!mock_symbols.empty()) {
            return mock_symbols;
        }
        
        // Generate contextual symbols based on query keywords
        std::vector<Symbol> results;
        
        if (query.find("function") != std::string::npos || query.find("method") != std::string::npos) {
            Symbol s1;
            s1.name = "process_command";
            s1.type = "function";
            s1.filePath = "src/core/voice_assistant_manager.cpp";
            s1.lineNumber = 42;
            s1.signature = "nlohmann::json process_command(const std::string\u0026, const nlohmann::json\u0026)";
            results.push_back(s1);
            
            Symbol s2;
            s2.name = "analyzeCurrentScope";
            s2.type = "method";
            s2.filePath = "src/core/voice_assistant_types.cpp";
            s2.lineNumber = 55;
            s2.signature = "ScopeInfo analyzeCurrentScope(const std::string\u0026, int, int)";
            results.push_back(s2);
        }
        
        if (query.find("class") != std::string::npos || query.find("struct") != std::string::npos) {
            Symbol s3;
            s3.name = "VoiceAssistantManager";
            s3.type = "class";
            s3.filePath = "src/core/voice_assistant_manager.hpp";
            s3.lineNumber = 25;
            s3.signature = "class VoiceAssistantManager";
            results.push_back(s3);
        }
        
        return results;
    }
    
    std::vector<std::string> getDependencies(const std::string& file) override {
        get_dependencies_calls++;
        
        if (!mock_dependencies.empty()) {
            return mock_dependencies;
        }
        
        // Return default mock dependencies
        return {
            "src/core/voice_assistant_types.hpp",
            "include/nlohmann/json.hpp",
            "src/win32app/IDE_Telemetry.hpp"
        };
    }
    
    bool initialize(const std::string& codebasePath) override {
        return true;
    }
    
    bool isReady() const override {
        return true;
    }
    
    void reset_counters() {
        analyze_scope_calls = 0;
        get_symbols_calls = 0;
        get_dependencies_calls = 0;
    }
};

// ============================================================================
// Test Suite: RAG Pipeline Basics
// ============================================================================

TEST_CASE("RAG Pipeline - Analyzer Not Initialized", "[rag][error_handling]") {
    VoiceAssistantManager manager;
    // Note: Not setting context analyzer
    
    auto result = manager.query_codebase("find functions", "test.cpp", 10);
    
    REQUIRE(result["status"] == "error");
    REQUIRE(result["error_code"] == "ANALYZER_NOT_READY");
    REQUIRE(result["message"].get<std::string>().find("not initialized") != std::string::npos);
    REQUIRE(result.contains("suggestion"));
}

TEST_CASE("RAG Pipeline - Basic Query Success", "[rag][happy_path]") {
    VoiceAssistantManager manager;
    auto mock_analyzer = std::make_shared<MockCodebaseContextAnalyzer>();
    manager.set_context_analyzer(mock_analyzer);
    
    auto result = manager.query_codebase("find all functions", "src/test.cpp", 25);
    
    SECTION("Response Structure") {
        REQUIRE(result["status"] == "success");
        REQUIRE(result.contains("query"));
        REQUIRE(result.contains("current_context"));
        REQUIRE(result.contains("results"));
        REQUIRE(result.contains("query_latency_ms"));
        REQUIRE(result.contains("timestamp"));
    }
    
    SECTION("Context Information") {
        auto context = result["current_context"];
        REQUIRE(context["file"] == "src/test.cpp");
        REQUIRE(context["line"] == 25);
        REQUIRE(context["scope_type"] == "function");
        REQUIRE(context["scope_name"] == "TestFunction");
    }
    
    SECTION("Mock Analyzer Called") {
        REQUIRE(mock_analyzer->analyze_scope_calls == 1);
        REQUIRE(mock_analyzer->get_symbols_calls == 1);
        REQUIRE(mock_analyzer->get_dependencies_calls == 1);
    }
    
    SECTION("Results Structure") {
        REQUIRE(result["result_count"] > 0);
        auto results = result["results"];
        REQUIRE(results.is_array());
        
        for (const auto& item : results) {
            REQUIRE(item.contains("name"));
            REQUIRE(item.contains("type"));
            REQUIRE(item.contains("file"));
            REQUIRE(item.contains("line"));
        }
    }
    
    SECTION("Dependencies Included") {
        REQUIRE(result.contains("dependencies"));
        REQUIRE(result.contains("dependency_count"));
        REQUIRE(result["dependency_count"] > 0);
    }
}

TEST_CASE("RAG Pipeline - Empty File Context", "[rag][edge_case]") {
    VoiceAssistantManager manager;
    auto mock_analyzer = std::make_shared<MockCodebaseContextAnalyzer>();
    manager.set_context_analyzer(mock_analyzer);
    
    auto result = manager.query_codebase("explain this code", "", 0);
    
    REQUIRE(result["status"] == "success");
    REQUIRE(result["current_context"]["file"] == "");
    REQUIRE(result["current_context"]["line"] == 0);
    // Dependencies should not be fetched for empty file
    REQUIRE(mock_analyzer->get_dependencies_calls == 0);
}

TEST_CASE("RAG Pipeline - Exception Handling", "[rag][error_handling]") {
    VoiceAssistantManager manager;
    auto mock_analyzer = std::make_shared<MockCodebaseContextAnalyzer>();
    mock_analyzer->should_throw = true;
    manager.set_context_analyzer(mock_analyzer);
    
    auto result = manager.query_codebase("find classes", "test.cpp", 10);
    
    REQUIRE(result["status"] == "error");
    REQUIRE(result["error_code"] == "RAG_EXCEPTION");
    REQUIRE(result.contains("message"));
    REQUIRE(result["message"].get<std::string>().find("Mock") != std::string::npos);
}

TEST_CASE("RAG Pipeline - Query Latency Tracking", "[rag][performance]") {
    VoiceAssistantManager manager;
    auto mock_analyzer = std::make_shared<MockCodebaseContextAnalyzer>();
    
    // Simulate slow analysis
    mock_analyzer->analyzeCurrentScope = [](const std::string&, int, int) {
        std::this_thread::sleep_for(std::chrono::milliseconds(10));
        ScopeInfo scope;
        scope.type = "class";
        scope.name = "SlowClass";
        return scope;
    };
    
    manager.set_context_analyzer(mock_analyzer);
    
    auto start = std::chrono::high_resolution_clock::now();
    auto result = manager.query_codebase("slow query", "test.cpp", 1);
    auto end = std::chrono::high_resolution_clock::now();
    
    auto actual_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    auto reported_ms = result["query_latency_ms"].get<long long>();
    
    REQUIRE(reported_ms >= 0);
    REQUIRE(reported_ms <= actual_ms + 5); // Allow 5ms tolerance
}

// ============================================================================
// Test Suite: Symbol Search Specificity
// ============================================================================

TEST_CASE("RAG Pipeline - Function Query Returns Functions", "[rag][symbol_search]") {
    VoiceAssistantManager manager;
    auto mock_analyzer = std::make_shared<MockCodebaseContextAnalyzer>();
    manager.set_context_analyzer(mock_analyzer);
    
    auto result = manager.query_codebase("find functions that process commands", "main.cpp", 50);
    
    REQUIRE(result["status"] == "success");
    auto results = result["results"];
    
    bool found_process_command = false;
    for (const auto& item : results) {
        if (item["name"] == "process_command") {
            found_process_command = true;
            REQUIRE(item["type"] == "function");
            REQUIRE(item.contains("signature"));
        }
    }
    
    REQUIRE(found_process_command);
}

TEST_CASE("RAG Pipeline - Class Query Returns Classes", "[rag][symbol_search]") {
    VoiceAssistantManager manager;
    auto mock_analyzer = std::make_shared<MockCodebaseContextAnalyzer>();
    manager.set_context_analyzer(mock_analyzer);
    
    auto result = manager.query_codebase("what classes are in the voice assistant", "main.cpp", 50);
    
    REQUIRE(result["status"] == "success");
    auto results = result["results"];
    
    bool found_manager_class = false;
    for (const auto& item : results) {
        if (item["name"] == "VoiceAssistantManager") {
            found_manager_class = true;
            REQUIRE(item["type"] == "class");
        }
    }
    
    REQUIRE(found_manager_class);
}

// ============================================================================
// Test Suite: Session Management
// ============================================================================

TEST_CASE("Voice Assistant - Session Creation", "[session]") {
    VoiceAssistantManager manager;
    
    std::string session_id = manager.create_session();
    
    REQUIRE(!session_id.empty());
    REQUIRE(session_id.find("session_") == 0);
    
    auto history = manager.get_session_history(session_id);
    REQUIRE(history["session_id"] == session_id);
    REQUIRE(history["messages"].empty());
}

TEST_CASE("Voice Assistant - Session End", "[session]") {
    VoiceAssistantManager manager;
    
    std::string session_id = manager.create_session();
    manager.end_session(session_id);
    
    auto history = manager.get_session_history(session_id);
    REQUIRE(history.contains("error"));
}

TEST_CASE("Voice Assistant - Session Message History", "[session]") {
    VoiceAssistantManager manager;
    
    std::string session_id = manager.create_session();
    auto result = manager.process_voice_input("hello", "hybrid", session_id);
    
    auto history = manager.get_session_history(session_id);
    REQUIRE(!history["messages"].empty());
    REQUIRE(history["messages"][0]["user_input"] == "hello");
}

// ============================================================================
// Test Suite: Intent Classification
// ============================================================================

TEST_CASE("Intent Utils - String Conversion", "[intent]") {
    using namespace VoiceAssistantUtils;
    
    REQUIRE(intent_to_string(IntentType::IDE_BUILD) == "ide_build");
    REQUIRE(intent_to_string(IntentType::CODE_EXPLAIN_SYMBOL) == "code_explain_symbol");
    REQUIRE(intent_to_string(IntentType::UNKNOWN) == "unknown");
    
    REQUIRE(string_to_intent("ide_build") == IntentType::IDE_BUILD);
    REQUIRE(string_to_intent("code_explain_symbol") == IntentType::CODE_EXPLAIN_SYMBOL);
    REQUIRE(string_to_intent("invalid_intent") == IntentType::UNKNOWN);
}

TEST_CASE("Intent Utils - IDE Action Detection", "[intent]") {
    using namespace VoiceAssistantUtils;
    
    REQUIRE(is_ide_action_intent(IntentType::IDE_BUILD) == true);
    REQUIRE(is_ide_action_intent(IntentType::IDE_RUN) == true);
    REQUIRE(is_ide_action_intent(IntentType::WEATHER) == false);
    REQUIRE(is_ide_action_intent(IntentType::CODE_EXPLAIN_SYMBOL) == false);
}

// ============================================================================
// Test Suite: Performance Benchmarks
// ============================================================================

TEST_CASE("RAG Pipeline - Performance Baseline", "[.][benchmark]") {
    VoiceAssistantManager manager;
    auto mock_analyzer = std::make_shared<MockCodebaseContextAnalyzer>();
    manager.set_context_analyzer(mock_analyzer);
    
    const int iterations = 100;
    std::vector<long long> latencies;
    latencies.reserve(iterations);
    
    for (int i = 0; i < iterations; ++i) {
        auto start = std::chrono::high_resolution_clock::now();
        auto result = manager.query_codebase("test query", "test.cpp", i);
        auto end = std::chrono::high_resolution_clock::now();
        
        latencies.push_back(
            std::chrono::duration_cast<std::chrono::microseconds>(end - start).count()
        );
    }
    
    // Calculate statistics
    long long sum = 0;
    for (auto lat : latencies) sum += lat;
    long long avg = sum / iterations;
    
    std::sort(latencies.begin(), latencies.end());
    long long p95 = latencies[static_cast<size_t>(iterations * 0.95)];
    long long p99 = latencies[static_cast<size_t>(iterations * 0.99)];
    
    std::cout << "RAG Pipeline Performance (" << iterations << " iterations):\n";
    std::cout << "  Average: " << avg << " μs\n";
    std::cout << "  P95: " << p95 << " μs\n";
    std::cout << "  P99: " << p99 << " μs\n";
    
    // Assert reasonable performance (should complete in < 10ms)
    REQUIRE(avg < 10000); // 10ms in microseconds
}

// ============================================================================
// Main Entry Point
// ============================================================================

// Catch2 provides its own main(), but we can add custom setup here if needed
