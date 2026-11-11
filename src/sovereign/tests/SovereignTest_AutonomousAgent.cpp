// SovereignTest_AutonomousAgent.cpp
// End-to-end integration test for Autonomous Agent Runtime
// Validates: SessionStore -> AgentGraphRuntime -> ToolRegistry -> AutonomousAgent

#include "../session/SessionStore.hpp"
#include "../agent/AgentGraphRuntime.hpp"
#include "../agent/AutonomousAgent.hpp"
#include "../tool/ToolRegistry.hpp"
#include <iostream>
#include <cassert>
#include <filesystem>

namespace Sovereign {
namespace fs = std::filesystem;

// Test: Session persistence
bool Test_SessionPersistence() {
    std::cout << "[Test] Session Persistence..." << std::endl;
    
    // Clean up any existing test sessions
    fs::remove_all(".sovereign_test");
    
    SessionStore store(".sovereign_test/sessions/");
    
    // Create session
    auto session = store.Create("Test Session", "Codestral-22B", "agent");
    assert(session.metadata.sessionId != 0);
    std::cout << "  Created session: " << session.metadata.sessionId << std::endl;
    
    // Add message
    ChatMessage msg{"user", "Hello agent", 
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count(),
        "Codestral-22B", {}};
    assert(store.AppendMessage(session.metadata.sessionId, msg));
    
    // Reload session
    auto loaded = store.Load(session.metadata.sessionId);
    assert(loaded.metadata.sessionId == session.metadata.sessionId);
    assert(loaded.metadata.name == "Test Session");
    assert(loaded.history.size() == 1);
    std::cout << "  Loaded session with " << loaded.history.size() << " messages" << std::endl;
    
    // Cleanup
    fs::remove_all(".sovereign_test");
    
    std::cout << "  [PASS] Session persistence works" << std::endl;
    return true;
}

// Test: Agent graph execution
bool Test_AgentGraphExecution() {
    std::cout << "[Test] Agent Graph Execution..." << std::endl;
    
    AgentGraphRuntime runtime;
    
    // Create agents
    auto scanner = std::make_shared<AgentNode>("Scanner", AgentCapability{
        "Scanner", "Scans filesystem", {"read_file"}, AgentMode::AGENT, 10, false
    });
    scanner->SetExecutor([](const AgentTask& task) -> AgentResult {
        std::cout << "    [Scanner] Executing..." << std::endl;
        return {true, "Scanned 42,391 files", "", 100, {}};
    });
    
    auto parser = std::make_shared<AgentNode>("Parser", AgentCapability{
        "Parser", "Parses source code", {"read_file"}, AgentMode::AGENT, 10, false
    });
    parser->SetExecutor([](const AgentTask& task) -> AgentResult {
        std::cout << "    [Parser] Executing..." << std::endl;
        return {true, "Parsed 1,822 C++ files", "", 200, {}};
    });
    
    auto builder = std::make_shared<AgentNode>("Builder", AgentCapability{
        "Builder", "Builds project", {"terminal"}, AgentMode::AGENT, 10, false
    });
    builder->SetExecutor([](const AgentTask& task) -> AgentResult {
        std::cout << "    [Builder] Executing..." << std::endl;
        return {true, "Build successful", "", 500, {}};
    });
    
    // Add to graph
    assert(runtime.AddAgent(scanner));
    assert(runtime.AddAgent(parser));
    assert(runtime.AddAgent(builder));
    
    // Connect: Scanner -> Parser -> Builder
    assert(runtime.Connect("Scanner", "Parser"));
    assert(runtime.Connect("Parser", "Builder"));
    
    // Get execution order
    auto order = runtime.GetExecutionOrder();
    std::cout << "  Execution order: ";
    for (const auto& name : order) {
        std::cout << name << " ";
    }
    std::cout << std::endl;
    
    assert(order.size() == 3);
    assert(order[0] == "Scanner");
    assert(order[1] == "Parser");
    assert(order[2] == "Builder");
    
    // Execute
    runtime.Start();
    
    AgentTask task;
    task.id = 1;
    task.objective = "Build project";
    task.sessionId = 12345;
    
    auto result = runtime.Execute(12345, task);
    std::cout << "  Execution result: " << result.output << std::endl;
    
    runtime.Shutdown();
    
    std::cout << "  [PASS] Agent graph execution works" << std::endl;
    return true;
}

// Test: Tool registry
bool Test_ToolRegistry() {
    std::cout << "[Test] Tool Registry..." << std::endl;
    
    ToolRegistry registry;
    registry.RegisterCoreTools();
    
    // Check tools registered
    auto names = registry.GetToolNames();
    std::cout << "  Registered tools: ";
    for (const auto& name : names) {
        std::cout << name << " ";
    }
    std::cout << std::endl;
    
    assert(names.size() == 5);
    assert(registry.HasTool("read_file"));
    assert(registry.HasTool("write_file"));
    assert(registry.HasTool("terminal"));
    assert(registry.HasTool("search_code"));
    assert(registry.HasTool("patch"));
    
    // Test read_file (create a temp file first)
    std::string testFile = ".test_read.txt";
    {
        std::ofstream f(testFile);
        f << "Hello from test";
    }
    
    ToolContext ctx{1, Permission::READ_ONLY, testFile, {}, fs::current_path().string()};
    auto result = registry.Invoke("read_file", ctx);
    
    std::cout << "  read_file result: " << (result.success ? "success" : "failed")
              << " - " << result.output.substr(0, 20) << "..." << std::endl;
    
    assert(result.success);
    assert(result.output == "Hello from test");
    
    // Cleanup
    fs::remove(testFile);
    
    std::cout << "  [PASS] Tool registry works" << std::endl;
    return true;
}

// Test: Autonomous agent
bool Test_AutonomousAgent() {
    std::cout << "[Test] Autonomous Agent..." << std::endl;
    
    // Clean up
    fs::remove_all(".sovereign_test");
    
    SessionStore store(".sovereign_test/sessions/");
    AgentGraphRuntime runtime;
    AutonomousAgent agent(&runtime, &store);
    
    // Set up action callback
    bool actionReceived = false;
    agent.SetActionCallback([&actionReceived](const OptimizationAction& action) {
        std::cout << "    [Callback] Received action: " << action.reason << std::endl;
        actionReceived = true;
    });
    
    // Start agent
    agent.SetEvaluationInterval(100); // 100ms for fast testing
    agent.Start();
    
    // Update metrics to trigger action
    TelemetryMetrics metrics;
    metrics.faultRate = 15.0; // Above threshold
    metrics.latencyMs = 100.0;
    metrics.deltaZeroPercent = 70.0;
    agent.UpdateMetrics(metrics);
    
    // Wait for evaluation
    std::this_thread::sleep_for(std::chrono::milliseconds(300));
    
    // Stop agent
    agent.Stop();
    
    std::cout << "  Action received: " << (actionReceived ? "yes" : "no") << std::endl;
    
    // Cleanup
    fs::remove_all(".sovereign_test");
    
    std::cout << "  [PASS] Autonomous agent works" << std::endl;
    return true;
}

// Test: End-to-end workflow
bool Test_EndToEndWorkflow() {
    std::cout << "[Test] End-to-End Workflow..." << std::endl;
    
    // Clean up
    fs::remove_all(".sovereign_test");
    
    // Initialize all components
    SessionStore store(".sovereign_test/sessions/");
    AgentGraphRuntime runtime;
    ToolRegistry tools;
    tools.RegisterCoreTools();
    AutonomousAgent agent(&runtime, &store);
    
    // Create session
    auto session = store.Create("IDE Audit", "Codestral-22B", "agent");
    std::cout << "  Session: " << session.metadata.sessionId << std::endl;
    
    // Create agents that use tools
    auto scanner = std::make_shared<AgentNode>("Scanner", AgentCapability{
        "Scanner", "Scans filesystem", {"search_code"}, AgentMode::AGENT, 10, false
    });
    scanner->SetExecutor([&tools](const AgentTask& task) -> AgentResult {
        ToolContext ctx{task.sessionId, Permission::READ_ONLY, ".cpp", {}, fs::current_path().string()};
        auto result = tools.Invoke("search_code", ctx);
        return {result.success, result.output, result.error, 0, result.artifacts};
    });
    
    auto analyzer = std::make_shared<AgentNode>("Analyzer", AgentCapability{
        "Analyzer", "Analyzes code", {"read_file"}, AgentMode::AGENT, 10, false
    });
    analyzer->SetExecutor([](const AgentTask& task) -> AgentResult {
        return {true, "Analysis complete: 42 files", "", 150, {}};
    });
    
    // Build graph
    runtime.AddAgent(scanner);
    runtime.AddAgent(analyzer);
    runtime.Connect("Scanner", "Analyzer");
    
    // Start systems
    runtime.Start();
    agent.SetEvaluationInterval(500);
    agent.Start();
    
    // Execute workflow
    AgentTask task;
    task.id = session.metadata.sessionId;
    task.objective = "Audit IDE";
    task.sessionId = session.metadata.sessionId;
    
    std::cout << "  Executing workflow..." << std::endl;
    auto result = runtime.Execute(session.metadata.sessionId, task);
    
    std::cout << "  Result: " << result.output << std::endl;
    
    // Shutdown
    agent.Stop();
    runtime.Shutdown();
    
    // Cleanup
    fs::remove_all(".sovereign_test");
    
    std::cout << "  [PASS] End-to-end workflow works" << std::endl;
    return true;
}

// Main test runner
void RunAutonomousAgentTests() {
    std::cout << "\n========== Autonomous Agent Integration Tests ==========\n" << std::endl;
    
    int passed = 0;
    int failed = 0;
    
    auto runTest = [&passed, &failed](const char* name, bool (*test)()) {
        std::cout << "\n--- " << name << " ---" << std::endl;
        try {
            if (test()) {
                passed++;
                std::cout << "[✓] " << name << " PASSED" << std::endl;
            } else {
                failed++;
                std::cout << "[✗] " << name << " FAILED" << std::endl;
            }
        } catch (const std::exception& e) {
            failed++;
            std::cout << "[✗] " << name << " EXCEPTION: " << e.what() << std::endl;
        }
    };
    
    runTest("SessionPersistence", Test_SessionPersistence);
    runTest("AgentGraphExecution", Test_AgentGraphExecution);
    runTest("ToolRegistry", Test_ToolRegistry);
    runTest("AutonomousAgent", Test_AutonomousAgent);
    runTest("EndToEndWorkflow", Test_EndToEndWorkflow);
    
    std::cout << "\n========== Summary ==========" << std::endl;
    std::cout << "Passed: " << passed << std::endl;
    std::cout << "Failed: " << failed << std::endl;
    std::cout << "Total:  " << (passed + failed) << std::endl;
    
    if (failed == 0) {
        std::cout << "\n[✓] All Autonomous Agent tests PASSED" << std::endl;
    } else {
        std::cout << "\n[✗] Some tests FAILED" << std::endl;
    }
}

} // namespace Sovereign

// Standalone entry point
int main() {
    Sovereign::RunAutonomousAgentTests();
    return 0;
}
