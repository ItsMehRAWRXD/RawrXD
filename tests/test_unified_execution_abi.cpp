// ============================================================================
// Unified Execution ABI Test Suite
// ============================================================================

#include "../src/cli/unified_execution_abi.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <chrono>
#include <cassert>
#include <functional>

using namespace RawrXD::CLI;

// ============================================================================
// Test Framework
// ============================================================================

struct TestResult {
    std::string name;
    bool passed;
    std::string message;
    double durationMs;
};

class TestRunner {
    std::vector<TestResult> results;
    int passed = 0;
    int failed = 0;
    
public:
    void Run(const std::string& name, std::function<bool()> test) {
        auto start = std::chrono::steady_clock::now();
        bool result = false;
        std::string message;
        
        try {
            result = test();
            message = result ? "PASSED" : "FAILED";
        } catch (const std::exception& e) {
            result = false;
            message = std::string("EXCEPTION: ") + e.what();
        } catch (...) {
            result = false;
            message = "UNKNOWN EXCEPTION";
        }
        
        auto end = std::chrono::steady_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        
        results.push_back({name, result, message, duration});
        
        if (result) {
            passed++;
            std::cout << "✅ " << name << " (" << std::fixed << std::setprecision(1) << duration << "ms)\n";
        } else {
            failed++;
            std::cout << "❌ " << name << ": " << message << "\n";
        }
    }
    
    void PrintSummary() const {
        std::cout << "\n" << std::string(60, '=') << "\n";
        std::cout << "Test Summary: " << passed << " passed, " << failed << " failed\n";
        std::cout << std::string(60, '=') << "\n";
    }
    
    bool AllPassed() const { return failed == 0; }
};

// ============================================================================
// Test Cases
// ============================================================================

void TestCLIExecutionResult(TestRunner& runner) {
    runner.Run("Result_Default_Construction", []() {
        CLIExecutionResult result;
        return !result.success && 
               result.command.empty() && 
               result.executionMs == 0.0 &&
               !result.IsValid();
    });
    
    runner.Run("Result_Valid_Success", []() {
        CLIExecutionResult result;
        result.command = "test";
        result.success = true;
        result.output = "output";
        return result.IsValid();
    });
    
    runner.Run("Result_Valid_Failure", []() {
        CLIExecutionResult result;
        result.command = "test";
        result.success = false;
        result.error = "error";
        return result.IsValid();
    });
    
    runner.Run("Result_Invalid_EmptyCommand", []() {
        CLIExecutionResult result;
        result.success = true;
        result.output = "output";
        return !result.IsValid(); // Empty command = invalid
    });
    
    runner.Run("Result_JSON_RoundTrip", []() {
        CLIExecutionResult original;
        original.command = "test";
        original.success = true;
        original.output = "output";
        original.executionMs = 123.45;
        original.backendUsed = "local";
        original.artifacts = {"artifact1", "artifact2"};
        
        auto json = original.ToJSON();
        auto restored = CLIExecutionResult::FromJSON(json);
        
        return restored.command == original.command &&
               restored.success == original.success &&
               restored.output == original.output &&
               restored.executionMs == original.executionMs &&
               restored.backendUsed == original.backendUsed &&
               restored.artifacts.size() == original.artifacts.size();
    });
}

void TestExecutionContext(TestRunner& runner) {
    runner.Run("Context_Default_Construction", []() {
        ExecutionContext ctx;
        return ctx.command.empty() && 
               ctx.args.empty() &&
               ctx.timeoutMs == 30000;
    });
    
    runner.Run("Context_With_Args", []() {
        ExecutionContext ctx;
        ctx.command = "/test";
        ctx.args = {"arg1", "arg2"};
        ctx.timeoutMs = 60000;
        return ctx.command == "/test" && 
               ctx.args.size() == 2 &&
               ctx.timeoutMs == 60000;
    });
}

void TestCommandRegistry(TestRunner& runner) {
    runner.Run("Registry_Singleton", []() {
        auto& reg1 = CommandRegistry::Instance();
        auto& reg2 = CommandRegistry::Instance();
        return &reg1 == &reg2;
    });
    
    runner.Run("Registry_Register_And_Resolve", []() {
        auto& registry = CommandRegistry::Instance();
        
        registry.Register({
            "/test",
            {"test", "t"},
            "Test command",
            "/test",
            ExecutionContext::Capability::ANALYSIS,
            [](const ExecutionContext&) {
                CLIExecutionResult r;
                r.success = true;
                r.output = "test output";
                return r;
            },
            false,
            false
        });
        
        auto cmd = registry.Resolve("/test");
        return cmd.has_value() && cmd->name == "/test";
    });
    
    runner.Run("Registry_Alias_Resolution", []() {
        auto& registry = CommandRegistry::Instance();
        
        auto cmd1 = registry.Resolve("/test");
        auto cmd2 = registry.Resolve("test");
        
        return cmd1.has_value() && cmd2.has_value() &&
               cmd1->name == cmd2->name;
    });
    
    runner.Run("Registry_Execute_Command", []() {
        auto& registry = CommandRegistry::Instance();
        auto result = registry.Execute("/test", {});
        return result.success && result.output == "test output";
    });
    
    runner.Run("Registry_Unknown_Command", []() {
        auto& registry = CommandRegistry::Instance();
        auto result = registry.Execute("/unknown", {});
        return !result.success && !result.error.empty();
    });
    
    runner.Run("Registry_GetAll", []() {
        auto& registry = CommandRegistry::Instance();
        auto all = registry.GetAll();
        return !all.empty();
    });
    
    runner.Run("Registry_GetByCapability", []() {
        auto& registry = CommandRegistry::Instance();
        auto analysis = registry.GetByCapability(ExecutionContext::Capability::ANALYSIS);
        return !analysis.empty();
    });
}

void TestExecutionPipeline(TestRunner& runner) {
    runner.Run("Pipeline_Singleton", []() {
        auto& pipe1 = ExecutionPipeline::Instance();
        auto& pipe2 = ExecutionPipeline::Instance();
        return &pipe1 == &pipe2;
    });
    
    runner.Run("Pipeline_Execute", []() {
        auto& pipeline = ExecutionPipeline::Instance();
        
        ExecutionContext ctx;
        ctx.command = "/test";
        
        auto result = pipeline.Execute(ctx);
        return result.command == "/test";
    });
    
    runner.Run("Pipeline_Stats", []() {
        auto& pipeline = ExecutionPipeline::Instance();
        pipeline.ResetStats();
        
        ExecutionContext ctx;
        ctx.command = "/test";
        pipeline.Execute(ctx);
        
        auto stats = pipeline.GetStats();
        return stats.totalExecutions == 1;
    });
    
    runner.Run("Pipeline_PreExecute_Hook", []() {
        auto& pipeline = ExecutionPipeline::Instance();
        
        bool hookCalled = false;
        pipeline.AddPreExecuteHook([&hookCalled](ExecutionContext&) {
            hookCalled = true;
        });
        
        ExecutionContext ctx;
        ctx.command = "/test";
        pipeline.Execute(ctx);
        
        return hookCalled;
    });
    
    runner.Run("Pipeline_PostExecute_Hook", []() {
        auto& pipeline = ExecutionPipeline::Instance();
        
        bool hookCalled = false;
        pipeline.AddPostExecuteHook([&hookCalled](CLIExecutionResult&) {
            hookCalled = true;
        });
        
        ExecutionContext ctx;
        ctx.command = "/test";
        pipeline.Execute(ctx);
        
        return hookCalled;
    });
}

void TestRuntimeStatusCommands(TestRunner& runner) {
    runner.Run("Runtime_EngineStatus", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::EngineStatus(ctx);
        return result.success && 
               result.command == "/engine status" &&
               result.output.find("RawrXD Engine Status") != std::string::npos;
    });
    
    runner.Run("Runtime_BackendStatus", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::BackendStatus(ctx);
        return result.success && result.output.find("Backend Status") != std::string::npos;
    });
    
    runner.Run("Runtime_MemoryStatus", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::MemoryStatus(ctx);
        return result.success && result.output.find("Memory Status") != std::string::npos;
    });
    
    runner.Run("Runtime_CompressionStatus", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::CompressionStatus(ctx);
        return result.success && 
               result.output.find("Compression Runtime") != std::string::npos &&
               result.output.find("6.7:1") != std::string::npos;
    });
    
    runner.Run("Runtime_KernelStatus", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::KernelStatus(ctx);
        return result.success && result.output.find("Kernel Status") != std::string::npos;
    });
    
    runner.Run("Runtime_ModelInspect", []() {
        ExecutionContext ctx;
        ctx.args = {"phi3-mini"};
        auto result = RuntimeStatusCommands::ModelInspect(ctx);
        return result.success && 
               result.output.find("Model Inspection") != std::string::npos &&
               result.output.find("phi3-mini") != std::string::npos;
    });
    
    runner.Run("Runtime_ModelList", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::ModelList(ctx);
        return result.success && result.output.find("Available Models") != std::string::npos;
    });
    
    runner.Run("Runtime_ProfileStart", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::ProfileStart(ctx);
        return result.success;
    });
    
    runner.Run("Runtime_ProfileStop", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::ProfileStop(ctx);
        return result.success && result.output.find("Inference Profile") != std::string::npos;
    });
    
    runner.Run("Runtime_ProfileBottlenecks", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::ProfileBottlenecks(ctx);
        return result.success && result.output.find("Bottlenecks") != std::string::npos;
    });
    
    runner.Run("Runtime_CompressionTune", []() {
        ExecutionContext ctx;
        ctx.args = {"7.0"};
        auto result = RuntimeStatusCommands::CompressionTune(ctx);
        return result.success && result.output.find("7.0:1") != std::string::npos;
    });
    
    runner.Run("Runtime_CompressionTune_Invalid", []() {
        ExecutionContext ctx;
        // No args
        auto result = RuntimeStatusCommands::CompressionTune(ctx);
        return !result.success && !result.error.empty();
    });
    
    runner.Run("Runtime_CompressionProfile", []() {
        ExecutionContext ctx;
        auto result = RuntimeStatusCommands::CompressionProfile(ctx);
        return result.success && result.output.find("Compression Profiles") != std::string::npos;
    });
}

// ============================================================================
// Main Test Runner
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════╗\n";
    std::cout << "║  Unified Execution ABI Test Suite v1.0                  ║\n";
    std::cout << "║  CLI Execution Contract — Comprehensive Testing         ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════╝\n\n";
    
    TestRunner runner;
    
    std::cout << "[Phase 1] CLI Execution Result Tests\n";
    std::cout << std::string(40, '-') << "\n";
    TestCLIExecutionResult(runner);
    
    std::cout << "\n[Phase 2] Execution Context Tests\n";
    std::cout << std::string(40, '-') << "\n";
    TestExecutionContext(runner);
    
    std::cout << "\n[Phase 3] Command Registry Tests\n";
    std::cout << std::string(40, '-') << "\n";
    TestCommandRegistry(runner);
    
    std::cout << "\n[Phase 4] Execution Pipeline Tests\n";
    std::cout << std::string(40, '-') << "\n";
    TestExecutionPipeline(runner);
    
    std::cout << "\n[Phase 5] Runtime Status Commands Tests\n";
    std::cout << std::string(40, '-') << "\n";
    TestRuntimeStatusCommands(runner);
    
    runner.PrintSummary();
    
    return runner.AllPassed() ? 0 : 1;
}
