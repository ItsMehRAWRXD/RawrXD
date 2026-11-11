// ============================================================================
// Test Execution Contracts
// ============================================================================
// Validates the execution framework contracts
// ============================================================================

#include "ExecutionRequest.hpp"
#include "ExecutionResult.hpp"
#include "ExecutionStatus.hpp"
#include "ExecutionTelemetry.hpp"
#include "Diagnostic.hpp"
#include "SimulatorBackend.hpp"

#include <iostream>
#include <cassert>

using namespace RawrXD::Execution;

void TestExecutionRequest() {
    std::cout << "Testing ExecutionRequest...\n";
    
    ExecutionRequest req;
    req.command = "run";
    req.model = "phi3.gguf";
    req.prompt = "Hello, world!";
    req.max_tokens = 100;
    req.temperature = 0.8f;
    req.stream = false;
    req.json = true;
    
    assert(req.command == "run");
    assert(req.model == "phi3.gguf");
    assert(req.max_tokens == 100);
    std::cout << "  ✓ ExecutionRequest works\n";
}

void TestExecutionStatus() {
    std::cout << "Testing ExecutionStatus...\n";
    
    auto status = ExecutionStatus::Success;
    assert(status == ExecutionStatus::Success);
    
    const char* str = ExecutionStatusToString(ExecutionStatus::Success);
    assert(std::string(str) == "Success");
    
    str = ExecutionStatusToString(ExecutionStatus::RuntimeFailure);
    assert(std::string(str) == "RuntimeFailure");
    
    std::cout << "  ✓ ExecutionStatus works\n";
}

void TestExecutionTelemetry() {
    std::cout << "Testing ExecutionTelemetry...\n";
    
    ExecutionTelemetry telemetry;
    telemetry.latency_ms = 1000;
    telemetry.generated_tokens = 200;
    
    telemetry.CalculateDerived();
    
    assert(telemetry.tokens_per_second == 200.0);
    std::cout << "  ✓ ExecutionTelemetry works\n";
}

void TestDiagnosticCollection() {
    std::cout << "Testing DiagnosticCollection...\n";
    
    DiagnosticCollection diagnostics;
    diagnostics.AddInfo("I001", "Test info message", "test");
    diagnostics.AddWarning("W001", "Test warning", "test");
    diagnostics.AddError("E001", "Test error", "test");
    
    assert(diagnostics.HasErrors());
    assert(diagnostics.HasWarnings());
    assert(diagnostics.GetAll().size() == 3);
    
    std::cout << "  ✓ DiagnosticCollection works\n";
}

void TestExecutionResult() {
    std::cout << "Testing ExecutionResult...\n";
    
    auto result = ExecutionResult::Success("Hello");
    assert(result.IsSuccess());
    assert(result.output == "Hello");
    
    auto error = ExecutionResult::Error(ExecutionStatus::RuntimeFailure, "Failed");
    assert(!error.IsSuccess());
    assert(error.HasErrors());
    
    std::cout << "  ✓ ExecutionResult works\n";
}

void TestSimulatorBackend() {
    std::cout << "Testing SimulatorBackend...\n";
    
    SimulatorBackend simulator;
    
    assert(std::string(simulator.GetName()) == "simulator");
    assert(!simulator.IsInitialized());
    
    bool init = simulator.Initialize();
    assert(init);
    assert(simulator.IsInitialized());
    assert(simulator.IsHealthy());
    
    assert(simulator.SupportsModel("any_model.gguf"));
    assert(simulator.SupportsStreaming());
    assert(simulator.SupportsCancellation());
    
    ExecutionRequest req;
    req.command = "run";
    req.model = "test.gguf";
    req.prompt = "Test prompt";
    req.max_tokens = 10;
    
    auto result = simulator.Execute(req);
    
    std::cout << "  Status: " << ExecutionStatusToString(result.status) << "\n";
    std::cout << "  Output: " << result.output.substr(0, 50) << "...\n";
    std::cout << "  Latency: " << result.telemetry.latency_ms << " ms\n";
    std::cout << "  Tokens: " << result.telemetry.generated_tokens << "\n";
    std::cout << "  TPS: " << result.telemetry.tokens_per_second << "\n";
    
    assert(result.IsSuccess());
    assert(result.telemetry.generated_tokens == 10);
    
    simulator.Shutdown();
    std::cout << "  ✓ SimulatorBackend works\n";
}

int main() {
    std::cout << "========================================\n";
    std::cout << "RawrXD Execution Contracts Test\n";
    std::cout << "========================================\n\n";
    
    try {
        TestExecutionRequest();
        TestExecutionStatus();
        TestExecutionTelemetry();
        TestDiagnosticCollection();
        TestExecutionResult();
        TestSimulatorBackend();
        
        std::cout << "\n========================================\n";
        std::cout << "All tests passed! ✓\n";
        std::cout << "========================================\n";
        return 0;
    } catch (const std::exception& e) {
        std::cerr << "\nTest failed with exception: " << e.what() << "\n";
        return 1;
    }
}
