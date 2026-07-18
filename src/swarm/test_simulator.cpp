// Phase A.1: Learning Simulator Test Runner
// Standalone test to validate scheduler mathematics

#include "LearningSimulator.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace Sovereign;

struct TestResult {
    std::string scenario;
    bool converged;
    uint32_t convergenceIteration;
    double successImprovement;
    double latencyImprovement;
    double explorationRate;
    bool allPassed;
    double durationMs;
};

void PrintResultRow(const TestResult& result) {
    std::cout << "| " << std::left << std::setw(18) << result.scenario
              << " | " << std::setw(8) << (result.converged ? "✓" : "✗")
              << " | " << std::setw(11) << (result.converged ? std::to_string(result.convergenceIteration) : "N/A")
              << " | " << std::setw(10) << std::fixed << std::setprecision(1) << (result.successImprovement * 100) << "%"
              << " | " << std::setw(10) << std::fixed << std::setprecision(1) << (result.latencyImprovement * 100) << "%"
              << " | " << std::setw(10) << std::fixed << std::setprecision(1) << (result.explorationRate * 100) << "%"
              << " | " << std::setw(6) << (result.allPassed ? "✓" : "✗")
              << " | " << std::setw(8) << std::fixed << std::setprecision(1) << result.durationMs << "ms"
              << " |\n";
}

TestResult RunScenario(const std::string& name, 
                       LearningSimulator::TestScenario (*scenarioFactory)()) {
    std::cout << "\n[RUNNING] " << name << "...\n";
    
    auto start = std::chrono::steady_clock::now();
    
    auto scenario = scenarioFactory();
    LearningSimulator simulator(scenario);
    auto snapshots = simulator.RunWithTracking(10);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    auto criteria = simulator.Validate();
    
    TestResult result;
    result.scenario = name;
    result.converged = criteria.converged;
    result.convergenceIteration = criteria.convergenceIteration;
    result.successImprovement = criteria.successRateImprovement;
    result.latencyImprovement = criteria.latencyImprovement;
    result.explorationRate = criteria.actualExplorationRate;
    result.allPassed = criteria.AllPassed();
    result.durationMs = static_cast<double>(duration);
    
    // Print detailed results
    simulator.PrintReport();
    
    return result;
}

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║         Phase A.1: Learning Simulator Validation Suite                   ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════════════════╝\n";
    std::cout << "\nRunning all test scenarios...\n";
    
    std::vector<TestResult> results;
    
    // Run all scenarios
    results.push_back(RunScenario("Stationary", LearningSimulator::CreateStationaryScenario));
    results.push_back(RunScenario("Latency Tradeoff", LearningSimulator::CreateLatencyTradeoffScenario));
    results.push_back(RunScenario("Noisy", LearningSimulator::CreateNoisyScenario));
    results.push_back(RunScenario("Dominant", LearningSimulator::CreateDominantScenario));
    
    // Summary table
    std::cout << "\n\n╔════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                         SUMMARY TABLE                                      ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════════════════╝\n";
    
    std::cout << "| " << std::left << std::setw(18) << "Scenario"
              << " | " << std::setw(8) << "Converged"
              << " | " << std::setw(11) << "Iterations"
              << " | " << std::setw(10) << "Success Δ"
              << " | " << std::setw(10) << "Latency Δ"
              << " | " << std::setw(10) << "Exploration"
              << " | " << std::setw(6) << "Pass"
              << " | " << std::setw(8) << "Time"
              << " |\n";
    std::cout << std::string(108, '-') << "\n";
    
    int passed = 0;
    int total = results.size();
    
    for (const auto& result : results) {
        PrintResultRow(result);
        if (result.allPassed) passed++;
    }
    
    std::cout << "\n╔════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  RESULT: " << passed << "/" << total << " scenarios passed all criteria"
              << std::string(54 - std::to_string(passed).length() - std::to_string(total).length(), ' ') << "║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════════════════╝\n";
    
    // Export results if requested
    if (argc > 1 && std::string(argv[1]) == "--export") {
        std::string path = (argc > 2) ? argv[2] : "simulator_results.json";
        
        // Export last scenario as example
        auto scenario = LearningSimulator::CreateStationaryScenario();
        LearningSimulator simulator(scenario);
        simulator.RunWithTracking(10);
        simulator.ExportJSON(path);
        
        std::cout << "\n[INFO] Exported results to: " << path << "\n";
    }
    
    return (passed == total) ? 0 : 1;
}
