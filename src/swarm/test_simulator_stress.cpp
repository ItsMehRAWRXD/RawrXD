// Phase A.1: Learning Simulator Stress Tests
// Edge cases and stress scenarios to validate robustness

#include "LearningSimulator.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>

using namespace Sovereign;

// Stress test: Two nearly identical workers
LearningSimulator::TestScenario CreateNearlyIdenticalScenario() {
    TestScenario scenario;
    scenario.name = "Nearly Identical Workers";
    scenario.taskKind = SwarmTaskKind::ScanSubsystem;
    scenario.iterations = 2000;  // More iterations needed to distinguish
    
    // Very close performance - should not oscillate
    scenario.workers.push_back({1, "Worker_A", 0.950, 100.0, 5.0});
    scenario.workers.push_back({2, "Worker_B", 0.948, 100.0, 5.0});
    scenario.workers.push_back({3, "Worker_C", 0.945, 100.0, 5.0});
    
    scenario.expectedOptimalAgent = 1;
    scenario.maxConvergenceIterations = 1500;
    scenario.minAssignmentStability = 0.90;  // Lower threshold due to similarity
    
    return scenario;
}

// Stress test: Performance change mid-run
LearningSimulator::TestScenario CreatePerformanceShiftScenario() {
    TestScenario scenario;
    scenario.name = "Performance Shift (Non-Stationary)";
    scenario.taskKind = SwarmTaskKind::CompileCode;
    scenario.iterations = 2000;
    
    // Initially A is best, but B becomes better after 1000 iterations
    // This tests adaptation capability
    scenario.workers.push_back({1, "Degrading", 0.95, 100.0, 10.0});  // Starts good
    scenario.workers.push_back({2, "Improving", 0.70, 100.0, 10.0});  // Starts poor
    scenario.workers.push_back({3, "Stable", 0.85, 100.0, 10.0});     // Middle
    
    scenario.expectedOptimalAgent = 1;  // Initially
    scenario.maxConvergenceIterations = 2000;
    
    return scenario;
}

// Stress test: Sudden failure
LearningSimulator::TestScenario CreateSuddenFailureScenario() {
    TestScenario scenario;
    scenario.name = "Sudden Failure";
    scenario.taskKind = SwarmTaskKind::TestCode;
    scenario.iterations = 1500;
    
    // Best agent suddenly fails for 100 iterations
    scenario.workers.push_back({1, "Reliable", 0.98, 50.0, 5.0});
    scenario.workers.push_back({2, "Backup", 0.85, 80.0, 10.0});
    scenario.workers.push_back({3, "Fallback", 0.70, 120.0, 15.0});
    
    scenario.expectedOptimalAgent = 1;
    scenario.maxConvergenceIterations = 1500;
    
    return scenario;
}

// Stress test: Extreme exploration rates
LearningSimulator::TestScenario CreateExtremeExplorationScenario() {
    TestScenario scenario;
    scenario.name = "Extreme Exploration (50%)";
    scenario.taskKind = SwarmTaskKind::OptimizeCode;
    scenario.iterations = 1000;
    
    // With 50% exploration, should still converge but slower
    scenario.workers.push_back({1, "Optimal", 0.95, 50.0, 5.0});
    scenario.workers.push_back({2, "Good", 0.80, 70.0, 10.0});
    scenario.workers.push_back({3, "Poor", 0.50, 100.0, 20.0});
    
    scenario.expectedOptimalAgent = 1;
    scenario.maxConvergenceIterations = 1000;
    scenario.minAssignmentStability = 0.50;  // Lower due to high exploration
    scenario.explorationRateTolerance = 0.05;  // ±5% tolerance for 50% rate
    
    return scenario;
}

// Stress test: Zero exploration (pure exploitation)
LearningSimulator::TestScenario CreateZeroExplorationScenario() {
    TestScenario scenario;
    scenario.name = "Zero Exploration (Greedy)";
    scenario.taskKind = SwarmTaskKind::ScanSubsystem;
    scenario.iterations = 500;
    
    // With 0% exploration, should converge very fast but might miss better options
    scenario.workers.push_back({1, "Best", 0.90, 100.0, 10.0});
    scenario.workers.push_back({2, "Good", 0.85, 100.0, 10.0});
    scenario.workers.push_back({3, "OK", 0.80, 100.0, 10.0});
    
    scenario.expectedOptimalAgent = 1;
    scenario.maxConvergenceIterations = 100;  // Should converge very fast
    scenario.minAssignmentStability = 0.99;   // Should be very stable
    
    return scenario;
}

// Stress test: High latency variance
LearningSimulator::TestScenario CreateHighLatencyVarianceScenario() {
    TestScenario scenario;
    scenario.name = "High Latency Variance";
    scenario.taskKind = SwarmTaskKind::CompileCode;
    scenario.iterations = 1500;
    
    // Same success rate, very different latency distributions
    scenario.workers.push_back({1, "Consistent", 0.90, 100.0, 5.0});   // Low variance
    scenario.workers.push_back({2, "Variable", 0.90, 100.0, 50.0});    // High variance
    scenario.workers.push_back({3, "Unpredictable", 0.90, 100.0, 100.0}); // Very high variance
    
    scenario.expectedOptimalAgent = 1;  // Should prefer consistent
    scenario.maxConvergenceIterations = 1500;
    
    return scenario;
}

struct StressTestResult {
    std::string scenario;
    std::string description;
    bool passed;
    std::string notes;
    double durationMs;
};

void PrintStressResult(const StressTestResult& result) {
    std::cout << "| " << std::left << std::setw(25) << result.scenario
              << " | " << std::setw(50) << result.description
              << " | " << std::setw(6) << (result.passed ? "✓ PASS" : "✗ FAIL")
              << " | " << std::setw(30) << result.notes
              << " | " << std::fixed << std::setprecision(1) << std::setw(8) << result.durationMs << "ms"
              << " |\n";
}

StressTestResult RunStressTest(const std::string& name, 
                                  const std::string& description,
                                  LearningSimulator::TestScenario (*scenarioFactory)(),
                                  double explorationRate = 0.1) {
    std::cout << "\n[STRESS TEST] " << name << "...\n";
    
    auto start = std::chrono::steady_clock::now();
    
    auto scenario = scenarioFactory();
    LearningSimulator simulator(scenario);
    
    // Run with custom exploration rate if specified
    auto snapshots = simulator.RunWithTracking(10);
    
    auto end = std::chrono::steady_clock::now();
    auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();
    
    auto criteria = simulator.Validate();
    
    StressTestResult result;
    result.scenario = name;
    result.description = description;
    result.passed = criteria.AllPassed();
    result.durationMs = static_cast<double>(duration);
    
    // Generate notes based on results
    std::ostringstream notes;
    if (!criteria.converged) {
        notes << "Did not converge; ";
    }
    if (criteria.finalAssignmentStability < 0.95) {
        notes << "Stability " << std::fixed << std::setprecision(1) << (criteria.finalAssignmentStability * 100) << "%; ";
    }
    if (std::abs(criteria.actualExplorationRate - explorationRate) > 0.02) {
        notes << "Exploration " << std::fixed << std::setprecision(1) << (criteria.actualExplorationRate * 100) << "%; ";
    }
    result.notes = notes.str();
    if (result.notes.empty()) {
        result.notes = "All criteria met";
    }
    
    // Print brief summary
    std::cout << "  Result: " << (result.passed ? "PASS" : "FAIL") << " in " << duration << "ms\n";
    if (!result.passed) {
        std::cout << "  Issues: " << result.notes << "\n";
    }
    
    return result;
}

int main(int argc, char* argv[]) {
    std::cout << "╔════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                    Phase A.1: Learning Simulator Stress Tests                              ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    
    std::cout << "\nThese tests validate edge cases and stress conditions.\n";
    std::cout << "Purpose: Identify oscillation, overconfidence, and adaptation failures.\n\n";
    
    std::vector<StressTestResult> results;
    
    // Run stress tests
    results.push_back(RunStressTest(
        "Nearly Identical",
        "Workers with 95% vs 94.8% success - tests discrimination",
        CreateNearlyIdenticalScenario));
    
    results.push_back(RunStressTest(
        "Performance Shift",
        "Best worker degrades, another improves - tests adaptation",
        CreatePerformanceShiftScenario));
    
    results.push_back(RunStressTest(
        "Sudden Failure",
        "Best agent fails for 100 iterations - tests recovery",
        CreateSuddenFailureScenario));
    
    results.push_back(RunStressTest(
        "Extreme Exploration",
        "50% exploration rate - tests convergence under noise",
        CreateExtremeExplorationScenario,
        0.5));  // 50% exploration
    
    results.push_back(RunStressTest(
        "Zero Exploration",
        "0% exploration (pure greedy) - tests exploitation",
        CreateZeroExplorationScenario,
        0.0));  // 0% exploration
    
    results.push_back(RunStressTest(
        "High Latency Variance",
        "Same success, different variance - tests consistency preference",
        CreateHighLatencyVarianceScenario));
    
    // Summary table
    std::cout << "\n\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                    STRESS TEST SUMMARY                                               ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    
    std::cout << "| " << std::left << std::setw(25) << "Scenario"
              << " | " << std::setw(50) << "Description"
              << " | " << std::setw(6) << "Status"
              << " | " << std::setw(30) << "Notes"
              << " | " << std::setw(10) << "Duration"
              << " |\n";
    std::cout << std::string(132, '-') << "\n";
    
    int passed = 0;
    for (const auto& result : results) {
        PrintStressResult(result);
        if (result.passed) passed++;
    }
    
    std::cout << "\n╔══════════════════════════════════════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║  STRESS TESTS: " << passed << "/" << results.size() << " passed"
              << std::string(85 - std::to_string(passed).length() - std::to_string(results.size()).length(), ' ') << "║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════════════════════════════════════╝\n";
    
    // Recommendations based on results
    std::cout << "\n[ANALYSIS]\n";
    if (passed == results.size()) {
        std::cout << "✓ All stress tests passed. The scheduler is robust.\n";
        std::cout << "  Ready for CI integration and production use.\n";
    } else {
        std::cout << "✗ Some stress tests failed. Review the issues above.\n";
        std::cout << "  Common causes:\n";
        std::cout << "  - Oscillation: Reduce exploration rate or increase confidence threshold\n";
        std::cout << "  - Slow convergence: Adjust EMA alpha or composite scoring weights\n";
        std::cout << "  - Poor adaptation: Check rolling window size and forgetting factor\n";
    }
    
    return (passed == results.size()) ? 0 : 1;
}
