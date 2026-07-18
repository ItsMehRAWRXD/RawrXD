#pragma once

#include "SovereignSwarm.hpp"
#include <random>
#include <fstream>
#include <iostream>

namespace Sovereign {

// Phase A.1: Deterministic Learning Simulator
// Simulates workers with known probabilities to validate scheduler mathematics
class LearningSimulator {
public:
    // Simulated worker with known characteristics
    struct SimulatedWorker {
        uint32_t agentId;
        std::string name;
        double successProbability;  // 0.0-1.0
        double meanLatencyMs;       // Average latency
        double latencyStdDevMs;     // Latency variance
        
        // Runtime tracking
        uint32_t totalExecutions = 0;
        uint32_t successfulExecutions = 0;
        double totalLatency = 0.0;
        
        // Simulate task execution
        std::pair<bool, int64_t> ExecuteTask(std::mt19937& rng);
    };
    
    // Convergence tracking
    struct ConvergenceSnapshot {
        uint32_t iteration;
        uint32_t selectedAgent;
        std::string agentName;
        double agentSuccessRate;
        double agentLatency;
        double overallSuccessRate;
        double overallLatency;
        double explorationRate;
        std::string selectionType;  // "exploitation" or "exploration"
    };
    
    // Benchmark criteria results
    struct BenchmarkCriteria {
        bool converged = false;
        uint32_t convergenceIteration = 0;
        double finalAssignmentStability = 0.0;
        double actualExplorationRate = 0.0;
        double successRateImprovement = 0.0;
        double latencyImprovement = 0.0;
        bool allAgentsExplored = false;
        
        std::string ToString() const;
        bool AllPassed() const;
    };
    
    // Test scenario configuration
    struct TestScenario {
        std::string name;
        std::vector<SimulatedWorker> workers;
        SwarmTaskKind taskKind;
        uint32_t iterations;
        double expectedOptimalAgent;
        
        // Criteria thresholds
        uint32_t maxConvergenceIterations = 500;
        double minAssignmentStability = 0.95;
        double explorationRateTolerance = 0.02;  // ±2%
        double minSuccessImprovement = 0.10;       // 10% better than random
        double minLatencyImprovement = 0.10;       // 10% better than round-robin
    };
    
    // Predefined test scenarios
    static TestScenario CreateStationaryScenario();      // Fixed worker performance
    static TestScenario CreateLatencyTradeoffScenario(); // Fast vs reliable
    static TestScenario CreateNoisyScenario();          // High variance
    static TestScenario CreateDominantScenario();       // One clearly best
    
    // Run simulation
    LearningSimulator(const TestScenario& scenario);
    
    // Execute full simulation
    void Run();
    
    // Run with convergence tracking
    std::vector<ConvergenceSnapshot> RunWithTracking(uint32_t snapshotInterval = 10);
    
    // Validate against criteria
    BenchmarkCriteria Validate() const;
    
    // Export results
    void ExportCSV(const std::string& path) const;
    void ExportJSON(const std::string& path) const;
    
    // Print report
    void PrintReport() const;
    void PrintConvergenceGraph(const std::vector<ConvergenceSnapshot>& snapshots) const;
    
    // Access results
    const std::vector<ConvergenceSnapshot>& GetSnapshots() const { return snapshots_; }
    const TestScenario& GetScenario() const { return scenario_; }
    
    // Static comparison baselines
    static double CalculateRandomBaseline(const TestScenario& scenario);
    static double CalculateRoundRobinBaseline(const TestScenario& scenario);
    
private:
    TestScenario scenario_;
    std::vector<ConvergenceSnapshot> snapshots_;
    std::mt19937 rng_{42};  // Fixed seed for reproducibility
    
    // Track assignments for stability calculation
    std::map<uint32_t, uint32_t> recentAssignments_;
    static constexpr size_t STABILITY_WINDOW = 100;
    
    void RecordSnapshot(uint32_t iteration, uint32_t selectedAgent, 
                       const std::string& selectionType);
    double CalculateAssignmentStability() const;
};

// Integration with SelfModelRegistry for testing
class SimulatedSelfModelInjector {
public:
    // Inject simulated performance data into registry
    static void InjectWorkerPerformance(uint32_t agentId, SwarmTaskKind kind,
                                       double successRate, double latencyMs,
                                       uint32_t sampleCount);
    
    // Create workers with known characteristics for testing
    static void SetupSimulatedWorkers(const std::vector<LearningSimulator::SimulatedWorker>& workers,
                                     SwarmTaskKind kind);
    
    // Verify registry matches expected state
    static bool VerifyRegistryState(const std::vector<LearningSimulator::SimulatedWorker>& workers,
                                   SwarmTaskKind kind);
};

} // namespace Sovereign
