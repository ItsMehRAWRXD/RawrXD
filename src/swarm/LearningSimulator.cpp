// Phase A.1: Deterministic Learning Simulator Implementation
#include "LearningSimulator.hpp"
#include <iomanip>
#include <sstream>
#include <fstream>
#include <set>
#include <algorithm>
#include <numeric>
#include <cmath>

namespace Sovereign {

// SimulatedWorker implementation
std::pair<bool, int64_t> LearningSimulator::SimulatedWorker::ExecuteTask(std::mt19937& rng) {
    std::uniform_real_distribution<double> successDist(0.0, 1.0);
    std::normal_distribution<double> latencyDist(meanLatencyMs, latencyStdDevMs);
    
    bool success = successDist(rng) < successProbability;
    int64_t latency = static_cast<int64_t>(std::max(1.0, latencyDist(rng)));
    
    totalExecutions++;
    if (success) successfulExecutions++;
    totalLatency += latency;
    
    return {success, latency};
}

// Predefined test scenarios
LearningSimulator::TestScenario LearningSimulator::CreateStationaryScenario() {
    TestScenario scenario;
    scenario.name = "Stationary Workers";
    scenario.taskKind = SwarmTaskKind::ScanSubsystem;
    scenario.iterations = 1000;
    
    // Agent A: Reliable but slow
    scenario.workers.push_back({1, "Reliable", 0.95, 120.0, 10.0});
    // Agent B: Fast but less reliable
    scenario.workers.push_back({2, "Fast", 0.80, 70.0, 15.0});
    // Agent C: Very fast but unreliable
    scenario.workers.push_back({3, "Risky", 0.60, 30.0, 5.0});
    
    // Expected optimal: Agent A (highest success rate)
    scenario.expectedOptimalAgent = 1;
    
    return scenario;
}

LearningSimulator::TestScenario LearningSimulator::CreateLatencyTradeoffScenario() {
    TestScenario scenario;
    scenario.name = "Latency vs Success Tradeoff";
    scenario.taskKind = SwarmTaskKind::OptimizeSubsystem;  // Use valid task kind
    scenario.iterations = 1000;
    
    // Agent A: High success, high latency
    scenario.workers.push_back({1, "Compiler_A", 0.97, 200.0, 20.0});
    // Agent B: Medium success, medium latency
    scenario.workers.push_back({2, "Compiler_B", 0.85, 100.0, 10.0});
    // Agent C: Low success, low latency
    scenario.workers.push_back({3, "Compiler_C", 0.70, 50.0, 5.0});
    
    // Expected optimal depends on composite scoring
    scenario.expectedOptimalAgent = 1;  // Likely A due to high success
    
    return scenario;
}

LearningSimulator::TestScenario LearningSimulator::CreateNoisyScenario() {
    TestScenario scenario;
    scenario.name = "High Variance Workers";
    scenario.taskKind = SwarmTaskKind::RepairSubsystem;  // Use valid task kind
    scenario.iterations = 2000;  // More iterations needed
    
    // High variance makes learning harder
    scenario.workers.push_back({1, "Stable", 0.90, 100.0, 50.0});
    scenario.workers.push_back({2, "Noisy", 0.85, 100.0, 80.0});
    scenario.workers.push_back({3, "Unpredictable", 0.88, 100.0, 100.0});
    
    scenario.expectedOptimalAgent = 1;
    scenario.maxConvergenceIterations = 1000;  // Allow more time
    
    return scenario;
}

LearningSimulator::TestScenario LearningSimulator::CreateDominantScenario() {
    TestScenario scenario;
    scenario.name = "Dominant Best Agent";
    scenario.taskKind = SwarmTaskKind::ExtendSubsystem;  // Use valid task kind
    scenario.iterations = 500;
    
    // One agent is clearly superior
    scenario.workers.push_back({1, "Optimal", 0.98, 50.0, 5.0});
    scenario.workers.push_back({2, "Mediocre", 0.70, 100.0, 20.0});
    scenario.workers.push_back({3, "Poor", 0.50, 150.0, 30.0});
    
    scenario.expectedOptimalAgent = 1;
    scenario.maxConvergenceIterations = 200;  // Should converge quickly
    
    return scenario;
}

// LearningSimulator implementation
LearningSimulator::LearningSimulator(const TestScenario& scenario) 
    : scenario_(scenario) {
    snapshots_.reserve(scenario.iterations / 10);
}

void LearningSimulator::Run() {
    // Reset registry
    SelfModelRegistry::GetInstance().ResetStatistics();
    
    // Run simulation
    for (uint32_t i = 0; i < scenario_.iterations; ++i) {
        // Select agent using learned assignment
        auto result = SelfModelRegistry::GetInstance().SelectAgentWithExploration(
            scenario_.taskKind, 0.1);
        
        uint32_t selectedAgent = result.agentId;
        if (selectedAgent == 0 || selectedAgent > scenario_.workers.size()) {
            selectedAgent = 1;  // Default to first agent
        }
        
        // Find worker
        SimulatedWorker* worker = nullptr;
        for (auto& w : scenario_.workers) {
            if (w.agentId == selectedAgent) {
                worker = &w;
                break;
            }
        }
        
        if (!worker) continue;
        
        // Execute task
        auto [success, latency] = worker->ExecuteTask(rng_);
        
        // Record result
        if (success) {
            SelfModelRegistry::GetInstance().RecordTaskSuccess(
                selectedAgent, scenario_.taskKind, latency);
        } else {
            SelfModelRegistry::GetInstance().RecordTaskFailure(
                selectedAgent, scenario_.taskKind, "simulated_failure");
        }
        
        // Record snapshot periodically
        if (i % 10 == 0) {
            RecordSnapshot(i, selectedAgent, 
                          result.wasExploration ? "exploration" : "exploitation");
        }
    }
}

std::vector<LearningSimulator::ConvergenceSnapshot> LearningSimulator::RunWithTracking(uint32_t snapshotInterval) {
    snapshots_.clear();
    
    // Reset registry
    SelfModelRegistry::GetInstance().ResetStatistics();
    
    // Calculate baselines
    double randomBaseline = CalculateRandomBaseline(scenario_);
    double roundRobinBaseline = CalculateRoundRobinBaseline(scenario_);
    
    std::cout << "[SIMULATOR] Baselines - Random: " << std::fixed << std::setprecision(1) << (randomBaseline * 100) << "%"
              << ", Round-Robin: " << (roundRobinBaseline * 100) << "%\n";
    
    // Run simulation
    for (uint32_t i = 0; i <= scenario_.iterations; ++i) {
        // Select agent using learned assignment
        auto result = SelfModelRegistry::GetInstance().SelectAgentWithExploration(
            scenario_.taskKind, 0.1);
        
        uint32_t selectedAgent = result.agentId;
        if (selectedAgent == 0 || selectedAgent > scenario_.workers.size()) {
            selectedAgent = 1;
        }
        
        // Find worker
        SimulatedWorker* worker = nullptr;
        for (auto& w : scenario_.workers) {
            if (w.agentId == selectedAgent) {
                worker = &w;
                break;
            }
        }
        
        if (!worker) continue;
        
        // Execute task
        auto [success, latency] = worker->ExecuteTask(rng_);
        
        // Record result
        if (success) {
            SelfModelRegistry::GetInstance().RecordTaskSuccess(
                selectedAgent, scenario_.taskKind, latency);
        } else {
            SelfModelRegistry::GetInstance().RecordTaskFailure(
                selectedAgent, scenario_.taskKind, "simulated_failure");
        }
        
        // Record snapshot
        if (i % snapshotInterval == 0 || i == scenario_.iterations) {
            RecordSnapshot(i, selectedAgent,
                          result.wasExploration ? "exploration" : "exploitation");
        }
    }
    
    return snapshots_;
}

void LearningSimulator::RecordSnapshot(uint32_t iteration, uint32_t selectedAgent,
                                      const std::string& selectionType) {
    ConvergenceSnapshot snapshot;
    snapshot.iteration = iteration;
    snapshot.selectedAgent = selectedAgent;
    snapshot.selectionType = selectionType;
    
    // Find worker info
    for (const auto& w : scenario_.workers) {
        if (w.agentId == selectedAgent) {
            snapshot.agentName = w.name;
            if (w.totalExecutions > 0) {
                snapshot.agentSuccessRate = static_cast<double>(w.successfulExecutions) / w.totalExecutions;
                snapshot.agentLatency = w.totalLatency / w.totalExecutions;
            }
            break;
        }
    }
    
    // Calculate overall stats
    uint32_t totalExecs = 0;
    uint32_t totalSuccess = 0;
    double totalLatency = 0.0;
    for (const auto& w : scenario_.workers) {
        totalExecs += w.totalExecutions;
        totalSuccess += w.successfulExecutions;
        totalLatency += w.totalLatency;
    }
    
    if (totalExecs > 0) {
        snapshot.overallSuccessRate = static_cast<double>(totalSuccess) / totalExecs;
        snapshot.overallLatency = totalLatency / totalExecs;
    }
    
    // Track exploration rate in recent window
    recentAssignments_[selectedAgent]++;
    if (recentAssignments_.size() > STABILITY_WINDOW) {
        recentAssignments_.erase(recentAssignments_.begin());
    }
    
    snapshots_.push_back(snapshot);
}

LearningSimulator::BenchmarkCriteria LearningSimulator::Validate() const {
    BenchmarkCriteria criteria;
    
    if (snapshots_.empty()) {
        return criteria;
    }
    
    // Check convergence
    uint32_t bestAgent = static_cast<uint32_t>(scenario_.expectedOptimalAgent);
    uint32_t stableCount = 0;
    uint32_t requiredStable = 50;  // Need 50 consecutive selections of same agent
    
    for (size_t i = 0; i < snapshots_.size(); ++i) {
        if (snapshots_[i].selectedAgent == bestAgent) {
            stableCount++;
            if (stableCount >= requiredStable && !criteria.converged) {
                criteria.converged = true;
                criteria.convergenceIteration = snapshots_[i].iteration;
            }
        } else {
            stableCount = 0;
        }
    }
    
    // Calculate assignment stability (last 100 selections)
    criteria.finalAssignmentStability = CalculateAssignmentStability();
    
    // Calculate actual exploration rate
    uint32_t explorationCount = 0;
    for (const auto& snap : snapshots_) {
        if (snap.selectionType == "exploration") {
            explorationCount++;
        }
    }
    if (!snapshots_.empty()) {
        criteria.actualExplorationRate = static_cast<double>(explorationCount) / snapshots_.size();
    }
    
    // Check if all agents were explored
    std::set<uint32_t> exploredAgents;
    for (const auto& snap : snapshots_) {
        exploredAgents.insert(snap.selectedAgent);
    }
    criteria.allAgentsExplored = (exploredAgents.size() == scenario_.workers.size());
    
    // Calculate improvements vs baselines
    double randomBaseline = CalculateRandomBaseline(scenario_);
    double roundRobinBaseline = CalculateRoundRobinBaseline(scenario_);
    
    if (!snapshots_.empty()) {
        double finalSuccessRate = snapshots_.back().overallSuccessRate;
        double finalLatency = snapshots_.back().overallLatency;
        
        criteria.successRateImprovement = finalSuccessRate - randomBaseline;
        
        // Latency improvement (lower is better)
        if (roundRobinBaseline > 0) {
            criteria.latencyImprovement = (roundRobinBaseline - finalLatency) / roundRobinBaseline;
        }
    }
    
    return criteria;
}

std::string LearningSimulator::BenchmarkCriteria::ToString() const {
    std::ostringstream oss;
    oss << "\n╔══════════════════════════════════════════════════════════════╗\n";
    oss << "║           Benchmark Validation Results                       ║\n";
    oss << "╚══════════════════════════════════════════════════════════════╝\n";
    
    oss << "Convergence: " << (converged ? "✓ PASS" : "✗ FAIL");
    if (converged) {
        oss << " at iteration " << convergenceIteration;
    }
    oss << "\n";
    
    oss << "Assignment Stability: " << std::fixed << std::setprecision(1) << (finalAssignmentStability * 100) << "%"
              << " (target: 95%)\n";
    
    oss << "Exploration Rate: " << std::fixed << std::setprecision(1) << (actualExplorationRate * 100) << "%"
              << " (target: 10% ± 2%)\n";
    
    oss << "Success Rate Improvement: " << std::fixed << std::setprecision(1) << (successRateImprovement * 100) << "%"
              << " (target: ≥10%)\n";
    
    oss << "Latency Improvement: " << std::fixed << std::setprecision(1) << (latencyImprovement * 100) << "%"
              << " (target: ≥10%)\n";
    
    oss << "All Agents Explored: " << (allAgentsExplored ? "✓ PASS" : "✗ FAIL") << "\n";
    
    oss << "\nOverall: " << (AllPassed() ? "✓ ALL CRITERIA PASSED" : "✗ SOME CRITERIA FAILED") << "\n";
    
    return oss.str();
}

bool LearningSimulator::BenchmarkCriteria::AllPassed() const {
    return converged &&
           finalAssignmentStability >= 0.95 &&
           actualExplorationRate >= 0.08 && actualExplorationRate <= 0.12 &&
           successRateImprovement >= 0.10 &&
           latencyImprovement >= 0.10 &&
           allAgentsExplored;
}

double LearningSimulator::CalculateAssignmentStability() const {
    if (snapshots_.size() < STABILITY_WINDOW) {
        return 0.0;
    }
    
    // Count occurrences of most frequent agent in last window
    std::map<uint32_t, uint32_t> counts;
    size_t start = snapshots_.size() > STABILITY_WINDOW ? snapshots_.size() - STABILITY_WINDOW : 0;
    
    for (size_t i = start; i < snapshots_.size(); ++i) {
        counts[snapshots_[i].selectedAgent]++;
    }
    
    if (counts.empty()) return 0.0;
    
    uint32_t maxCount = 0;
    for (const auto& [agent, count] : counts) {
        maxCount = std::max(maxCount, count);
    }
    
    return static_cast<double>(maxCount) / std::min(STABILITY_WINDOW, snapshots_.size() - start);
}

double LearningSimulator::CalculateRandomBaseline(const TestScenario& scenario) {
    double totalSuccess = 0.0;
    for (const auto& w : scenario.workers) {
        totalSuccess += w.successProbability;
    }
    return totalSuccess / scenario.workers.size();
}

double LearningSimulator::CalculateRoundRobinBaseline(const TestScenario& scenario) {
    double totalLatency = 0.0;
    for (const auto& w : scenario.workers) {
        totalLatency += w.meanLatencyMs;
    }
    return totalLatency / scenario.workers.size();
}

void LearningSimulator::PrintReport() const {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           Learning Simulator Report                            ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << "Scenario: " << scenario_.name << "\n";
    std::cout << "Iterations: " << scenario_.iterations << "\n\n";
    
    std::cout << "Worker Configuration:\n";
    std::cout << std::left << std::setw(12) << "Agent"
              << std::setw(15) << "Success%"
              << std::setw(15) << "Latency(ms)"
              << std::setw(15) << "StdDev"
              << std::setw(15) << "Expected"
              << "\n";
    std::cout << std::string(72, '-') << "\n";
    
    for (const auto& w : scenario_.workers) {
        std::cout << std::left << std::setw(12) << w.name
                  << std::setw(14) << std::fixed << std::setprecision(1) << (w.successProbability * 100) << "%"
                  << std::setw(14) << std::fixed << std::setprecision(1) << w.meanLatencyMs
                  << std::setw(14) << std::fixed << std::setprecision(1) << w.latencyStdDevMs
                  << std::setw(14) << (w.agentId == scenario_.expectedOptimalAgent ? "OPTIMAL" : "")
                  << "\n";
    }
    
    // Print validation results
    auto criteria = Validate();
    std::cout << criteria.ToString() << "\n";
    
    // Print final worker statistics
    std::cout << "\nActual Worker Performance:\n";
    std::cout << std::left << std::setw(12) << "Agent"
              << std::setw(15) << "Executions"
              << std::setw(15) << "Success%"
              << std::setw(15) << "Avg Latency"
              << "\n";
    std::cout << std::string(57, '-') << "\n";
    
    for (const auto& w : scenario_.workers) {
        double actualSuccess = w.totalExecutions > 0 
            ? static_cast<double>(w.successfulExecutions) / w.totalExecutions 
            : 0.0;
        double actualLatency = w.totalExecutions > 0
            ? w.totalLatency / w.totalExecutions
            : 0.0;
        
        std::cout << std::left << std::setw(12) << w.name
                  << std::setw(14) << w.totalExecutions
                  << std::setw(14) << std::fixed << std::setprecision(1) << (actualSuccess * 100) << "%"
                  << std::setw(14) << std::fixed << std::setprecision(1) << actualLatency << "ms"
                  << "\n";
    }
}

void LearningSimulator::PrintConvergenceGraph(const std::vector<ConvergenceSnapshot>& snapshots) const {
    std::cout << "\n╔══════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           Convergence Over Time                                ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════╝\n";
    std::cout << std::left << std::setw(12) << "Iteration"
              << std::setw(12) << "Agent"
              << std::setw(12) << "Success%"
              << std::setw(14) << "Latency(ms)"
              << std::setw(12) << "Type"
              << "\n";
    std::cout << std::string(62, '-') << "\n";
    
    // Print every Nth snapshot
    size_t step = snapshots.size() > 20 ? snapshots.size() / 20 : 1;
    for (size_t i = 0; i < snapshots.size(); i += step) {
        const auto& snap = snapshots[i];
        std::cout << std::left << std::setw(12) << snap.iteration
                  << std::setw(12) << snap.agentName
                  << std::setw(11) << std::fixed << std::setprecision(1) << (snap.agentSuccessRate * 100) << "%"
                  << std::setw(13) << std::fixed << std::setprecision(1) << snap.agentLatency
                  << std::setw(12) << snap.selectionType
                  << "\n";
    }
}

void LearningSimulator::ExportCSV(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return;
    
    file << "iteration,agent_id,agent_name,success_rate,latency,overall_success,overall_latency,selection_type\n";
    
    for (const auto& snap : snapshots_) {
        file << snap.iteration << ","
             << snap.selectedAgent << ","
             << snap.agentName << ","
             << snap.agentSuccessRate << ","
             << snap.agentLatency << ","
             << snap.overallSuccessRate << ","
             << snap.overallLatency << ","
             << snap.selectionType << "\n";
    }
}

void LearningSimulator::ExportJSON(const std::string& path) const {
    nlohmann::json j;
    
    j["scenario"] = scenario_.name;
    j["iterations"] = scenario_.iterations;
    j["expected_optimal"] = scenario_.expectedOptimalAgent;
    
    auto criteria = Validate();
    j["validation"]["converged"] = criteria.converged;
    j["validation"]["convergence_iteration"] = criteria.convergenceIteration;
    j["validation"]["assignment_stability"] = criteria.finalAssignmentStability;
    j["validation"]["exploration_rate"] = criteria.actualExplorationRate;
    j["validation"]["success_improvement"] = criteria.successRateImprovement;
    j["validation"]["latency_improvement"] = criteria.latencyImprovement;
    j["validation"]["all_agents_explored"] = criteria.allAgentsExplored;
    j["validation"]["all_passed"] = criteria.AllPassed();
    
    j["workers"] = nlohmann::json::array();
    for (const auto& w : scenario_.workers) {
        nlohmann::json worker;
        worker["id"] = w.agentId;
        worker["name"] = w.name;
        worker["expected_success"] = w.successProbability;
        worker["expected_latency"] = w.meanLatencyMs;
        worker["actual_executions"] = w.totalExecutions;
        worker["actual_success_rate"] = w.totalExecutions > 0 
            ? static_cast<double>(w.successfulExecutions) / w.totalExecutions : 0.0;
        worker["actual_latency"] = w.totalExecutions > 0
            ? w.totalLatency / w.totalExecutions : 0.0;
        j["workers"].push_back(worker);
    }
    
    j["snapshots"] = nlohmann::json::array();
    for (const auto& snap : snapshots_) {
        nlohmann::json s;
        s["iteration"] = snap.iteration;
        s["agent_id"] = snap.selectedAgent;
        s["agent_name"] = snap.agentName;
        s["success_rate"] = snap.agentSuccessRate;
        s["latency"] = snap.agentLatency;
        s["selection_type"] = snap.selectionType;
        j["snapshots"].push_back(s);
    }
    
    std::ofstream file(path);
    if (file.is_open()) {
        file << j.dump(2);
    }
}

// SimulatedSelfModelInjector implementation
void SimulatedSelfModelInjector::InjectWorkerPerformance(uint32_t agentId, SwarmTaskKind kind,
                                                          double successRate, double latencyMs,
                                                          uint32_t sampleCount) {
    auto& registry = SelfModelRegistry::GetInstance();
    
    // Inject synthetic success records
    for (uint32_t i = 0; i < sampleCount; ++i) {
        bool success = (static_cast<double>(i) / sampleCount) < successRate;
        if (success) {
            registry.RecordTaskSuccess(agentId, kind, static_cast<int64_t>(latencyMs));
        } else {
            registry.RecordTaskFailure(agentId, kind, "simulated");
        }
    }
}

void SimulatedSelfModelInjector::SetupSimulatedWorkers(
    const std::vector<LearningSimulator::SimulatedWorker>& workers,
    SwarmTaskKind kind) {
    
    for (const auto& w : workers) {
        InjectWorkerPerformance(w.agentId, kind, w.successProbability, w.meanLatencyMs, 100);
    }
}

bool SimulatedSelfModelInjector::VerifyRegistryState(
    const std::vector<LearningSimulator::SimulatedWorker>& workers,
    SwarmTaskKind kind) {
    
    auto& registry = SelfModelRegistry::GetInstance();
    
    for (const auto& w : workers) {
        auto rankings = registry.GetAgentRankings(kind);
        // Verify agent exists in rankings
        bool found = false;
        for (const auto& [agentId, score] : rankings) {
            if (agentId == w.agentId) {
                found = true;
                break;
            }
        }
        if (!found) return false;
    }
    
    return true;
}

} // namespace Sovereign
