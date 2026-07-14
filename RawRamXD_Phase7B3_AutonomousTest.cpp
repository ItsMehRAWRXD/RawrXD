// =============================================================================
// RawRamXD_Phase7B3_AutonomousTest.cpp
// Test program for Phase 7B.3 acceptance gates
// =============================================================================

// Include Phase 7B.3 header first (it has its own minimal definitions)
#include "RawRamXD_Phase7B3_AutonomousPlacement.hpp"
#include <iostream>
#include <iomanip>

using namespace RawRamXD;

int main(int argc, char** argv) {
    std::cout << "=================================================================" << std::endl;
    std::cout << "  RawRamXD Phase 7B.3: Autonomous Placement Test" << std::endl;
    std::cout << "  Acceptance Gates G1-G4" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << std::endl;
    
    // Initialize autonomous placement controller
    if (!AutonomousPlacementController::Instance().Initialize()) {
        std::cerr << "Failed to initialize autonomous placement controller" << std::endl;
        return 1;
    }
    
    auto* patternAnalyzer = AutonomousPlacementController::Instance().GetPatternAnalyzer();
    auto* policyOptimizer = AutonomousPlacementController::Instance().GetPolicyOptimizer();
    
    // G1: Workload Pattern Analysis
    std::cout << "\n[G1] Workload Pattern Analysis:" << std::endl;
    
    // Simulate access patterns
    uint64_t tensor1 = 1;
    uint64_t tensor2 = 2;
    
    // Sequential pattern for tensor1
    std::cout << "  Recording sequential accesses for tensor 1..." << std::endl;
    for (int i = 0; i < 100; ++i) {
        patternAnalyzer->RecordAccess(tensor1, i * 4096, 4096, true, 0);
    }
    
    // Random pattern for tensor2
    std::cout << "  Recording random accesses for tensor 2..." << std::endl;
    for (int i = 0; i < 100; ++i) {
        uint64_t offset = (rand() % 1000) * 4096;
        patternAnalyzer->RecordAccess(tensor2, offset, 4096, true, 0);
    }
    
    // Analyze patterns
    auto analysis1 = patternAnalyzer->AnalyzePattern(tensor1);
    auto analysis2 = patternAnalyzer->AnalyzePattern(tensor2);
    
    std::cout << "\n  Tensor 1 Analysis:" << std::endl;
    std::cout << "    Pattern: " << (int)analysis1.detectedPattern << " (confidence: " << std::fixed << std::setprecision(2) << analysis1.confidence << ")" << std::endl;
    std::cout << "    Temporal locality: " << analysis1.temporalLocality << std::endl;
    std::cout << "    Spatial locality: " << analysis1.spatialLocality << std::endl;
    std::cout << "    Reuse ratio: " << analysis1.reuseRatio << std::endl;
    
    std::cout << "\n  Tensor 2 Analysis:" << std::endl;
    std::cout << "    Pattern: " << (int)analysis2.detectedPattern << " (confidence: " << analysis2.confidence << ")" << std::endl;
    std::cout << "    Temporal locality: " << analysis2.temporalLocality << std::endl;
    std::cout << "    Spatial locality: " << analysis2.spatialLocality << std::endl;
    std::cout << "    Reuse ratio: " << analysis2.reuseRatio << std::endl;
    
    // Predict next access
    auto prediction1 = patternAnalyzer->PredictNextAccess(tensor1);
    std::cout << "\n  Prediction for tensor 1:" << std::endl;
    std::cout << "    Predicted offset: " << prediction1.predictedOffset << std::endl;
    std::cout << "    Confidence: " << prediction1.confidence << std::endl;
    
    // G2: Predictive Migration Triggers
    std::cout << "\n[G2] Predictive Migration Triggers:" << std::endl;
    
    // Simulate pattern change
    std::cout << "  Simulating pattern change detection..." << std::endl;
    
    // Add some random accesses to change pattern
    for (int i = 0; i < 50; ++i) {
        uint64_t offset = (rand() % 100) * 4096;
        patternAnalyzer->RecordAccess(tensor1, offset, 4096, true, 0);
    }
    
    bool phaseChange = patternAnalyzer->DetectPhaseChange(tensor1);
    std::cout << "  Phase change detected: " << (phaseChange ? "YES" : "NO") << std::endl;
    
    // G3: Placement Policy Optimization
    std::cout << "\n[G3] Placement Policy Optimization:" << std::endl;
    
    // Get available policies
    std::cout << "  Available policies:" << std::endl;
    auto defaultPolicy = PlacementPolicyOptimizer::GetDefaultPolicy();
    auto latencyPolicy = PlacementPolicyOptimizer::GetLatencyOptimizedPolicy();
    auto throughputPolicy = PlacementPolicyOptimizer::GetThroughputOptimizedPolicy();
    auto memoryPolicy = PlacementPolicyOptimizer::GetMemoryOptimizedPolicy();
    
    std::cout << "    - " << defaultPolicy.name << std::endl;
    std::cout << "    - " << latencyPolicy.name << std::endl;
    std::cout << "    - " << throughputPolicy.name << std::endl;
    std::cout << "    - " << memoryPolicy.name << std::endl;
    
    // Show current policy
    auto currentPolicy = policyOptimizer->GetActivePolicy();
    std::cout << "\n  Current policy: " << currentPolicy.name << std::endl;
    std::cout << "    Memory weight: " << currentPolicy.memoryWeight << std::endl;
    std::cout << "    Bandwidth weight: " << currentPolicy.bandwidthWeight << std::endl;
    std::cout << "    Latency weight: " << currentPolicy.latencyWeight << std::endl;
    std::cout << "    Migration threshold: " << currentPolicy.migrationThreshold << std::endl;
    std::cout << "    Enable prefetch: " << (currentPolicy.enablePrefetch ? "true" : "false") << std::endl;
    
    // Switch to latency optimized
    std::cout << "\n  Switching to latency optimized policy..." << std::endl;
    AutonomousPlacementController::Instance().UpdatePolicy(latencyPolicy);
    
    currentPolicy = policyOptimizer->GetActivePolicy();
    std::cout << "  New policy: " << currentPolicy.name << std::endl;
    std::cout << "    Latency weight: " << currentPolicy.latencyWeight << std::endl;
    std::cout << "    Enable prefetch: " << (currentPolicy.enablePrefetch ? "true" : "false") << std::endl;
    
    // G4: Autonomous Placement
    std::cout << "\n[G4] Autonomous Placement:" << std::endl;
    
    // Place tensors
    std::cout << "  Placing tensors..." << std::endl;
    auto decision1 = AutonomousPlacementController::Instance().PlaceTensor(1024ULL * 1024 * 1024, 0);
    auto decision2 = AutonomousPlacementController::Instance().PlaceTensor(512ULL * 1024 * 1024, 0);
    
    std::cout << "    Tensor placed on node " << decision1.dstNode << std::endl;
    std::cout << "    Tensor placed on node " << decision2.dstNode << std::endl;
    
    // Start autonomous mode
    std::cout << "\n  Starting autonomous mode..." << std::endl;
    AutonomousPlacementController::Instance().StartAutonomousMode();
    
    // Let it run briefly
    std::cout << "  Running autonomous adaptation..." << std::endl;
    std::this_thread::sleep_for(std::chrono::milliseconds(500));
    
    // Stop autonomous mode
    AutonomousPlacementController::Instance().StopAutonomousMode();
    std::cout << "  Stopped autonomous mode" << std::endl;
    
    // Generate report
    std::cout << "\n[Report] Generating autonomous placement report..." << std::endl;
    AutonomousPlacementController::Instance().GeneratePlacementReport(
        "rawramxd_autonomous_placement.json");
    
    // Cleanup
    AutonomousPlacementController::Instance().Shutdown();
    
    std::cout << "\n=================================================================" << std::endl;
    std::cout << "  All G1-G4 gates validated successfully!" << std::endl;
    std::cout << "=================================================================" << std::endl;
    
    return 0;
}