/**
 * AdaptiveSchedulingTest.cpp
 *
 * Phase B.2 Batches 18-22: Final Integration Testing
 *
 * Validates the complete adaptive scheduling system:
 * 1. Exploration rate adaptation based on convergence
 * 2. Worker auto-scaling
 * 3. Convergence-based task prioritization
 * 4. Integration with telemetry feedback loop
 */

#include <iostream>
#include <iomanip>
#include <cassert>
#include "../src/swarm/SovereignSwarm.hpp"
#include "../src/swarm/InfinitePerfectionTelemetry.hpp"
#include "../infinite/InfinitePerfectionEngine.hpp"

using namespace Sovereign;
using namespace InfinitePerfection;

class AdaptiveSchedulingTest {
public:
    bool Run() {
        std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║     Adaptive Scheduling Integration Test                     ║" << std::endl;
        std::cout << "║     Phase B.2 Batches 18-22: Final Validation                  ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;
        std::cout << std::endl;

        // Initialize
        std::cout << "[SETUP] Initializing engine and swarm..." << std::endl;
        auto& engine = InfinitePerfectionEngine::GetInstance();
        engine.Initialize();
        
        SwarmAgentContext ctx;
        ctx.engine = &engine;
        ctx.infiniteTelemetry = new InfinitePerfectionTelemetry(&engine);
        
        SovereignSwarm swarm(ctx);
        auto& scheduler = swarm.GetScheduler();
        
        // Enable adaptive features
        scheduler.SetLearnedAssignmentEnabled(true);
        scheduler.SetTargetConvergenceRate(0.85);
        scheduler.SetAutoScaleWorkers(true);
        scheduler.PrioritizeConvergingTasks(true);
        
        std::cout << "        ✓ Adaptive scheduling enabled" << std::endl;
        std::cout << "        Target convergence: 0.85" << std::endl;
        std::cout << "        Auto-scale workers: ON" << std::endl;
        std::cout << "        Prioritize converging: ON" << std::endl;

        // Test 1: Exploration rate adaptation
        std::cout << std::endl << "[TEST 1] Exploration rate adaptation..." << std::endl;
        double initialRate = scheduler.GetExplorationRate();
        std::cout << "         Initial rate: " << std::fixed << std::setprecision(2) 
                  << (initialRate * 100) << "%" << std::endl;
        
        // Simulate high convergence - should reduce exploration
        scheduler.AdaptExplorationRate(0.95);
        double highRate = scheduler.GetExplorationRate();
        std::cout << "         After high convergence (0.95): " << std::setprecision(2) 
                  << (highRate * 100) << "%" << std::endl;
        
        // Simulate low convergence - should increase exploration
        scheduler.AdaptExplorationRate(0.50);
        double lowRate = scheduler.GetExplorationRate();
        std::cout << "         After low convergence (0.50): " << std::setprecision(2) 
                  << (lowRate * 100) << "%" << std::endl;
        
        bool test1 = (highRate < initialRate) && (lowRate > highRate);
        std::cout << "         " << (test1 ? "✓ PASS" : "✗ FAIL") << std::endl;

        // Test 2: Worker auto-scaling
        std::cout << std::endl << "[TEST 2] Worker auto-scaling..." << std::endl;
        uint32_t workersHigh = scheduler.GetOptimalWorkerCount(0.95);
        uint32_t workersLow = scheduler.GetOptimalWorkerCount(0.50);
        
        std::cout << "         Workers at high convergence (0.95): " << workersHigh << std::endl;
        std::cout << "         Workers at low convergence (0.50): " << workersLow << std::endl;
        
        bool test2 = workersLow >= workersHigh;
        std::cout << "         " << (test2 ? "✓ PASS" : "✗ FAIL") << std::endl;

        // Test 3: Full Unity Sequence with adaptive scheduling
        std::cout << std::endl << "[TEST 3] Unity Sequence with adaptive scheduling..." << std::endl;
        
        auto result = swarm.ExecuteUnitySequence(engine);
        
        std::cout << "         Harmony Index: " << std::fixed << std::setprecision(4) 
                  << result.finalHarmonyIndex << std::endl;
        std::cout << "         Success: " << (result.success ? "YES" : "NO") << std::endl;
        
        bool test3 = result.success && result.finalHarmonyIndex > 0.7;
        std::cout << "         " << (test3 ? "✓ PASS" : "✗ FAIL") << std::endl;

        // Cleanup
        delete ctx.infiniteTelemetry;
        engine.Shutdown();

        // Summary
        std::cout << std::endl;
        std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
        if (test1 && test2 && test3) {
            std::cout << "║  ALL TESTS PASSED ✓                                            ║" << std::endl;
        } else {
            std::cout << "║  SOME TESTS FAILED ✗                                           ║" << std::endl;
        }
        std::cout << "╠════════════════════════════════════════════════════════════════╣" << std::endl;
        std::cout << "║  Test 1 (Exploration Adaptation): " << (test1 ? "PASS" : "FAIL") << "                          ║" << std::endl;
        std::cout << "║  Test 2 (Worker Auto-scaling):    " << (test2 ? "PASS" : "FAIL") << "                          ║" << std::endl;
        std::cout << "║  Test 3 (Unity Sequence):         " << (test3 ? "PASS" : "FAIL") << "                          ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;

        return test1 && test2 && test3;
    }
};

int main() {
    AdaptiveSchedulingTest test;
    bool passed = test.Run();
    return passed ? 0 : 1;
}
