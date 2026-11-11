/**
 * SwarmFeedbackLoopTest.cpp
 *
 * Phase B.2 Batch 5/5: Full Feedback Loop Validation
 *
 * Validates the complete Swarm → Engine → Telemetry → Swarm feedback loop:
 * 1. Initialize Swarm with InfinitePerfectionEngine
 * 2. Execute Unity Sequence (Order → Harmony)
 * 3. Capture telemetry after first pass
 * 4. Feed metrics back into scheduler
 * 5. Execute second pass with adapted parameters
 * 6. Verify convergence improvement
 */

#include <iostream>
#include <iomanip>
#include <chrono>
#include <cassert>
#include "../src/swarm/SovereignSwarm.hpp"
#include "../src/swarm/InfinitePerfectionTelemetry.hpp"
#include "../infinite/InfinitePerfectionEngine.hpp"

using namespace Sovereign;
using namespace InfinitePerfection;

struct TestResult {
    bool passed;
    std::string message;
    double initialHarmonyIndex;
    double adaptedHarmonyIndex;
    double improvement;
};

class SwarmFeedbackLoopTest {
public:
    TestResult Run() {
        std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║     Swarm Feedback Loop Integration Test                     ║" << std::endl;
        std::cout << "║     Phase B.2 Batch 5/5: Full System Validation              ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;
        std::cout << std::endl;

        // Step 1: Initialize Engine and Swarm
        std::cout << "[STEP 1] Initializing InfinitePerfectionEngine..." << std::endl;
        auto& engine = InfinitePerfectionEngine::GetInstance();
        engine.Initialize();
        assert(engine.IsInitialized() && "Engine should be initialized");
        std::cout << "         ✓ Engine initialized" << std::endl;

        // Create Swarm context with engine
        std::cout << "[STEP 2] Creating SwarmAgentContext..." << std::endl;
        SwarmAgentContext ctx;
        ctx.engine = &engine;
        ctx.infiniteTelemetry = new InfinitePerfectionTelemetry(&engine);
        std::cout << "         ✓ Swarm context created with engine bridge" << std::endl;

        // Create Swarm
        std::cout << "[STEP 3] Creating SovereignSwarm..." << std::endl;
        SovereignSwarm swarm(ctx);
        std::cout << "         ✓ Swarm created" << std::endl;

        // Step 4: First Pass - Execute Unity Sequence
        std::cout << std::endl;
        std::cout << "[PASS 1] Executing Unity Sequence (Order → Harmony)..." << std::endl;
        std::cout << "         Running: Order → Resonance → Amplification → Integration → Convergence → Coherence → Harmony" << std::endl;

        auto result1 = swarm.ExecuteUnitySequence(engine);
        double initialHarmonyIndex = result1.finalHarmonyIndex;

        std::cout << "         ✓ First pass complete" << std::endl;
        std::cout << "         Initial Harmony Index: " << std::fixed << std::setprecision(4) << initialHarmonyIndex << std::endl;

        // Capture telemetry after first pass
        std::cout << "[STEP 5] Capturing telemetry after first pass..." << std::endl;
        auto snapshot1 = ctx.infiniteTelemetry->GetSnapshot();
        std::cout << "         Total cycles executed: " << snapshot1.totalCyclesExecuted << std::endl;
        std::cout << "         Average convergence rate: " << std::setprecision(4) << snapshot1.averageConvergenceRate << std::endl;
        std::cout << "         Converged: " << (snapshot1.unityCycle.isConverged ? "YES" : "NO") << std::endl;

        // Step 6: Adapt scheduler based on metrics
        std::cout << std::endl;
        std::cout << "[STEP 6] Adapting scheduler based on convergence metrics..." << std::endl;

        // Adjust exploration rate based on convergence
        double currentExplorationRate = swarm.GetScheduler().GetExplorationRate();
        if (snapshot1.averageConvergenceRate < 0.8) {
            // Lower exploration to exploit known good paths
            swarm.GetScheduler().SetExplorationRate(0.05);
            std::cout << "         Lowered exploration rate: " << currentExplorationRate << " → 0.05" << std::endl;
        }

        // Enable learned assignment for second pass
        swarm.GetScheduler().SetLearnedAssignmentEnabled(true);
        std::cout << "         Enabled learned task assignment" << std::endl;

        // Step 7: Second Pass - Execute Unity Sequence with adaptations
        std::cout << std::endl;
        std::cout << "[PASS 2] Executing Unity Sequence with adapted parameters..." << std::endl;

        auto result2 = swarm.ExecuteUnitySequence(engine);
        double adaptedHarmonyIndex = result2.finalHarmonyIndex;

        std::cout << "         ✓ Second pass complete" << std::endl;
        std::cout << "         Adapted Harmony Index: " << std::setprecision(4) << adaptedHarmonyIndex << std::endl;

        // Capture telemetry after second pass
        std::cout << "[STEP 8] Capturing telemetry after second pass..." << std::endl;
        auto snapshot2 = ctx.infiniteTelemetry->GetSnapshot();
        std::cout << "         Total cycles executed: " << snapshot2.totalCyclesExecuted << std::endl;
        std::cout << "         Average convergence rate: " << std::setprecision(4) << snapshot2.averageConvergenceRate << std::endl;
        std::cout << "         Converged: " << (snapshot2.unityCycle.isConverged ? "YES" : "NO") << std::endl;

        // Step 9: Validate improvement
        std::cout << std::endl;
        std::cout << "[VALIDATION] Computing feedback loop metrics..." << std::endl;

        double improvement = ((adaptedHarmonyIndex - initialHarmonyIndex) / initialHarmonyIndex) * 100.0;

        std::cout << "         Initial Harmony Index: " << std::setprecision(4) << initialHarmonyIndex << std::endl;
        std::cout << "         Adapted Harmony Index:  " << std::setprecision(4) << adaptedHarmonyIndex << std::endl;
        std::cout << "         Improvement: " << std::setprecision(2) << improvement << "%" << std::endl;

        // Cleanup
        delete ctx.infiniteTelemetry;
        engine.Shutdown();

        // Determine pass/fail
        bool passed = (improvement > 10.0) || (adaptedHarmonyIndex > 0.85);

        std::cout << std::endl;
        std::cout << "╔════════════════════════════════════════════════════════════════╗" << std::endl;
        if (passed) {
            std::cout << "║  TEST PASSED ✓                                                 ║" << std::endl;
        } else {
            std::cout << "║  TEST FAILED ✗                                                 ║" << std::endl;
        }
        std::cout << "╠════════════════════════════════════════════════════════════════╣" << std::endl;
        std::cout << "║  Initial Harmony Index: " << std::setw(10) << std::setprecision(4) << initialHarmonyIndex << "                          ║" << std::endl;
        std::cout << "║  Adapted Harmony Index:  " << std::setw(10) << std::setprecision(4) << adaptedHarmonyIndex << "                          ║" << std::endl;
        std::cout << "║  Improvement:            " << std::setw(10) << std::setprecision(2) << improvement << "%" << "                          ║" << std::endl;
        std::cout << "╚════════════════════════════════════════════════════════════════╝" << std::endl;

        TestResult result;
        result.passed = passed;
        result.initialHarmonyIndex = initialHarmonyIndex;
        result.adaptedHarmonyIndex = adaptedHarmonyIndex;
        result.improvement = improvement;
        result.message = passed ? "Feedback loop validated" : "Insufficient improvement";

        return result;
    }
};

int main() {
    SwarmFeedbackLoopTest test;
    auto result = test.Run();

    return result.passed ? 0 : 1;
}
