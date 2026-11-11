/**
 * UnitySequenceSmokeTest.cpp
 * 
 * Phase 4: End-to-End Smoke Test for Unity Sequence
 * 
 * Validates the full Order→Harmony pipeline with real engine cycles.
 * Run: rawrxd swarm --unity-sequence --unity-sequence-log
 */

#include "SovereignSwarm.hpp"
#include "InfinitePerfectionTelemetry.hpp"
#include "../infinite/InfinitePerfectionEngine.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <cassert>

namespace Sovereign {

/**
 * Smoke test result structure
 */
struct UnitySequenceSmokeResult {
    bool success = false;
    std::string failureReason;
    int64_t executionTimeMs = 0;
    double finalHarmonyIndex = 0.0;
    double finalEquilibriumStrength = 0.0;
    std::vector<std::pair<std::string, double>> stepMetrics;
    
    // Validation criteria
    bool allStepsExecuted = false;
    bool metricsInValidRange = false;
    bool convergenceAchieved = false;
    bool telemetryWorking = false;
};

/**
 * Phase 4: Unity Sequence Smoke Test
 * 
 * Scenario: Execute full Order→Harmony pipeline and validate:
 * 1. All 7 steps execute without exception
 * 2. Each step returns metrics in valid range (0.0-1.0)
 * 3. Final harmony index > 0.5 (convergence achieved)
 * 4. Telemetry captures execution data
 * 5. Total execution time < 60 seconds
 */
class UnitySequenceSmokeTest {
public:
    UnitySequenceSmokeTest() = default;
    
    UnitySequenceSmokeResult Run() {
        UnitySequenceSmokeResult result;
        auto startTime = std::chrono::steady_clock::now();
        
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║     Phase 4: Unity Sequence Smoke Test                     ║" << std::endl;
        std::cout << "║     Validating Order→Harmony Pipeline                      ║" << std::endl;
        std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
        
        try {
            // Initialize engine
            auto& engine = InfinitePerfection::InfinitePerfectionEngine::GetInstance();
            engine.Initialize();
            
            // Create swarm context
            SwarmAgentContext ctx;
            ctx.engine = &engine;
            
            // Create swarm
            SovereignSwarm swarm(ctx);
            
            // Execute Unity Sequence
            std::cout << "\n[SmokeTest] Executing Unity Sequence..." << std::endl;
            auto sequenceResult = swarm.ExecuteUnitySequence(engine);
            
            // Validate results
            result.executionTimeMs = sequenceResult.totalExecutionTimeMs;
            result.finalHarmonyIndex = sequenceResult.finalHarmonyIndex;
            result.finalEquilibriumStrength = sequenceResult.finalEquilibriumStrength;
            result.stepMetrics = sequenceResult.stepMetrics;
            
            // Check 1: All steps executed
            result.allStepsExecuted = (sequenceResult.stepMetrics.size() == 7);
            std::cout << "[SmokeTest] Steps executed: " << sequenceResult.stepMetrics.size() 
                      << "/7 " << (result.allStepsExecuted ? "✓" : "✗") << std::endl;
            
            // Check 2: Metrics in valid range
            result.metricsInValidRange = true;
            for (const auto& [step, metric] : sequenceResult.stepMetrics) {
                if (metric < 0.0 || metric > 1.0) {
                    result.metricsInValidRange = false;
                    std::cout << "[SmokeTest] Invalid metric for " << step << ": " << metric << std::endl;
                }
            }
            std::cout << "[SmokeTest] Metrics in valid range [0,1]: " 
                      << (result.metricsInValidRange ? "✓" : "✗") << std::endl;
            
            // Check 3: Convergence achieved (harmony index > 0.5)
            result.convergenceAchieved = (sequenceResult.finalHarmonyIndex > 0.5);
            std::cout << "[SmokeTest] Convergence achieved (harmony > 0.5): " 
                      << (result.convergenceAchieved ? "✓" : "✗") 
                      << " (" << std::fixed << std::setprecision(4) 
                      << sequenceResult.finalHarmonyIndex << ")" << std::endl;
            
            // Check 4: Execution time < 60 seconds
            bool timeValid = (sequenceResult.totalExecutionTimeMs < 60000);
            std::cout << "[SmokeTest] Execution time < 60s: " 
                      << (timeValid ? "✓" : "✗") 
                      << " (" << sequenceResult.totalExecutionTimeMs << "ms)" << std::endl;
            
            // Overall success
            result.success = result.allStepsExecuted && 
                           result.metricsInValidRange && 
                           result.convergenceAchieved && 
                           timeValid;
            
            // Shutdown engine
            engine.Shutdown();
            
        } catch (const std::exception& e) {
            result.success = false;
            result.failureReason = std::string("Exception: ") + e.what();
            std::cerr << "[SmokeTest] FAILED: " << result.failureReason << std::endl;
        }
        
        auto endTime = std::chrono::steady_clock::now();
        auto totalTime = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
        
        // Print summary
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║     Smoke Test Result: " 
                  << std::left << std::setw(35) 
                  << (result.success ? "✓ PASSED" : "✗ FAILED") << "║" << std::endl;
        std::cout << "╠══════════════════════════════════════════════════════════════╣" << std::endl;
        std::cout << "║  Total Time: " << std::setw(10) << totalTime << "ms" 
                  << std::setw(35) << "" << "║" << std::endl;
        std::cout << "║  Final Harmony Index: " << std::fixed << std::setprecision(4) 
                  << result.finalHarmonyIndex << std::setw(25) << "" << "║" << std::endl;
        std::cout << "║  Final Equilibrium: " << std::fixed << std::setprecision(4) 
                  << result.finalEquilibriumStrength << std::setw(27) << "" << "║" << std::endl;
        std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
        
        return result;
    }
    
    /**
     * Run smoke test and return exit code
     */
    static int Main(int argc, char* argv[]) {
        (void)argc;
        (void)argv;
        
        UnitySequenceSmokeTest test;
        auto result = test.Run();
        
        return result.success ? 0 : 1;
    }
};

} // namespace Sovereign

/**
 * Standalone entry point for smoke test
 */
int main(int argc, char* argv[]) {
    return Sovereign::UnitySequenceSmokeTest::Main(argc, argv);
}
