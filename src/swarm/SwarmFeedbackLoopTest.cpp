/**
 * SwarmFeedbackLoopTest.cpp
 * 
 * Phase B.2 Batch 5/5: Full Feedback Validation
 * 
 * Validates the complete feedback loop:
 * 1. Initialize Swarm
 * 2. Execute Unity Sequence
 * 3. Capture telemetry
 * 4. Evaluate convergence
 * 5. Feed metrics back into scheduler
 * 6. Execute second pass
 * 7. Verify adaptation
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
 * Feedback loop test result
 */
struct FeedbackLoopTestResult {
    bool success = false;
    std::string failureReason;
    
    // Pass 1 metrics
    double pass1HarmonyIndex = 0.0;
    int64_t pass1ExecutionTimeMs = 0;
    
    // Pass 2 metrics
    double pass2HarmonyIndex = 0.0;
    int64_t pass2ExecutionTimeMs = 0;
    
    // Improvement metrics
    double harmonyImprovement = 0.0;  // Percentage improvement
    double timeImprovement = 0.0;     // Percentage improvement
    
    // Validation criteria
    bool pass1Completed = false;
    bool pass2Completed = false;
    bool convergenceImproved = false;
    bool adaptationSuccessful = false;
};

/**
 * Phase B.2 Batch 5/5: Full Feedback Validation Test
 * 
 * Expected outcome:
 * PASS
 * 
 * Initial Harmony Index: 0.71
 * Adaptive Pass Index:    0.93
 * Improvement:            +31%
 */
class SwarmFeedbackLoopTest {
public:
    SwarmFeedbackLoopTest() = default;
    
    FeedbackLoopTestResult Run() {
        FeedbackLoopTestResult result;
        
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║     Phase B.2 Batch 5/5: Full Feedback Validation            ║" << std::endl;
        std::cout << "║     Validating Adaptive Feedback Loop                        ║" << std::endl;
        std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
        
        try {
            // Step 1: Initialize Swarm and Engine
            std::cout << "\n[FeedbackTest] Step 1: Initializing Swarm and Engine..." << std::endl;
            
            auto& engine = InfinitePerfection::InfinitePerfectionEngine::GetInstance();
            engine.Initialize();
            
            SwarmAgentContext ctx;
            ctx.engine = &engine;
            
            SovereignSwarm swarm(ctx);
            
            // Enable learned assignment for adaptive behavior
            swarm.GetScheduler().SetLearnedAssignmentEnabled(true);
            swarm.GetScheduler().SetExplorationRate(0.1);
            
            std::cout << "[FeedbackTest] ✓ Swarm initialized with learned assignment" << std::endl;
            
            // Step 2: Execute Unity Sequence (Pass 1)
            std::cout << "\n[FeedbackTest] Step 2: Executing Unity Sequence (Pass 1)..." << std::endl;
            
            auto pass1Start = std::chrono::steady_clock::now();
            auto pass1Result = swarm.ExecuteUnitySequence(engine);
            auto pass1End = std::chrono::steady_clock::now();
            
            result.pass1HarmonyIndex = pass1Result.finalHarmonyIndex;
            result.pass1ExecutionTimeMs = pass1Result.totalExecutionTimeMs;
            result.pass1Completed = pass1Result.success;
            
            std::cout << "[FeedbackTest] Pass 1 Complete:" << std::endl;
            std::cout << "  - Harmony Index: " << std::fixed << std::setprecision(4) 
                      << result.pass1HarmonyIndex << std::endl;
            std::cout << "  - Execution Time: " << result.pass1ExecutionTimeMs << "ms" << std::endl;
            std::cout << "  - Success: " << (result.pass1Completed ? "✓" : "✗") << std::endl;
            
            // Step 3: Capture telemetry
            std::cout << "\n[FeedbackTest] Step 3: Capturing telemetry..." << std::endl;
            
            InfinitePerfectionTelemetry telemetry(&engine);
            auto snapshot = telemetry.GetSnapshot();
            double convergenceScore = telemetry.GetConvergenceScore();
            bool isConverged = telemetry.IsConverged();
            
            std::cout << "[FeedbackTest] Telemetry captured:" << std::endl;
            std::cout << "  - Convergence Score: " << std::fixed << std::setprecision(4) 
                      << convergenceScore << std::endl;
            std::cout << "  - Converged: " << (isConverged ? "✓ YES" : "✗ NO") << std::endl;
            
            // Step 4: Evaluate convergence
            std::cout << "\n[FeedbackTest] Step 4: Evaluating convergence..." << std::endl;
            
            if (!isConverged) {
                std::cout << "[FeedbackTest] Convergence not achieved, will adapt..." << std::endl;
            }
            
            // Step 5: Feed metrics back into scheduler
            std::cout << "\n[FeedbackTest] Step 5: Feeding metrics back to scheduler..." << std::endl;
            
            // Record performance data for each step
            for (const auto& [step, metric] : pass1Result.stepMetrics) {
                SwarmTaskKind kind = StringToTaskKind(step);
                SelfModelRegistry::GetInstance().RecordTaskSuccess(0, kind, 
                    static_cast<int64_t>(metric * 1000)); // Scale to ms
            }
            
            std::cout << "[FeedbackTest] ✓ Performance data recorded in SelfModelRegistry" << std::endl;
            
            // Adjust exploration rate based on convergence
            if (isConverged) {
                swarm.GetScheduler().SetExplorationRate(0.05); // Lower exploration
                std::cout << "[FeedbackTest] Adjusted: exploration rate -> 5% (converged)" << std::endl;
            } else {
                swarm.GetScheduler().SetExplorationRate(0.15); // Higher exploration
                std::cout << "[FeedbackTest] Adjusted: exploration rate -> 15% (exploring)" << std::endl;
            }
            
            // Step 6: Execute Unity Sequence (Pass 2)
            std::cout << "\n[FeedbackTest] Step 6: Executing Unity Sequence (Pass 2)..." << std::endl;
            std::cout << "[FeedbackTest] (With adapted scheduler based on Pass 1 metrics)" << std::endl;
            
            auto pass2Start = std::chrono::steady_clock::now();
            auto pass2Result = swarm.ExecuteUnitySequence(engine);
            auto pass2End = std::chrono::steady_clock::now();
            
            result.pass2HarmonyIndex = pass2Result.finalHarmonyIndex;
            result.pass2ExecutionTimeMs = pass2Result.totalExecutionTimeMs;
            result.pass2Completed = pass2Result.success;
            
            std::cout << "[FeedbackTest] Pass 2 Complete:" << std::endl;
            std::cout << "  - Harmony Index: " << std::fixed << std::setprecision(4) 
                      << result.pass2HarmonyIndex << std::endl;
            std::cout << "  - Execution Time: " << result.pass2ExecutionTimeMs << "ms" << std::endl;
            std::cout << "  - Success: " << (result.pass2Completed ? "✓" : "✗") << std::endl;
            
            // Step 7: Verify adaptation
            std::cout << "\n[FeedbackTest] Step 7: Verifying adaptation..." << std::endl;
            
            result.harmonyImprovement = ((result.pass2HarmonyIndex - result.pass1HarmonyIndex) 
                                          / result.pass1HarmonyIndex) * 100.0;
            result.timeImprovement = ((result.pass1ExecutionTimeMs - result.pass2ExecutionTimeMs) 
                                       / static_cast<double>(result.pass1ExecutionTimeMs)) * 100.0;
            
            result.convergenceImproved = (result.pass2HarmonyIndex > result.pass1HarmonyIndex);
            result.adaptationSuccessful = result.convergenceImproved || (result.timeImprovement > 0);
            
            std::cout << "[FeedbackTest] Improvement Analysis:" << std::endl;
            std::cout << "  - Harmony Improvement: " << std::showpos << std::fixed 
                      << std::setprecision(1) << result.harmonyImprovement << "%" << std::endl;
            std::cout << "  - Time Improvement: " << std::showpos << std::fixed 
                      << std::setprecision(1) << result.timeImprovement << "%" << std::endl;
            std::cout << "  - Convergence Improved: " << (result.convergenceImproved ? "✓ YES" : "✗ NO") << std::endl;
            std::cout << "  - Adaptation Successful: " << (result.adaptationSuccessful ? "✓ YES" : "✗ NO") << std::endl;
            
            // Overall success criteria
            result.success = result.pass1Completed && result.pass2Completed && result.adaptationSuccessful;
            
            // Shutdown engine
            engine.Shutdown();
            
        } catch (const std::exception& e) {
            result.success = false;
            result.failureReason = std::string("Exception: ") + e.what();
            std::cerr << "[FeedbackTest] FAILED: " << result.failureReason << std::endl;
        }
        
        // Print final summary
        PrintSummary(result);
        
        return result;
    }
    
private:
    SwarmTaskKind StringToTaskKind(const std::string& step) {
        if (step == "Order") return SwarmTaskKind::ComputeOrderTopology;
        if (step == "Resonance") return SwarmTaskKind::AmplifyPatterns;
        if (step == "Amplification") return SwarmTaskKind::ScaleAmplification;
        if (step == "Integration") return SwarmTaskKind::DetectCrossPatterns;
        if (step == "Convergence") return SwarmTaskKind::AlignToSharedGoals;
        if (step == "Coherence") return SwarmTaskKind::SynchronizePhases;
        if (step == "Harmony") return SwarmTaskKind::AchievePerfectUnity;
        return SwarmTaskKind::ScanSubsystem;
    }
    
    void PrintSummary(const FeedbackLoopTestResult& result) {
        std::cout << "\n╔══════════════════════════════════════════════════════════════╗" << std::endl;
        std::cout << "║     Feedback Loop Test Result: " 
                  << std::left << std::setw(35) 
                  << (result.success ? "✓ PASSED" : "✗ FAILED") << "║" << std::endl;
        std::cout << "╠══════════════════════════════════════════════════════════════╣" << std::endl;
        std::cout << "║  Pass 1 Harmony Index: " << std::fixed << std::setprecision(4) 
                  << std::setw(10) << result.pass1HarmonyIndex << std::setw(20) << " ║" << std::endl;
        std::cout << "║  Pass 2 Harmony Index: " << std::fixed << std::setprecision(4) 
                  << std::setw(10) << result.pass2HarmonyIndex << std::setw(20) << " ║" << std::endl;
        std::cout << "║  Improvement: " << std::showpos << std::fixed << std::setprecision(1) 
                  << std::setw(6) << result.harmonyImprovement << "%" 
                  << std::setw(28) << " ║" << std::endl;
        std::cout << "╠══════════════════════════════════════════════════════════════╣" << std::endl;
        std::cout << "║  Pass 1 Time: " << std::setw(10) << result.pass1ExecutionTimeMs 
                  << "ms" << std::setw(25) << " ║" << std::endl;
        std::cout << "║  Pass 2 Time: " << std::setw(10) << result.pass2ExecutionTimeMs 
                  << "ms" << std::setw(25) << " ║" << std::endl;
        std::cout << "║  Time Improvement: " << std::showpos << std::fixed << std::setprecision(1) 
                  << std::setw(6) << result.timeImprovement << "%" 
                  << std::setw(22) << " ║" << std::endl;
        std::cout << "╚══════════════════════════════════════════════════════════════╝" << std::endl;
        
        if (result.success) {
            std::cout << "\n[FeedbackTest] ✓ Feedback loop validated successfully!" << std::endl;
            std::cout << "[FeedbackTest] The Swarm adapts based on telemetry feedback." << std::endl;
        }
    }
};

} // namespace Sovereign

/**
 * Standalone entry point for feedback loop test
 */
int main(int argc, char* argv[]) {
    (void)argc;
    (void)argv;
    
    Sovereign::SwarmFeedbackLoopTest test;
    auto result = test.Run();
    
    return result.success ? 0 : 1;
}
