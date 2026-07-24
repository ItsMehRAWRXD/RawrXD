// ============================================================================
// test_blocking_agent.cpp - Test the BlockingAgent functionality
// ============================================================================

#include "BlockingAgent.hpp"
#include <iostream>
#include <vector>
#include <string>

using namespace RawrXD::Executive;

int main() {
    std::cout << "=================================================================" << std::endl;
    std::cout << "BlockingAgent Test - Priority-Based Goal Blocking Evaluation" << std::endl;
    std::cout << "=================================================================" << std::endl;
    std::cout << std::endl;
    
    // Create and initialize the BlockingAgent
    BlockingAgent agent;
    if (!agent.Initialize(nullptr)) {
        std::cerr << "Failed to initialize BlockingAgent" << std::endl;
        return 1;
    }
    
    std::cout << "✓ BlockingAgent initialized" << std::endl;
    std::cout << "  Critical threshold: " << agent.GetCriticalThreshold() << std::endl;
    std::cout << "  High threshold: " << agent.GetHighThreshold() << std::endl;
    std::cout << std::endl;
    
    // Register goals with dependencies
    // Goal A (Critical) depends on Goal B (High)
    // Goal B (High) depends on Goal C (Medium)
    // Goal D (Critical) depends on Goal C (Medium)
    // Goal E (Low) depends on nothing
    
    std::cout << "Registering goals..." << std::endl;
    
    // Goal C (Medium) - base goal
    agent.RegisterGoal("goal_c", 1, {});  // Medium priority
    std::cout << "  ✓ Goal C (Medium, no deps)" << std::endl;
    
    // Goal B (High) - depends on C
    agent.RegisterGoal("goal_b", 2, {"goal_c"});  // High priority
    agent.AddDependency("goal_b", "goal_c");
    std::cout << "  ✓ Goal B (High, depends on C)" << std::endl;
    
    // Goal A (Critical) - depends on B
    agent.RegisterGoal("goal_a", 3, {"goal_b"});  // Critical priority
    agent.AddDependency("goal_a", "goal_b");
    std::cout << "  ✓ Goal A (Critical, depends on B)" << std::endl;
    
    // Goal D (Critical) - depends on C
    agent.RegisterGoal("goal_d", 3, {"goal_c"});  // Critical priority
    agent.AddDependency("goal_d", "goal_c");
    std::cout << "  ✓ Goal D (Critical, depends on C)" << std::endl;
    
    // Goal E (Low) - no dependencies
    agent.RegisterGoal("goal_e", 0, {});  // Low priority
    std::cout << "  ✓ Goal E (Low, no deps)" << std::endl;
    
    std::cout << std::endl;
    std::cout << "Dependency graph: " << agent.GetRegisteredGoalCount() << " goals, " 
              << agent.GetDependencyEdgeCount() << " edges" << std::endl;
    std::cout << std::endl;
    
    // Test 1: Evaluate blocking for Goal C
    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Test 1: Evaluate blocking for Goal C (Medium)" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;
    
    BlockingEvaluation evalC = agent.EvaluateBlocking("goal_c");
    std::cout << "  Is blocking: " << (evalC.isBlocking ? "YES" : "NO") << std::endl;
    std::cout << "  Blocked Critical: " << evalC.blockedCriticalCount << std::endl;
    std::cout << "  Blocked High: " << evalC.blockedHighCount << std::endl;
    std::cout << "  Total blocked: " << evalC.blockedGoalIds.size() << std::endl;
    std::cout << "  Blocking score: " << evalC.blockingScore << std::endl;
    std::cout << "  Recommendation: " << evalC.recommendation << std::endl;
    std::cout << "  Blocked goals: ";
    for (const auto& id : evalC.blockedGoalIds) {
        std::cout << id << " ";
    }
    std::cout << std::endl;
    std::cout << std::endl;
    
    // Test 2: Evaluate blocking for Goal B
    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Test 2: Evaluate blocking for Goal B (High)" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;
    
    BlockingEvaluation evalB = agent.EvaluateBlocking("goal_b");
    std::cout << "  Is blocking: " << (evalB.isBlocking ? "YES" : "NO") << std::endl;
    std::cout << "  Blocked Critical: " << evalB.blockedCriticalCount << std::endl;
    std::cout << "  Blocked High: " << evalB.blockedHighCount << std::endl;
    std::cout << "  Total blocked: " << evalB.blockedGoalIds.size() << std::endl;
    std::cout << "  Blocking score: " << evalB.blockingScore << std::endl;
    std::cout << "  Recommendation: " << evalB.recommendation << std::endl;
    std::cout << std::endl;
    
    // Test 3: Evaluate blocking for Goal E
    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Test 3: Evaluate blocking for Goal E (Low, no deps)" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;
    
    BlockingEvaluation evalE = agent.EvaluateBlocking("goal_e");
    std::cout << "  Is blocking: " << (evalE.isBlocking ? "YES" : "NO") << std::endl;
    std::cout << "  Blocked Critical: " << evalE.blockedCriticalCount << std::endl;
    std::cout << "  Blocked High: " << evalE.blockedHighCount << std::endl;
    std::cout << "  Total blocked: " << evalE.blockedGoalIds.size() << std::endl;
    std::cout << "  Blocking score: " << evalE.blockingScore << std::endl;
    std::cout << "  Recommendation: " << evalE.recommendation << std::endl;
    std::cout << std::endl;
    
    // Test 4: Priority voting
    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Test 4: Priority Voting" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;
    
    std::vector<std::string> goals = {"goal_a", "goal_b", "goal_c", "goal_d", "goal_e"};
    for (const auto& goalId : goals) {
        PriorityVote vote = agent.VoteOnPriority(goalId);
        std::cout << "  " << goalId << ": priority=" << vote.priority 
                  << ", confidence=" << vote.confidence 
                  << ", reason=" << vote.reason << std::endl;
    }
    std::cout << std::endl;
    
    // Test 5: Find critical blockers
    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Test 5: Find Critical Blockers" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;
    
    std::vector<std::string> criticalBlockers = agent.FindCriticalBlockers(2);
    std::cout << "  Critical blockers found: " << criticalBlockers.size() << std::endl;
    for (const auto& blocker : criticalBlockers) {
        std::cout << "    - " << blocker << std::endl;
    }
    std::cout << std::endl;
    
    // Test 6: Suggest execution order
    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Test 6: Suggested Execution Order" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;
    
    std::vector<std::string> executionOrder = agent.SuggestExecutionOrder(goals);
    std::cout << "  Execution order (highest blocking first):" << std::endl;
    for (size_t i = 0; i < executionOrder.size(); ++i) {
        std::cout << "    " << (i + 1) << ". " << executionOrder[i] << std::endl;
    }
    std::cout << std::endl;
    
    // Test 7: Dependency chain queries
    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Test 7: Dependency Chain Queries" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;
    
    std::cout << "  Goal A depends on: ";
    std::vector<std::string> depsA = agent.GetDependencyChain("goal_a");
    for (const auto& dep : depsA) {
        std::cout << dep << " ";
    }
    std::cout << std::endl;
    
    std::cout << "  Goal C is depended on by: ";
    std::vector<std::string> dependentsC = agent.GetDependentChain("goal_c");
    for (const auto& dep : dependentsC) {
        std::cout << dep << " ";
    }
    std::cout << std::endl;
    std::cout << std::endl;
    
    // Test 8: Cycle detection
    std::cout << "-----------------------------------------------------------------" << std::endl;
    std::cout << "Test 8: Cycle Detection" << std::endl;
    std::cout << "-----------------------------------------------------------------" << std::endl;
    
    bool wouldCreateCycle = agent.WouldCreateCycle("goal_c", "goal_a");
    std::cout << "  Would adding C -> A create cycle? " << (wouldCreateCycle ? "YES" : "NO") << std::endl;
    
    bool wouldCreateCycle2 = agent.WouldCreateCycle("goal_e", "goal_c");
    std::cout << "  Would adding E -> C create cycle? " << (wouldCreateCycle2 ? "YES" : "NO") << std::endl;
    std::cout << std::endl;
    
    // Shutdown
    agent.Shutdown();
    std::cout << "✓ BlockingAgent shutdown complete" << std::endl;
    std::cout << std::endl;
    
    std::cout << "=================================================================" << std::endl;
    std::cout << "All tests completed successfully!" << std::endl;
    std::cout << "=================================================================" << std::endl;
    
    return 0;
}
