// ============================================================================
// AgenticPlatformTest.cpp - Complete test harness for the agentic platform
// ============================================================================

#include "../agentic/AgenticReversePlatform.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <thread>
#include <vector>
#include <cstdlib>

using namespace RawrXD::Agentic;

// ============================================================================
// Test utilities
// ============================================================================

struct TestCase {
    std::string name;
    std::function<bool()> test;
    bool passed = false;
    double duration_ms = 0.0;
    std::string error;
};

class TestHarness {
public:
    std::vector<TestCase> tests;
    
    void add(const std::string& name, std::function<bool()> test) {
        tests.push_back({name, std::move(test)});
    }
    
    bool runAll() {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║     Agentic Reverse Platform - Test Suite                            ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n";
        
        size_t passed = 0, failed = 0;
        
        for (auto& test : tests) {
            std::cout << "\n  [" << (test.passed ? "  " : "  ") << "] " << test.name << "... ";
            std::cout.flush();
            
            auto start = std::chrono::high_resolution_clock::now();
            try {
                test.passed = test.test();
            } catch (const std::exception& e) {
                test.passed = false;
                test.error = e.what();
            } catch (...) {
                test.passed = false;
                test.error = "Unknown exception";
            }
            auto end = std::chrono::high_resolution_clock::now();
            test.duration_ms = std::chrono::duration<double, std::milli>(end - start).count();
            
            if (test.passed) {
                std::cout << "\r  [✓] " << test.name << " (" << std::fixed << std::setprecision(1) 
                          << test.duration_ms << "ms)\n";
                passed++;
            } else {
                std::cout << "\r  [✗] " << test.name << " (" << std::fixed << std::setprecision(1) 
                          << test.duration_ms << "ms)\n";
                if (!test.error.empty()) {
                    std::cout << "       Error: " << test.error << "\n";
                }
                failed++;
            }
        }
        
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║     Test Summary                                                     ║\n";
        std::cout << "╠══════════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Total: " << std::setw(4) << tests.size() << "  Passed: " << std::setw(4) << passed 
                  << "  Failed: " << std::setw(4) << failed << "                    ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n";
        
        return failed == 0;
    }
};

// ============================================================================
// Test: Platform Initialization
// ============================================================================

bool testPlatformInitialization() {
    AgenticReversePlatform platform;
    platform.initializeDefaultSwarm(1);
    return platform.isInitialized() && platform.getOrchestrator()->agentCount() > 0;
}

// ============================================================================
// Test: Tool Registration
// ============================================================================

bool testToolRegistration() {
    AgenticReversePlatform platform;
    platform.initializeDefaultSwarm(1);
    auto tools = platform.getToolRegistry();
    return tools->toolCount() >= 5; // At least 5 default tools
}

// ============================================================================
// Test: Tool Execution
// ============================================================================

bool testToolExecution() {
    AgenticReversePlatform platform;
    platform.initializeDefaultSwarm(1);
    auto tools = platform.getToolRegistry();
    
    // Test entropy tool
    auto result = tools->execute(ToolCapability::CALCULATE_ENTROPY, {{"data", "AABBCCDD"}});
    if (!result.success) return false;
    
    // Test pattern generation
    result = tools->execute(ToolCapability::GENERATE_PATTERNS, {{"data", "AABB"}});
    if (!result.success) return false;
    
    // Test pattern comparison
    result = tools->execute(ToolCapability::COMPARE_PATTERNS, 
        {{"pattern_a", "AABB"}, {"pattern_b", "AACC"}});
    if (!result.success) return false;
    
    return true;
}

// ============================================================================
// Test: Blackboard Operations
// ============================================================================

bool testBlackboard() {
    auto blackboard = std::make_shared<Blackboard>();
    
    // Post entry
    BlackboardEntry entry;
    entry.region_address = 0x401000;
    entry.region_size = 256;
    entry.entropy = 6.5;
    entry.status = "analyzed";
    entry.updated_by_agent = "test";
    blackboard->postEntry(entry);
    
    // Read entry
    auto read = blackboard->getEntry(0x401000);
    if (!read.has_value()) return false;
    if (read->entropy != 6.5) return false;
    
    // Update entry
    blackboard->updateEntry(0x401000, "confidence", "0.85");
    read = blackboard->getEntry(0x401000);
    if (!read.has_value() || read->confidence != 0.85) return false;
    
    // Find high entropy
    auto high = blackboard->findHighEntropy(5.0);
    if (high.size() != 1) return false;
    
    // Subscribe
    bool notified = false;
    auto sub = blackboard->subscribe([&](const BlackboardEntry&) { notified = true; });
    
    BlackboardEntry entry2;
    entry2.region_address = 0x402000;
    blackboard->postEntry(entry2);
    
    if (!notified) return false;
    
    return true;
}

// ============================================================================
// Test: Knowledge Graph
// ============================================================================

bool testKnowledgeGraph() {
    auto kg = std::make_shared<KnowledgeGraph>();
    
    // Add facts
    kg->addFact("compiler_signatures", "msvc_2019", "0x55 0x8B 0xEC", 0.9);
    kg->addFact("packers", "upx", "UPX signature", 0.95);
    kg->addFact("malware_families", "emotet", "Emotet loader pattern", 0.8);
    
    // Query
    auto result = kg->query("compiler_signatures", "msvc_2019");
    if (!result.has_value()) return false;
    if (result->confidence != 0.9) return false;
    
    // Search
    auto search_results = kg->search("UPX");
    if (search_results.empty()) return false;
    
    // Verify
    kg->verifyEntry("compiler_signatures", "msvc_2019");
    result = kg->query("compiler_signatures", "msvc_2019");
    if (!result->verified) return false;
    
    // Stats
    auto stats = kg->getStats();
    if (stats.total_entries != 3) return false;
    
    return true;
}

// ============================================================================
// Test: Agent Creation and Capabilities
// ============================================================================

bool testAgentCreation() {
    auto tools = std::make_shared<ToolRegistry>();
    auto blackboard = std::make_shared<Blackboard>();
    auto knowledge = std::make_shared<KnowledgeGraph>();
    
    // Register tools
    tools->registerTool(std::make_shared<EntropyTool>());
    tools->registerTool(std::make_shared<PatternGenTool>());
    
    // Create agents
    AgentID scout_id{"Scout", AgentRole::SCOUT, 0};
    auto scout = std::make_shared<ScoutAgent>(scout_id, tools, blackboard, knowledge);
    
    AgentID pattern_id{"Pattern", AgentRole::PATTERN, 0};
    auto pattern = std::make_shared<PatternAgent>(pattern_id, tools, blackboard, knowledge);
    
    // Check capabilities
    if (!scout->canHandle(ToolCapability::CALCULATE_ENTROPY)) return false;
    if (!pattern->canHandle(ToolCapability::GENERATE_PATTERNS)) return false;
    if (scout->canHandle(ToolCapability::GENERATE_PATTERNS)) return false; // Scout shouldn't have this
    
    return true;
}

// ============================================================================
// Test: Agent Reasoning Cycle
// ============================================================================

bool testAgentReasoning() {
    auto tools = std::make_shared<ToolRegistry>();
    auto blackboard = std::make_shared<Blackboard>();
    auto knowledge = std::make_shared<KnowledgeGraph>();
    
    tools->registerTool(std::make_shared<EntropyTool>());
    tools->registerTool(std::make_shared<PatternGenTool>());
    
    // Post a blackboard entry to trigger the agent
    BlackboardEntry entry;
    entry.region_address = 0x401000;
    entry.region_size = 256;
    entry.entropy = 0.0; // Unexplored - scout should act
    entry.status = "unexplored";
    blackboard->postEntry(entry);
    
    // Create scout agent
    AgentID scout_id{"Scout", AgentRole::SCOUT, 0};
    auto scout = std::make_shared<ScoutAgent>(scout_id, tools, blackboard, knowledge);
    
    // Set goal
    AgentGoal goal;
    goal.description = "Explore binary regions";
    goal.required_tools = {ToolCapability::CALCULATE_ENTROPY};
    scout->setGoal(goal);
    
    // Run reasoning cycle
    auto result = scout->thinkAndAct();
    
    // Agent should have observed the blackboard entry and made a decision
    return scout->getObservations().size() > 0;
}

// ============================================================================
// Test: Mission Orchestration
// ============================================================================

bool testMissionOrchestration() {
    auto tools = std::make_shared<ToolRegistry>();
    auto blackboard = std::make_shared<Blackboard>();
    auto knowledge = std::make_shared<KnowledgeGraph>();
    
    tools->registerTool(std::make_shared<EntropyTool>());
    tools->registerTool(std::make_shared<PatternGenTool>());
    tools->registerTool(std::make_shared<PatternCompareTool>());
    tools->registerTool(std::make_shared<ValidationTool>());
    tools->registerTool(std::make_shared<ExportTool>());
    tools->registerTool(std::make_shared<OptimizerTool>());
    tools->registerTool(std::make_shared<MergeResultsTool>());
    tools->registerTool(std::make_shared<KnowledgeQueryTool>());
    
    MissionOrchestrator orchestrator(tools, blackboard, knowledge);
    orchestrator.createDefaultSwarm(1);
    
    // Execute a mission
    auto mission = orchestrator.executeMission("Test mission", {}, std::chrono::seconds(30));
    
    return mission.is_complete;
}

// ============================================================================
// Test: Self-Improvement
// ============================================================================

bool testSelfImprovement() {
    auto knowledge = std::make_shared<KnowledgeGraph>();
    SelfImprovement si(knowledge);
    
    // Create a mission
    Mission mission;
    mission.id = "test_mission_1";
    mission.description = "Test mission for evaluation";
    mission.is_complete = true;
    mission.is_successful = true;
    
    // Create agent results
    std::vector<AgentResult> results;
    
    AgentResult r1; r1.success = true; r1.confidence = 0.9; r1.summary = "Pattern found";
    AgentResult r2; r2.success = true; r2.confidence = 0.3; r2.summary = "Low confidence match";
    AgentResult r3; r3.success = false; r3.confidence = 0.0; r3.summary = "Failed analysis";
    
    results.push_back(r1);
    results.push_back(r2);
    results.push_back(r3);
    
    // Evaluate
    auto eval = si.evaluateMission(mission, results);
    
    // Should detect low confidence and disagreements
    if (eval.overall_confidence < 0.3 || eval.overall_confidence > 0.6) return false;
    
    // Should generate recommendations
    if (eval.recommendations.empty()) return false;
    
    // Generate verification tasks
    auto tasks = si.generateVerificationTasks(eval);
    if (tasks.empty()) return false;
    
    // Retrain
    si.retrainWeights(eval);
    
    return true;
}

// ============================================================================
// Test: Full Platform Integration
// ============================================================================

bool testFullPlatform() {
    AgenticReversePlatform platform;
    platform.initializeDefaultSwarm(1);
    
    // Create test binary
    std::vector<uint8_t> test_binary = {
        0x55, 0x8B, 0xEC, 0x6A, 0x00, 0xFF, 0x15, 0x5D, 0xC3,
        0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x6A, 0x00,
        0x55, 0x8B, 0xEC, 0x6A, 0x01, 0x6A, 0x00, 0xFF, 0x15,
        0x5D, 0xC3, 0x90, 0x90, 0x90,
    };
    
    // Add knowledge
    platform.addKnowledge("compiler_signatures", "msvc_prologue", "0x55 0x8B 0xEC", 0.9);
    platform.addKnowledge("pattern_signatures", "test_pattern", "x86 prologue", 0.85);
    
    // Analyze
    platform.analyzeBinary(test_binary, "test_binary");
    
    // Export knowledge
    platform.exportKnowledge("output/knowledge_export.txt");
    
    // Print status
    platform.printStatus();
    
    return true;
}

// ============================================================================
// Test: Agent Swarm Diversity
// ============================================================================

bool testSwarmDiversity() {
    AgenticReversePlatform platform;
    platform.initializeDefaultSwarm(2); // 2 agents per role
    
    auto stats = platform.getOrchestrator()->getSwarmStats();
    
    // Should have 13 roles * 2 = 26 agents
    if (stats.total_agents < 13) return false;
    
    // Should have multiple roles
    if (stats.role_counts.size() < 10) return false;
    
    return true;
}

// ============================================================================
// Test: Tool Discovery
// ============================================================================

bool testToolDiscovery() {
    AgenticReversePlatform platform;
    platform.initializeDefaultSwarm(1);
    
    auto tools = platform.getToolRegistry();
    auto all_tools = tools->listAllTools();
    
    // Each tool should have a name and description
    for (const auto& tool : all_tools) {
        if (tool->getName().empty()) return false;
        if (tool->getDescription().empty()) return false;
    }
    
    // Should be able to find tools by capability
    auto entropy_tool = tools->getTool(ToolCapability::CALCULATE_ENTROPY);
    if (!entropy_tool) return false;
    
    auto pattern_tool = tools->getTool(ToolCapability::GENERATE_PATTERNS);
    if (!pattern_tool) return false;
    
    return true;
}

// ============================================================================
// Main
// ============================================================================

int main() {
    TestHarness harness;
    
    // Register all tests
    harness.add("Platform Initialization", testPlatformInitialization);
    harness.add("Tool Registration", testToolRegistration);
    harness.add("Tool Execution", testToolExecution);
    harness.add("Blackboard Operations", testBlackboard);
    harness.add("Knowledge Graph", testKnowledgeGraph);
    harness.add("Agent Creation and Capabilities", testAgentCreation);
    harness.add("Agent Reasoning Cycle", testAgentReasoning);
    harness.add("Mission Orchestration", testMissionOrchestration);
    harness.add("Self-Improvement", testSelfImprovement);
    harness.add("Full Platform Integration", testFullPlatform);
    harness.add("Swarm Diversity", testSwarmDiversity);
    harness.add("Tool Discovery", testToolDiscovery);
    
    // Run all tests
    bool all_passed = harness.runAll();
    
    return all_passed ? 0 : 1;
}
