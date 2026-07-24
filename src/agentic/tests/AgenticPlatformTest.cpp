// ============================================================================
// AgenticPlatformTest.cpp - Comprehensive test of the autonomous agentic platform
// ============================================================================

#include "../AgenticReversePlatform.hpp"
#include "../AgentTypes.hpp"
#include "../BaseAgent.hpp"
#include "../MissionOrchestrator.hpp"
#include "../Blackboard.hpp"
#include "../KnowledgeGraph.hpp"
#include "../ToolRegistry.hpp"
#include "../SelfImprovement.hpp"
#include <iostream>
#include <iomanip>
#include <chrono>
#include <vector>
#include <string>

using namespace RawrXD::Agentic;

// Test utilities
struct TestResult {
    std::string name;
    bool passed;
    std::string message;
    double duration_ms;
};

class TestRunner {
public:
    std::vector<TestResult> results;
    
    void run(const std::string& name, std::function<bool()> test) {
        auto start = std::chrono::high_resolution_clock::now();
        bool passed = false;
        std::string message;
        
        try {
            passed = test();
            message = passed ? "OK" : "FAILED";
        } catch (const std::exception& e) {
            message = std::string("EXCEPTION: ") + e.what();
        } catch (...) {
            message = "UNKNOWN EXCEPTION";
        }
        
        auto end = std::chrono::high_resolution_clock::now();
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        
        results.push_back({name, passed, message, duration});
    }
    
    void printSummary() {
        std::cout << "\n" << std::string(70, '=') << "\n";
        std::cout << "TEST SUMMARY\n";
        std::cout << std::string(70, '=') << "\n";
        
        size_t passed = 0, failed = 0;
        double total_time = 0.0;
        
        for (const auto& r : results) {
            std::cout << (r.passed ? "[PASS]" : "[FAIL]") << " " 
                      << std::left << std::setw(40) << r.name
                      << " " << std::right << std::setw(8) << std::fixed << std::setprecision(2) 
                      << r.duration_ms << "ms"
                      << " - " << r.message << "\n";
            
            if (r.passed) passed++;
            else failed++;
            total_time += r.duration_ms;
        }
        
        std::cout << std::string(70, '-') << "\n";
        std::cout << "Total: " << results.size() << " | Passed: " << passed 
                  << " | Failed: " << failed << " | Time: " << total_time << "ms\n";
        std::cout << std::string(70, '=') << "\n";
    }
};

// ============================================================================
// TEST CASES
// ============================================================================

int main() {
    std::cout << "\n";
    std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║     Agentic Reverse Engineering Platform Test Suite v1.0           ║\n";
    std::cout << "║     Autonomous Multi-Agent System with Self-Improvement          ║\n";
    std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n\n";
    
    TestRunner runner;
    
    // Test 1: Platform initialization
    runner.run("Platform Initialization", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        return platform.isInitialized();
    });
    
    // Test 2: Tool registry
    runner.run("Tool Registry", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        auto tools = platform.getToolRegistry();
        return tools && tools->toolCount() >= 8;
    });
    
    // Test 3: Blackboard
    runner.run("Blackboard Operations", []() {
        Blackboard bb;
        BlackboardEntry entry;
        entry.region_address = 0x401000;
        entry.region_size = 4096;
        entry.entropy = 5.5;
        entry.status = "analyzed";
        entry.last_updated = std::chrono::steady_clock::now();
        entry.updated_by_agent = "test";
        
        bb.postEntry(entry);
        
        auto retrieved = bb.getEntry(0x401000);
        return retrieved.has_value() && retrieved->entropy == 5.5;
    });
    
    // Test 4: Knowledge graph
    runner.run("Knowledge Graph", []() {
        KnowledgeGraph kg;
        kg.addFact("compiler_signatures", "msvc_2022", "Known MSVC 2022 signature", 0.9);
        
        auto result = kg.query("compiler_signatures", "msvc_2022");
        return result.has_value() && result->confidence == 0.9;
    });
    
    // Test 5: Agent creation
    runner.run("Agent Creation", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        auto orchestrator = platform.getOrchestrator();
        return orchestrator && orchestrator->agentCount() >= 13;
    });
    
    // Test 6: Mission execution
    runner.run("Mission Execution", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        
        auto mission = platform.executeMission("Test mission: analyze binary");
        return mission.is_complete;
    });
    
    // Test 7: Binary analysis
    runner.run("Binary Analysis", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        
        std::vector<uint8_t> test_data = {
            0x55, 0x8B, 0xEC, 0x6A, 0x00, 0xFF, 0x15, 0x5D, 0xC3,
            0x55, 0x8B, 0xEC, 0x83, 0xEC, 0x20, 0x6A, 0x00,
            0x55, 0x8B, 0xEC, 0x6A, 0x01, 0x6A, 0x00, 0xFF, 0x15,
            0x5D, 0xC3, 0x90, 0x90, 0x90,
        };
        
        platform.analyzeBinary(test_data, "test_binary");
        
        auto bb = platform.getBlackboard();
        return bb && bb->entryCount() > 0;
    });
    
    // Test 8: Knowledge export
    runner.run("Knowledge Export", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        
        platform.addKnowledge("test_category", "test_key", "test_value", 0.8);
        
        std::string test_path = "d:/__test_knowledge.json";
        platform.exportKnowledge(test_path);
        
        // Check file exists
        std::ifstream file(test_path);
        bool exists = file.good();
        file.close();
        return exists;
    });
    
    // Test 9: Swarm statistics
    runner.run("Swarm Statistics", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(2);
        
        auto orchestrator = platform.getOrchestrator();
        auto stats = orchestrator->getSwarmStats();
        
        return stats.total_agents >= 26 && stats.role_counts.size() >= 10;
    });
    
    // Test 10: Self-improvement
    runner.run("Self-Improvement", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        
        auto si = platform.getSelfImprovement();
        return si != nullptr;
    });
    
    // Test 11: Continuous operation
    runner.run("Continuous Operation", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        
        auto start = std::chrono::steady_clock::now();
        platform.runContinuous(std::chrono::seconds(1));
        auto end = std::chrono::steady_clock::now();
        
        auto duration = std::chrono::duration_cast<std::chrono::seconds>(end - start).count();
        return duration >= 1;
    });
    
    // Test 12: Pattern generation tool
    runner.run("Pattern Generation Tool", []() {
        ToolRegistry registry;
        registry.registerTool(std::make_shared<PatternGenTool>());
        
        std::unordered_map<std::string, std::string> params;
        params["data"] = "55AA";
        params["types"] = "inverse";
        
        auto result = registry.execute(ToolCapability::GENERATE_PATTERNS, params);
        return result.success && !result.data.empty();
    });
    
    // Test 13: Entropy calculation tool
    runner.run("Entropy Calculation Tool", []() {
        ToolRegistry registry;
        registry.registerTool(std::make_shared<EntropyTool>());
        
        std::unordered_map<std::string, std::string> params;
        params["data"] = "55AA55AA55AA55AA";
        
        auto result = registry.execute(ToolCapability::CALCULATE_ENTROPY, params);
        return result.success && result.metadata.count("entropy");
    });
    
    // Test 14: Agent decision making
    runner.run("Agent Decision Making", []() {
        auto tools = std::make_shared<ToolRegistry>();
        auto bb = std::make_shared<Blackboard>();
        auto kg = std::make_shared<KnowledgeGraph>();
        
        AgentID id;
        id.name = "TestScout";
        id.role = AgentRole::SCOUT;
        id.instance_id = 0;
        
        ScoutAgent scout(id, tools, bb, kg);
        
        AgentGoal goal;
        goal.description = "Find interesting regions";
        scout.setGoal(goal);
        
        auto result = scout.thinkAndAct();
        return result.success;
    });
    
    // Test 15: Blackboard subscription
    runner.run("Blackboard Subscription", []() {
        Blackboard bb;
        
        int notification_count = 0;
        bb.subscribe([&](const BlackboardEntry& entry) {
            notification_count++;
        });
        
        BlackboardEntry entry1;
        entry1.region_address = 0x1000;
        entry1.status = "analyzed";
        bb.postEntry(entry1);
        
        BlackboardEntry entry2;
        entry2.region_address = 0x2000;
        entry2.status = "analyzed";
        bb.postEntry(entry2);
        
        return notification_count >= 2;
    });
    
    // Test 16: Knowledge search
    runner.run("Knowledge Search", []() {
        KnowledgeGraph kg;
        kg.addFact("malware_families", "emotet", "Banking trojan", 0.9);
        kg.addFact("malware_families", "trickbot", "Banking trojan", 0.85);
        kg.addFact("packers", "upx", "Common packer", 0.95);
        
        auto results = kg.search("banking");
        return results.size() >= 2;
    });
    
    // Test 17: Mission planner
    runner.run("Mission Planner", []() {
        auto tools = std::make_shared<ToolRegistry>();
        auto bb = std::make_shared<Blackboard>();
        auto kg = std::make_shared<KnowledgeGraph>();
        
        AgentID planner_id;
        planner_id.name = "Planner";
        planner_id.role = AgentRole::PLANNER;
        planner_id.instance_id = 0;
        
        PlannerAgent planner(planner_id, tools, bb, kg);
        
        Mission mission;
        mission.id = "test_mission";
        mission.description = "Test mission";
        
        std::vector<std::shared_ptr<BaseAgent>> agents;
        auto plan = planner.buildPlan(mission, agents);
        
        return plan.steps.size() >= 7;
    });
    
    // Test 18: Platform status report
    runner.run("Platform Status Report", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        
        // Capture cout
        std::stringstream buffer;
        auto old = std::cout.rdbuf(buffer.rdbuf());
        
        platform.printStatus();
        
        std::cout.rdbuf(old);
        std::string output = buffer.str();
        
        return output.find("Platform Status Report") != std::string::npos;
    });
    
    // Test 19: Large binary analysis
    runner.run("Large Binary Analysis", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(1);
        
        std::vector<uint8_t> large_data(1024 * 1024);
        for (size_t i = 0; i < large_data.size(); ++i) {
            large_data[i] = (i % 137 == 0) ? 0x55 : static_cast<uint8_t>(i % 256);
        }
        
        auto start = std::chrono::high_resolution_clock::now();
        platform.analyzeBinary(large_data, "large_binary");
        auto end = std::chrono::high_resolution_clock::now();
        
        double duration = std::chrono::duration<double, std::milli>(end - start).count();
        std::cout << "\n      Processed 1MB in " << std::fixed << std::setprecision(2) << duration << "ms";
        
        return duration < 10000.0; // Should complete in under 10 seconds
    });
    
    // Test 20: Full pipeline integration
    runner.run("Full Pipeline Integration", []() {
        AgenticReversePlatform platform;
        platform.initializeDefaultSwarm(2);
        
        // Add knowledge
        platform.addKnowledge("compiler_signatures", "msvc", "Microsoft Visual C++", 0.9);
        platform.addKnowledge("packers", "upx", "UPX packer", 0.95);
        
        // Analyze binary
        std::vector<uint8_t> test_data(4096);
        for (size_t i = 0; i < test_data.size(); ++i) {
            test_data[i] = static_cast<uint8_t>((i * 7 + 13) % 256);
        }
        
        platform.analyzeBinary(test_data, "integration_test");
        
        // Check results
        auto bb = platform.getBlackboard();
        auto kg = platform.getKnowledgeGraph();
        auto orchestrator = platform.getOrchestrator();
        
        bool bb_ok = bb && bb->entryCount() > 0;
        bool kg_ok = kg && kg->getStats().total_entries > 0;
        bool swarm_ok = orchestrator && orchestrator->agentCount() > 0;
        
        return bb_ok && kg_ok && swarm_ok;
    });
    
    // Print summary
    runner.printSummary();
    
    // Calculate pass rate
    size_t passed = 0;
    for (const auto& r : runner.results) {
        if (r.passed) passed++;
    }
    
    std::cout << "\n";
    if (passed == runner.results.size()) {
        std::cout << "✓ ALL TESTS PASSED! Agentic Platform is fully operational.\n";
        return 0;
    } else {
        std::cout << "✗ Some tests failed. Review output above.\n";
        return 1;
    }
}
