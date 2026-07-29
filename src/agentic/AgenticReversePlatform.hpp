// ============================================================================
// AgenticReversePlatform.hpp - Top-level autonomous reverse-engineering platform
// ============================================================================
#pragma once

#include "AgentTypes.hpp"
#include "ToolRegistry.hpp"
#include "Blackboard.hpp"
#include "KnowledgeGraph.hpp"
#include "BaseAgent.hpp"
#include "MissionOrchestrator.hpp"
#include "SelfImprovement.hpp"
#include <memory>
#include <iostream>
#include <sstream>
#include <iomanip>
#include <thread>

namespace RawrXD::Agentic {

// ============================================================================
// AgenticReversePlatform - the complete autonomous reverse-engineering system
// ============================================================================

class AgenticReversePlatform {
public:
    AgenticReversePlatform() {
        // Create shared components
        tools_ = std::make_shared<ToolRegistry>();
        blackboard_ = std::make_shared<Blackboard>();
        knowledge_ = std::make_shared<KnowledgeGraph>();
        
        // Register default tools
        registerDefaultTools();
        
        // Create orchestrator
        orchestrator_ = std::make_shared<MissionOrchestrator>(tools_, blackboard_, knowledge_);
        
        // Create self-improvement
        self_improvement_ = std::make_shared<SelfImprovement>(knowledge_);
        
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║     Agentic Reverse Engineering Platform v1.0                        ║\n";
        std::cout << "║     Autonomous Multi-Agent System with Self-Improvement              ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n";
        std::cout << "\n";
    }

    ~AgenticReversePlatform() = default;

    // === Initialization ===

    // Initialize with default agent swarm
    void initializeDefaultSwarm(size_t agents_per_role = 1) {
        orchestrator_->createDefaultSwarm(agents_per_role);
        initialized_ = true;
        
        std::cout << "[Platform] Initialized with " << orchestrator_->agentCount() << " agents\n";
    }

    // Register a custom agent
    void registerAgent(std::shared_ptr<BaseAgent> agent) {
        orchestrator_->registerAgent(agent);
    }

    // === Mission Execution ===

    // Execute a single mission
    Mission executeMission(const std::string& description,
                           std::chrono::seconds deadline = std::chrono::seconds(300)) {
        if (!initialized_) {
            std::cerr << "[Platform] Not initialized - call initializeDefaultSwarm() first\n";
            return Mission{};
        }
        
        return orchestrator_->executeMission(description, {}, deadline);
    }

    // Run continuous operation
    void runContinuous(std::chrono::seconds duration = std::chrono::seconds(60)) {
        if (!initialized_) {
            std::cerr << "[Platform] Not initialized - call initializeDefaultSwarm() first\n";
            return;
        }
        
        orchestrator_->runContinuous(duration);
    }

    // === Analysis Methods ===

    // Analyze binary data with the full agentic pipeline
    void analyzeBinary(const std::vector<uint8_t>& data, const std::string& name = "unknown") {
        if (!initialized_) {
            std::cerr << "[Platform] Not initialized\n";
            return;
        }
        
        std::cout << "\n[Platform] Analyzing binary: " << name 
                  << " (" << data.size() << " bytes)\n";
        
        // Post initial blackboard entry
        BlackboardEntry entry;
        entry.region_address = 0x1000;
        entry.region_size = data.size();
        entry.region_name = name;
        entry.status = "unexplored";
        entry.last_updated = std::chrono::steady_clock::now();
        entry.updated_by_agent = "platform";
        blackboard_->postEntry(entry);
        
        // Execute mission
        auto mission = executeMission("Analyze binary: " + name);
        
        // Self-evaluate
        std::vector<AgentResult> results;
        for (const auto& agent : orchestrator_->getAgents()) {
            AgentResult r;
            r.success = agent->getState() == AgentState::COMPLETED;
            r.summary = agent->getId().name + " completed";
            r.confidence = agent->getConfidence();
            results.push_back(r);
        }
        
        auto eval = self_improvement_->evaluateMission(mission, results);
        
        // Retrain if needed
        if (eval.needs_retraining) {
            self_improvement_->retrainWeights(eval);
        }
        
        // Generate verification tasks
        auto verification_tasks = self_improvement_->generateVerificationTasks(eval);
        if (!verification_tasks.empty()) {
            std::cout << "[Platform] Generated " << verification_tasks.size() 
                      << " verification tasks\n";
        }
        
        // Generate new hypotheses
        auto hypotheses = self_improvement_->generateNewHypotheses(eval);
        if (!hypotheses.empty()) {
            std::cout << "[Platform] Generated " << hypotheses.size() 
                      << " new hypotheses\n";
        }
    }

    // === Knowledge Management ===

    void addKnowledge(const std::string& category, const std::string& key, 
                      const std::string& value, double confidence = 0.8) {
        knowledge_->addFact(category, key, value, confidence);
    }

    void exportKnowledge(const std::string& path) {
        knowledge_->exportToFile(path);
        std::cout << "[Platform] Knowledge exported to: " << path << "\n";
    }

    // === Status and Reporting ===

    void printStatus() const {
        std::cout << "\n";
        std::cout << "╔══════════════════════════════════════════════════════════════════════╗\n";
        std::cout << "║     Platform Status Report                                           ║\n";
        std::cout << "╚══════════════════════════════════════════════════════════════════════╝\n";
        
        // Tool registry
        std::cout << "\n[Tools] " << tools_->toolCount() << " registered\n";
        std::cout << tools_->listCapabilities();
        
        // Swarm
        auto swarm_stats = orchestrator_->getSwarmStats();
        std::cout << "\n[Swarm]\n";
        std::cout << "  Total agents: " << swarm_stats.total_agents << "\n";
        std::cout << "  Active: " << swarm_stats.active_agents << "\n";
        std::cout << "  Completed: " << swarm_stats.completed_agents << "\n";
        std::cout << "  Failed: " << swarm_stats.failed_agents << "\n";
        std::cout << "  Average confidence: " << std::fixed << std::setprecision(3) 
                  << swarm_stats.average_confidence << "\n";
        std::cout << "  Missions completed: " << swarm_stats.missions_completed << "\n";
        
        for (const auto& [role, count] : swarm_stats.role_counts) {
            std::cout << "    " << role << ": " << count << "\n";
        }
        
        // Blackboard
        std::cout << "\n[Blackboard] " << blackboard_->entryCount() << " entries\n";
        
        // Knowledge graph
        auto kg_stats = knowledge_->getStats();
        std::cout << "\n[Knowledge Graph]\n";
        std::cout << "  Total entries: " << kg_stats.total_entries << "\n";
        std::cout << "  Verified: " << kg_stats.verified_entries << "\n";
        std::cout << "  Categories: " << kg_stats.categories_count << "\n";
        std::cout << "  Average confidence: " << std::fixed << std::setprecision(3) 
                  << kg_stats.average_confidence << "\n";
        
        // Self-improvement
        auto imp_stats = self_improvement_->getStats();
        std::cout << "\n[Self-Improvement]\n";
        std::cout << "  Evaluations: " << imp_stats.total_evaluations << "\n";
        std::cout << "  Retraining events: " << imp_stats.retraining_events << "\n";
        std::cout << "  Verification tasks: " << imp_stats.verification_tasks_generated << "\n";
        std::cout << "  New hypotheses: " << imp_stats.new_hypotheses_generated << "\n";
        std::cout << "  Avg confidence improvement: " << std::fixed << std::setprecision(3) 
                  << imp_stats.average_confidence_improvement << "\n";
        
        std::cout << "\n";
    }

    // === Accessors ===

    std::shared_ptr<ToolRegistry> getToolRegistry() const { return tools_; }
    std::shared_ptr<Blackboard> getBlackboard() const { return blackboard_; }
    std::shared_ptr<KnowledgeGraph> getKnowledgeGraph() const { return knowledge_; }
    std::shared_ptr<MissionOrchestrator> getOrchestrator() const { return orchestrator_; }
    std::shared_ptr<SelfImprovement> getSelfImprovement() const { return self_improvement_; }
    
    bool isInitialized() const { return initialized_; }

private:
    void registerDefaultTools() {
        tools_->registerTool(std::make_shared<PatternGenTool>());
        tools_->registerTool(std::make_shared<EntropyTool>());
        tools_->registerTool(std::make_shared<PatternCompareTool>());
        tools_->registerTool(std::make_shared<KnowledgeQueryTool>());
        tools_->registerTool(std::make_shared<ValidationTool>());
        tools_->registerTool(std::make_shared<ExportTool>());
        tools_->registerTool(std::make_shared<OptimizerTool>());
        tools_->registerTool(std::make_shared<MergeResultsTool>());
    }

    std::shared_ptr<ToolRegistry> tools_;
    std::shared_ptr<Blackboard> blackboard_;
    std::shared_ptr<KnowledgeGraph> knowledge_;
    std::shared_ptr<MissionOrchestrator> orchestrator_;
    std::shared_ptr<SelfImprovement> self_improvement_;
    bool initialized_ = false;
};

} // namespace RawrXD::Agentic
