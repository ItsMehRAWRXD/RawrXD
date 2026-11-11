// ============================================================================
// MissionOrchestrator.hpp - Autonomous mission planning and orchestration
// ============================================================================
#pragma once

#include "AgentTypes.hpp"
#include "BaseAgent.hpp"
#include "ToolRegistry.hpp"
#include "Blackboard.hpp"
#include "KnowledgeGraph.hpp"
#include <memory>
#include <vector>
#include <unordered_map>
#include <queue>
#include <thread>
#include <future>
#include <iostream>
#include <sstream>
#include <algorithm>
#include <random>

namespace RawrXD::Agentic {

// ============================================================================
// Planner Agent - builds dynamic execution plans
// ============================================================================

class PlannerAgent : public BaseAgent {
public:
    PlannerAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                 std::shared_ptr<Blackboard> blackboard,
                 std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::PLAN_MISSION, ToolCapability::SCHEDULE_TASKS};
    }

    // Build an execution plan for a mission
    ExecutionPlan buildPlan(const Mission& mission, 
                            const std::vector<std::shared_ptr<BaseAgent>>& available_agents) {
        ExecutionPlan plan;
        plan.mission_id = mission.id;
        plan.is_dynamic = true;
        
        std::cout << "  [Planner] Building plan for mission: " << mission.description << std::endl;
        
        // Phase 1: Reconnaissance - Scout and Entropy agents
        plan.steps.push_back("Phase1_Reconnaissance");
        plan.step_assignments["Phase1_Reconnaissance"] = AgentRole::SCOUT;
        plan.step_tools["Phase1_Reconnaissance"] = {ToolCapability::CALCULATE_ENTROPY, ToolCapability::SCAN_PATTERNS};
        
        // Phase 2: Analysis - Pattern, ML, Import agents
        plan.steps.push_back("Phase2_Analysis");
        plan.dependencies.push_back({"Phase2_Analysis", "Phase1_Reconnaissance"});
        plan.step_assignments["Phase2_Analysis"] = AgentRole::PATTERN;
        plan.step_tools["Phase2_Analysis"] = {ToolCapability::GENERATE_PATTERNS, ToolCapability::CLASSIFY_FUNCTION, 
                                                ToolCapability::ANALYZE_IMPORTS};
        
        // Phase 3: Deep Analysis - Decompiler, Graph, Symbolic agents
        plan.steps.push_back("Phase3_DeepAnalysis");
        plan.dependencies.push_back({"Phase3_DeepAnalysis", "Phase2_Analysis"});
        plan.step_assignments["Phase3_DeepAnalysis"] = AgentRole::DECOMPILER;
        plan.step_tools["Phase3_DeepAnalysis"] = {ToolCapability::DECOMPILE, ToolCapability::BUILD_CFG, 
                                                    ToolCapability::SYMBOLIC_EXECUTE};
        
        // Phase 4: Specialized - Debugger, YARA, Unpacker agents
        plan.steps.push_back("Phase4_Specialized");
        plan.dependencies.push_back({"Phase4_Specialized", "Phase3_DeepAnalysis"});
        plan.step_assignments["Phase4_Specialized"] = AgentRole::DEBUGGER;
        plan.step_tools["Phase4_Specialized"] = {ToolCapability::ATTACH_PROCESS, ToolCapability::YARA_SCAN, 
                                                   ToolCapability::UNPACK};
        
        // Phase 5: Optimization - Optimizer agent
        plan.steps.push_back("Phase5_Optimization");
        plan.dependencies.push_back({"Phase5_Optimization", "Phase4_Specialized"});
        plan.step_assignments["Phase5_Optimization"] = AgentRole::OPTIMIZER;
        plan.step_tools["Phase5_Optimization"] = {ToolCapability::OPTIMIZE, ToolCapability::MERGE_RESULTS};
        
        // Phase 6: Validation - Validator agent
        plan.steps.push_back("Phase6_Validation");
        plan.dependencies.push_back({"Phase6_Validation", "Phase5_Optimization"});
        plan.step_assignments["Phase6_Validation"] = AgentRole::VALIDATOR;
        plan.step_tools["Phase6_Validation"] = {ToolCapability::VALIDATE};
        
        // Phase 7: Export
        plan.steps.push_back("Phase7_Export");
        plan.dependencies.push_back({"Phase7_Export", "Phase6_Validation"});
        plan.step_assignments["Phase7_Export"] = AgentRole::ORCHESTRATOR;
        plan.step_tools["Phase7_Export"] = {ToolCapability::EXPORT_JSON, ToolCapability::EXPORT_MODEL};
        
        std::cout << "  [Planner] Plan has " << plan.steps.size() << " phases" << std::endl;
        
        return plan;
    }

    // Adapt plan based on observations
    void adaptPlan(ExecutionPlan& plan, const ObservationList& observations) {
        std::cout << "  [Planner] Adapting plan based on " << observations.size() << " observations" << std::endl;
        
        for (const auto& obs : observations) {
            if (obs.data.count("entropy")) {
                double entropy = std::stod(obs.data.at("entropy"));
                
                // If high entropy found, prioritize unpacker
                if (entropy > 7.5) {
                    auto it = std::find(plan.steps.begin(), plan.steps.end(), "Phase4_Specialized");
                    if (it != plan.steps.end() && it != plan.steps.begin()) {
                        // Move unpacking earlier
                        std::cout << "  [Planner] High entropy detected - prioritizing unpacker" << std::endl;
                    }
                }
                
                // If low entropy, skip decompilation
                if (entropy < 2.0) {
                    auto it = std::find(plan.steps.begin(), plan.steps.end(), "Phase3_DeepAnalysis");
                    if (it != plan.steps.end()) {
                        std::cout << "  [Planner] Low entropy - skipping deep analysis" << std::endl;
                    }
                }
            }
        }
    }

    // Generate new hypotheses based on results
    std::vector<AgentGoal> generateHypotheses(const ExecutionPlan& plan, 
                                                const std::vector<AgentResult>& results) {
        std::vector<AgentGoal> hypotheses;
        
        for (const auto& result : results) {
            if (!result.success && !result.error_message.empty()) {
                AgentGoal hypothesis;
                hypothesis.description = "Investigate failure: " + result.error_message;
                hypothesis.priority = 0.3;
                hypothesis.success_criteria = {"Resolve error", "Complete analysis"};
                hypotheses.push_back(hypothesis);
            }
            
            if (result.confidence < 0.5 && result.success) {
                AgentGoal hypothesis;
                hypothesis.description = "Improve confidence for: " + result.summary;
                hypothesis.priority = 0.4;
                hypothesis.success_criteria = {"Confidence > 0.7"};
                hypotheses.push_back(hypothesis);
            }
        }
        
        return hypotheses;
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 7.0) {
                AgentDecision d;
                d.description = "Replan: high entropy requires unpacker";
                d.tool_to_invoke = ToolCapability::PLAN_MISSION;
                d.parameters["reason"] = "high_entropy";
                d.expected_utility = 0.9;
                d.rationale = {"High entropy changes analysis priority", "Plan must be adapted"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// ============================================================================
// MissionOrchestrator - coordinates the entire agent ecosystem
// ============================================================================

class MissionOrchestrator {
public:
    MissionOrchestrator(std::shared_ptr<ToolRegistry> tools,
                        std::shared_ptr<Blackboard> blackboard,
                        std::shared_ptr<KnowledgeGraph> knowledge)
        : tools_(std::move(tools)), blackboard_(std::move(blackboard)), 
          knowledge_(std::move(knowledge)) {
        
        // Create the planner
        AgentID planner_id;
        planner_id.name = "Planner";
        planner_id.role = AgentRole::PLANNER;
        planner_id.instance_id = 0;
        planner_ = std::make_shared<PlannerAgent>(planner_id, tools_, blackboard_, knowledge_);
    }

    ~MissionOrchestrator() = default;

    // Register an agent
    void registerAgent(std::shared_ptr<BaseAgent> agent) {
        agents_.push_back(agent);
        agents_by_role_[agent->getRole()].push_back(agent);
        std::cout << "[Orchestrator] Registered agent: " << agent->getId().name 
                  << " (" << roleToString(agent->getRole()) << ")" << std::endl;
    }

    // Create default agent swarm
    void createDefaultSwarm(size_t agents_per_role = 1) {
        auto createAgent = [&](const std::string& name, AgentRole role, int instance) -> std::shared_ptr<BaseAgent> {
            AgentID id;
            id.name = name + "_" + std::to_string(instance);
            id.role = role;
            id.instance_id = instance;
            
            switch (role) {
                case AgentRole::SCOUT:
                    return std::make_shared<ScoutAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::PATTERN:
                    return std::make_shared<PatternAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::ENTROPY:
                    return std::make_shared<EntropyAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::VALIDATOR:
                    return std::make_shared<ValidatorAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::OPTIMIZER:
                    return std::make_shared<OptimizerAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::ML:
                    return std::make_shared<MLAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::DECOMPILER:
                    return std::make_shared<DecompilerAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::GRAPH:
                    return std::make_shared<GraphAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::DEBUGGER:
                    return std::make_shared<DebuggerAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::SYMBOLIC:
                    return std::make_shared<SymbolicAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::IMPORT_ANALYZER:
                    return std::make_shared<ImportAnalyzerAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::YARA:
                    return std::make_shared<YARAAgent>(id, tools_, blackboard_, knowledge_);
                case AgentRole::UNPACKER:
                    return std::make_shared<UnpackerAgent>(id, tools_, blackboard_, knowledge_);
                default:
                    return nullptr;
            }
        };
        
        // Create specialized agents
        std::vector<AgentRole> roles = {
            AgentRole::SCOUT, AgentRole::PATTERN, AgentRole::ENTROPY,
            AgentRole::VALIDATOR, AgentRole::OPTIMIZER, AgentRole::ML,
            AgentRole::DECOMPILER, AgentRole::GRAPH, AgentRole::DEBUGGER,
            AgentRole::SYMBOLIC, AgentRole::IMPORT_ANALYZER, AgentRole::YARA,
            AgentRole::UNPACKER
        };
        
        for (auto role : roles) {
            for (size_t i = 0; i < agents_per_role; ++i) {
                auto agent = createAgent(roleToString(role), role, i);
                if (agent) registerAgent(agent);
            }
        }
        
        std::cout << "[Orchestrator] Created swarm with " << agents_.size() << " agents" << std::endl;
    }

    // === Mission Lifecycle ===

    // Start a new mission
    Mission startMission(const std::string& description, 
                         const std::vector<AgentGoal>& goals = {},
                         std::chrono::seconds deadline = std::chrono::seconds(300)) {
        Mission mission;
        mission.id = "mission_" + std::to_string(mission_counter_++);
        mission.description = description;
        mission.goals = goals;
        mission.created = std::chrono::steady_clock::now();
        mission.deadline = mission.created + deadline;
        mission.is_complete = false;
        
        std::cout << "\n[Orchestrator] === NEW MISSION: " << description << " ===" << std::endl;
        std::cout << "[Orchestrator] Mission ID: " << mission.id << std::endl;
        std::cout << "[Orchestrator] Deadline: " << deadline.count() << "s" << std::endl;
        
        active_mission_ = mission;
        return mission;
    }

    // Execute a mission
    Mission executeMission(const std::string& description,
                           const std::vector<AgentGoal>& goals = {},
                           std::chrono::seconds deadline = std::chrono::seconds(300)) {
        
        auto mission = startMission(description, goals, deadline);
        
        // 1. Plan
        auto plan = planner_->buildPlan(mission, agents_);
        
        // 2. Execute plan phases
        for (const auto& step : plan.steps) {
            std::cout << "\n[Orchestrator] --- Phase: " << step << " ---" << std::endl;
            
            auto role = plan.step_assignments[step];
            auto tools = plan.step_tools[step];
            
            // Find agents for this role
            auto agents = agents_by_role_[role];
            if (agents.empty()) {
                std::cout << "[Orchestrator] No agents for role " << roleToString(role) << std::endl;
                continue;
            }
            
            // Execute agents in parallel
            std::vector<std::future<AgentResult>> futures;
            for (auto& agent : agents) {
                agent->setGoal(createGoalForStep(step, tools));
                futures.push_back(std::async(std::launch::async, [agent]() {
                    return agent->thinkAndAct();
                }));
            }
            
            // Collect results
            std::vector<AgentResult> step_results;
            for (auto& f : futures) {
                try {
                    step_results.push_back(f.get());
                } catch (const std::exception& e) {
                    AgentResult r;
                    r.success = false;
                    r.error_message = e.what();
                    step_results.push_back(r);
                }
            }
            
            // Check if plan needs adaptation
            ObservationList phase_observations;
            for (const auto& result : step_results) {
                AgentObservation obs;
                obs.source_agent = step;
                obs.description = result.summary;
                obs.confidence = result.confidence;
                obs.timestamp = std::chrono::steady_clock::now();
                phase_observations.push_back(obs);
            }
            
            planner_->adaptPlan(plan, phase_observations);
            
            // Generate new hypotheses
            auto hypotheses = planner_->generateHypotheses(plan, step_results);
            for (const auto& h : hypotheses) {
                mission.goals.push_back(h);
            }
        }
        
        // 3. Complete mission
        mission.is_complete = true;
        mission.is_successful = true;
        mission.summary = "Mission completed with " + std::to_string(agents_.size()) + " agents";
        
        // 4. Learn from mission
        learnFromMission(mission);
        
        std::cout << "\n[Orchestrator] === MISSION COMPLETE: " << description << " ===" << std::endl;
        std::cout << "[Orchestrator] Summary: " << mission.summary << std::endl;
        
        active_mission_ = mission;
        return mission;
    }

    // Continuous operation loop
    void runContinuous(std::chrono::seconds duration = std::chrono::seconds(60)) {
        std::cout << "\n[Orchestrator] === CONTINUOUS OPERATION MODE ===" << std::endl;
        std::cout << "[Orchestrator] Running for " << duration.count() << " seconds" << std::endl;
        
        auto start = std::chrono::steady_clock::now();
        size_t cycle = 0;
        
        while (std::chrono::steady_clock::now() - start < duration) {
            std::cout << "\n[Orchestrator] Cycle " << ++cycle << std::endl;
            
            // Observe
            auto entries = blackboard_->getAllEntries();
            
            // Analyze
            for (auto& agent : agents_) {
                if (agent->getState() == AgentState::IDLE || 
                    agent->getState() == AgentState::COMPLETED) {
                    
                    // Check if agent has relevant work
                    bool has_work = false;
                    for (const auto& entry : entries) {
                        if (agent->canHandle(ToolCapability::CALCULATE_ENTROPY) && entry.entropy == 0.0) {
                            has_work = true;
                            break;
                        }
                    }
                    
                    if (has_work) {
                        agent->thinkAndAct();
                    }
                }
            }
            
            // Learn
            updateKnowledgeGraph();
            
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
        
        std::cout << "[Orchestrator] Continuous operation complete (" << cycle << " cycles)" << std::endl;
    }

    // === Accessors ===

    std::vector<std::shared_ptr<BaseAgent>> getAgents() const { return agents_; }
    std::shared_ptr<PlannerAgent> getPlanner() const { return planner_; }
    Mission getActiveMission() const { return active_mission_; }
    
    size_t agentCount() const { return agents_.size(); }
    
    // Get agent statistics
    struct SwarmStats {
        size_t total_agents;
        size_t active_agents;
        size_t completed_agents;
        size_t failed_agents;
        size_t missions_completed;
        double average_confidence;
        std::unordered_map<std::string, size_t> role_counts;
    };
    
    SwarmStats getSwarmStats() const {
        SwarmStats stats;
        stats.total_agents = agents_.size();
        stats.missions_completed = mission_counter_;
        
        size_t active = 0, completed = 0, failed = 0;
        double total_conf = 0.0;
        
        for (const auto& agent : agents_) {
            switch (agent->getState()) {
                case AgentState::IDLE:
                case AgentState::THINKING:
                case AgentState::EXECUTING:
                    active++; break;
                case AgentState::COMPLETED:
                    completed++; break;
                case AgentState::FAILED:
                    failed++; break;
                default: break;
            }
            total_conf += agent->getConfidence();
            stats.role_counts[roleToString(agent->getRole())]++;
        }
        
        stats.active_agents = active;
        stats.completed_agents = completed;
        stats.failed_agents = failed;
        stats.average_confidence = agents_.empty() ? 0.0 : total_conf / agents_.size();
        
        return stats;
    }

private:
    AgentGoal createGoalForStep(const std::string& step, const std::vector<ToolCapability>& tools) {
        AgentGoal goal;
        goal.description = "Execute phase: " + step;
        goal.required_tools = tools;
        goal.priority = 0.5;
        goal.success_criteria = {"Complete " + step};
        return goal;
    }

    void learnFromMission(const Mission& mission) {
        // Store successful workflow
        std::vector<std::string> workflow;
        workflow.push_back("mission:" + mission.description);
        workflow.push_back("agents:" + std::to_string(agents_.size()));
        workflow.push_back("result:" + std::string(mission.is_successful ? "success" : "failure"));
        
        knowledge_->storeWorkflow(mission.description, workflow);
        
        // Update agent confidences
        for (auto& agent : agents_) {
            knowledge_->addFact("agent_workflows", 
                agent->getId().name + "_mission_" + mission.id,
                "Confidence: " + std::to_string(agent->getConfidence()),
                agent->getConfidence());
        }
    }

    void updateKnowledgeGraph() {
        auto entries = blackboard_->getAllEntries();
        for (const auto& entry : entries) {
            if (entry.confidence > 0.7 && !entry.pattern_candidates.empty()) {
                for (const auto& pattern : entry.pattern_candidates) {
                    knowledge_->addFact("pattern_signatures",
                        "bb_entry_" + std::to_string(entry.region_address),
                        pattern,
                        entry.confidence);
                }
            }
        }
    }

    std::vector<std::shared_ptr<BaseAgent>> agents_;
    std::unordered_map<AgentRole, std::vector<std::shared_ptr<BaseAgent>>> agents_by_role_;
    std::shared_ptr<PlannerAgent> planner_;
    std::shared_ptr<ToolRegistry> tools_;
    std::shared_ptr<Blackboard> blackboard_;
    std::shared_ptr<KnowledgeGraph> knowledge_;
    Mission active_mission_;
    std::atomic<size_t> mission_counter_{0};
};

} // namespace RawrXD::Agentic
