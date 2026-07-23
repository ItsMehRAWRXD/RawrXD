// ============================================================================
// BaseAgent.hpp - Autonomous agent with goal-driven reasoning loop
// ============================================================================
#pragma once

#include "AgentTypes.hpp"
#include "ToolRegistry.hpp"
#include "Blackboard.hpp"
#include "KnowledgeGraph.hpp"
#include <memory>
#include <iostream>
#include <sstream>
#include <random>
#include <cmath>

namespace RawrXD::Agentic {

// ============================================================================
// BaseAgent - the fundamental autonomous unit
// Each agent has: goal, tools, memory, observations, confidence, ability to escalate
// ============================================================================

class BaseAgent {
public:
    BaseAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
              std::shared_ptr<Blackboard> blackboard,
              std::shared_ptr<KnowledgeGraph> knowledge)
        : id_(std::move(id)), tools_(std::move(tools)), 
          blackboard_(std::move(blackboard)), knowledge_(std::move(knowledge)) {
        rng_.seed(std::random_device{}());
    }

    virtual ~BaseAgent() = default;

    // === Core API ===

    // Set the agent's current goal
    void setGoal(const AgentGoal& goal) {
        current_goal_ = goal;
        state_ = AgentState::IDLE;
        std::cout << "  [" << id_.name << "] Goal set: " << goal.description << std::endl;
    }

    // Add an observation
    void addObservation(const AgentObservation& obs) {
        observations_.push_back(obs);
        memory_[obs.description] = obs.data.empty() ? "observed" : obs.data.begin()->second;
    }

    // Run one reasoning cycle: Observe -> Decide -> Execute -> Learn
    virtual AgentResult thinkAndAct() {
        auto start = std::chrono::high_resolution_clock::now();
        state_ = AgentState::THINKING;
        
        // 1. Observe - gather context from blackboard and memory
        auto observations = observe();
        
        // 2. Decide - choose next action based on goal and observations
        auto decisions = decide(observations);
        
        if (decisions.empty()) {
            state_ = AgentState::COMPLETED;
            AgentResult r;
            r.success = true;
            r.summary = "No actions needed";
            r.confidence = 1.0;
            return r;
        }
        
        // 3. Execute - invoke tools
        state_ = AgentState::EXECUTING;
        AgentResult result;
        
        for (const auto& decision : decisions) {
            if (decision.requires_escalation) {
                state_ = AgentState::ESCALATED;
                result.summary = "Escalating: " + decision.description;
                result.metadata["escalated"] = "true";
                break;
            }
            
            auto tool_result = tools_->execute(decision.tool_to_invoke, decision.parameters);
            
            // Store in memory
            memory_[decision.description] = tool_result.success ? "success" : "failed";
            
            // Post to blackboard if significant
            if (tool_result.success && !tool_result.data.empty()) {
                BlackboardEntry entry;
                entry.region_address = 0;
                entry.region_size = tool_result.data.size();
                entry.confidence = tool_result.confidence;
                entry.status = tool_result.success ? "analyzed" : "failed";
                entry.updated_by_agent = id_.name;
                entry.last_updated = std::chrono::steady_clock::now();
                blackboard_->postEntry(entry);
            }
            
            result = tool_result;
        }
        
        // 4. Learn - update knowledge
        learn(result);
        
        auto end = std::chrono::high_resolution_clock::now();
        result.processing_time_us = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count();
        
        state_ = AgentState::COMPLETED;
        return result;
    }

    // === Accessors ===

    const AgentID& getId() const { return id_; }
    AgentRole getRole() const { return id_.role; }
    AgentState getState() const { return state_; }
    const AgentGoal& getGoal() const { return current_goal_; }
    const AgentMemory& getMemory() const { return memory_; }
    const ObservationList& getObservations() const { return observations_; }
    
    double getConfidence() const { return confidence_; }
    void setConfidence(double c) { confidence_ = std::max(0.0, std::min(1.0, c)); }

    // Check if agent can handle a given capability
    virtual bool canHandle(ToolCapability cap) const {
        for (const auto& tc : capabilities_) {
            if (tc == cap) return true;
        }
        return false;
    }

    // Get capabilities
    const std::vector<ToolCapability>& getCapabilities() const { return capabilities_; }

    // Reset for new mission
    virtual void reset() {
        observations_.clear();
        memory_.clear();
        state_ = AgentState::IDLE;
        confidence_ = 0.5;
    }

    // String representation
    virtual std::string toString() const {
        return "Agent[" + id_.name + ", " + roleToString(id_.role) + ", " + 
               stateToString(state_) + ", conf=" + std::to_string(confidence_) + "]";
    }

protected:
    // === Override these in specialized agents ===

    // Observe the environment (blackboard, memory, knowledge graph)
    virtual ObservationList observe() {
        ObservationList obs;
        
        // Check blackboard for relevant entries
        auto entries = blackboard_->getAllEntries();
        for (const auto& entry : entries) {
            if (isRelevantToRole(entry)) {
                AgentObservation o;
                o.source_agent = id_.name;
                o.description = "Blackboard entry at 0x" + 
                    std::to_string(entry.region_address) + " [" + entry.status + "]";
                o.data["entropy"] = std::to_string(entry.entropy);
                o.data["confidence"] = std::to_string(entry.confidence);
                o.confidence = entry.confidence;
                o.region_address = entry.region_address;
                o.region_size = entry.region_size;
                o.timestamp = std::chrono::steady_clock::now();
                obs.push_back(o);
            }
        }
        
        return obs;
    }

    // Decide what to do based on observations
    virtual DecisionList decide(const ObservationList& observations) {
        DecisionList decisions;
        
        for (const auto& obs : observations) {
            auto decision = evaluateObservation(obs);
            if (decision.has_value()) {
                decisions.push_back(decision.value());
            }
        }
        
        return decisions;
    }

    // Learn from results
    virtual void learn(const AgentResult& result) {
        if (result.success) {
            confidence_ = std::min(1.0, confidence_ + 0.05);
        } else {
            confidence_ = std::max(0.0, confidence_ - 0.05);
        }
    }

    // Check if a blackboard entry is relevant to this agent's role
    virtual bool isRelevantToRole(const BlackboardEntry& entry) const {
        return true; // Override in subclasses
    }

    // Evaluate a single observation and decide on action
    virtual std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) {
        return std::nullopt; // Override in subclasses
    }

    // === Utility ===

    std::string stateToString(AgentState s) const {
        switch (s) {
            case AgentState::IDLE: return "IDLE";
            case AgentState::THINKING: return "THINKING";
            case AgentState::EXECUTING: return "EXECUTING";
            case AgentState::WAITING_FOR_TOOL: return "WAITING_FOR_TOOL";
            case AgentState::WAITING_FOR_INPUT: return "WAITING_FOR_INPUT";
            case AgentState::COMPLETED: return "COMPLETED";
            case AgentState::FAILED: return "FAILED";
            case AgentState::ESCALATED: return "ESCALATED";
            default: return "UNKNOWN";
        }
    }

    // Members
    AgentID id_;
    AgentState state_ = AgentState::IDLE;
    AgentGoal current_goal_;
    AgentMemory memory_;
    ObservationList observations_;
    std::vector<ToolCapability> capabilities_;
    double confidence_ = 0.5;
    
    std::shared_ptr<ToolRegistry> tools_;
    std::shared_ptr<Blackboard> blackboard_;
    std::shared_ptr<KnowledgeGraph> knowledge_;
    
    std::mt19937 rng_;
};

// ============================================================================
// Specialized Agent Implementations
// ============================================================================

// --- Scout Agent: Find interesting regions ---
class ScoutAgent : public BaseAgent {
public:
    ScoutAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
               std::shared_ptr<Blackboard> blackboard,
               std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::CALCULATE_ENTROPY, ToolCapability::SCAN_PATTERNS};
    }

protected:
    bool isRelevantToRole(const BlackboardEntry& entry) const override {
        return entry.entropy == 0.0 || entry.status == "unexplored";
    }

    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy") && std::stod(obs.data.at("entropy")) == 0.0) {
            AgentDecision d;
            d.description = "Calculate entropy for unexplored region";
            d.tool_to_invoke = ToolCapability::CALCULATE_ENTROPY;
            d.parameters["data"] = "unexplored";
            d.expected_utility = 0.8;
            d.rationale = {"Region has no entropy data", "Scout should characterize this region"};
            return d;
        }
        return std::nullopt;
    }
};

// --- Pattern Agent: Build signatures ---
class PatternAgent : public BaseAgent {
public:
    PatternAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                 std::shared_ptr<Blackboard> blackboard,
                 std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::GENERATE_PATTERNS, ToolCapability::COMPARE_PATTERNS,
                         ToolCapability::EXPORT_JSON, ToolCapability::EXPORT_MODEL};
    }

protected:
    bool isRelevantToRole(const BlackboardEntry& entry) const override {
        return entry.entropy > 3.0 && entry.pattern_candidates.empty();
    }

    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 3.0 && entropy < 7.5) {
                AgentDecision d;
                d.description = "Generate patterns for region with entropy " + std::to_string(entropy);
                d.tool_to_invoke = ToolCapability::GENERATE_PATTERNS;
                d.parameters["data"] = "region_data";
                d.parameters["types"] = "inverse,complement,xor";
                d.expected_utility = 0.7;
                d.rationale = {"Entropy indicates structured data", "Pattern generation may reveal structure"};
                return d;
            }
        }
        return std::nullopt;
    }

    void learn(const AgentResult& result) override {
        if (result.success && !result.data.empty()) {
            confidence_ = std::min(1.0, confidence_ + 0.1);
            // Store discovered pattern in knowledge graph
            knowledge_->addFact("pattern_signatures", 
                "pattern_" + std::to_string(result.data.size()),
                "Discovered " + std::to_string(result.data.size()) + " byte pattern",
                result.confidence);
        }
        BaseAgent::learn(result);
    }
};

// --- Entropy Agent: Analyze entropy ---
class EntropyAgent : public BaseAgent {
public:
    EntropyAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                 std::shared_ptr<Blackboard> blackboard,
                 std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::CALCULATE_ENTROPY};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 7.0) {
                AgentDecision d;
                d.description = "High entropy detected - may be packed or encrypted";
                d.tool_to_invoke = ToolCapability::CALCULATE_ENTROPY;
                d.parameters["data"] = "high_entropy_region";
                d.expected_utility = 0.9;
                d.rationale = {"Entropy > 7.0 suggests packing or encryption", 
                               "Further analysis needed"};
                d.requires_escalation = true; // Notify orchestrator
                return d;
            } else if (entropy < 2.0 && entropy > 0.0) {
                AgentDecision d;
                d.description = "Low entropy - may be padding or structured data";
                d.tool_to_invoke = ToolCapability::CALCULATE_ENTROPY;
                d.parameters["data"] = "low_entropy_region";
                d.expected_utility = 0.5;
                d.rationale = {"Low entropy suggests repetitive data"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- Validator Agent: Verify confidence ---
class ValidatorAgent : public BaseAgent {
public:
    ValidatorAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                   std::shared_ptr<Blackboard> blackboard,
                   std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::VALIDATE, ToolCapability::COMPARE_PATTERNS};
    }

protected:
    bool isRelevantToRole(const BlackboardEntry& entry) const override {
        return entry.confidence > 0.0 && entry.confidence < 0.7;
    }

    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("confidence")) {
            double conf = std::stod(obs.data.at("confidence"));
            if (conf > 0.0 && conf < 0.7) {
                AgentDecision d;
                d.description = "Validate low-confidence result";
                d.tool_to_invoke = ToolCapability::VALIDATE;
                d.parameters["confidence"] = std::to_string(conf);
                d.parameters["pattern"] = "candidate";
                d.expected_utility = 0.6;
                d.rationale = {"Confidence below threshold", "Validation needed before accepting result"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- Optimizer Agent: Merge duplicates ---
class OptimizerAgent : public BaseAgent {
public:
    OptimizerAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                   std::shared_ptr<Blackboard> blackboard,
                   std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::OPTIMIZE, ToolCapability::MERGE_RESULTS};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        // Check if there are duplicate entries on the blackboard
        auto entries = blackboard_->getAllEntries();
        std::unordered_map<double, int> entropy_counts;
        for (const auto& e : entries) {
            entropy_counts[e.entropy]++;
        }
        
        for (const auto& [entropy, count] : entropy_counts) {
            if (count > 3) {
                AgentDecision d;
                d.description = "Merge duplicate entries with entropy " + std::to_string(entropy);
                d.tool_to_invoke = ToolCapability::OPTIMIZE;
                d.parameters["patterns"] = "duplicates";
                d.expected_utility = 0.5;
                d.rationale = {"Multiple entries with same entropy", "Merging reduces redundancy"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- ML Agent: Classify functions ---
class MLAgent : public BaseAgent {
public:
    MLAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
            std::shared_ptr<Blackboard> blackboard,
            std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::CLASSIFY_FUNCTION, ToolCapability::TRAIN_MODEL};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 4.0 && entropy < 6.5) {
                AgentDecision d;
                d.description = "Classify function in region with entropy " + std::to_string(entropy);
                d.tool_to_invoke = ToolCapability::CLASSIFY_FUNCTION;
                d.parameters["entropy"] = std::to_string(entropy);
                d.expected_utility = 0.6;
                d.rationale = {"Entropy in typical code range", "ML classification may identify function type"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- Decompiler Agent: Recover control flow ---
class DecompilerAgent : public BaseAgent {
public:
    DecompilerAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                    std::shared_ptr<Blackboard> blackboard,
                    std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::DECOMPILE, ToolCapability::BUILD_CFG};
    }

protected:
    bool isRelevantToRole(const BlackboardEntry& entry) const override {
        return entry.decompiler_pending && !entry.decompiler_complete;
    }

    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 3.0 && entropy < 7.0) {
                AgentDecision d;
                d.description = "Decompile region with entropy " + std::to_string(entropy);
                d.tool_to_invoke = ToolCapability::DECOMPILE;
                d.parameters["address"] = std::to_string(obs.region_address);
                d.expected_utility = 0.75;
                d.rationale = {"Entropy suggests code region", "Decompilation will recover control flow"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- Graph Agent: Build CFGs ---
class GraphAgent : public BaseAgent {
public:
    GraphAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
               std::shared_ptr<Blackboard> blackboard,
               std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::BUILD_CFG};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 4.0 && entropy < 6.5) {
                AgentDecision d;
                d.description = "Build CFG for code region";
                d.tool_to_invoke = ToolCapability::BUILD_CFG;
                d.parameters["address"] = std::to_string(obs.region_address);
                d.expected_utility = 0.7;
                d.rationale = {"Code region identified", "CFG will reveal control flow structure"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- Debugger Agent: Execute samples ---
class DebuggerAgent : public BaseAgent {
public:
    DebuggerAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                  std::shared_ptr<Blackboard> blackboard,
                  std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::ATTACH_PROCESS, ToolCapability::SET_BREAKPOINT,
                         ToolCapability::READ_MEMORY, ToolCapability::EXECUTE_SAMPLE};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 7.5) {
                AgentDecision d;
                d.description = "Attach debugger to high-entropy region";
                d.tool_to_invoke = ToolCapability::ATTACH_PROCESS;
                d.parameters["address"] = std::to_string(obs.region_address);
                d.expected_utility = 0.8;
                d.rationale = {"High entropy may indicate runtime-generated code", 
                               "Debugger can capture dynamic behavior"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- Symbolic Agent: Symbolic execution ---
class SymbolicAgent : public BaseAgent {
public:
    SymbolicAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                  std::shared_ptr<Blackboard> blackboard,
                  std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::SYMBOLIC_EXECUTE};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 5.0 && entropy < 7.0) {
                AgentDecision d;
                d.description = "Run symbolic execution on complex region";
                d.tool_to_invoke = ToolCapability::SYMBOLIC_EXECUTE;
                d.parameters["address"] = std::to_string(obs.region_address);
                d.expected_utility = 0.65;
                d.rationale = {"Complex code region", "Symbolic execution may reveal hidden paths"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- Import Analyzer Agent ---
class ImportAnalyzerAgent : public BaseAgent {
public:
    ImportAnalyzerAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                        std::shared_ptr<Blackboard> blackboard,
                        std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::ANALYZE_IMPORTS};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 2.0 && entropy < 4.0) {
                AgentDecision d;
                d.description = "Analyze imports for region";
                d.tool_to_invoke = ToolCapability::ANALYZE_IMPORTS;
                d.parameters["address"] = std::to_string(obs.region_address);
                d.expected_utility = 0.6;
                d.rationale = {"Moderate entropy may indicate import table", 
                               "Import analysis reveals API usage"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- YARA Agent ---
class YARAAgent : public BaseAgent {
public:
    YARAAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
              std::shared_ptr<Blackboard> blackboard,
              std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::YARA_SCAN};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 6.0) {
                AgentDecision d;
                d.description = "Run YARA scan on suspicious region";
                d.tool_to_invoke = ToolCapability::YARA_SCAN;
                d.parameters["address"] = std::to_string(obs.region_address);
                d.expected_utility = 0.7;
                d.rationale = {"Suspicious entropy level", "YARA may identify known malware family"};
                return d;
            }
        }
        return std::nullopt;
    }
};

// --- Unpacker Agent ---
class UnpackerAgent : public BaseAgent {
public:
    UnpackerAgent(AgentID id, std::shared_ptr<ToolRegistry> tools,
                  std::shared_ptr<Blackboard> blackboard,
                  std::shared_ptr<KnowledgeGraph> knowledge)
        : BaseAgent(std::move(id), std::move(tools), std::move(blackboard), std::move(knowledge)) {
        capabilities_ = {ToolCapability::UNPACK};
    }

protected:
    std::optional<AgentDecision> evaluateObservation(const AgentObservation& obs) override {
        if (obs.data.count("entropy")) {
            double entropy = std::stod(obs.data.at("entropy"));
            if (entropy > 7.5) {
                AgentDecision d;
                d.description = "Unpack high-entropy region";
                d.tool_to_invoke = ToolCapability::UNPACK;
                d.parameters["address"] = std::to_string(obs.region_address);
                d.expected_utility = 0.85;
                d.rationale = {"Very high entropy suggests packing", 
                               "Unpacking may reveal original code"};
                return d;
            }
        }
        return std::nullopt;
    }
};

} // namespace RawrXD::Agentic
