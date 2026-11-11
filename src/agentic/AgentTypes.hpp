// ============================================================================
// AgentTypes.hpp - Core types for the agentic reverse-engineering platform
// ============================================================================
#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <functional>
#include <memory>
#include <chrono>
#include <cstdint>
#include <atomic>
#include <variant>
#include <optional>

namespace RawrXD::Agentic {

// ============================================================================
// Enums
// ============================================================================

enum class AgentRole {
    SCOUT,          // Find interesting regions
    PATTERN,        // Build signatures
    DECOMPILER,     // Recover control flow
    DEBUGGER,       // Execute samples
    GRAPH,          // Build CFGs
    ML,             // Classify functions
    OPTIMIZER,      // Merge duplicate discoveries
    VALIDATOR,      // Verify confidence
    PLANNER,        // Build execution plans
    ORCHESTRATOR,   // Coordinate missions
    SYMBOLIC,       // Symbolic execution
    ENTROPY,        // Entropy analysis
    IMPORT_ANALYZER,// Import analysis
    YARA,           // YARA scanning
    MEMORY_DUMPER,  // Memory dumping
    HEX_DIFF,       // Hex diffing
    MODEL_TRAINER,  // Model training
    UNPACKER,       // Unpacking
    UNKNOWN
};

enum class AgentState {
    IDLE,
    THINKING,
    EXECUTING,
    WAITING_FOR_TOOL,
    WAITING_FOR_INPUT,
    COMPLETED,
    FAILED,
    ESCALATED
};

enum class ToolCapability {
    READ_MEMORY,
    WRITE_MEMORY,
    SCAN_PATTERNS,
    DISASSEMBLE,
    DECOMPILE,
    BUILD_CFG,
    CALCULATE_ENTROPY,
    GENERATE_PATTERNS,
    COMPARE_PATTERNS,
    EXPORT_JSON,
    EXPORT_MODEL,
    ATTACH_PROCESS,
    DETACH_PROCESS,
    SET_BREAKPOINT,
    EXECUTE_SAMPLE,
    YARA_SCAN,
    HEX_DIFF,
    SYMBOLIC_EXECUTE,
    TRAIN_MODEL,
    CLASSIFY_FUNCTION,
    ANALYZE_IMPORTS,
    DUMP_MEMORY,
    UNPACK,
    VALIDATE,
    OPTIMIZE,
    MERGE_RESULTS,
    QUERY_KNOWLEDGE,
    UPDATE_KNOWLEDGE,
    PLAN_MISSION,
    SCHEDULE_TASKS
};

enum class ConfidenceLevel {
    VERY_LOW = 0,
    LOW = 1,
    MEDIUM = 2,
    HIGH = 3,
    VERY_HIGH = 4,
    CERTAIN = 5
};

// ============================================================================
// Structs
// ============================================================================

struct AgentID {
    std::string name;
    AgentRole role;
    uint64_t instance_id;
    
    bool operator==(const AgentID& other) const {
        return name == other.name && role == other.role && instance_id == other.instance_id;
    }
    
    std::string toString() const {
        return name + "_" + std::to_string(static_cast<int>(role)) + "_" + std::to_string(instance_id);
    }
};

struct AgentGoal {
    std::string description;
    std::vector<ToolCapability> required_tools;
    std::vector<std::string> success_criteria;
    double priority = 0.5;
    std::chrono::steady_clock::time_point deadline;
    bool is_critical = false;
};

struct AgentObservation {
    std::string source_agent;
    std::string description;
    std::unordered_map<std::string, std::string> data;
    double confidence = 1.0;
    std::chrono::steady_clock::time_point timestamp;
    uint64_t region_address = 0;
    size_t region_size = 0;
};

struct AgentDecision {
    std::string description;
    ToolCapability tool_to_invoke;
    std::unordered_map<std::string, std::string> parameters;
    double expected_utility = 0.0;
    std::vector<std::string> rationale;
    bool requires_escalation = false;
};

struct AgentResult {
    bool success = false;
    std::string summary;
    std::vector<uint8_t> data;
    std::unordered_map<std::string, std::string> metadata;
    double confidence = 0.0;
    std::vector<std::string> warnings;
    std::string error_message;
    std::chrono::steady_clock::time_point timestamp;
    uint64_t processing_time_us = 0;
};

struct ToolInvocation {
    ToolCapability tool;
    std::unordered_map<std::string, std::string> params;
    std::chrono::steady_clock::time_point start_time;
    std::chrono::steady_clock::time_point end_time;
    AgentResult result;
    bool completed = false;
};

struct BlackboardEntry {
    uint64_t region_address = 0;
    size_t region_size = 0;
    std::string region_name;
    double entropy = 0.0;
    std::vector<std::string> pattern_candidates;
    bool decompiler_pending = false;
    bool decompiler_complete = false;
    double confidence = 0.0;
    std::vector<std::string> tags;
    std::string status;
    std::chrono::steady_clock::time_point last_updated;
    std::string updated_by_agent;
};

struct KnowledgeEntry {
    std::string key;
    std::string value;
    std::string category;
    double confidence = 0.0;
    std::vector<std::string> sources;
    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point last_accessed;
    size_t access_count = 0;
    bool verified = false;
};

struct Mission {
    std::string id;
    std::string description;
    std::vector<AgentGoal> goals;
    std::vector<std::string> assigned_agents;
    std::chrono::steady_clock::time_point created;
    std::chrono::steady_clock::time_point deadline;
    bool is_complete = false;
    bool is_successful = false;
    std::string summary;
    std::vector<std::string> lessons_learned;
};

struct ExecutionPlan {
    std::string mission_id;
    std::vector<std::string> steps;
    std::vector<std::pair<std::string, std::string>> dependencies; // step -> depends_on
    std::unordered_map<std::string, AgentRole> step_assignments;
    std::unordered_map<std::string, std::vector<ToolCapability>> step_tools;
    bool is_dynamic = true; // Can be modified during execution
};

struct SelfEvaluation {
    std::string mission_id;
    double overall_confidence = 0.0;
    std::vector<std::pair<std::string, double>> agent_confidences;
    std::vector<std::string> disagreements;
    std::vector<std::string> recommendations;
    std::vector<std::string> successful_workflows;
    bool needs_retraining = false;
};

// ============================================================================
// Type aliases
// ============================================================================

using AgentMemory = std::unordered_map<std::string, std::string>;
using ToolResult = std::variant<AgentResult, std::vector<uint8_t>, std::string, double>;
using ObservationList = std::vector<AgentObservation>;
using DecisionList = std::vector<AgentDecision>;

// ============================================================================
// Utility
// ============================================================================

inline std::string roleToString(AgentRole role) {
    switch (role) {
        case AgentRole::SCOUT: return "SCOUT";
        case AgentRole::PATTERN: return "PATTERN";
        case AgentRole::DECOMPILER: return "DECOMPILER";
        case AgentRole::DEBUGGER: return "DEBUGGER";
        case AgentRole::GRAPH: return "GRAPH";
        case AgentRole::ML: return "ML";
        case AgentRole::OPTIMIZER: return "OPTIMIZER";
        case AgentRole::VALIDATOR: return "VALIDATOR";
        case AgentRole::PLANNER: return "PLANNER";
        case AgentRole::ORCHESTRATOR: return "ORCHESTRATOR";
        case AgentRole::SYMBOLIC: return "SYMBOLIC";
        case AgentRole::ENTROPY: return "ENTROPY";
        case AgentRole::IMPORT_ANALYZER: return "IMPORT_ANALYZER";
        case AgentRole::YARA: return "YARA";
        case AgentRole::MEMORY_DUMPER: return "MEMORY_DUMPER";
        case AgentRole::HEX_DIFF: return "HEX_DIFF";
        case AgentRole::MODEL_TRAINER: return "MODEL_TRAINER";
        case AgentRole::UNPACKER: return "UNPACKER";
        default: return "UNKNOWN";
    }
}

inline std::string toolToString(ToolCapability tool) {
    switch (tool) {
        case ToolCapability::READ_MEMORY: return "READ_MEMORY";
        case ToolCapability::WRITE_MEMORY: return "WRITE_MEMORY";
        case ToolCapability::SCAN_PATTERNS: return "SCAN_PATTERNS";
        case ToolCapability::DISASSEMBLE: return "DISASSEMBLE";
        case ToolCapability::DECOMPILE: return "DECOMPILE";
        case ToolCapability::BUILD_CFG: return "BUILD_CFG";
        case ToolCapability::CALCULATE_ENTROPY: return "CALCULATE_ENTROPY";
        case ToolCapability::GENERATE_PATTERNS: return "GENERATE_PATTERNS";
        case ToolCapability::COMPARE_PATTERNS: return "COMPARE_PATTERNS";
        case ToolCapability::EXPORT_JSON: return "EXPORT_JSON";
        case ToolCapability::EXPORT_MODEL: return "EXPORT_MODEL";
        case ToolCapability::ATTACH_PROCESS: return "ATTACH_PROCESS";
        case ToolCapability::DETACH_PROCESS: return "DETACH_PROCESS";
        case ToolCapability::SET_BREAKPOINT: return "SET_BREAKPOINT";
        case ToolCapability::EXECUTE_SAMPLE: return "EXECUTE_SAMPLE";
        case ToolCapability::YARA_SCAN: return "YARA_SCAN";
        case ToolCapability::HEX_DIFF: return "HEX_DIFF";
        case ToolCapability::SYMBOLIC_EXECUTE: return "SYMBOLIC_EXECUTE";
        case ToolCapability::TRAIN_MODEL: return "TRAIN_MODEL";
        case ToolCapability::CLASSIFY_FUNCTION: return "CLASSIFY_FUNCTION";
        case ToolCapability::ANALYZE_IMPORTS: return "ANALYZE_IMPORTS";
        case ToolCapability::DUMP_MEMORY: return "DUMP_MEMORY";
        case ToolCapability::UNPACK: return "UNPACK";
        case ToolCapability::VALIDATE: return "VALIDATE";
        case ToolCapability::OPTIMIZE: return "OPTIMIZE";
        case ToolCapability::MERGE_RESULTS: return "MERGE_RESULTS";
        case ToolCapability::QUERY_KNOWLEDGE: return "QUERY_KNOWLEDGE";
        case ToolCapability::UPDATE_KNOWLEDGE: return "UPDATE_KNOWLEDGE";
        case ToolCapability::PLAN_MISSION: return "PLAN_MISSION";
        case ToolCapability::SCHEDULE_TASKS: return "SCHEDULE_TASKS";
        default: return "UNKNOWN";
    }
}

inline std::string confidenceToString(ConfidenceLevel level) {
    switch (level) {
        case ConfidenceLevel::VERY_LOW: return "VERY_LOW";
        case ConfidenceLevel::LOW: return "LOW";
        case ConfidenceLevel::MEDIUM: return "MEDIUM";
        case ConfidenceLevel::HIGH: return "HIGH";
        case ConfidenceLevel::VERY_HIGH: return "VERY_HIGH";
        case ConfidenceLevel::CERTAIN: return "CERTAIN";
        default: return "UNKNOWN";
    }
}

} // namespace RawrXD::Agentic

// Hash specialization for AgentID
namespace std {
    template<> struct hash<RawrXD::Agentic::AgentID> {
        size_t operator()(const RawrXD::Agentic::AgentID& id) const noexcept {
            return hash<string>()(id.toString());
        }
    };
}
