/**
 * @file cognitive_types.hpp
 * @brief Core type definitions for the RawrXD Cognitive Architecture
 * @description Foundation types shared across Mission Director, Reflection Agent,
 *              Dynamic Planner, and Enhanced Blackboard. These types represent
 *              the atomic units of cognition: Evidence, Hypothesis, Task, Goal.
 * @version 1.0.0
 * @date 2026-07-22
 */

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <chrono>
#include <variant>
#include <optional>
#include <atomic>
#include <mutex>
#include <shared_mutex>
#include <cstdint>

namespace rawrxd::cognitive {

// ============================================================================
// Forward Declarations
// ============================================================================

class EnhancedBlackboard;
class MissionDirector;
class ReflectionAgent;
class DynamicPlanner;
class AutonomousOrchestrator;

// ============================================================================
// Confidence Type
// ============================================================================

using Confidence = float; // 0.0f - 1.0f

// ============================================================================
// Evidence - Atomic piece of information discovered by an agent
// ============================================================================

struct Evidence {
    std::string id;                    // Unique identifier (UUID)
    std::string description;           // Human-readable description
    std::string source_agent;          // Agent that produced this evidence
    std::string target_hypothesis;     // Hypothesis this evidence relates to
    Confidence confidence{0.5f};         // Individual confidence [0.0, 1.0]
    float weight{1.0f};                // +1.0 for supporting, -1.0 for contradicting
    std::chrono::system_clock::time_point timestamp;
    std::unordered_map<std::string, std::string> metadata; // Agent-specific data
    std::vector<std::string> supports;      // Evidence IDs this supports
    std::vector<std::string> contradicts;   // Evidence IDs this contradicts

    Evidence() = default;
    Evidence(std::string desc, std::string agent, Confidence conf = 0.5f, float w = 1.0f)
        : description(std::move(desc)), source_agent(std::move(agent)),
          confidence(conf), weight(w), timestamp(std::chrono::system_clock::now()) {}
};

// ============================================================================
// Hypothesis - An interpretation of multiple evidence pieces
// ============================================================================

struct Hypothesis {
    std::string id;                    // Unique identifier
    std::string claim;                 // The actual hypothesis statement
    std::string domain;                // e.g., "packing", "crypto", "network"
    Confidence confidence{0.0f};     // Aggregated confidence [0.0, 1.0]
    
    enum class Status {
        UNVERIFIED,    // Initial state
        UNDER_TEST,    // Being actively investigated
        CONFIRMED,     // High confidence, verified
        REFUTED,       // Contradicted by evidence
        MUTATED,       // Modified based on new evidence
        DEPRECATED     // Replaced by better hypothesis
    } status{Status::UNVERIFIED};
    
    std::vector<std::string> supporting_evidence;
    std::vector<std::string> contradicting_evidence;
    std::vector<std::string> pending_verification;
    std::string proposed_next_action;  // Suggested next step
    std::string parent_mission;        // Mission this belongs to
    
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point last_updated;
    
    // Priority for investigation (higher = more urgent)
    int priority{50};
    
    Hypothesis() = default;
    Hypothesis(std::string c, std::string dom, int pri = 50)
        : claim(std::move(c)), domain(std::move(dom)), priority(pri),
          created(std::chrono::system_clock::now()),
          last_updated(std::chrono::system_clock::now()) {}
};

// ============================================================================
// Mission Goal Types
// ============================================================================

enum class MissionType {
    EXTRACT_C2,           // Extract command & control endpoints
    IDENTIFY_MALWARE,     // Classify malware family
    REVERSE_PROTOCOL,     // Reverse engineer network protocol
    FIND_VULNERABILITY,   // Discover security vulnerabilities
    UNPACK_BINARY,        // Deobfuscate packed binary
    ANALYZE_CRYPTO,       // Identify cryptographic algorithms
    TRACE_EXECUTION,      // Dynamic execution tracing
    EXFILTRATION_PATTERN, // Detect data exfiltration patterns
    GENERIC_ANALYSIS,     // Open-ended analysis
    CUSTOM                // User-defined goal
};

std::string MissionTypeToString(MissionType type);
MissionType StringToMissionType(const std::string& str);

// ============================================================================
// SubGoal - Decomposed unit of work
// ============================================================================

struct SubGoal {
    std::string id;                    // Unique identifier
    std::string description;           // What needs to be done
    MissionType mission_type;          // Parent mission type
    std::vector<std::string> dependencies; // IDs of sub-goals that must complete first
    std::vector<std::string> required_capabilities; // e.g., "entropy", "decompiler"
    int priority{50};                  // 0-100, higher = more urgent
    Confidence confidence_threshold{0.7f}; // Minimum confidence to consider complete
    std::chrono::seconds timeout{300}; // Default 5 minutes
    
    enum class Status {
        PENDING,      // Waiting to start
        IN_PROGRESS,  // Currently executing
        COMPLETE,     // Finished successfully
        FAILED,       // Execution failed
        BLOCKED,      // Waiting for dependencies
        CANCELLED     // Explicitly cancelled
    } status{Status::PENDING};
    
    Confidence current_confidence{0.0f};
    std::string assigned_agent;        // Agent currently working on this
    std::vector<std::string> evidence_ids; // Evidence produced by this sub-goal
    std::string parent_mission;
    std::chrono::system_clock::time_point created;
    std::chrono::system_clock::time_point started;
    std::chrono::system_clock::time_point completed;
    std::string failure_reason;        // If status == FAILED
    
    SubGoal() = default;
    SubGoal(std::string desc, MissionType mt, int pri = 50)
        : description(std::move(desc)), mission_type(mt), priority(pri),
          created(std::chrono::system_clock::now()) {}
    
    bool IsRunnable() const {
        return status == Status::PENDING || status == Status::BLOCKED;
    }
    
    bool IsTerminal() const {
        return status == Status::COMPLETE || 
               status == Status::FAILED || 
               status == Status::CANCELLED;
    }
};

// ============================================================================
// Task - Executable unit scheduled by DynamicPlanner
// ============================================================================

struct Task {
    std::string id;
    SubGoal subgoal;
    std::vector<std::string> dependencies;
    int priority{50};
    std::chrono::system_clock::time_point scheduled_time;
    std::chrono::seconds deadline{300};
    std::chrono::system_clock::time_point started_time;
    std::string assigned_agent;
    bool completed{false};
    bool failed{false};
    std::string failure_reason;
    
    bool operator<(const Task& other) const {
        return priority < other.priority; // Higher priority first in max-heap
    }
    
    bool IsExpired() const {
        return std::chrono::system_clock::now() > (scheduled_time + deadline);
    }
};

// ============================================================================
// Capability - What an agent can do
// ============================================================================

struct Capability {
    std::string name;                  // e.g., "entropy_analysis"
    std::string description;
    std::vector<std::string> required_tools;
    float estimated_cost{1.0f};        // Relative computational cost
    float typical_accuracy{0.8f};    // Historical accuracy
    std::chrono::milliseconds typical_duration{1000};
    
    bool operator==(const Capability& other) const { return name == other.name; }
};

// ============================================================================
// Agent Performance Metrics
// ============================================================================

struct AgentPerformance {
    std::string agent_name;
    int total_tasks{0};
    int successful_tasks{0};
    int failed_tasks{0};
    float average_confidence{0.0f};
    float average_duration_ms{0.0f};
    std::chrono::system_clock::time_point last_executed;
    std::unordered_map<std::string, float> capability_scores; // Per-capability success rate
    
    float SuccessRate() const {
        return total_tasks > 0 ? static_cast<float>(successful_tasks) / total_tasks : 0.0f;
    }
};

// ============================================================================
// Mission Metrics
// ============================================================================

struct MissionMetrics {
    std::string mission_id;
    std::string goal_description;
    MissionType type;
    std::chrono::system_clock::time_point start_time;
    std::chrono::system_clock::time_point end_time;
    int total_subgoals{0};
    int completed_subgoals{0};
    int failed_subgoals{0};
    int replans_triggered{0};
    Confidence final_confidence{0.0f};
    std::vector<std::string> key_findings;
    std::vector<std::string> unresolved_questions;
    std::unordered_map<std::string, float> agent_contributions;
    float total_execution_time_ms{0.0f};
    
    float CompletionPercentage() const {
        return total_subgoals > 0 ? 
            static_cast<float>(completed_subgoals) / total_subgoals * 100.0f : 0.0f;
    }
    
    bool IsComplete() const {
        return completed_subgoals + failed_subgoals >= total_subgoals;
    }
};

// ============================================================================
// Cognitive State Snapshot
// ============================================================================

struct CognitiveState {
    std::vector<Hypothesis> active_hypotheses;
    std::vector<Evidence> recent_evidence;
    std::vector<Task> pending_tasks;
    std::vector<Task> active_tasks;
    std::unordered_map<std::string, Confidence> confidence_by_domain;
    std::string current_focus;         // Most important hypothesis being worked on
    std::string current_phase;         // Current mission phase
    std::chrono::system_clock::time_point last_update;
    int total_reflections{0};
    int total_replans{0};
};

// ============================================================================
// Utility Functions
// ============================================================================

std::string GenerateUUID();
std::string StatusToString(SubGoal::Status status);
std::string StatusToString(Hypothesis::Status status);
Confidence AggregateConfidence(const std::vector<std::string>& evidence_ids,
                                const std::unordered_map<std::string, Evidence>& evidence_pool);

} // namespace rawrxd::cognitive
