/**
 * @file mission_director.cpp
 * @brief Implementation of Mission Director goal decomposition engine
 */

#include "mission_director.hpp"
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <queue>

namespace rawrxd::cognitive {

// ============================================================================
// DependencyGraph Implementation
// ============================================================================

bool DependencyGraph::HasCycle() const {
    std::unordered_map<std::string, int> in_degree;
    for (const auto& [node, deps] : reverse_edges) {
        in_degree[node] = static_cast<int>(deps.size());
    }
    
    std::queue<std::string> queue;
    for (const auto& [node, degree] : in_degree) {
        if (degree == 0) queue.push(node);
    }
    
    int visited = 0;
    while (!queue.empty()) {
        auto node = queue.front(); queue.pop();
        visited++;
        
        auto it = edges.find(node);
        if (it != edges.end()) {
            for (const auto& dependent : it->second) {
                in_degree[dependent]--;
                if (in_degree[dependent] == 0) queue.push(dependent);
            }
        }
    }
    
    return visited != static_cast<int>(in_degree.size());
}

std::vector<std::string> DependencyGraph::GetRoots() const {
    std::vector<std::string> roots;
    for (const auto& [node, deps] : reverse_edges) {
        if (deps.empty()) roots.push_back(node);
    }
    return roots;
}

std::vector<std::string> DependencyGraph::GetLeaves() const {
    std::vector<std::string> leaves;
    for (const auto& [node, dependents] : edges) {
        if (dependents.empty()) leaves.push_back(node);
    }
    return leaves;
}

std::vector<std::string> DependencyGraph::GetReadyNodes(const std::unordered_set<std::string>& completed) const {
    std::vector<std::string> ready;
    for (const auto& [node, deps] : reverse_edges) {
        if (completed.count(node)) continue; // Already done
        
        bool all_deps_met = true;
        for (const auto& dep : deps) {
            if (!completed.count(dep)) {
                all_deps_met = false;
                break;
            }
        }
        if (all_deps_met) ready.push_back(node);
    }
    return ready;
}

// ============================================================================
// MissionDirector Implementation
// ============================================================================

MissionDirector::MissionDirector(EnhancedBlackboard* blackboard)
    : m_blackboard(blackboard) {
    RegisterBuiltinTemplates();
}

void MissionDirector::RegisterBuiltinTemplates() {
    // C2 Extraction Template
    RegisterTemplate(MissionType::EXTRACT_C2,
        "C2 Extraction",
        "Extract command and control endpoints from a binary",
        [this](const std::string& target, const std::unordered_map<std::string, std::string>& params) {
            return DecomposeC2Extraction(target, params);
        });
    
    // Malware Classification Template
    RegisterTemplate(MissionType::IDENTIFY_MALWARE,
        "Malware Classification",
        "Identify and classify malware family",
        [this](const std::string& target, const std::unordered_map<std::string, std::string>& params) {
            return DecomposeMalwareClassification(target, params);
        });
    
    // Unpack Binary Template
    RegisterTemplate(MissionType::UNPACK_BINARY,
        "Binary Unpacking",
        "Deobfuscate and unpack a packed binary",
        [this](const std::string& target, const std::unordered_map<std::string, std::string>& params) {
            return DecomposeUnpackBinary(target, params);
        });
    
    // Protocol Reverse Engineering Template
    RegisterTemplate(MissionType::REVERSE_PROTOCOL,
        "Protocol Reverse Engineering",
        "Reverse engineer network protocol implementation",
        [this](const std::string& target, const std::unordered_map<std::string, std::string>& params) {
            return DecomposeProtocolReverse(target, params);
        });
    
    // Crypto Analysis Template
    RegisterTemplate(MissionType::ANALYZE_CRYPTO,
        "Cryptographic Analysis",
        "Identify and analyze cryptographic algorithms",
        [this](const std::string& target, const std::unordered_map<std::string, std::string>& params) {
            return DecomposeCryptoAnalysis(target, params);
        });
    
    // Generic Analysis Template
    RegisterTemplate(MissionType::GENERIC_ANALYSIS,
        "Generic Analysis",
        "Open-ended binary analysis",
        [this](const std::string& target, const std::unordered_map<std::string, std::string>& params) {
            return DecomposeGenericAnalysis(target, params);
        });
}

// ============================================================================
// Goal Decomposition
// ============================================================================

std::vector<SubGoal> MissionDirector::DecomposeGoal(const std::string& goal_description,
                                                      MissionType goal_type,
                                                      const std::string& target_artifact,
                                                      const std::unordered_map<std::string, std::string>& parameters) {
    std::unique_lock lock(m_mutex);
    
    auto templ = GetTemplate(goal_type);
    if (!templ) {
        // Fallback to generic analysis
        templ = GetTemplate(MissionType::GENERIC_ANALYSIS);
    }
    
    if (!templ) {
        // Ultimate fallback: single sub-goal
        std::vector<SubGoal> fallback;
        fallback.push_back(CreateSubGoal(
            goal_description, goal_type, {}, {}, 50, 0.7f, "mission_" + GenerateUUID()));
        return fallback;
    }
    
    auto subgoals = templ->decomposer(target_artifact, parameters);
    
    // Post-process: ensure all sub-goals have proper mission IDs
    std::string mission_id = "mission_" + GenerateUUID();
    for (auto& sg : subgoals) {
        sg.parent_mission = mission_id;
        if (sg.id.empty()) sg.id = GenerateUUID();
    }
    
    // Build and validate dependency graph
    auto graph = BuildDependencyGraph(subgoals);
    if (graph.HasCycle()) {
        // Remove cycles by clearing dependencies that create cycles
        // (simplification: make all sub-goals independent)
        for (auto& sg : subgoals) {
            sg.dependencies.clear();
        }
    }
    
    return subgoals;
}

std::vector<SubGoal> MissionDirector::DynamicDecompose(const std::string& parent_goal_id,
                                                         const std::unordered_map<std::string, float>& discovered_features) {
    std::vector<SubGoal> new_subgoals;
    
    // Analyze discovered features and generate new sub-goals
    for (const auto& [feature, confidence] : discovered_features) {
        if (feature == "packed" && confidence > 0.7f) {
            new_subgoals.push_back(CreateSubGoal(
                "Unpack binary and analyze unpacked payload",
                MissionType::UNPACK_BINARY,
                {parent_goal_id},
                {"entropy", "pattern", "unpacker"},
                80, 0.8f, parent_goal_id));
        }
        else if (feature == "encrypted_strings" && confidence > 0.6f) {
            new_subgoals.push_back(CreateSubGoal(
                "Decrypt and analyze encrypted strings",
                MissionType::ANALYZE_CRYPTO,
                {parent_goal_id},
                {"crypto", "strings"},
                75, 0.7f, parent_goal_id));
        }
        else if (feature == "network_apis" && confidence > 0.6f) {
            new_subgoals.push_back(CreateSubGoal(
                "Trace network API calls and extract endpoints",
                MissionType::EXTRACT_C2,
                {parent_goal_id},
                {"debugger", "api_trace", "network"},
                85, 0.8f, parent_goal_id));
        }
        else if (feature == "vm_detected" && confidence > 0.8f) {
            new_subgoals.push_back(CreateSubGoal(
                "Analyze virtual machine / bytecode protection",
                MissionType::UNPACK_BINARY,
                {parent_goal_id},
                {"vm", "decompiler", "pattern"},
                90, 0.9f, parent_goal_id));
        }
    }
    
    return new_subgoals;
}

// ============================================================================
// Replanning
// ============================================================================

std::vector<SubGoal> MissionDirector::Replan(const std::vector<SubGoal>& current_plan,
                                               const std::vector<std::string>& completed_ids,
                                               const std::vector<std::string>& failed_ids,
                                               const std::unordered_map<std::string, float>& new_evidence_confidences) {
    std::vector<SubGoal> updated_plan = current_plan;
    std::unordered_set<std::string> completed_set(completed_ids.begin(), completed_ids.end());
    std::unordered_set<std::string> failed_set(failed_ids.begin(), failed_ids.end());
    
    // Update statuses
    for (auto& sg : updated_plan) {
        if (completed_set.count(sg.id)) {
            sg.status = SubGoal::Status::COMPLETE;
        } else if (failed_set.count(sg.id)) {
            sg.status = SubGoal::Status::FAILED;
        } else {
            // Check if dependencies are met
            bool deps_met = true;
            for (const auto& dep : sg.dependencies) {
                if (!completed_set.count(dep)) {
                    deps_met = false;
                    break;
                }
            }
            sg.status = deps_met ? SubGoal::Status::PENDING : SubGoal::Status::BLOCKED;
        }
    }
    
    // Recalculate priorities based on new evidence
    RecalculatePriorities(updated_plan, new_evidence_confidences);
    
    // For failed sub-goals, add retry sub-goals with alternative approaches
    for (const auto& sg : updated_plan) {
        if (sg.status == SubGoal::Status::FAILED) {
            // Add a retry with different capabilities
            SubGoal retry = sg;
            retry.id = GenerateUUID();
            retry.status = SubGoal::Status::PENDING;
            retry.description = "[RETRY] " + sg.description;
            retry.priority = std::min(sg.priority + 10, 100); // Boost priority
            retry.confidence_threshold = std::max(sg.confidence_threshold - 0.1f, 0.3f); // Lower threshold
            
            // Swap capabilities for alternatives
            if (!retry.required_capabilities.empty()) {
                std::rotate(retry.required_capabilities.begin(),
                           retry.required_capabilities.begin() + 1,
                           retry.required_capabilities.end());
            }
            
            updated_plan.push_back(retry);
        }
    }
    
    return updated_plan;
}

void MissionDirector::InjectSubGoals(std::vector<SubGoal>& plan,
                                     const std::vector<SubGoal>& new_subgoals,
                                     const std::string& after_dependency) {
    for (const auto& new_sg : new_subgoals) {
        SubGoal sg = new_sg;
        sg.id = GenerateUUID();
        if (!after_dependency.empty()) {
            sg.dependencies.push_back(after_dependency);
        }
        plan.push_back(sg);
    }
}

// ============================================================================
// Dependency Management
// ============================================================================

DependencyGraph MissionDirector::BuildDependencyGraph(const std::vector<SubGoal>& subgoals) const {
    DependencyGraph graph;
    
    for (const auto& sg : subgoals) {
        // Add node
        if (graph.edges.find(sg.id) == graph.edges.end()) {
            graph.edges[sg.id] = {};
        }
        if (graph.reverse_edges.find(sg.id) == graph.reverse_edges.end()) {
            graph.reverse_edges[sg.id] = {};
        }
        
        // Add edges
        for (const auto& dep : sg.dependencies) {
            graph.edges[dep].push_back(sg.id);
            graph.reverse_edges[sg.id].push_back(dep);
        }
    }
    
    // Compute topological order
    std::unordered_map<std::string, int> in_degree;
    for (const auto& [node, deps] : graph.reverse_edges) {
        in_degree[node] = static_cast<int>(deps.size());
    }
    
    std::queue<std::string> queue;
    for (const auto& [node, degree] : in_degree) {
        if (degree == 0) queue.push(node);
    }
    
    while (!queue.empty()) {
        auto node = queue.front(); queue.pop();
        graph.topological_order.push_back(node);
        
        auto it = graph.edges.find(node);
        if (it != graph.edges.end()) {
            for (const auto& dependent : it->second) {
                in_degree[dependent]--;
                if (in_degree[dependent] == 0) queue.push(dependent);
            }
        }
    }
    
    return graph;
}

bool MissionDirector::ValidateDependencies(const std::vector<SubGoal>& subgoals) const {
    auto graph = BuildDependencyGraph(subgoals);
    return !graph.HasCycle();
}

std::vector<std::string> MissionDirector::FindCriticalPath(const std::vector<SubGoal>& subgoals) const {
    auto graph = BuildDependencyGraph(subgoals);
    
    // Find longest path from roots to leaves
    std::unordered_map<std::string, int> longest_path;
    std::unordered_map<std::string, std::string> predecessor;
    
    for (const auto& node : graph.topological_order) {
        longest_path[node] = 1;
        
        auto rev_it = graph.reverse_edges.find(node);
        if (rev_it != graph.reverse_edges.end()) {
            for (const auto& dep : rev_it->second) {
                if (longest_path[dep] + 1 > longest_path[node]) {
                    longest_path[node] = longest_path[dep] + 1;
                    predecessor[node] = dep;
                }
            }
        }
    }
    
    // Find leaf with longest path
    std::string best_leaf;
    int best_length = 0;
    for (const auto& leaf : graph.GetLeaves()) {
        if (longest_path[leaf] > best_length) {
            best_length = longest_path[leaf];
            best_leaf = leaf;
        }
    }
    
    // Reconstruct path
    std::vector<std::string> path;
    std::string current = best_leaf;
    while (!current.empty()) {
        path.push_back(current);
        auto it = predecessor.find(current);
        if (it != predecessor.end()) {
            current = it->second;
        } else {
            break;
        }
    }
    
    std::reverse(path.begin(), path.end());
    return path;
}

// ============================================================================
// Priority Calculation
// ============================================================================

void MissionDirector::RecalculatePriorities(std::vector<SubGoal>& subgoals,
                                            const std::unordered_map<std::string, float>& global_confidences) {
    for (auto& sg : subgoals) {
        sg.priority = this->CalculatePriority(sg, global_confidences);
    }
}

int MissionDirector::CalculatePriority(const SubGoal& sg,
                                       const std::unordered_map<std::string, float>& global_confidences) const {
    int base_priority = sg.priority;
    
    // Boost priority for sub-goals with high-confidence evidence
    for (const auto& [domain, confidence] : global_confidences) {
        if (std::find(sg.required_capabilities.begin(), sg.required_capabilities.end(), domain) 
            != sg.required_capabilities.end()) {
            base_priority += static_cast<int>(confidence * 20); // Up to +20 boost
        }
    }
    
    // Boost for sub-goals on critical path
    // (simplified: boost if many dependents)
    auto graph = BuildDependencyGraph({sg});
    auto it = graph.edges.find(sg.id);
    if (it != graph.edges.end()) {
        base_priority += static_cast<int>(it->second.size() * 5); // +5 per dependent
    }
    
    return std::min(base_priority, 100);
}

// ============================================================================
// Template Management
// ============================================================================

void MissionDirector::RegisterTemplate(const DecompositionTemplate& templ) {
    std::unique_lock lock(m_mutex);
    m_templates[templ.mission_type] = templ;
}

void MissionDirector::RegisterTemplate(MissionType type,
                                       const std::string& name,
                                       const std::string& description,
                                       std::function<std::vector<SubGoal>(const std::string&, 
                                                                              const std::unordered_map<std::string, std::string>&)> decomposer) {
    DecompositionTemplate templ;
    templ.mission_type = type;
    templ.name = name;
    templ.description = description;
    templ.decomposer = decomposer;
    RegisterTemplate(templ);
}

bool MissionDirector::HasTemplate(MissionType type) const {
    std::shared_lock lock(m_mutex);
    return m_templates.find(type) != m_templates.end();
}

std::optional<DecompositionTemplate> MissionDirector::GetTemplate(MissionType type) const {
    std::shared_lock lock(m_mutex);
    auto it = m_templates.find(type);
    if (it != m_templates.end()) return it->second;
    return std::nullopt;
}

std::vector<DecompositionTemplate> MissionDirector::GetAllTemplates() const {
    std::shared_lock lock(m_mutex);
    std::vector<DecompositionTemplate> result;
    for (const auto& [type, templ] : m_templates) {
        result.push_back(templ);
    }
    return result;
}

// ============================================================================
// Visualization
// ============================================================================

std::string MissionDirector::GenerateDependencyGraphviz(const std::vector<SubGoal>& subgoals) const {
    auto graph = BuildDependencyGraph(subgoals);
    
    std::ostringstream oss;
    oss << "digraph Mission {\n";
    oss << "  rankdir=TB;\n";
    oss << "  node [shape=box, style=\"rounded,filled\", fontname=\"Helvetica\"];\n\n";
    
    // Nodes
    for (const auto& sg : subgoals) {
        std::string color = "lightblue";
        switch (sg.status) {
            case SubGoal::Status::COMPLETE: color = "lightgreen"; break;
            case SubGoal::Status::FAILED: color = "lightcoral"; break;
            case SubGoal::Status::IN_PROGRESS: color = "lightyellow"; break;
            case SubGoal::Status::BLOCKED: color = "lightgray"; break;
            default: color = "lightblue"; break;
        }
        
        oss << "  \"" << sg.id << "\" [label=\"" << sg.description.substr(0, 30);
        if (sg.description.length() > 30) oss << "...";
        oss << "\", fillcolor=" << color << "];\n";
    }
    
    // Edges
    for (const auto& sg : subgoals) {
        for (const auto& dep : sg.dependencies) {
            oss << "  \"" << dep << "\" -> \"" << sg.id << "\";\n";
        }
    }
    
    oss << "}\n";
    return oss.str();
}

std::string MissionDirector::GenerateMissionSummary(const std::vector<SubGoal>& subgoals,
                                                     const std::string& mission_id) const {
    std::ostringstream oss;
    
    int total = static_cast<int>(subgoals.size());
    int complete = 0, failed = 0, in_progress = 0, pending = 0, blocked = 0;
    
    for (const auto& sg : subgoals) {
        switch (sg.status) {
            case SubGoal::Status::COMPLETE: complete++; break;
            case SubGoal::Status::FAILED: failed++; break;
            case SubGoal::Status::IN_PROGRESS: in_progress++; break;
            case SubGoal::Status::PENDING: pending++; break;
            case SubGoal::Status::BLOCKED: blocked++; break;
            default: break;
        }
    }
    
    float progress = total > 0 ? (static_cast<float>(complete) / total * 100.0f) : 0.0f;
    
    oss << "=== Mission Summary: " << mission_id << " ===\n";
    oss << "Total SubGoals: " << total << "\n";
    oss << "Progress: " << std::fixed << std::setprecision(1) << progress << "%\n";
    oss << "  Complete: " << complete << "\n";
    oss << "  In Progress: " << in_progress << "\n";
    oss << "  Pending: " << pending << "\n";
    oss << "  Blocked: " << blocked << "\n";
    oss << "  Failed: " << failed << "\n";
    
    auto graph = BuildDependencyGraph(subgoals);
    auto critical_path = FindCriticalPath(subgoals);
    oss << "\nCritical Path Length: " << critical_path.size() << " nodes\n";
    
    return oss.str();
}

// ============================================================================
// Utility
// ============================================================================

std::vector<SubGoal> MissionDirector::FilterByStatus(const std::vector<SubGoal>& subgoals,
                                                      SubGoal::Status status) const {
    std::vector<SubGoal> result;
    for (const auto& sg : subgoals) {
        if (sg.status == status) result.push_back(sg);
    }
    return result;
}

std::vector<SubGoal> MissionDirector::GetRunnableSubGoals(const std::vector<SubGoal>& subgoals) const {
    std::vector<SubGoal> result;
    std::unordered_set<std::string> completed;
    
    for (const auto& sg : subgoals) {
        if (sg.status == SubGoal::Status::COMPLETE) {
            completed.insert(sg.id);
        }
    }
    
    for (const auto& sg : subgoals) {
        if (sg.status == SubGoal::Status::PENDING || sg.status == SubGoal::Status::BLOCKED) {
            bool deps_met = true;
            for (const auto& dep : sg.dependencies) {
                if (!completed.count(dep)) {
                    deps_met = false;
                    break;
                }
            }
            if (deps_met) result.push_back(sg);
        }
    }
    
    return result;
}

float MissionDirector::CalculateMissionProgress(const std::vector<SubGoal>& subgoals) const {
    if (subgoals.empty()) return 0.0f;
    
    int complete = 0;
    for (const auto& sg : subgoals) {
        if (sg.status == SubGoal::Status::COMPLETE) complete++;
    }
    
    return static_cast<float>(complete) / static_cast<float>(subgoals.size());
}

// ============================================================================
// Built-in Decomposition Templates
// ============================================================================

std::vector<SubGoal> MissionDirector::DecomposeC2Extraction(const std::string& target,
                                                             const std::unordered_map<std::string, std::string>& params) {
    std::vector<SubGoal> subgoals;
    std::string mission_id = "c2_" + GenerateUUID();
    
    // Phase 1: Initial reconnaissance
    auto sg1 = CreateSubGoal("Static analysis: identify network-related imports and strings",
                             MissionType::EXTRACT_C2, {}, {"strings", "imports"}, 60, 0.6f, mission_id);
    
    // Phase 2: String decryption
    auto sg2 = CreateSubGoal("Decrypt and analyze encrypted/obfuscated strings",
                             MissionType::EXTRACT_C2, {sg1.id}, {"crypto", "strings"}, 70, 0.7f, mission_id);
    
    // Phase 3: API tracing
    auto sg3 = CreateSubGoal("Trace network API calls (WinInet, WinHTTP, sockets)",
                             MissionType::EXTRACT_C2, {sg1.id}, {"debugger", "api_trace"}, 80, 0.8f, mission_id);
    
    // Phase 4: Dynamic analysis
    auto sg4 = CreateSubGoal("Execute in sandbox and capture network traffic",
                             MissionType::EXTRACT_C2, {sg3.id}, {"sandbox", "network"}, 90, 0.9f, mission_id);
    
    // Phase 5: Configuration extraction
    auto sg5 = CreateSubGoal("Extract C2 configuration from memory or registry",
                             MissionType::EXTRACT_C2, {sg2.id, sg4.id}, {"memory", "registry"}, 85, 0.8f, mission_id);
    
    subgoals.push_back(sg1);
    subgoals.push_back(sg2);
    subgoals.push_back(sg3);
    subgoals.push_back(sg4);
    subgoals.push_back(sg5);
    
    return subgoals;
}

std::vector<SubGoal> MissionDirector::DecomposeMalwareClassification(const std::string& target,
                                                                       const std::unordered_map<std::string, std::string>& params) {
    std::vector<SubGoal> subgoals;
    std::string mission_id = "classify_" + GenerateUUID();
    
    auto sg1 = CreateSubGoal("Calculate file hashes and check known databases",
                             MissionType::IDENTIFY_MALWARE, {}, {"hash", "database"}, 50, 0.5f, mission_id);
    
    auto sg2 = CreateSubGoal("Extract and analyze PE headers and sections",
                             MissionType::IDENTIFY_MALWARE, {sg1.id}, {"pe_parser", "entropy"}, 60, 0.6f, mission_id);
    
    auto sg3 = CreateSubGoal("Identify packer/ compiler signatures",
                             MissionType::IDENTIFY_MALWARE, {sg2.id}, {"signature", "pattern"}, 70, 0.7f, mission_id);
    
    auto sg4 = CreateSubGoal("Extract and classify embedded strings",
                             MissionType::IDENTIFY_MALWARE, {sg2.id}, {"strings", "ml"}, 65, 0.6f, mission_id);
    
    auto sg5 = CreateSubGoal("Generate behavioral profile from API imports",
                             MissionType::IDENTIFY_MALWARE, {sg3.id, sg4.id}, {"api_analysis", "ml"}, 75, 0.7f, mission_id);
    
    auto sg6 = CreateSubGoal("Compare against known malware families",
                             MissionType::IDENTIFY_MALWARE, {sg5.id}, {"database", "ml", "similarity"}, 80, 0.8f, mission_id);
    
    subgoals.push_back(sg1);
    subgoals.push_back(sg2);
    subgoals.push_back(sg3);
    subgoals.push_back(sg4);
    subgoals.push_back(sg5);
    subgoals.push_back(sg6);
    
    return subgoals;
}

std::vector<SubGoal> MissionDirector::DecomposeUnpackBinary(const std::string& target,
                                                              const std::unordered_map<std::string, std::string>& params) {
    std::vector<SubGoal> subgoals;
    std::string mission_id = "unpack_" + GenerateUUID();
    
    auto sg1 = CreateSubGoal("Detect packer type and version",
                             MissionType::UNPACK_BINARY, {}, {"signature", "entropy", "pattern"}, 70, 0.7f, mission_id);
    
    auto sg2 = CreateSubGoal("Identify unpacking stub entry point",
                             MissionType::UNPACK_BINARY, {sg1.id}, {"decompiler", "debugger"}, 75, 0.7f, mission_id);
    
    auto sg3 = CreateSubGoal("Trace execution to OEP (Original Entry Point)",
                             MissionType::UNPACK_BINARY, {sg2.id}, {"debugger", "trace"}, 85, 0.8f, mission_id);
    
    auto sg4 = CreateSubGoal("Dump unpacked memory regions",
                             MissionType::UNPACK_BINARY, {sg3.id}, {"memory", "dump"}, 80, 0.8f, mission_id);
    
    auto sg5 = CreateSubGoal("Reconstruct PE headers for dumped image",
                             MissionType::UNPACK_BINARY, {sg4.id}, {"pe_rebuild", "fix_imports"}, 75, 0.7f, mission_id);
    
    auto sg6 = CreateSubGoal("Validate unpacked binary integrity",
                             MissionType::UNPACK_BINARY, {sg5.id}, {"pe_validator", "hash"}, 70, 0.7f, mission_id);
    
    subgoals.push_back(sg1);
    subgoals.push_back(sg2);
    subgoals.push_back(sg3);
    subgoals.push_back(sg4);
    subgoals.push_back(sg5);
    subgoals.push_back(sg6);
    
    return subgoals;
}

std::vector<SubGoal> MissionDirector::DecomposeProtocolReverse(const std::string& target,
                                                                 const std::unordered_map<std::string, std::string>& params) {
    std::vector<SubGoal> subgoals;
    std::string mission_id = "protocol_" + GenerateUUID();
    
    auto sg1 = CreateSubGoal("Identify network-related functions and callbacks",
                             MissionType::REVERSE_PROTOCOL, {}, {"api_trace", "decompiler"}, 60, 0.6f, mission_id);
    
    auto sg2 = CreateSubGoal("Capture sample network traffic",
                             MissionType::REVERSE_PROTOCOL, {}, {"pcap", "proxy"}, 70, 0.7f, mission_id);
    
    auto sg3 = CreateSubGoal("Analyze packet structure and fields",
                             MissionType::REVERSE_PROTOCOL, {sg2.id}, {"protocol", "structure"}, 75, 0.7f, mission_id);
    
    auto sg4 = CreateSubGoal("Identify encryption/encoding in protocol",
                             MissionType::REVERSE_PROTOCOL, {sg3.id}, {"crypto", "pattern"}, 80, 0.8f, mission_id);
    
    auto sg5 = CreateSubGoal("Map protocol state machine",
                             MissionType::REVERSE_PROTOCOL, {sg3.id, sg4.id}, {"state_machine", "trace"}, 85, 0.8f, mission_id);
    
    auto sg6 = CreateSubGoal("Generate protocol documentation",
                             MissionType::REVERSE_PROTOCOL, {sg5.id}, {"documentation", "test"}, 60, 0.5f, mission_id);
    
    subgoals.push_back(sg1);
    subgoals.push_back(sg2);
    subgoals.push_back(sg3);
    subgoals.push_back(sg4);
    subgoals.push_back(sg5);
    subgoals.push_back(sg6);
    
    return subgoals;
}

std::vector<SubGoal> MissionDirector::DecomposeCryptoAnalysis(const std::string& target,
                                                                const std::unordered_map<std::string, std::string>& params) {
    std::vector<SubGoal> subgoals;
    std::string mission_id = "crypto_" + GenerateUUID();
    
    auto sg1 = CreateSubGoal("Identify cryptographic constants (S-boxes, IVs, magic numbers)",
                             MissionType::ANALYZE_CRYPTO, {}, {"constants", "signature"}, 70, 0.7f, mission_id);
    
    auto sg2 = CreateSubGoal("Detect known crypto API calls",
                             MissionType::ANALYZE_CRYPTO, {}, {"api_trace", "imports"}, 65, 0.6f, mission_id);
    
    auto sg3 = CreateSubGoal("Analyze entropy distribution in data sections",
                             MissionType::ANALYZE_CRYPTO, {sg1.id}, {"entropy", "statistics"}, 75, 0.7f, mission_id);
    
    auto sg4 = CreateSubGoal("Identify custom encryption routines",
                             MissionType::ANALYZE_CRYPTO, {sg2.id, sg3.id}, {"decompiler", "pattern"}, 80, 0.8f, mission_id);
    
    auto sg5 = CreateSubGoal("Extract keys and parameters from memory",
                             MissionType::ANALYZE_CRYPTO, {sg4.id}, {"memory", "debugger"}, 85, 0.8f, mission_id);
    
    auto sg6 = CreateSubGoal("Validate crypto identification with test decryption",
                             MissionType::ANALYZE_CRYPTO, {sg5.id}, {"test", "validator"}, 75, 0.7f, mission_id);
    
    subgoals.push_back(sg1);
    subgoals.push_back(sg2);
    subgoals.push_back(sg3);
    subgoals.push_back(sg4);
    subgoals.push_back(sg5);
    subgoals.push_back(sg6);
    
    return subgoals;
}

std::vector<SubGoal> MissionDirector::DecomposeGenericAnalysis(const std::string& target,
                                                                 const std::unordered_map<std::string, std::string>& params) {
    std::vector<SubGoal> subgoals;
    std::string mission_id = "generic_" + GenerateUUID();
    
    auto sg1 = CreateSubGoal("Perform initial static analysis (headers, sections, imports)",
                             MissionType::GENERIC_ANALYSIS, {}, {"pe_parser", "entropy"}, 50, 0.5f, mission_id);
    
    auto sg2 = CreateSubGoal("Extract and analyze strings",
                             MissionType::GENERIC_ANALYSIS, {sg1.id}, {"strings", "analysis"}, 55, 0.5f, mission_id);
    
    auto sg3 = CreateSubGoal("Identify code patterns and signatures",
                             MissionType::GENERIC_ANALYSIS, {sg1.id}, {"pattern", "signature"}, 60, 0.6f, mission_id);
    
    auto sg4 = CreateSubGoal("Generate control flow graphs for key functions",
                             MissionType::GENERIC_ANALYSIS, {sg3.id}, {"cfg", "decompiler"}, 65, 0.6f, mission_id);
    
    auto sg5 = CreateSubGoal("Perform dynamic analysis in sandbox",
                             MissionType::GENERIC_ANALYSIS, {sg4.id}, {"sandbox", "trace"}, 70, 0.7f, mission_id);
    
    auto sg6 = CreateSubGoal("Generate comprehensive analysis report",
                             MissionType::GENERIC_ANALYSIS, {sg2.id, sg5.id}, {"report", "summary"}, 50, 0.5f, mission_id);
    
    subgoals.push_back(sg1);
    subgoals.push_back(sg2);
    subgoals.push_back(sg3);
    subgoals.push_back(sg4);
    subgoals.push_back(sg5);
    subgoals.push_back(sg6);
    
    return subgoals;
}

// ============================================================================
// Helper Methods
// ============================================================================

SubGoal MissionDirector::CreateSubGoal(const std::string& description,
                                       MissionType type,
                                       const std::vector<std::string>& deps,
                                       const std::vector<std::string>& capabilities,
                                       int priority,
                                       Confidence threshold,
                                       const std::string& mission_id) {
    SubGoal sg(description, type, priority);
    sg.id = GenerateUUID();
    sg.dependencies = deps;
    sg.required_capabilities = capabilities;
    sg.confidence_threshold = threshold;
    sg.parent_mission = mission_id;
    sg.created = std::chrono::system_clock::now();
    return sg;
}

bool MissionDirector::AreDependenciesMet(const SubGoal& sg,
                                          const std::unordered_set<std::string>& completed_ids) const {
    for (const auto& dep : sg.dependencies) {
        if (!completed_ids.count(dep)) return false;
    }
    return true;
}

void MissionDirector::UpdateDependencyGraph(DependencyGraph& graph,
                                              const std::vector<SubGoal>& subgoals) const {
    // Rebuild graph from subgoals
    graph = BuildDependencyGraph(subgoals);
}

} // namespace rawrxd::cognitive
