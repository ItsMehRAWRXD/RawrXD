/**
 * EmergentRoleFormation.cpp
 *
 * Phase C.2 Batch 2/5: Emergent Role Formation Implementation
 */

#include "EmergentRoleFormation.hpp"
#include <iostream>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <numeric>
#include <cmath>
#include <random>
#include <fstream>

namespace Emergent {

// EmergentRole implementation
std::string EmergentRole::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"roleId\":\"" << roleId << "\",";
    json << "\"type\":" << static_cast<int>(type) << ",";
    json << "\"name\":\"" << name << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"agentId\":\"" << agentId << "\",";
    json << "\"assignedAtMs\":" << assignedAtMs << ",";
    json << "\"expiresAtMs\":" << expiresAtMs << ",";
    json << "\"confidence\":" << std::fixed << std::setprecision(4) << confidence << ",";
    json << "\"stability\":" << stability << ",";
    json << "\"consecutiveAssignments\":" << consecutiveAssignments << ",";
    json << "\"capabilities\":[";
    for (size_t i = 0; i < capabilities.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << capabilities[i] << "\"";
    }
    json << "]}";
    return json.str();
}

// EmergentSubGroup implementation
std::string EmergentSubGroup::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"groupId\":\"" << groupId << "\",";
    json << "\"name\":\"" << name << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"memberIds\":[";
    for (size_t i = 0; i < memberIds.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << memberIds[i] << "\"";
    }
    json << "],";
    json << "\"leaderId\":\"" << leaderId << "\",";
    json << "\"cohesion\":" << cohesion << ",";
    json << "\"stability\":" << stability << ",";
    json << "\"formedAtMs\":" << formedAtMs << ",";
    json << "\"lastActivityMs\":" << lastActivityMs << "}";
    return json.str();
}

// SpecializationPattern implementation
std::string SpecializationPattern::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"patternId\":\"" << patternId << "\",";
    json << "\"name\":\"" << name << "\",";
    json << "\"description\":\"" << description << "\",";
    json << "\"domain\":\"" << domain << "\",";
    json << "\"agentIds\":[";
    for (size_t i = 0; i < agentIds.size(); ++i) {
        if (i > 0) json << ",";
        json << "\"" << agentIds[i] << "\"";
    }
    json << "],";
    json << "\"expertiseLevel\":" << expertiseLevel << ",";
    json << "\"efficiencyGain\":" << efficiencyGain << ",";
    json << "\"taskCount\":" << taskCount << ",";
    json << "\"successRate\":" << successRate << "}";
    return json.str();
}

// EmergentHierarchy implementation
std::string EmergentHierarchy::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"hierarchyId\":\"" << hierarchyId << "\",";
    json << "\"levels\":[";
    for (size_t i = 0; i < levels.size(); ++i) {
        if (i > 0) json << ",";
        json << "{";
        json << "\"level\":" << levels[i].level << ",";
        json << "\"agentIds\":[";
        for (size_t j = 0; j < levels[i].agentIds.size(); ++j) {
            if (j > 0) json << ",";
            json << "\"" << levels[i].agentIds[j] << "\"";
        }
        json << "],";
        json << "\"authorityWeight\":" << levels[i].authorityWeight << "}";
    }
    json << "],";
    json << "\"establishedAtMs\":" << establishedAtMs << ",";
    json << "\"stability\":" << stability << "}";
    return json.str();
}

// RoleFormationResult implementation
std::string RoleFormationResult::ToJson() const {
    std::ostringstream json;
    json << "{";
    json << "\"assignedRoles\":[";
    for (size_t i = 0; i < assignedRoles.size(); ++i) {
        if (i > 0) json << ",";
        json << assignedRoles[i].ToJson();
    }
    json << "],";
    json << "\"formedGroups\":[";
    for (size_t i = 0; i < formedGroups.size(); ++i) {
        if (i > 0) json << ",";
        json << formedGroups[i].ToJson();
    }
    json << "],";
    json << "\"specializations\":[";
    for (size_t i = 0; i < specializations.size(); ++i) {
        if (i > 0) json << ",";
        json << specializations[i].ToJson();
    }
    json << "],";
    json << "\"hierarchies\":[";
    for (size_t i = 0; i < hierarchies.size(); ++i) {
        if (i > 0) json << ",";
        json << hierarchies[i].ToJson();
    }
    json << "],";
    json << "\"formationDurationMs\":" << formationDurationMs << "}";
    return json.str();
}

void RoleFormationResult::PrintSummary() const {
    std::cout << "\n╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║           EMERGENT ROLE FORMATION RESULTS                        ║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    std::cout << "║  Roles Assigned:      " << std::setw(10) << assignedRoles.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Groups Formed:      " << std::setw(10) << formedGroups.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Specializations:    " << std::setw(10) << specializations.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Hierarchies:        " << std::setw(10) << hierarchies.size() << std::string(26, ' ') << "║\n";
    std::cout << "║  Formation Time:      " << std::setw(10) << formationDurationMs << " ms" << std::string(23, ' ') << "║\n";
    std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
    
    if (!assignedRoles.empty()) {
        std::cout << "║  Assigned Roles:                                                 ║\n";
        for (const auto& role : assignedRoles) {
            std::cout << "║    " << std::left << std::setw(15) << role.name 
                      << " -> " << std::setw(20) << role.agentId
                      << " (conf: " << std::fixed << std::setprecision(2) << role.confidence << ")"
                      << std::string(8, ' ') << "║\n";
        }
    }
    
    if (!formedGroups.empty()) {
        std::cout << "╠════════════════════════════════════════════════════════════════╣\n";
        std::cout << "║  Formed Groups:                                                 ║\n";
        for (const auto& group : formedGroups) {
            std::cout << "║    " << std::left << std::setw(20) << group.name
                      << " (" << group.memberIds.size() << " members, cohesion: " 
                      << std::fixed << std::setprecision(2) << group.cohesion << ")"
                      << std::string(10, ' ') << "║\n";
        }
    }
    
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n";
}

// EmergentRoleFormation implementation
EmergentRoleFormation::EmergentRoleFormation() = default;
EmergentRoleFormation::~EmergentRoleFormation() = default;

bool EmergentRoleFormation::Initialize(const RoleFormationConfig& config) {
    config_ = config;
    agentProfiles_.clear();
    currentRoles_.clear();
    currentGroups_.clear();
    currentSpecializations_.clear();
    currentHierarchies_.clear();
    std::cout << "[EmergentRoleFormation] Initialized\n";
    return true;
}

void EmergentRoleFormation::UpdateAgentProfile(const AgentBehaviorProfile& profile) {
    agentProfiles_[profile.agentId] = profile;
}

void EmergentRoleFormation::UpdateAgentProfiles(const std::vector<AgentBehaviorProfile>& profiles) {
    for (const auto& profile : profiles) {
        UpdateAgentProfile(profile);
    }
}

RoleFormationResult EmergentRoleFormation::FormRoles() {
    auto startTime = std::chrono::high_resolution_clock::now();
    
    RoleFormationResult result;
    
    std::cout << "[EmergentRoleFormation] Forming roles for " << agentProfiles_.size() << " agents...\n";
    
    // Run formation algorithms
    result.assignedRoles = AssignRoles();
    result.formedGroups = FormSubGroups();
    result.specializations = DetectSpecializations();
    result.hierarchies = BuildHierarchies();
    
    // Update current state
    currentRoles_ = result.assignedRoles;
    currentGroups_ = result.formedGroups;
    currentSpecializations_ = result.specializations;
    currentHierarchies_ = result.hierarchies;
    
    auto endTime = std::chrono::high_resolution_clock::now();
    result.formationDurationMs = std::chrono::duration_cast<std::chrono::milliseconds>(endTime - startTime).count();
    
    std::cout << "[EmergentRoleFormation] Formation complete: " 
              << result.assignedRoles.size() << " roles, "
              << result.formedGroups.size() << " groups\n";
    
    return result;
}

std::vector<EmergentRole> EmergentRoleFormation::AssignRoles() {
    std::vector<EmergentRole> roles;
    
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    for (const auto& [agentId, profile] : agentProfiles_) {
        // Determine best role for this agent
        EmergentRoleType roleType = DetermineRoleType(profile);
        double confidence = CalculateRoleConfidence(profile, roleType);
        
        if (confidence >= config_.minConfidenceForAssignment) {
            EmergentRole role;
            role.roleId = GenerateRoleId();
            role.type = roleType;
            role.agentId = agentId;
            role.assignedAtMs = currentTime;
            role.expiresAtMs = config_.roleExpirationMs > 0 ? currentTime + config_.roleExpirationMs : 0;
            role.confidence = confidence;
            role.stability = 0.5;  // Initial stability
            role.consecutiveAssignments = 1;
            
            // Set role name based on type
            switch (roleType) {
                case EmergentRoleType::COORDINATOR: role.name = "Coordinator"; break;
                case EmergentRoleType::SPECIALIST: role.name = "Specialist"; break;
                case EmergentRoleType::GENERALIST: role.name = "Generalist"; break;
                case EmergentRoleType::MONITOR: role.name = "Monitor"; break;
                case EmergentRoleType::OPTIMIZER: role.name = "Optimizer"; break;
                case EmergentRoleType::EXPLORER: role.name = "Explorer"; break;
                case EmergentRoleType::STABILIZER: role.name = "Stabilizer"; break;
                case EmergentRoleType::ADAPTER: role.name = "Adapter"; break;
                default: role.name = "Unknown"; break;
            }
            
            role.description = "Emergent " + role.name + " role based on observed behavior";
            
            // Extract capabilities from profile
            for (const auto& [capability, level] : profile.capabilities) {
                if (level > 0.7) {
                    role.capabilities.push_back(capability);
                }
            }
            
            roles.push_back(role);
        }
    }
    
    return roles;
}

std::vector<EmergentSubGroup> EmergentRoleFormation::FormSubGroups() {
    std::vector<EmergentSubGroup> groups;
    
    if (agentProfiles_.size() < static_cast<size_t>(config_.minGroupSize)) {
        return groups;
    }
    
    // Simple clustering based on similarity
    std::vector<std::string> ungrouped;
    for (const auto& [agentId, _] : agentProfiles_) {
        ungrouped.push_back(agentId);
    }
    
    int groupNum = 1;
    while (ungrouped.size() >= static_cast<size_t>(config_.minGroupSize)) {
        // Start a new group with first ungrouped agent
        EmergentSubGroup group;
        group.groupId = GenerateGroupId();
        group.name = "Group-" + std::to_string(groupNum++);
        group.formedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        group.lastActivityMs = group.formedAtMs;
        
        std::string seedAgent = ungrouped.front();
        group.memberIds.push_back(seedAgent);
        ungrouped.erase(ungrouped.begin());
        
        // Find similar agents
        for (auto it = ungrouped.begin(); it != ungrouped.end(); ) {
            if (group.memberIds.size() >= static_cast<size_t>(config_.maxGroupSize)) break;
            
            double similarity = CalculateSimilarity(
                agentProfiles_[seedAgent], agentProfiles_[*it]);
            
            if (similarity >= config_.minCohesionForGroup) {
                group.memberIds.push_back(*it);
                it = ungrouped.erase(it);
            } else {
                ++it;
            }
        }
        
        if (group.memberIds.size() >= static_cast<size_t>(config_.minGroupSize)) {
            group.cohesion = config_.minCohesionForGroup + 0.1;  // Estimated
            group.stability = 0.7;
            group.description = "Emergent sub-group of " + std::to_string(group.memberIds.size()) + " similar agents";
            groups.push_back(group);
        }
    }
    
    return groups;
}

std::vector<SpecializationPattern> EmergentRoleFormation::DetectSpecializations() {
    std::vector<SpecializationPattern> patterns;
    
    // Look for agents with high expertise in specific domains
    for (const auto& [agentId, profile] : agentProfiles_) {
        for (const auto& [domain, expertise] : profile.capabilities) {
            if (expertise >= config_.minExpertiseForSpecialist) {
                SpecializationPattern pattern;
                pattern.patternId = "spec-" + agentId + "-" + domain;
                pattern.name = domain + " Specialist";
                pattern.description = "High expertise in " + domain;
                pattern.domain = domain;
                pattern.agentIds.push_back(agentId);
                pattern.expertiseLevel = expertise;
                pattern.efficiencyGain = expertise * 0.3;  // Estimated
                pattern.taskCount = static_cast<int>(profile.recentTasks.size());
                pattern.successRate = profile.performance.empty() ? 0.8 : 0.85;
                patterns.push_back(pattern);
            }
        }
    }
    
    return patterns;
}

std::vector<EmergentHierarchy> EmergentRoleFormation::BuildHierarchies() {
    std::vector<EmergentHierarchy> hierarchies;
    
    if (currentRoles_.empty()) {
        return hierarchies;
    }
    
    // Build simple hierarchy based on role types
    EmergentHierarchy hierarchy;
    hierarchy.hierarchyId = "hier-" + std::to_string(std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count());
    hierarchy.establishedAtMs = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::system_clock::now().time_since_epoch()).count();
    hierarchy.stability = 0.8;
    
    // Level 0: Coordinators
    HierarchyLevel level0;
    level0.level = 0;
    level0.authorityWeight = 1.0;
    for (const auto& role : currentRoles_) {
        if (role.type == EmergentRoleType::COORDINATOR) {
            level0.agentIds.push_back(role.agentId);
        }
    }
    if (!level0.agentIds.empty()) {
        hierarchy.levels.push_back(level0);
    }
    
    // Level 1: Specialists and Optimizers
    HierarchyLevel level1;
    level1.level = 1;
    level1.authorityWeight = 0.7;
    for (const auto& role : currentRoles_) {
        if (role.type == EmergentRoleType::SPECIALIST || role.type == EmergentRoleType::OPTIMIZER) {
            level1.agentIds.push_back(role.agentId);
        }
    }
    if (!level1.agentIds.empty()) {
        hierarchy.levels.push_back(level1);
    }
    
    // Level 2: Others
    HierarchyLevel level2;
    level2.level = 2;
    level2.authorityWeight = 0.4;
    for (const auto& role : currentRoles_) {
        if (role.type != EmergentRoleType::COORDINATOR && 
            role.type != EmergentRoleType::SPECIALIST && 
            role.type != EmergentRoleType::OPTIMIZER) {
            level2.agentIds.push_back(role.agentId);
        }
    }
    if (!level2.agentIds.empty()) {
        hierarchy.levels.push_back(level2);
    }
    
    if (hierarchy.levels.size() > 1) {
        hierarchies.push_back(hierarchy);
    }
    
    return hierarchies;
}

void EmergentRoleFormation::RevokeRole(const std::string& roleId) {
    currentRoles_.erase(
        std::remove_if(currentRoles_.begin(), currentRoles_.end(),
            [&roleId](const EmergentRole& role) { return role.roleId == roleId; }),
        currentRoles_.end()
    );
}

void EmergentRoleFormation::ExpireOldRoles() {
    auto now = std::chrono::system_clock::now();
    auto currentTime = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    currentRoles_.erase(
        std::remove_if(currentRoles_.begin(), currentRoles_.end(),
            [currentTime](const EmergentRole& role) { 
                return role.expiresAtMs > 0 && role.expiresAtMs < currentTime; 
            }),
        currentRoles_.end()
    );
}

bool EmergentRoleFormation::SaveFormation(const std::string& path) const {
    std::ofstream file(path);
    if (!file.is_open()) return false;
    
    file << "{";
    file << "\"roles\":[";
    for (size_t i = 0; i < currentRoles_.size(); ++i) {
        if (i > 0) file << ",";
        file << currentRoles_[i].ToJson();
    }
    file << "],";
    file << "\"groups\":[";
    for (size_t i = 0; i < currentGroups_.size(); ++i) {
        if (i > 0) file << ",";
        file << currentGroups_[i].ToJson();
    }
    file << "]}";
    return true;
}

bool EmergentRoleFormation::LoadFormation(const std::string& path) {
    // Simplified load
    return false;
}

// Helper methods
EmergentRoleType EmergentRoleFormation::DetermineRoleType(const AgentBehaviorProfile& profile) {
    // Analyze profile to determine best role
    double coordination = profile.capabilities["coordination"];
    double expertise = 0.0;
    for (const auto& [cap, level] : profile.capabilities) {
        if (level > expertise) expertise = level;
    }
    double monitoring = profile.capabilities["monitoring"];
    double optimization = profile.capabilities["optimization"];
    double exploration = profile.preferences["novelty"];
    double stability = profile.preferences["consistency"];
    double adaptation = profile.capabilities["adaptation"];
    
    // Find highest scoring role
    std::map<EmergentRoleType, double> scores;
    scores[EmergentRoleType::COORDINATOR] = coordination;
    scores[EmergentRoleType::SPECIALIST] = expertise > 0.8 ? expertise : 0;
    scores[EmergentRoleType::MONITOR] = monitoring;
    scores[EmergentRoleType::OPTIMIZER] = optimization;
    scores[EmergentRoleType::EXPLORER] = exploration;
    scores[EmergentRoleType::STABILIZER] = stability;
    scores[EmergentRoleType::ADAPTER] = adaptation;
    
    // Default to generalist if no strong preference
    EmergentRoleType bestRole = EmergentRoleType::GENERALIST;
    double bestScore = 0.5;
    
    for (const auto& [role, score] : scores) {
        if (score > bestScore) {
            bestScore = score;
            bestRole = role;
        }
    }
    
    return bestRole;
}

double EmergentRoleFormation::CalculateRoleConfidence(const AgentBehaviorProfile& profile, EmergentRoleType role) {
    // Calculate confidence based on profile match to role
    double confidence = 0.5;  // Base confidence
    
    switch (role) {
        case EmergentRoleType::COORDINATOR:
            confidence = profile.capabilities["coordination"] * 0.9;
            break;
        case EmergentRoleType::SPECIALIST:
            for (const auto& [cap, level] : profile.capabilities) {
                if (level > confidence) confidence = level;
            }
            break;
        case EmergentRoleType::MONITOR:
            confidence = profile.capabilities["monitoring"] * 0.9;
            break;
        case EmergentRoleType::OPTIMIZER:
            confidence = profile.capabilities["optimization"] * 0.9;
            break;
        case EmergentRoleType::EXPLORER:
            confidence = profile.preferences["novelty"] * 0.9;
            break;
        case EmergentRoleType::STABILIZER:
            confidence = profile.preferences["consistency"] * 0.9;
            break;
        case EmergentRoleType::ADAPTER:
            confidence = profile.capabilities["adaptation"] * 0.9;
            break;
        default:
            confidence = 0.5;
            break;
    }
    
    return confidence;
}

double EmergentRoleFormation::CalculateSimilarity(const AgentBehaviorProfile& a, const AgentBehaviorProfile& b) {
    if (a.capabilities.empty() || b.capabilities.empty()) return 0.0;
    
    double dotProduct = 0.0;
    double normA = 0.0;
    double normB = 0.0;
    
    for (const auto& [key, valA] : a.capabilities) {
        auto it = b.capabilities.find(key);
        if (it != b.capabilities.end()) {
            dotProduct += valA * it->second;
        }
        normA += valA * valA;
    }
    
    for (const auto& [key, valB] : b.capabilities) {
        normB += valB * valB;
    }
    
    if (normA == 0.0 || normB == 0.0) return 0.0;
    return dotProduct / (std::sqrt(normA) * std::sqrt(normB));
}

std::string EmergentRoleFormation::GenerateRoleId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "role-" << ms << "-" << dis(gen);
    return id.str();
}

std::string EmergentRoleFormation::GenerateGroupId() const {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<> dis(1000, 9999);
    
    auto now = std::chrono::system_clock::now();
    auto ms = std::chrono::duration_cast<std::chrono::milliseconds>(
        now.time_since_epoch()).count();
    
    std::ostringstream id;
    id << "group-" << ms << "-" << dis(gen);
    return id.str();
}

// CLI Implementation
void EmergentRoleFormationCLI::PrintBanner() {
    std::cout << "╔════════════════════════════════════════════════════════════════╗\n";
    std::cout << "║                                                                ║\n";
    std::cout << "║     EMERGENT ROLE FORMATION - Phase C.2                        ║\n";
    std::cout << "║     Adaptive Role Assignment & Hierarchy Building              ║\n";
    std::cout << "║                                                                ║\n";
    std::cout << "╚════════════════════════════════════════════════════════════════╝\n\n";
}

void EmergentRoleFormationCLI::PrintUsage() {
    std::cout << "Usage: emergent-roles [OPTIONS]\n\n";
    std::cout << "Options:\n";
    std::cout << "  --agents N          Number of agents to simulate\n";
    std::cout << "  --confidence X      Minimum confidence threshold (0-1)\n";
    std::cout << "  --output PATH       Save formation to file\n";
    std::cout << "  --json              Output results as JSON\n";
    std::cout << "  --help              Show this help\n\n";
}

RoleFormationConfig EmergentRoleFormationCLI::ParseArgs(int argc, char* argv[]) {
    RoleFormationConfig config;
    
    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        
        if (arg == "--confidence" && i + 1 < argc) {
            config.minConfidenceForAssignment = std::stod(argv[++i]);
        } else if (arg == "--help" || arg == "-h") {
            PrintUsage();
            exit(0);
        }
    }
    
    return config;
}

int EmergentRoleFormationCLI::Run(int argc, char* argv[]) {
    PrintBanner();
    
    if (argc > 1 && (std::string(argv[1]) == "--help" || std::string(argv[1]) == "-h")) {
        PrintUsage();
        return 0;
    }
    
    RoleFormationConfig config = ParseArgs(argc, argv);
    
    // Create formation engine
    EmergentRoleFormation formation;
    formation.Initialize(config);
    
    // Generate synthetic agent profiles
    std::cout << "[Demo] Generating synthetic agent profiles...\n";
    
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_real_distribution<> capabilityDist(0.3, 1.0);
    std::uniform_real_distribution<> preferenceDist(0.0, 1.0);
    
    int numAgents = 10;
    for (int i = 1; i <= numAgents; ++i) {
        AgentBehaviorProfile profile;
        profile.agentId = "agent-" + std::to_string(i);
        profile.capabilities["coordination"] = capabilityDist(gen);
        profile.capabilities["monitoring"] = capabilityDist(gen);
        profile.capabilities["optimization"] = capabilityDist(gen);
        profile.capabilities["adaptation"] = capabilityDist(gen);
        profile.preferences["novelty"] = preferenceDist(gen);
        profile.preferences["consistency"] = preferenceDist(gen);
        profile.lastUpdatedMs = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::system_clock::now().time_since_epoch()).count();
        formation.UpdateAgentProfile(profile);
    }
    
    // Form roles
    std::cout << "[Demo] Forming emergent roles...\n";
    auto result = formation.FormRoles();
    
    // Print summary
    result.PrintSummary();
    
    // Check for output path
    std::string outputPath;
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--output" && i + 1 < argc) {
            outputPath = argv[i + 1];
        }
    }
    
    if (!outputPath.empty()) {
        if (formation.SaveFormation(outputPath)) {
            std::cout << "Formation saved to: " << outputPath << "\n";
        }
    }
    
    // Output JSON if requested
    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--json") {
            std::cout << "\n" << result.ToJson() << "\n";
        }
    }
    
    return 0;
}

} // namespace Emergent
