#pragma once

/**
 * EmergentRoleFormation.hpp
 *
 * Phase C.2 Batch 2/5: Emergent Role Formation
 *
 * Agents form roles, sub-groups, specialization patterns,
 * and adaptive hierarchies based on observed behavior.
 */

#include <vector>
#include <map>
#include <memory>
#include <string>
#include <functional>

namespace Emergent {

/**
 * Role types that emerge from behavior
 */
enum class EmergentRoleType {
    COORDINATOR,      // Orchestrates group activities
    SPECIALIST,       // Deep expertise in specific area
    GENERALIST,       // Broad capability across areas
    MONITOR,          // Watches for anomalies/patterns
    OPTIMIZER,        // Focuses on efficiency improvements
    EXPLORER,         // Seeks novel solutions
    STABILIZER,       // Maintains consistency
    ADAPTER           // Responds to changes
};

/**
 * Emergent role assigned to an agent
 */
struct EmergentRole {
    std::string roleId;
    EmergentRoleType type;
    std::string name;
    std::string description;
    
    // Assignment
    std::string agentId;
    int64_t assignedAtMs;
    int64_t expiresAtMs;  // 0 = never
    
    // Confidence metrics
    double confidence;
    double stability;     // How long role has been held
    int consecutiveAssignments;
    
    // Capabilities this role enables
    std::vector<std::string> capabilities;
    std::map<std::string, double> performanceMetrics;
    
    std::string ToJson() const;
};

/**
 * Sub-group of agents with shared characteristics
 */
struct EmergentSubGroup {
    std::string groupId;
    std::string name;
    std::string description;
    
    // Members
    std::vector<std::string> memberIds;
    std::string leaderId;  // Optional
    
    // Characteristics
    std::map<std::string, double> centroid;
    double cohesion;       // How tightly grouped (0-1)
    double stability;
    
    // Temporal
    int64_t formedAtMs;
    int64_t lastActivityMs;
    
    std::string ToJson() const;
};

/**
 * Specialization pattern observed
 */
struct SpecializationPattern {
    std::string patternId;
    std::string name;
    std::string description;
    
    // What is being specialized
    std::string domain;
    std::vector<std::string> agentIds;
    
    // Specialization metrics
    double expertiseLevel;  // 0-1
    double efficiencyGain;  // vs generalist approach
    int taskCount;
    double successRate;
    
    std::string ToJson() const;
};

/**
 * Adaptive hierarchy level
 */
struct HierarchyLevel {
    int level;
    std::vector<std::string> agentIds;
    std::map<std::string, std::string> responsibilities;
    double authorityWeight;
};

/**
 * Emergent hierarchy structure
 */
struct EmergentHierarchy {
    std::string hierarchyId;
    std::vector<HierarchyLevel> levels;
    int64_t establishedAtMs;
    double stability;
    
    std::string ToJson() const;
};

/**
 * Role formation configuration
 */
struct RoleFormationConfig {
    // Role assignment
    double minConfidenceForAssignment = 0.75;
    int minConsecutiveForStability = 3;
    int64_t roleExpirationMs = 300000;  // 5 minutes
    
    // Sub-group formation
    double minCohesionForGroup = 0.80;
    int minGroupSize = 2;
    int maxGroupSize = 10;
    
    // Specialization
    double minExpertiseForSpecialist = 0.85;
    double minEfficiencyGain = 0.20;  // 20% improvement
    
    // Hierarchy
    int maxHierarchyDepth = 3;
    double minAuthorityWeight = 0.30;
};

/**
 * Role formation result
 */
struct RoleFormationResult {
    std::vector<EmergentRole> assignedRoles;
    std::vector<EmergentSubGroup> formedGroups;
    std::vector<SpecializationPattern> specializations;
    std::vector<EmergentHierarchy> hierarchies;
    
    int64_t formationDurationMs;
    
    std::string ToJson() const;
    void PrintSummary() const;
};

/**
 * Agent behavior profile
 */
struct AgentBehaviorProfile {
    std::string agentId;
    std::map<std::string, double> capabilities;
    std::map<std::string, double> preferences;
    std::map<std::string, double> performance;
    std::vector<std::string> recentTasks;
    int64_t lastUpdatedMs;
};

/**
 * Emergent Role Formation
 *
 * Analyzes agent behaviors to form emergent roles and structures
 */
class EmergentRoleFormation {
public:
    EmergentRoleFormation();
    ~EmergentRoleFormation();
    
    // Initialize
    bool Initialize(const RoleFormationConfig& config = RoleFormationConfig{});
    
    // Update agent profile
    void UpdateAgentProfile(const AgentBehaviorProfile& profile);
    void UpdateAgentProfiles(const std::vector<AgentBehaviorProfile>& profiles);
    
    // Run role formation
    RoleFormationResult FormRoles();
    
    // Specific formation algorithms
    std::vector<EmergentRole> AssignRoles();
    std::vector<EmergentSubGroup> FormSubGroups();
    std::vector<SpecializationPattern> DetectSpecializations();
    std::vector<EmergentHierarchy> BuildHierarchies();
    
    // Get current state
    const std::vector<EmergentRole>& GetCurrentRoles() const { return currentRoles_; }
    const std::vector<EmergentSubGroup>& GetCurrentGroups() const { return currentGroups_; }
    
    // Revoke/expire roles
    void RevokeRole(const std::string& roleId);
    void ExpireOldRoles();
    
    // Export/Import
    bool SaveFormation(const std::string& path) const;
    bool LoadFormation(const std::string& path);
    
private:
    RoleFormationConfig config_;
    std::map<std::string, AgentBehaviorProfile> agentProfiles_;
    std::vector<EmergentRole> currentRoles_;
    std::vector<EmergentSubGroup> currentGroups_;
    std::vector<SpecializationPattern> currentSpecializations_;
    std::vector<EmergentHierarchy> currentHierarchies_;
    
    // Helper methods
    EmergentRoleType DetermineRoleType(const AgentBehaviorProfile& profile);
    double CalculateRoleConfidence(const AgentBehaviorProfile& profile, EmergentRoleType role);
    double CalculateSimilarity(const AgentBehaviorProfile& a, const AgentBehaviorProfile& b);
    std::string GenerateRoleId() const;
    std::string GenerateGroupId() const;
};

/**
 * Role formation CLI
 */
class EmergentRoleFormationCLI {
public:
    static int Run(int argc, char* argv[]);
    
private:
    static void PrintBanner();
    static void PrintUsage();
    static RoleFormationConfig ParseArgs(int argc, char* argv[]);
};

} // namespace Emergent
