// RawrXD Access Control System
// Phase Q.2: RBAC, ABAC, and policy-based access control
// Fine-grained permissions with audit logging

#pragma once

#include <string>
#include <vector>
#include <map>
#include <set>
#include <memory>
#include <mutex>
#include <chrono>
#include <functional>

namespace RawrXD {
namespace Security {

// Forward declarations
class AuditLogger;

// Permission types
enum class Permission {
    // Model operations
    MODEL_READ,
    MODEL_WRITE,
    MODEL_DELETE,
    MODEL_EXECUTE,
    MODEL_ADMIN,
    
    // Inference operations
    INFERENCE_REQUEST,
    INFERENCE_BATCH,
    INFERENCE_STREAMING,
    INFERENCE_ADMIN,
    
    // Data operations
    DATA_READ,
    DATA_WRITE,
    DATA_DELETE,
    DATA_EXPORT,
    DATA_ADMIN,
    
    // System operations
    SYSTEM_READ,
    SYSTEM_WRITE,
    SYSTEM_CONFIGURE,
    SYSTEM_ADMIN,
    
    // User operations
    USER_READ,
    USER_WRITE,
    USER_DELETE,
    USER_ADMIN,
    
    // Security operations
    SECURITY_READ,
    SECURITY_WRITE,
    SECURITY_AUDIT,
    SECURITY_ADMIN
};

// Resource types
enum class ResourceType {
    MODEL,
    DATASET,
    ENDPOINT,
    API_KEY,
    USER,
    ROLE,
    POLICY,
    SYSTEM_CONFIG,
    LOG,
    SECRET
};

// Resource identifier
struct Resource {
    ResourceType type;
    std::string id;
    std::string path;  // Hierarchical path like "models/gpt4/instances"
    std::map<std::string, std::string> attributes;
    
    bool matches(const std::string& pattern) const;
};

// Subject (user or service)
struct Subject {
    std::string id;
    std::string type;  // "user", "service", "api_key"
    std::vector<std::string> roles;
    std::map<std::string, std::string> attributes;  // ABAC attributes
    std::set<Permission> directPermissions;
    
    // Session info
    std::string sessionId;
    std::chrono::system_clock::time_point sessionExpiry;
    std::string ipAddress;
    std::string userAgent;
};

// Role definition
struct Role {
    std::string id;
    std::string name;
    std::string description;
    std::set<Permission> permissions;
    std::vector<std::string> parentRoles;  // Role inheritance
    std::map<std::string, std::string> resourceConstraints;  // e.g., {"model": "gpt-*"}
    bool isActive;
    std::chrono::system_clock::time_point createdAt;
    std::chrono::system_clock::time_point expiresAt;
};

// Policy rule for ABAC
struct PolicyRule {
    std::string id;
    std::string name;
    std::string description;
    
    // Effect
    enum class Effect {
        ALLOW,
        DENY
    } effect;
    
    // Conditions (all must match)
    struct Condition {
        std::string attribute;     // e.g., "subject.department"
        std::string operator_;   // "==", "!=", "in", "contains", "regex"
        std::string value;
    };
    std::vector<Condition> conditions;
    
    // Actions
    std::vector<Permission> actions;
    
    // Resources
    std::vector<ResourceType> resourceTypes;
    std::vector<std::string> resourcePatterns;
    
    // Priority (higher = evaluated first)
    int priority = 0;
    bool isActive = true;
};

// Access request
struct AccessRequest {
    Subject subject;
    Permission permission;
    Resource resource;
    std::map<std::string, std::string> context;  // Additional context
    std::chrono::system_clock::time_point timestamp;
};

// Access decision
struct AccessDecision {
    bool allowed;
    std::string reason;
    std::vector<std::string> matchedPolicies;
    std::vector<std::string> matchedRoles;
    std::chrono::microseconds evaluationTime;
};

// Access control configuration
struct AccessControlConfig {
    // Default policy
    bool defaultDeny = true;  // Deny by default
    
    // Caching
    bool enableCaching = true;
    uint32_t cacheTTLSeconds = 300;  // 5 minutes
    uint32_t maxCacheSize = 10000;
    
    // Evaluation
    uint32_t maxPolicyEvaluationTimeMs = 100;
    uint32_t maxConditionsPerPolicy = 10;
    
    // Audit
    bool auditAllRequests = true;
    bool auditDeniedOnly = false;
    
    // Session
    uint32_t sessionTimeoutMinutes = 60;
    uint32_t maxConcurrentSessions = 10;
};

// Access control system
class AccessControlSystem {
public:
    AccessControlSystem(AuditLogger* auditLogger);
    ~AccessControlSystem();
    
    // Lifecycle
    bool initialize(const AccessControlConfig& config);
    bool shutdown();
    bool isInitialized() const { return initialized_; }
    
    // Authorization
    AccessDecision authorize(const AccessRequest& request);
    bool checkPermission(const Subject& subject, Permission permission);
    bool checkPermission(const Subject& subject, Permission permission, const Resource& resource);
    
    // Role management
    std::string createRole(const Role& role);
    bool updateRole(const std::string& roleId, const Role& role);
    bool deleteRole(const std::string& roleId);
    Role getRole(const std::string& roleId) const;
    std::vector<Role> getAllRoles() const;
    std::vector<Role> getRolesForSubject(const std::string& subjectId) const;
    
    // Role assignment
    bool assignRole(const std::string& subjectId, const std::string& roleId);
    bool revokeRole(const std::string& subjectId, const std::string& roleId);
    std::vector<std::string> getSubjectRoles(const std::string& subjectId) const;
    
    // Policy management
    std::string createPolicy(const PolicyRule& policy);
    bool updatePolicy(const std::string& policyId, const PolicyRule& policy);
    bool deletePolicy(const std::string& policyId);
    PolicyRule getPolicy(const std::string& policyId) const;
    std::vector<PolicyRule> getAllPolicies() const;
    std::vector<PolicyRule> getActivePolicies() const;
    bool enablePolicy(const std::string& policyId);
    bool disablePolicy(const std::string& policyId);
    
    // Subject management
    bool registerSubject(const Subject& subject);
    bool updateSubject(const std::string& subjectId, const Subject& subject);
    bool unregisterSubject(const std::string& subjectId);
    Subject getSubject(const std::string& subjectId) const;
    bool subjectExists(const std::string& subjectId) const;
    
    // Direct permissions
    bool grantPermission(const std::string& subjectId, Permission permission);
    bool revokePermission(const std::string& subjectId, Permission permission);
    
    // Permission queries
    std::set<Permission> getEffectivePermissions(const std::string& subjectId) const;
    std::set<Permission> getEffectivePermissions(const std::string& subjectId, 
                                                      const Resource& resource) const;
    std::vector<Subject> getSubjectsWithPermission(Permission permission) const;
    
    // Session management
    std::string createSession(const Subject& subject, uint32_t durationMinutes);
    bool validateSession(const std::string& sessionId);
    bool terminateSession(const std::string& sessionId);
    void terminateAllSessions(const std::string& subjectId);
    std::vector<std::string> getActiveSessions(const std::string& subjectId) const;
    
    // Impersonation
    bool impersonate(const std::string& adminId, const std::string& targetSubjectId);
    bool stopImpersonation(const std::string& adminId);
    std::string getImpersonatedSubject(const std::string& adminId) const;
    
    // Statistics
    struct AuthStats {
        uint64_t totalRequests;
        uint64_t allowedRequests;
        uint64_t deniedRequests;
        double avgEvaluationTimeMs;
        uint64_t cacheHits;
        uint64_t cacheMisses;
        
        std::map<Permission, uint64_t> requestsByPermission;
        std::map<ResourceType, uint64_t> requestsByResource;
    };
    AuthStats getStats() const;
    
    // Configuration
    AccessControlConfig getConfig() const { return config_; }
    bool updateConfig(const AccessControlConfig& config);
    
    // Import/Export
    std::string exportPolicy(const std::string& policyId) const;
    bool importPolicy(const std::string& json);
    std::string exportRole(const std::string& roleId) const;
    bool importRole(const std::string& json);

private:
    bool evaluatePolicy(const PolicyRule& policy, const AccessRequest& request);
    bool evaluateCondition(const PolicyRule::Condition& condition, 
                           const AccessRequest& request);
    std::set<Permission> computeEffectivePermissions(const Subject& subject) const;
    std::set<Permission> computeEffectivePermissions(const Subject& subject,
                                                        const Resource& resource) const;
    void cleanupExpiredSessions();
    
    std::atomic<bool> running_;
    std::atomic<bool> initialized_;
    mutable std::mutex mutex_;
    
    AccessControlConfig config_;
    AuditLogger* auditLogger_;
    
    // Data stores
    std::map<std::string, Role> roles_;
    std::map<std::string, PolicyRule> policies_;
    std::map<std::string, Subject> subjects_;
    std::map<std::string, std::string> sessions_;  // sessionId -> subjectId
    std::map<std::string, std::chrono::system_clock::time_point> sessionExpiry_;
    std::map<std::string, std::string> impersonations_;  // adminId -> targetId
    
    // Cache
    struct CacheKey {
        std::string subjectId;
        Permission permission;
        std::string resourceId;
        
        bool operator<(const CacheKey& other) const {
            if (subjectId != other.subjectId) return subjectId < other.subjectId;
            if (permission != other.permission) return permission < other.permission;
            return resourceId < other.resourceId;
        }
    };
    std::map<CacheKey, std::pair<bool, std::chrono::steady_clock::time_point>> cache_;
    
    // Statistics
    std::atomic<uint64_t> totalRequests_{0};
    std::atomic<uint64_t> allowedRequests_{0};
    std::atomic<uint64_t> deniedRequests_{0};
    std::atomic<uint64_t> cacheHits_{0};
    std::atomic<uint64_t> cacheMisses_{0};
};

// Permission helper functions
std::string permissionToString(Permission permission);
Permission permissionFromString(const std::string& str);
std::string resourceTypeToString(ResourceType type);
ResourceType resourceTypeFromString(const std::string& str);

} // namespace Security
} // namespace RawrXD
