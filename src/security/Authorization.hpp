/**
 * Authorization.hpp
 *
 * Phase G Batch 2/5: Authorization & Access Control
 *
 * Role-based access control (RBAC) and attribute-based access control (ABAC)
 * with fine-grained permissions and policy enforcement.
 */

#pragma once

#include "Authentication.hpp"
#include <set>
#include <vector>
#include <map>

namespace Security {

// ============================================================================
// Permission
// ============================================================================

/**
 * Represents a permission to perform an action on a resource.
 */
struct Permission {
    std::string resource;    // Resource type (e.g., "model", "agent", "config")
    std::string action;      // Action (e.g., "read", "write", "execute", "delete")
    std::string condition;   // Optional condition expression
    
    Permission() = default;
    Permission(const std::string& res, const std::string& act);
    
    std::string ToString() const;
    bool operator==(const Permission& other) const;
    bool operator<(const Permission& other) const;
};

// ============================================================================
// Role
// ============================================================================

/**
 * Role with associated permissions.
 */
class Role {
public:
    std::string id;
    std::string name;
    std::string description;
    std::set<Permission> permissions;
    std::set<std::string> parentRoles;
    std::map<std::string, std::string> attributes;
    bool enabled;
    
    Role();
    
    // Permission management
    void AddPermission(const Permission& perm);
    void RemovePermission(const Permission& perm);
    bool HasPermission(const Permission& perm) const;
    bool HasPermission(const std::string& resource, const std::string& action) const;
    
    // Inheritance
    void AddParentRole(const std::string& roleId);
    void RemoveParentRole(const std::string& roleId);
    std::set<std::string> GetParentRoles() const;
    
    // Serialization
    std::string ToJson() const;
    static Role FromJson(const std::string& json);
};

// ============================================================================
// Policy
// ============================================================================

/**
 * Access control policy.
 */
struct Policy {
    std::string id;
    std::string name;
    std::string description;
    
    // Subjects (who)
    std::vector<std::string> subjects;      // Identity IDs or patterns
    std::vector<std::string> roles;         // Role IDs
    
    // Resources (what)
    std::vector<std::string> resources;       // Resource patterns
    std::vector<std::string> actions;       // Action patterns
    
    // Effect
    enum class Effect {
        ALLOW,
        DENY
    };
    Effect effect;
    
    // Conditions (when/where)
    std::string condition;                  // Expression for ABAC
    
    // Priority
    uint32_t priority;
    bool enabled;
    
    Policy();
    
    bool Matches(const std::string& subject, const std::string& role,
                 const std::string& resource, const std::string& action,
                 const std::map<std::string, std::string>& context) const;
};

// ============================================================================
// Access Control Decision
// ============================================================================

enum class AccessDecision {
    ALLOW,      // Access granted
    DENY,       // Access denied
    ABSTAIN     // No decision (default)
};

struct AuthorizationResult {
    AccessDecision decision;
    std::string policyId;       // Policy that made the decision
    std::string reason;         // Human-readable explanation
    std::map<std::string, std::string> attributes;
    
    static AuthorizationResult Allow(const std::string& policyId);
    static AuthorizationResult Deny(const std::string& policyId, const std::string& reason);
    static AuthorizationResult Abstain();
    
    bool IsAllowed() const { return decision == AccessDecision::ALLOW; }
};

// ============================================================================
// RBAC Engine
// ============================================================================

/**
 * Role-Based Access Control engine.
 */
class RBACEngine {
public:
    RBACEngine();
    ~RBACEngine();
    
    // Role management
    bool CreateRole(const Role& role);
    bool UpdateRole(const Role& role);
    bool DeleteRole(const std::string& roleId);
    std::optional<Role> GetRole(const std::string& roleId);
    std::vector<Role> GetAllRoles();
    
    // Role assignment
    bool AssignRole(const std::string& identityId, const std::string& roleId);
    bool RevokeRole(const std::string& identityId, const std::string& roleId);
    std::vector<std::string> GetIdentityRoles(const std::string& identityId);
    std::vector<std::string> GetRoleIdentities(const std::string& roleId);
    
    // Permission checking
    bool HasPermission(const std::string& identityId, const Permission& perm);
    bool HasPermission(const std::string& identityId, const std::string& resource,
                       const std::string& action);
    
    // Get effective permissions (including inherited)
    std::set<Permission> GetEffectivePermissions(const std::string& identityId);
    
    // Authorization
    AuthorizationResult Authorize(const std::string& identityId,
                                    const std::string& resource,
                                    const std::string& action);
    
private:
    std::map<std::string, Role> roles_;
    std::map<std::string, std::set<std::string>> identityRoles_;  // identityId -> roleIds
    mutable std::mutex mutex_;
    
    std::set<Permission> GetRolePermissions(const std::string& roleId,
                                             std::set<std::string>& visited);
};

// ============================================================================
// ABAC Engine
// ============================================================================

/**
 * Attribute-Based Access Control engine.
 */
class ABACEngine {
public:
    struct AttributeContext {
        std::map<std::string, std::string> subjectAttributes;
        std::map<std::string, std::string> resourceAttributes;
        std::map<std::string, std::string> actionAttributes;
        std::map<std::string, std::string> environmentAttributes;
    };
    
    ABACEngine();
    ~ABACEngine();
    
    // Policy management
    bool AddPolicy(const Policy& policy);
    bool UpdatePolicy(const Policy& policy);
    bool DeletePolicy(const std::string& policyId);
    std::optional<Policy> GetPolicy(const std::string& policyId);
    std::vector<Policy> GetAllPolicies();
    
    // Authorization with attributes
    AuthorizationResult Authorize(const std::string& subject,
                                   const std::string& resource,
                                   const std::string& action,
                                   const AttributeContext& context);
    
    // Policy evaluation
    bool EvaluateCondition(const std::string& condition,
                           const AttributeContext& context);
    
private:
    std::map<std::string, Policy> policies_;
    mutable std::mutex mutex_;
    
    // Policy decision point
    AccessDecision EvaluatePolicies(const std::vector<Policy>& applicablePolicies);
};

// ============================================================================
// Resource Hierarchy
// ============================================================================

/**
 * Hierarchical resource access control.
 */
class ResourceHierarchy {
public:
    struct ResourceNode {
        std::string id;
        std::string type;
        std::string parentId;
        std::map<std::string, std::string> attributes;
    };
    
    // Resource management
    bool AddResource(const ResourceNode& resource);
    bool RemoveResource(const std::string& resourceId);
    std::optional<ResourceNode> GetResource(const std::string& resourceId);
    
    // Hierarchy queries
    std::vector<std::string> GetAncestors(const std::string& resourceId);
    std::vector<std::string> GetDescendants(const std::string& resourceId);
    std::vector<std::string> GetChildren(const std::string& resourceId);
    
    // Permission inheritance
    bool InheritsPermissions(const std::string& resourceId,
                              const std::string& ancestorId);
    
private:
    std::map<std::string, ResourceNode> resources_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Access Control List (ACL)
// ============================================================================

/**
 * Direct ACL for fine-grained control.
 */
class AccessControlList {
public:
    struct ACLEntry {
        std::string identityId;
        std::string resourceId;
        std::set<std::string> permissions;  // read, write, execute, etc.
        bool allowed;
        uint64_t expiresAt;
    };
    
    // Entry management
    bool AddEntry(const ACLEntry& entry);
    bool RemoveEntry(const std::string& identityId, const std::string& resourceId);
    bool UpdateEntry(const ACLEntry& entry);
    
    // Query
    std::optional<ACLEntry> GetEntry(const std::string& identityId,
                                      const std::string& resourceId);
    std::vector<ACLEntry> GetResourceEntries(const std::string& resourceId);
    std::vector<ACLEntry> GetIdentityEntries(const std::string& identityId);
    
    // Check access
    bool CheckAccess(const std::string& identityId, const std::string& resourceId,
                     const std::string& permission);
    
    // Cleanup expired entries
    void CleanupExpired();
    
private:
    std::map<std::pair<std::string, std::string>, ACLEntry> entries_;
    mutable std::mutex mutex_;
};

// ============================================================================
// Authorization Manager
// ============================================================================

/**
 * Central authorization coordinator.
 */
class AuthorizationManager {
public:
    enum class Strategy {
        RBAC_ONLY,      // Role-based only
        ABAC_ONLY,      // Attribute-based only
        RBAC_THEN_ABAC, // RBAC first, then ABAC
        ABAC_THEN_RBAC, // ABAC first, then RBAC
        UNANIMOUS,      // Both must allow
        ANY             // Either can allow
    };
    
    struct Config {
        Strategy strategy = Strategy::RBAC_THEN_ABAC;
        bool enableACL = true;
        bool defaultDeny = true;
        bool enableCaching = true;
        uint64_t cacheTTLMs = 60000;
    };
    
    AuthorizationManager();
    ~AuthorizationManager();
    
    // Initialize
    bool Initialize(const Config& config);
    void Shutdown();
    
    // Authorization check
    AuthorizationResult CheckAccess(const std::string& identityId,
                                     const std::string& resource,
                                     const std::string& action);
    AuthorizationResult CheckAccess(const std::string& identityId,
                                     const std::string& resource,
                                     const std::string& action,
                                     const ABACEngine::AttributeContext& context);
    
    // Batch authorization
    std::vector<AuthorizationResult> CheckAccessBatch(
        const std::string& identityId,
        const std::vector<std::tuple<std::string, std::string>>& requests);
    
    // Component access
    RBACEngine* GetRBAC() { return rbac_.get(); }
    ABACEngine* GetABAC() { return abac_.get(); }
    AccessControlList* GetACL() { return acl_.get(); }
    
    // Preload/cache
    void PreloadIdentity(const std::string& identityId);
    void InvalidateCache(const std::string& identityId);
    
    // Status
    std::string GetStatusJson() const;
    
private:
    Config config_;
    
    std::unique_ptr<RBACEngine> rbac_;
    std::unique_ptr<ABACEngine> abac_;
    std::unique_ptr<AccessControlList> acl_;
    
    // Cache
    struct CacheEntry {
        AuthorizationResult result;
        uint64_t expiresAt;
    };
    std::map<std::string, CacheEntry> cache_;  // key: identity:resource:action
    mutable std::mutex cacheMutex_;
    
    std::string MakeCacheKey(const std::string& identityId,
                            const std::string& resource,
                            const std::string& action);
    std::optional<AuthorizationResult> GetCached(const std::string& key);
    void SetCached(const std::string& key, const AuthorizationResult& result);
};

// ============================================================================
// Permission Checker
// ============================================================================

/**
 * RAII permission checker for scoped access.
 */
class PermissionChecker {
public:
    PermissionChecker(AuthorizationManager* authz,
                      const std::string& identityId);
    
    bool Can(const std::string& resource, const std::string& action);
    bool Can(const Permission& perm);
    
    void Require(const std::string& resource, const std::string& action);
    void Require(const Permission& perm);
    
private:
    AuthorizationManager* authz_;
    std::string identityId_;
};

// ============================================================================
// Macros
// ============================================================================

#define REQUIRE_PERMISSION(authz, identity, resource, action) \
    do { \
        Security::PermissionChecker checker(authz, identity); \
        checker.Require(resource, action); \
    } while(0)

} // namespace Security
