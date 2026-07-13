// Phase N.4/5: Role-Based Access Control (RBAC)
// RawrXD RBAC - Fine-grained permissions system

#pragma once

#include <cstring>
#include <string>
#include <vector>
#include <memory>
#include <unordered_map>
#include <unordered_set>
#include <chrono>

namespace RawrXD {
namespace Enterprise {

// Permission actions
enum class PermissionAction {
    CREATE,
    READ,
    UPDATE,
    DELETE,
    EXECUTE,
    ADMIN
};

// Resource types
enum class ResourceType {
    MODEL,
    API_KEY,
    TENANT,
    USER,
    CONFIGURATION,
    LOG,
    INFERENCE,
    PLUGIN,
    SECRET,
    POLICY
};

// Permission definition
struct Permission {
    ResourceType resource_type;
    PermissionAction action;
    std::string resource_id;  // Optional: specific resource
    std::string condition;    // Optional: condition expression
    
    std::string ToString() const {
        std::string result;
        switch (action) {
            case PermissionAction::CREATE: result = "create"; break;
            case PermissionAction::READ: result = "read"; break;
            case PermissionAction::UPDATE: result = "update"; break;
            case PermissionAction::DELETE: result = "delete"; break;
            case PermissionAction::EXECUTE: result = "execute"; break;
            case PermissionAction::ADMIN: result = "admin"; break;
        }
        result += ":";
        switch (resource_type) {
            case ResourceType::MODEL: result += "model"; break;
            case ResourceType::API_KEY: result += "api_key"; break;
            case ResourceType::TENANT: result += "tenant"; break;
            case ResourceType::USER: result += "user"; break;
            case ResourceType::CONFIGURATION: result += "configuration"; break;
            case ResourceType::LOG: result += "log"; break;
            case ResourceType::INFERENCE: result += "inference"; break;
            case ResourceType::PLUGIN: result += "plugin"; break;
            case ResourceType::SECRET: result += "secret"; break;
            case ResourceType::POLICY: result += "policy"; break;
        }
        if (!resource_id.empty()) {
            result += ":" + resource_id;
        }
        return result;
    }
};

// Role definition
struct Role {
    std::string id;
    std::string name;
    std::string description;
    std::vector<Permission> permissions;
    std::vector<std::string> inherited_roles;
    std::unordered_map<std::string, std::string> metadata;
    bool system_role;  // Cannot be deleted
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point updated_at;
};

// Predefined system roles
namespace SystemRoles {
    inline Role SuperAdmin() {
        return {
            .id = "superadmin",
            .name = "Super Administrator",
            .description = "Full system access",
            .permissions = {},  // All permissions implied
            .system_role = true
        };
    }
    
    inline Role TenantAdmin() {
        return {
            .id = "tenant_admin",
            .name = "Tenant Administrator",
            .description = "Full tenant access",
            .permissions = {
                {ResourceType::MODEL, PermissionAction::ADMIN, "", ""},
                {ResourceType::API_KEY, PermissionAction::ADMIN, "", ""},
                {ResourceType::USER, PermissionAction::ADMIN, "", ""},
                {ResourceType::CONFIGURATION, PermissionAction::ADMIN, "", ""},
                {ResourceType::INFERENCE, PermissionAction::ADMIN, "", ""},
                {ResourceType::PLUGIN, PermissionAction::ADMIN, "", ""},
                {ResourceType::LOG, PermissionAction::READ, "", ""}
            },
            .system_role = true
        };
    }
    
    inline Role Developer() {
        return {
            .id = "developer",
            .name = "Developer",
            .description = "Can use inference and manage API keys",
            .permissions = {
                {ResourceType::INFERENCE, PermissionAction::EXECUTE, "", ""},
                {ResourceType::API_KEY, PermissionAction::CREATE, "", ""},
                {ResourceType::API_KEY, PermissionAction::READ, "", ""},
                {ResourceType::API_KEY, PermissionAction::DELETE, "", ""},
                {ResourceType::MODEL, PermissionAction::READ, "", ""},
                {ResourceType::LOG, PermissionAction::READ, "", ""}
            },
            .system_role = true
        };
    }
    
    inline Role Viewer() {
        return {
            .id = "viewer",
            .name = "Viewer",
            .description = "Read-only access",
            .permissions = {
                {ResourceType::MODEL, PermissionAction::READ, "", ""},
                {ResourceType::LOG, PermissionAction::READ, "", ""}
            },
            .system_role = true
        };
    }
    
    inline Role InferenceOnly() {
        return {
            .id = "inference_only",
            .name = "Inference Only",
            .description = "Can only make inference requests",
            .permissions = {
                {ResourceType::INFERENCE, PermissionAction::EXECUTE, "", ""}
            },
            .system_role = true
        };
    }
}

// User/Principal
struct Principal {
    std::string id;
    std::string tenant_id;
    std::string name;
    std::string email;
    std::vector<std::string> role_ids;
    std::unordered_map<std::string, std::string> attributes;
    bool active;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point last_login;
};

// Access control decision
struct AccessDecision {
    bool allowed;
    std::string reason;
    std::vector<std::string> matched_policies;
    std::chrono::system_clock::time_point evaluated_at;
};

// Policy definition for ABAC (Attribute-Based Access Control)
struct Policy {
    std::string id;
    std::string name;
    std::string description;
    int priority;  // Higher number = higher priority
    
    // Subject conditions
    std::vector<std::string> subject_conditions;  // e.g., "role == 'admin'"
    
    // Resource conditions
    std::vector<std::string> resource_conditions;  // e.g., "type == 'model'"
    
    // Action conditions
    std::vector<PermissionAction> allowed_actions;
    
    // Environment conditions
    std::vector<std::string> environment_conditions;  // e.g., "time < 17:00"
    
    // Effect
    enum class Effect { ALLOW, DENY } effect;
    
    bool active;
    std::chrono::system_clock::time_point created_at;
};

// RBAC Manager
class RBACManager {
public:
    RBACManager();
    ~RBACManager();
    
    // Initialization
    bool Initialize(const std::string& config_path);
    void Shutdown();
    
    // Role management
    bool CreateRole(const Role& role);
    bool UpdateRole(const Role& role);
    bool DeleteRole(const std::string& role_id);
    std::optional<Role> GetRole(const std::string& role_id) const;
    std::vector<Role> ListRoles() const;
    std::vector<Role> ListSystemRoles() const;
    std::vector<Role> ListCustomRoles() const;
    
    // Permission management
    bool AddPermissionToRole(const std::string& role_id, const Permission& permission);
    bool RemovePermissionFromRole(const std::string& role_id, const Permission& permission);
    bool ClearRolePermissions(const std::string& role_id);
    std::vector<Permission> GetRolePermissions(const std::string& role_id) const;
    std::vector<Permission> GetEffectivePermissions(const std::string& role_id) const;
    
    // Principal management
    bool CreatePrincipal(const Principal& principal);
    bool UpdatePrincipal(const Principal& principal);
    bool DeletePrincipal(const std::string& principal_id);
    std::optional<Principal> GetPrincipal(const std::string& principal_id) const;
    std::optional<Principal> GetPrincipalByEmail(const std::string& email) const;
    std::vector<Principal> ListPrincipals(const std::string& tenant_id = "") const;
    
    // Role assignment
    bool AssignRole(const std::string& principal_id, const std::string& role_id);
    bool RemoveRole(const std::string& principal_id, const std::string& role_id);
    std::vector<std::string> GetPrincipalRoles(const std::string& principal_id) const;
    std::vector<std::string> GetEffectiveRoles(const std::string& principal_id) const;
    
    // Access control checks
    AccessDecision CheckAccess(const std::string& principal_id,
                                const Permission& permission) const;
    AccessDecision CheckAccess(const Principal& principal,
                                const Permission& permission) const;
    bool HasPermission(const std::string& principal_id,
                       ResourceType resource_type,
                       PermissionAction action,
                       const std::string& resource_id = "") const;
    
    // Policy management (ABAC)
    bool CreatePolicy(const Policy& policy);
    bool UpdatePolicy(const Policy& policy);
    bool DeletePolicy(const std::string& policy_id);
    std::optional<Policy> GetPolicy(const std::string& policy_id) const;
    std::vector<Policy> ListPolicies() const;
    std::vector<Policy> GetApplicablePolicies(const Principal& principal,
                                                    const Permission& permission) const;
    
    // Permission evaluation
    bool EvaluateCondition(const std::string& condition,
                           const Principal& principal,
                           const Permission& permission) const;
    
    // Bulk operations
    bool BulkAssignRole(const std::vector<std::string>& principal_ids,
                        const std::string& role_id);
    bool BulkRevokeRole(const std::vector<std::string>& principal_ids,
                        const std::string& role_id);
    
    // Validation
    bool ValidateRole(const Role& role) const;
    bool ValidatePrincipal(const Principal& principal) const;
    bool ValidatePolicy(const Policy& policy) const;
    
    // Import/Export
    bool ExportRoles(const std::string& file_path) const;
    bool ImportRoles(const std::string& file_path);
    bool ExportPolicies(const std::string& file_path) const;
    bool ImportPolicies(const std::string& file_path);
    
    // Statistics
    struct Statistics {
        uint32_t total_roles;
        uint32_t total_principals;
        uint32_t total_policies;
        uint32_t access_checks_performed;
        uint32_t access_granted;
        uint32_t access_denied;
        double average_check_time_ms;
    };
    Statistics GetStatistics() const;
    void ResetStatistics();
    
private:
    std::unordered_map<std::string, Role> roles_;
    std::unordered_map<std::string, Principal> principals_;
    std::unordered_map<std::string, Policy> policies_;
    mutable std::shared_mutex mutex_;
    bool initialized_ = false;
    
    mutable Statistics stats_;
    mutable std::mutex stats_mutex_;
    
    void InitializeSystemRoles();
    std::vector<Permission> ExpandPermissions(const std::vector<Permission>& permissions) const;
    bool CheckPolicyMatch(const Policy& policy,
                          const Principal& principal,
                          const Permission& permission) const;
};

// API key management
struct APIKey {
    std::string id;
    std::string key_hash;  // Hashed key
    std::string key_prefix;  // First 8 chars for identification
    std::string tenant_id;
    std::string principal_id;
    std::string name;
    std::string description;
    std::vector<std::string> role_ids;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    std::chrono::system_clock::time_point last_used;
    uint32_t usage_count;
    std::vector<std::string> allowed_ips;
    std::vector<std::string> allowed_models;
    bool active;
    bool revoked;
    std::string revoked_reason;
};

class APIKeyManager {
public:
    bool Initialize(std::shared_ptr<RBACManager> rbac);
    
    // Key generation
    struct GeneratedKey {
        std::string api_key;  // Full key (shown only once)
        std::string key_id;
    };
    GeneratedKey GenerateKey(const std::string& tenant_id,
                             const std::string& principal_id,
                             const std::string& name,
                             const std::string& description,
                             const std::vector<std::string>& role_ids,
                             std::chrono::hours ttl = std::chrono::hours(24 * 365));
    
    // Key validation
    std::optional<APIKey> ValidateKey(const std::string& api_key);
    bool RevokeKey(const std::string& key_id, const std::string& reason);
    bool DeleteKey(const std::string& key_id);
    
    // Key lookup
    std::optional<APIKey> GetKey(const std::string& key_id) const;
    std::vector<APIKey> ListKeys(const std::string& tenant_id = "",
                                     const std::string& principal_id = "") const;
    
    // Key rotation
    GeneratedKey RotateKey(const std::string& key_id);
    
    // Usage tracking
    void RecordUsage(const std::string& key_id);
    
private:
    std::unordered_map<std::string, APIKey> keys_;
    std::unordered_map<std::string, std::string> key_index_;  // hash -> id
    std::shared_ptr<RBACManager> rbac_;
    mutable std::mutex mutex_;
    
    std::string HashKey(const std::string& key) const;
    std::string GenerateSecureKey();
};

// Session management
struct Session {
    std::string id;
    std::string principal_id;
    std::string tenant_id;
    std::string ip_address;
    std::string user_agent;
    std::chrono::system_clock::time_point created_at;
    std::chrono::system_clock::time_point expires_at;
    std::chrono::system_clock::time_point last_activity;
    bool active;
    std::unordered_map<std::string, std::string> metadata;
};

class SessionManager {
public:
    bool Initialize(std::chrono::minutes default_ttl = std::chrono::minutes(60));
    
    Session CreateSession(const std::string& principal_id,
                          const std::string& tenant_id,
                          const std::string& ip_address,
                          const std::string& user_agent);
    
    std::optional<Session> GetSession(const std::string& session_id);
    bool ValidateSession(const std::string& session_id);
    bool RefreshSession(const std::string& session_id);
    bool InvalidateSession(const std::string& session_id);
    bool InvalidateAllSessions(const std::string& principal_id);
    
    std::vector<Session> GetActiveSessions(const std::string& principal_id);
    
    void CleanupExpiredSessions();
    
private:
    std::unordered_map<std::string, Session> sessions_;
    std::chrono::minutes default_ttl_;
    mutable std::mutex mutex_;
};

// Global RBAC configuration
extern std::unique_ptr<RBACManager> g_rbac_manager;
extern std::unique_ptr<APIKeyManager> g_api_key_manager;
extern std::unique_ptr<SessionManager> g_session_manager;

// Initialize RBAC
bool InitializeRBAC(const std::string& config_path);
void ShutdownRBAC();
bool IsRBACEnabled();

// Convenience functions
inline bool CheckPermission(const std::string& principal_id,
                             ResourceType resource_type,
                             PermissionAction action) {
    if (!g_rbac_manager) return true;  // RBAC not enabled
    return g_rbac_manager->HasPermission(principal_id, resource_type, action);
}

} // namespace Enterprise
} // namespace RawrXD
