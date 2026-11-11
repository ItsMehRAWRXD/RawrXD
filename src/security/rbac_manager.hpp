// RawrXD Role-Based Access Control Manager
// Phase AG: Security Hardening

#pragma once

#include <string>
#include <vector>
#include <unordered_map>
#include <unordered_set>
#include <memory>
#include <mutex>

namespace rawrxd {
namespace security {

// Permission types
enum class Permission {
    // Model permissions
    MODEL_LOAD,
    MODEL_UNLOAD,
    MODEL_LIST,
    
    // Inference permissions
    INFERENCE_EXECUTE,
    INFERENCE_STREAM,
    INFERENCE_BATCH,
    
    // Configuration permissions
    CONFIG_READ,
    CONFIG_WRITE,
    CONFIG_DELETE,
    
    // User management permissions
    USER_CREATE,
    USER_READ,
    USER_UPDATE,
    USER_DELETE,
    
    // System permissions
    SYSTEM_STATUS,
    SYSTEM_SHUTDOWN,
    SYSTEM_MAINTENANCE,
    
    // Audit permissions
    AUDIT_READ,
    AUDIT_EXPORT,
    
    // Admin permissions
    ADMIN_FULL
};

// Role definition
struct Role {
    std::string id;
    std::string name;
    std::string description;
    std::unordered_set<Permission> permissions;
    std::unordered_set<std::string> allowed_resources;
    std::unordered_set<std::string> denied_resources;
    bool is_system_role;
    
    Role() : is_system_role(false) {}
    
    bool hasPermission(Permission perm) const {
        return permissions.find(perm) != permissions.end() ||
               permissions.find(Permission::ADMIN_FULL) != permissions.end();
    }
};

// User definition
struct User {
    std::string id;
    std::string username;
    std::string email;
    std::vector<std::string> role_ids;
    std::unordered_map<std::string, std::string> attributes;
    bool is_active;
    bool is_system_user;
    
    User() : is_active(true), is_system_user(false) {}
};

// Resource definition
struct Resource {
    std::string id;
    std::string type;  // "model", "config", "user", "system"
    std::string owner;
    std::unordered_map<std::string, std::string> attributes;
};

// Access check result
struct AccessCheckResult {
    bool allowed;
    std::string reason;
    std::vector<std::string> matched_roles;
    
    AccessCheckResult(bool a = false, const std::string& r = "") 
        : allowed(a), reason(r) {}
};

/**
 * RBAC Manager - Role-Based Access Control
 * 
 * Manages users, roles, and permissions for fine-grained access control.
 */
class RBACManager {
public:
    RBACManager();
    ~RBACManager();
    
    // Initialize with default roles
    bool initialize();
    
    // Role management
    bool createRole(const Role& role);
    bool updateRole(const Role& role);
    bool deleteRole(const std::string& role_id);
    Role getRole(const std::string& role_id) const;
    std::vector<Role> getAllRoles() const;
    
    // User management
    bool createUser(const User& user);
    bool updateUser(const User& user);
    bool deleteUser(const std::string& user_id);
    User getUser(const std::string& user_id) const;
    User getUserByUsername(const std::string& username) const;
    std::vector<User> getAllUsers() const;
    
    // Role assignment
    bool assignRole(const std::string& user_id, const std::string& role_id);
    bool revokeRole(const std::string& user_id, const std::string& role_id);
    std::vector<Role> getUserRoles(const std::string& user_id) const;
    
    // Permission checking
    AccessCheckResult checkAccess(const std::string& user_id, 
                                   Permission permission,
                                   const std::string& resource_id = "") const;
    bool hasPermission(const std::string& user_id, Permission permission) const;
    std::vector<Permission> getUserPermissions(const std::string& user_id) const;
    
    // Resource ownership
    bool setResourceOwner(const std::string& resource_id, const std::string& user_id);
    std::string getResourceOwner(const std::string& resource_id) const;
    
    // Permission to string conversion
    static std::string permissionToString(Permission perm);
    static Permission stringToPermission(const std::string& str);
    
    // Default roles
    static Role createAdminRole();
    static Role createOperatorRole();
    static Role createUserRole();
    static Role createReadOnlyRole();
    
private:
    std::unordered_map<std::string, Role> roles_;
    std::unordered_map<std::string, User> users_;
    std::unordered_map<std::string, Resource> resources_;
    
    mutable std::mutex roles_mutex_;
    mutable std::mutex users_mutex_;
    mutable std::mutex resources_mutex_;
    
    bool initialized_;
};

// Global RBAC manager accessor
RBACManager* getRBACManager();
void setRBACManager(std::unique_ptr<RBACManager> manager);

} // namespace security
} // namespace rawrxd
