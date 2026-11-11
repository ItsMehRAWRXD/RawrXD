// RawrXD RBAC Manager Implementation
// Phase AG: Security Hardening

#include "rbac_manager.hpp"
#include <algorithm>
#include <sstream>

namespace rawrxd {
namespace security {

// Global RBAC manager instance
static std::unique_ptr<RBACManager> g_rbac_manager;

RBACManager* getRBACManager() {
    return g_rbac_manager.get();
}

void setRBACManager(std::unique_ptr<RBACManager> manager) {
    g_rbac_manager = std::move(manager);
}

// RBACManager implementation
RBACManager::RBACManager() : initialized_(false) {}

RBACManager::~RBACManager() = default;

bool RBACManager::initialize() {
    // Create default system roles
    createRole(createAdminRole());
    createRole(createOperatorRole());
    createRole(createUserRole());
    createRole(createReadOnlyRole());
    
    initialized_ = true;
    return true;
}

bool RBACManager::createRole(const Role& role) {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    
    if (roles_.find(role.id) != roles_.end()) {
        return false; // Role already exists
    }
    
    roles_[role.id] = role;
    return true;
}

bool RBACManager::updateRole(const Role& role) {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    
    if (roles_.find(role.id) == roles_.end()) {
        return false; // Role doesn't exist
    }
    
    // Don't allow modifying system roles
    if (roles_[role.id].is_system_role && !role.is_system_role) {
        return false;
    }
    
    roles_[role.id] = role;
    return true;
}

bool RBACManager::deleteRole(const std::string& role_id) {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    
    auto it = roles_.find(role_id);
    if (it == roles_.end()) {
        return false;
    }
    
    // Don't allow deleting system roles
    if (it->second.is_system_role) {
        return false;
    }
    
    roles_.erase(it);
    return true;
}

Role RBACManager::getRole(const std::string& role_id) const {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    
    auto it = roles_.find(role_id);
    if (it != roles_.end()) {
        return it->second;
    }
    
    return Role(); // Return empty role
}

std::vector<Role> RBACManager::getAllRoles() const {
    std::lock_guard<std::mutex> lock(roles_mutex_);
    
    std::vector<Role> result;
    for (const auto& [id, role] : roles_) {
        result.push_back(role);
    }
    return result;
}

bool RBACManager::createUser(const User& user) {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    if (users_.find(user.id) != users_.end()) {
        return false; // User already exists
    }
    
    users_[user.id] = user;
    return true;
}

bool RBACManager::updateUser(const User& user) {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    if (users_.find(user.id) == users_.end()) {
        return false; // User doesn't exist
    }
    
    users_[user.id] = user;
    return true;
}

bool RBACManager::deleteUser(const std::string& user_id) {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    auto it = users_.find(user_id);
    if (it == users_.end()) {
        return false;
    }
    
    // Don't allow deleting system users
    if (it->second.is_system_user) {
        return false;
    }
    
    users_.erase(it);
    return true;
}

User RBACManager::getUser(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    auto it = users_.find(user_id);
    if (it != users_.end()) {
        return it->second;
    }
    
    return User(); // Return empty user
}

User RBACManager::getUserByUsername(const std::string& username) const {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    for (const auto& [id, user] : users_) {
        if (user.username == username) {
            return user;
        }
    }
    
    return User(); // Return empty user
}

std::vector<User> RBACManager::getAllUsers() const {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    std::vector<User> result;
    for (const auto& [id, user] : users_) {
        result.push_back(user);
    }
    return result;
}

bool RBACManager::assignRole(const std::string& user_id, const std::string& role_id) {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    auto it = users_.find(user_id);
    if (it == users_.end()) {
        return false;
    }
    
    // Check if role exists
    {
        std::lock_guard<std::mutex> role_lock(roles_mutex_);
        if (roles_.find(role_id) == roles_.end()) {
            return false;
        }
    }
    
    // Check if already assigned
    auto& user = it->second;
    if (std::find(user.role_ids.begin(), user.role_ids.end(), role_id) != user.role_ids.end()) {
        return true; // Already assigned
    }
    
    user.role_ids.push_back(role_id);
    return true;
}

bool RBACManager::revokeRole(const std::string& user_id, const std::string& role_id) {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    auto it = users_.find(user_id);
    if (it == users_.end()) {
        return false;
    }
    
    auto& user = it->second;
    auto role_it = std::find(user.role_ids.begin(), user.role_ids.end(), role_id);
    if (role_it == user.role_ids.end()) {
        return false; // Role not assigned
    }
    
    user.role_ids.erase(role_it);
    return true;
}

std::vector<Role> RBACManager::getUserRoles(const std::string& user_id) const {
    std::lock_guard<std::mutex> lock(users_mutex_);
    
    auto it = users_.find(user_id);
    if (it == users_.end()) {
        return {};
    }
    
    std::vector<Role> result;
    {
        std::lock_guard<std::mutex> role_lock(roles_mutex_);
        for (const auto& role_id : it->second.role_ids) {
            auto role_it = roles_.find(role_id);
            if (role_it != roles_.end()) {
                result.push_back(role_it->second);
            }
        }
    }
    
    return result;
}

AccessCheckResult RBACManager::checkAccess(const std::string& user_id,
                                              Permission permission,
                                              const std::string& resource_id) const {
    AccessCheckResult result;
    
    // Get user
    User user = getUser(user_id);
    if (user.id.empty()) {
        result.reason = "User not found";
        return result;
    }
    
    if (!user.is_active) {
        result.reason = "User is inactive";
        return result;
    }
    
    // Get user roles
    std::vector<Role> roles = getUserRoles(user_id);
    if (roles.empty()) {
        result.reason = "User has no roles assigned";
        return result;
    }
    
    // Check each role
    for (const auto& role : roles) {
        if (role.hasPermission(permission)) {
            // Check resource restrictions
            if (!resource_id.empty()) {
                if (!role.allowed_resources.empty() && 
                    role.allowed_resources.find(resource_id) == role.allowed_resources.end()) {
                    continue; // Resource not in allowed list
                }
                
                if (role.denied_resources.find(resource_id) != role.denied_resources.end()) {
                    continue; // Resource in denied list
                }
            }
            
            result.allowed = true;
            result.matched_roles.push_back(role.name);
        }
    }
    
    if (!result.allowed) {
        result.reason = "Permission denied";
    }
    
    return result;
}

bool RBACManager::hasPermission(const std::string& user_id, Permission permission) const {
    AccessCheckResult result = checkAccess(user_id, permission);
    return result.allowed;
}

std::vector<Permission> RBACManager::getUserPermissions(const std::string& user_id) const {
    std::vector<Permission> result;
    
    std::vector<Role> roles = getUserRoles(user_id);
    std::unordered_set<Permission> unique_perms;
    
    for (const auto& role : roles) {
        for (const auto& perm : role.permissions) {
            if (unique_perms.insert(perm).second) {
                result.push_back(perm);
            }
        }
    }
    
    return result;
}

bool RBACManager::setResourceOwner(const std::string& resource_id, const std::string& user_id) {
    std::lock_guard<std::mutex> lock(resources_mutex_);
    
    resources_[resource_id].owner = user_id;
    return true;
}

std::string RBACManager::getResourceOwner(const std::string& resource_id) const {
    std::lock_guard<std::mutex> lock(resources_mutex_);
    
    auto it = resources_.find(resource_id);
    if (it != resources_.end()) {
        return it->second.owner;
    }
    
    return "";
}

std::string RBACManager::permissionToString(Permission perm) {
    switch (perm) {
        case Permission::MODEL_LOAD: return "model:load";
        case Permission::MODEL_UNLOAD: return "model:unload";
        case Permission::MODEL_LIST: return "model:list";
        case Permission::INFERENCE_EXECUTE: return "inference:execute";
        case Permission::INFERENCE_STREAM: return "inference:stream";
        case Permission::INFERENCE_BATCH: return "inference:batch";
        case Permission::CONFIG_READ: return "config:read";
        case Permission::CONFIG_WRITE: return "config:write";
        case Permission::CONFIG_DELETE: return "config:delete";
        case Permission::USER_CREATE: return "user:create";
        case Permission::USER_READ: return "user:read";
        case Permission::USER_UPDATE: return "user:update";
        case Permission::USER_DELETE: return "user:delete";
        case Permission::SYSTEM_STATUS: return "system:status";
        case Permission::SYSTEM_SHUTDOWN: return "system:shutdown";
        case Permission::SYSTEM_MAINTENANCE: return "system:maintenance";
        case Permission::AUDIT_READ: return "audit:read";
        case Permission::AUDIT_EXPORT: return "audit:export";
        case Permission::ADMIN_FULL: return "admin:full";
        default: return "unknown";
    }
}

Permission RBACManager::stringToPermission(const std::string& str) {
    static const std::unordered_map<std::string, Permission> mapping = {
        {"model:load", Permission::MODEL_LOAD},
        {"model:unload", Permission::MODEL_UNLOAD},
        {"model:list", Permission::MODEL_LIST},
        {"inference:execute", Permission::INFERENCE_EXECUTE},
        {"inference:stream", Permission::INFERENCE_STREAM},
        {"inference:batch", Permission::INFERENCE_BATCH},
        {"config:read", Permission::CONFIG_READ},
        {"config:write", Permission::CONFIG_WRITE},
        {"config:delete", Permission::CONFIG_DELETE},
        {"user:create", Permission::USER_CREATE},
        {"user:read", Permission::USER_READ},
        {"user:update", Permission::USER_UPDATE},
        {"user:delete", Permission::USER_DELETE},
        {"system:status", Permission::SYSTEM_STATUS},
        {"system:shutdown", Permission::SYSTEM_SHUTDOWN},
        {"system:maintenance", Permission::SYSTEM_MAINTENANCE},
        {"audit:read", Permission::AUDIT_READ},
        {"audit:export", Permission::AUDIT_EXPORT},
        {"admin:full", Permission::ADMIN_FULL}
    };
    
    auto it = mapping.find(str);
    if (it != mapping.end()) {
        return it->second;
    }
    
    return Permission::ADMIN_FULL; // Default to no permission
}

// Default role creators
Role RBACManager::createAdminRole() {
    Role role;
    role.id = "admin";
    role.name = "Administrator";
    role.description = "Full system access";
    role.permissions = {Permission::ADMIN_FULL};
    role.is_system_role = true;
    return role;
}

Role RBACManager::createOperatorRole() {
    Role role;
    role.id = "operator";
    role.name = "Operator";
    role.description = "Can manage models and execute inference";
    role.permissions = {
        Permission::MODEL_LOAD,
        Permission::MODEL_UNLOAD,
        Permission::MODEL_LIST,
        Permission::INFERENCE_EXECUTE,
        Permission::INFERENCE_STREAM,
        Permission::INFERENCE_BATCH,
        Permission::CONFIG_READ,
        Permission::CONFIG_WRITE,
        Permission::SYSTEM_STATUS
    };
    role.is_system_role = true;
    return role;
}

Role RBACManager::createUserRole() {
    Role role;
    role.id = "user";
    role.name = "User";
    role.description = "Standard user with inference access";
    role.permissions = {
        Permission::MODEL_LIST,
        Permission::INFERENCE_EXECUTE,
        Permission::INFERENCE_STREAM,
        Permission::CONFIG_READ
    };
    role.is_system_role = true;
    return role;
}

Role RBACManager::createReadOnlyRole() {
    Role role;
    role.id = "readonly";
    role.name = "Read Only";
    role.description = "View-only access";
    role.permissions = {
        Permission::MODEL_LIST,
        Permission::CONFIG_READ,
        Permission::SYSTEM_STATUS
    };
    role.is_system_role = true;
    return role;
}

} // namespace security
} // namespace rawrxd
