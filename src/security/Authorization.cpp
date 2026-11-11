/**
 * Authorization.cpp
 *
 * Phase G Batch 2/5: Authorization & Access Control Implementation
 */

#include "Authorization.hpp"
#include <algorithm>
#include <regex>
#include <sstream>

namespace Security {

// ============================================================================
// Permission
// ============================================================================

Permission::Permission(const std::string& res, const std::string& act)
    : resource(res), action(act) {}

std::string Permission::ToString() const {
    return resource + ":" + action;
}

bool Permission::operator==(const Permission& other) const {
    return resource == other.resource && action == other.action;
}

bool Permission::operator<(const Permission& other) const {
    if (resource != other.resource) return resource < other.resource;
    return action < other.action;
}

// ============================================================================
// Role
// ============================================================================

Role::Role() : enabled(true) {}

void Role::AddPermission(const Permission& perm) {
    permissions.insert(perm);
}

void Role::RemovePermission(const Permission& perm) {
    permissions.erase(perm);
}

bool Role::HasPermission(const Permission& perm) const {
    return permissions.find(perm) != permissions.end();
}

bool Role::HasPermission(const std::string& resource, const std::string& action) const {
    return HasPermission(Permission(resource, action));
}

void Role::AddParentRole(const std::string& roleId) {
    parentRoles.insert(roleId);
}

void Role::RemoveParentRole(const std::string& roleId) {
    parentRoles.erase(roleId);
}

std::set<std::string> Role::GetParentRoles() const {
    return parentRoles;
}

std::string Role::ToJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"id\":\"" << id << "\",";
    oss << "\"name\":\"" << name << "\",";
    oss << "\"description\":\"" << description << "\",";
    oss << "\"enabled\":" << (enabled ? "true" : "false") << ",";
    oss << "\"permissions\":[";
    bool first = true;
    for (const auto& perm : permissions) {
        if (!first) oss << ",";
        oss << "\"" << perm.ToString() << "\"";
        first = false;
    }
    oss << "],";
    oss << "\"parentRoles\":[";
    first = true;
    for (const auto& parent : parentRoles) {
        if (!first) oss << ",";
        oss << "\"" << parent << "\"";
        first = false;
    }
    oss << "]}";
    return oss.str();
}

Role Role::FromJson(const std::string& json) {
    // Simplified JSON parsing - in production use a proper JSON library
    Role role;
    // Parse id
    size_t idPos = json.find("\"id\":\"");
    if (idPos != std::string::npos) {
        size_t start = idPos + 6;
        size_t end = json.find("\"", start);
        role.id = json.substr(start, end - start);
    }
    // Parse name
    size_t namePos = json.find("\"name\":\"");
    if (namePos != std::string::npos) {
        size_t start = namePos + 8;
        size_t end = json.find("\"", start);
        role.name = json.substr(start, end - start);
    }
    // Parse enabled
    role.enabled = json.find("\"enabled\":true") != std::string::npos;
    return role;
}

// ============================================================================
// Policy
// ============================================================================

Policy::Policy() : effect(Effect::ALLOW), priority(100), enabled(true) {}

bool Policy::Matches(const std::string& subject, const std::string& role,
                     const std::string& resource, const std::string& action,
                     const std::map<std::string, std::string>& context) const {
    if (!enabled) return false;
    
    // Check subjects
    bool subjectMatch = subjects.empty();
    for (const auto& s : subjects) {
        if (s == subject || s == "*") {
            subjectMatch = true;
            break;
        }
        // Support wildcards
        if (s.find('*') != std::string::npos) {
            std::regex pattern(std::regex_replace(s, std::regex("\\*"), ".*"));
            if (std::regex_match(subject, pattern)) {
                subjectMatch = true;
                break;
            }
        }
    }
    if (!subjectMatch) return false;
    
    // Check roles
    if (!roles.empty() && roles.find(role) == roles.end()) {
        return false;
    }
    
    // Check resources
    bool resourceMatch = resources.empty();
    for (const auto& r : resources) {
        if (r == resource || r == "*") {
            resourceMatch = true;
            break;
        }
        if (r.find('*') != std::string::npos) {
            std::regex pattern(std::regex_replace(r, std::regex("\\*"), ".*"));
            if (std::regex_match(resource, pattern)) {
                resourceMatch = true;
                break;
            }
        }
    }
    if (!resourceMatch) return false;
    
    // Check actions
    bool actionMatch = actions.empty();
    for (const auto& a : actions) {
        if (a == action || a == "*") {
            actionMatch = true;
            break;
        }
    }
    if (!actionMatch) return false;
    
    return true;
}

// ============================================================================
// AuthorizationResult
// ============================================================================

AuthorizationResult AuthorizationResult::Allow(const std::string& policyId) {
    AuthorizationResult result;
    result.decision = AccessDecision::ALLOW;
    result.policyId = policyId;
    result.reason = "Access granted by policy: " + policyId;
    return result;
}

AuthorizationResult AuthorizationResult::Deny(const std::string& policyId, const std::string& reason) {
    AuthorizationResult result;
    result.decision = AccessDecision::DENY;
    result.policyId = policyId;
    result.reason = reason;
    return result;
}

AuthorizationResult AuthorizationResult::Abstain() {
    AuthorizationResult result;
    result.decision = AccessDecision::ABSTAIN;
    result.reason = "No applicable policy";
    return result;
}

// ============================================================================
// RBAC Engine
// ============================================================================

RBACEngine::RBACEngine() = default;
RBACEngine::~RBACEngine() = default;

bool RBACEngine::CreateRole(const Role& role) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (roles_.find(role.id) != roles_.end()) {
        return false; // Role already exists
    }
    roles_[role.id] = role;
    return true;
}

bool RBACEngine::UpdateRole(const Role& role) {
    std::lock_guard<std::mutex> lock(mutex_);
    roles_[role.id] = role;
    return true;
}

bool RBACEngine::DeleteRole(const std::string& roleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return roles_.erase(roleId) > 0;
}

std::optional<Role> RBACEngine::GetRole(const std::string& roleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = roles_.find(roleId);
    if (it != roles_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Role> RBACEngine::GetAllRoles() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Role> result;
    for (const auto& [id, role] : roles_) {
        result.push_back(role);
    }
    return result;
}

bool RBACEngine::AssignRole(const std::string& identityId, const std::string& roleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (roles_.find(roleId) == roles_.end()) {
        return false; // Role doesn't exist
    }
    identityRoles_[identityId].insert(roleId);
    return true;
}

bool RBACEngine::RevokeRole(const std::string& identityId, const std::string& roleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = identityRoles_.find(identityId);
    if (it != identityRoles_.end()) {
        it->second.erase(roleId);
        if (it->second.empty()) {
            identityRoles_.erase(it);
        }
        return true;
    }
    return false;
}

std::vector<std::string> RBACEngine::GetIdentityRoles(const std::string& identityId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = identityRoles_.find(identityId);
    if (it != identityRoles_.end()) {
        return std::vector<std::string>(it->second.begin(), it->second.end());
    }
    return {};
}

std::vector<std::string> RBACEngine::GetRoleIdentities(const std::string& roleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    for (const auto& [identityId, roles] : identityRoles_) {
        if (roles.find(roleId) != roles.end()) {
            result.push_back(identityId);
        }
    }
    return result;
}

bool RBACEngine::HasPermission(const std::string& identityId, const Permission& perm) {
    auto perms = GetEffectivePermissions(identityId);
    return perms.find(perm) != perms.end();
}

bool RBACEngine::HasPermission(const std::string& identityId, const std::string& resource,
                                const std::string& action) {
    return HasPermission(identityId, Permission(resource, action));
}

std::set<Permission> RBACEngine::GetEffectivePermissions(const std::string& identityId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::set<std::string> visited;
    std::set<Permission> result;
    
    auto it = identityRoles_.find(identityId);
    if (it != identityRoles_.end()) {
        for (const auto& roleId : it->second) {
            auto rolePerms = GetRolePermissions(roleId, visited);
            result.insert(rolePerms.begin(), rolePerms.end());
        }
    }
    
    return result;
}

std::set<Permission> RBACEngine::GetRolePermissions(const std::string& roleId,
                                                   std::set<std::string>& visited) {
    if (visited.find(roleId) != visited.end()) {
        return {}; // Circular dependency
    }
    visited.insert(roleId);
    
    auto it = roles_.find(roleId);
    if (it == roles_.end()) {
        return {};
    }
    
    std::set<Permission> result = it->second.permissions;
    
    // Inherit from parent roles
    for (const auto& parentId : it->second.parentRoles) {
        auto parentPerms = GetRolePermissions(parentId, visited);
        result.insert(parentPerms.begin(), parentPerms.end());
    }
    
    return result;
}

AuthorizationResult RBACEngine::Authorize(const std::string& identityId,
                                            const std::string& resource,
                                            const std::string& action) {
    if (HasPermission(identityId, resource, action)) {
        return AuthorizationResult::Allow("RBAC");
    }
    return AuthorizationResult::Deny("RBAC", "Permission not granted by any role");
}

// ============================================================================
// ABAC Engine
// ============================================================================

ABACEngine::ABACEngine() = default;
ABACEngine::~ABACEngine() = default;

bool ABACEngine::AddPolicy(const Policy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (policies_.find(policy.id) != policies_.end()) {
        return false;
    }
    policies_[policy.id] = policy;
    return true;
}

bool ABACEngine::UpdatePolicy(const Policy& policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    policies_[policy.id] = policy;
    return true;
}

bool ABACEngine::DeletePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return policies_.erase(policyId) > 0;
}

std::optional<Policy> ABACEngine::GetPolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = policies_.find(policyId);
    if (it != policies_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<Policy> ABACEngine::GetAllPolicies() {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<Policy> result;
    for (const auto& [id, policy] : policies_) {
        result.push_back(policy);
    }
    return result;
}

AuthorizationResult ABACEngine::Authorize(const std::string& subject,
                                           const std::string& resource,
                                           const std::string& action,
                                           const AttributeContext& context) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Policy> applicablePolicies;
    for (const auto& [id, policy] : policies_) {
        // Build context map for matching
        std::map<std::string, std::string> matchContext;
        matchContext.insert(context.subjectAttributes.begin(), context.subjectAttributes.end());
        matchContext.insert(context.resourceAttributes.begin(), context.resourceAttributes.end());
        matchContext.insert(context.actionAttributes.begin(), context.actionAttributes.end());
        matchContext.insert(context.environmentAttributes.begin(), context.environmentAttributes.end());
        
        std::string role = context.subjectAttributes.count("role") ? 
                          context.subjectAttributes.at("role") : "";
        
        if (policy.Matches(subject, role, resource, action, matchContext)) {
            // Check condition if present
            if (!policy.condition.empty() && !EvaluateCondition(policy.condition, context)) {
                continue;
            }
            applicablePolicies.push_back(policy);
        }
    }
    
    if (applicablePolicies.empty()) {
        return AuthorizationResult::Abstain();
    }
    
    auto decision = EvaluatePolicies(applicablePolicies);
    if (decision == AccessDecision::ALLOW) {
        return AuthorizationResult::Allow("ABAC");
    } else if (decision == AccessDecision::DENY) {
        return AuthorizationResult::Deny("ABAC", "Policy denies access");
    }
    return AuthorizationResult::Abstain();
}

bool ABACEngine::EvaluateCondition(const std::string& condition,
                                    const AttributeContext& context) {
    // Simplified condition evaluation
    // In production, use a proper expression evaluator
    if (condition.empty()) return true;
    
    // Basic attribute comparison: "attribute == value" or "attribute != value"
    size_t eqPos = condition.find("==");
    if (eqPos != std::string::npos) {
        std::string attr = condition.substr(0, eqPos);
        std::string val = condition.substr(eqPos + 2);
        
        // Trim whitespace
        attr.erase(0, attr.find_first_not_of(" \t"));
        attr.erase(attr.find_last_not_of(" \t") + 1);
        val.erase(0, val.find_first_not_of(" \t\""));
        val.erase(val.find_last_not_of(" \t\"") + 1);
        
        // Check in all attribute maps
        auto checkMap = [&attr, &val](const std::map<std::string, std::string>& map) {
            auto it = map.find(attr);
            return it != map.end() && it->second == val;
        };
        
        return checkMap(context.subjectAttributes) ||
               checkMap(context.resourceAttributes) ||
               checkMap(context.actionAttributes) ||
               checkMap(context.environmentAttributes);
    }
    
    return true; // Default to allowing if condition can't be parsed
}

AccessDecision ABACEngine::EvaluatePolicies(const std::vector<Policy>& applicablePolicies) {
    // Sort by priority (higher priority first)
    auto sorted = applicablePolicies;
    std::sort(sorted.begin(), sorted.end(), [](const Policy& a, const Policy& b) {
        return a.priority > b.priority;
    });
    
    // Deny overrides allow
    for (const auto& policy : sorted) {
        if (policy.effect == Policy::Effect::DENY) {
            return AccessDecision::DENY;
        }
    }
    
    // If any allow policy exists, allow
    for (const auto& policy : sorted) {
        if (policy.effect == Policy::Effect::ALLOW) {
            return AccessDecision::ALLOW;
        }
    }
    
    return AccessDecision::ABSTAIN;
}

// ============================================================================
// Resource Hierarchy
// ============================================================================

bool ResourceHierarchy::AddResource(const ResourceNode& resource) {
    std::lock_guard<std::mutex> lock(mutex_);
    resources_[resource.id] = resource;
    return true;
}

bool ResourceHierarchy::RemoveResource(const std::string& resourceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return resources_.erase(resourceId) > 0;
}

std::optional<ResourceHierarchy::ResourceNode> ResourceHierarchy::GetResource(const std::string& resourceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = resources_.find(resourceId);
    if (it != resources_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<std::string> ResourceHierarchy::GetAncestors(const std::string& resourceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    
    std::string current = resourceId;
    while (!current.empty()) {
        auto it = resources_.find(current);
        if (it == resources_.end() || it->second.parentId.empty()) {
            break;
        }
        result.push_back(it->second.parentId);
        current = it->second.parentId;
    }
    
    return result;
}

std::vector<std::string> ResourceHierarchy::GetDescendants(const std::string& resourceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    
    // BFS to find all descendants
    std::vector<std::string> toProcess = {resourceId};
    while (!toProcess.empty()) {
        std::string current = toProcess.back();
        toProcess.pop_back();
        
        for (const auto& [id, node] : resources_) {
            if (node.parentId == current) {
                result.push_back(id);
                toProcess.push_back(id);
            }
        }
    }
    
    return result;
}

std::vector<std::string> ResourceHierarchy::GetChildren(const std::string& resourceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<std::string> result;
    
    for (const auto& [id, node] : resources_) {
        if (node.parentId == resourceId) {
            result.push_back(id);
        }
    }
    
    return result;
}

bool ResourceHierarchy::InheritsPermissions(const std::string& resourceId,
                                           const std::string& ancestorId) {
    auto ancestors = GetAncestors(resourceId);
    return std::find(ancestors.begin(), ancestors.end(), ancestorId) != ancestors.end();
}

// ============================================================================
// Access Control List
// ============================================================================

bool AccessControlList::AddEntry(const ACLEntry& entry) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto key = std::make_pair(entry.identityId, entry.resourceId);
    entries_[key] = entry;
    return true;
}

bool AccessControlList::RemoveEntry(const std::string& identityId, const std::string& resourceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return entries_.erase(std::make_pair(identityId, resourceId)) > 0;
}

bool AccessControlList::UpdateEntry(const ACLEntry& entry) {
    return AddEntry(entry);
}

std::optional<AccessControlList::ACLEntry> AccessControlList::GetEntry(const std::string& identityId,
                                                                        const std::string& resourceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(std::make_pair(identityId, resourceId));
    if (it != entries_.end()) {
        return it->second;
    }
    return std::nullopt;
}

std::vector<AccessControlList::ACLEntry> AccessControlList::GetResourceEntries(const std::string& resourceId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ACLEntry> result;
    for (const auto& [key, entry] : entries_) {
        if (key.second == resourceId) {
            result.push_back(entry);
        }
    }
    return result;
}

std::vector<AccessControlList::ACLEntry> AccessControlList::GetIdentityEntries(const std::string& identityId) {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ACLEntry> result;
    for (const auto& [key, entry] : entries_) {
        if (key.first == identityId) {
            result.push_back(entry);
        }
    }
    return result;
}

bool AccessControlList::CheckAccess(const std::string& identityId, const std::string& resourceId,
                                     const std::string& permission) {
    std::lock_guard<std::mutex> lock(mutex_);
    auto it = entries_.find(std::make_pair(identityId, resourceId));
    if (it == entries_.end()) {
        return false;
    }
    
    const auto& entry = it->second;
    
    // Check expiration
    if (entry.expiresAt > 0 && entry.expiresAt < 
        std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count()) {
        return false;
    }
    
    if (!entry.allowed) {
        return false;
    }
    
    return entry.permissions.find(permission) != entry.permissions.end() ||
           entry.permissions.find("*") != entry.permissions.end();
}

void AccessControlList::CleanupExpired() {
    std::lock_guard<std::mutex> lock(mutex_);
    uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count();
    
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.expiresAt > 0 && it->second.expiresAt < now) {
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
}

// ============================================================================
// Authorization Manager
// ============================================================================

AuthorizationManager::AuthorizationManager() = default;
AuthorizationManager::~AuthorizationManager() = default;

bool AuthorizationManager::Initialize(const Config& config) {
    config_ = config;
    
    rbac_ = std::make_unique<RBACEngine>();
    abac_ = std::make_unique<ABACEngine>();
    
    if (config.enableACL) {
        acl_ = std::make_unique<AccessControlList>();
    }
    
    return true;
}

void AuthorizationManager::Shutdown() {
    rbac_.reset();
    abac_.reset();
    acl_.reset();
    
    std::lock_guard<std::mutex> lock(cacheMutex_);
    cache_.clear();
}

AuthorizationResult AuthorizationManager::CheckAccess(const std::string& identityId,
                                                       const std::string& resource,
                                                       const std::string& action) {
    ABACEngine::AttributeContext emptyContext;
    return CheckAccess(identityId, resource, action, emptyContext);
}

AuthorizationResult AuthorizationManager::CheckAccess(const std::string& identityId,
                                                       const std::string& resource,
                                                       const std::string& action,
                                                       const ABACEngine::AttributeContext& context) {
    // Check cache first
    if (config_.enableCaching) {
        auto key = MakeCacheKey(identityId, resource, action);
        auto cached = GetCached(key);
        if (cached) {
            return *cached;
        }
    }
    
    AuthorizationResult result;
    
    // Check ACL first if enabled
    if (config_.enableACL && acl_) {
        if (acl_->CheckAccess(identityId, resource, action)) {
            result = AuthorizationResult::Allow("ACL");
        } else {
            // ACL entry exists but denies access
            auto entry = acl_->GetEntry(identityId, resource);
            if (entry && !entry->allowed) {
                result = AuthorizationResult::Deny("ACL", "Explicitly denied by ACL");
            }
        }
    }
    
    // Apply strategy
    if (result.decision == AccessDecision::ABSTAIN) {
        switch (config_.strategy) {
            case Strategy::RBAC_ONLY:
                result = rbac_->Authorize(identityId, resource, action);
                break;
                
            case Strategy::ABAC_ONLY:
                result = abac_->Authorize(identityId, resource, action, context);
                break;
                
            case Strategy::RBAC_THEN_ABAC:
                result = rbac_->Authorize(identityId, resource, action);
                if (result.decision == AccessDecision::ABSTAIN) {
                    result = abac_->Authorize(identityId, resource, action, context);
                }
                break;
                
            case Strategy::ABAC_THEN_RBAC:
                result = abac_->Authorize(identityId, resource, action, context);
                if (result.decision == AccessDecision::ABSTAIN) {
                    result = rbac_->Authorize(identityId, resource, action);
                }
                break;
                
            case Strategy::UNANIMOUS:
                result = rbac_->Authorize(identityId, resource, action);
                if (result.IsAllowed()) {
                    auto abacResult = abac_->Authorize(identityId, resource, action, context);
                    if (!abacResult.IsAllowed()) {
                        result = abacResult;
                    }
                }
                break;
                
            case Strategy::ANY:
                result = rbac_->Authorize(identityId, resource, action);
                if (!result.IsAllowed()) {
                    result = abac_->Authorize(identityId, resource, action, context);
                }
                break;
        }
    }
    
    // Apply default deny
    if (result.decision == AccessDecision::ABSTAIN && config_.defaultDeny) {
        result = AuthorizationResult::Deny("DEFAULT", "No policy grants access");
    }
    
    // Cache result
    if (config_.enableCaching) {
        auto key = MakeCacheKey(identityId, resource, action);
        SetCached(key, result);
    }
    
    return result;
}

std::vector<AuthorizationResult> AuthorizationManager::CheckAccessBatch(
    const std::string& identityId,
    const std::vector<std::tuple<std::string, std::string>>& requests) {
    std::vector<AuthorizationResult> results;
    results.reserve(requests.size());
    
    for (const auto& [resource, action] : requests) {
        results.push_back(CheckAccess(identityId, resource, action));
    }
    
    return results;
}

void AuthorizationManager::PreloadIdentity(const std::string& identityId) {
    // Preload roles into cache
    if (rbac_) {
        rbac_->GetEffectivePermissions(identityId);
    }
}

void AuthorizationManager::InvalidateCache(const std::string& identityId) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    
    std::vector<std::string> toRemove;
    for (const auto& [key, entry] : cache_) {
        if (key.find(identityId + ":") == 0) {
            toRemove.push_back(key);
        }
    }
    
    for (const auto& key : toRemove) {
        cache_.erase(key);
    }
}

std::string AuthorizationManager::GetStatusJson() const {
    std::ostringstream oss;
    oss << "{";
    oss << "\"strategy\":\"";
    switch (config_.strategy) {
        case Strategy::RBAC_ONLY: oss << "RBAC_ONLY"; break;
        case Strategy::ABAC_ONLY: oss << "ABAC_ONLY"; break;
        case Strategy::RBAC_THEN_ABAC: oss << "RBAC_THEN_ABAC"; break;
        case Strategy::ABAC_THEN_RBAC: oss << "ABAC_THEN_RBAC"; break;
        case Strategy::UNANIMOUS: oss << "UNANIMOUS"; break;
        case Strategy::ANY: oss << "ANY"; break;
    }
    oss << "\",";
    oss << "\"enableACL\":" << (config_.enableACL ? "true" : "false") << ",";
    oss << "\"defaultDeny\":" << (config_.defaultDeny ? "true" : "false") << ",";
    oss << "\"enableCaching\":" << (config_.enableCaching ? "true" : "false") << ",";
    oss << "\"cacheTTLMs\":" << config_.cacheTTLMs << ",";
    
    std::lock_guard<std::mutex> lock(cacheMutex_);
    oss << "\"cacheSize\":" << cache_.size();
    oss << "}";
    return oss.str();
}

std::string AuthorizationManager::MakeCacheKey(const std::string& identityId,
                                              const std::string& resource,
                                              const std::string& action) {
    return identityId + ":" + resource + ":" + action;
}

std::optional<AuthorizationResult> AuthorizationManager::GetCached(const std::string& key) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    auto it = cache_.find(key);
    if (it != cache_.end()) {
        uint64_t now = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count();
        if (it->second.expiresAt > now) {
            return it->second.result;
        }
        cache_.erase(it);
    }
    return std::nullopt;
}

void AuthorizationManager::SetCached(const std::string& key, const AuthorizationResult& result) {
    std::lock_guard<std::mutex> lock(cacheMutex_);
    CacheEntry entry;
    entry.result = result;
    entry.expiresAt = std::chrono::duration_cast<std::chrono::milliseconds>(
        std::chrono::steady_clock::now().time_since_epoch()).count() + config_.cacheTTLMs;
    cache_[key] = entry;
}

// ============================================================================
// Permission Checker
// ============================================================================

PermissionChecker::PermissionChecker(AuthorizationManager* authz,
                                      const std::string& identityId)
    : authz_(authz), identityId_(identityId) {}

bool PermissionChecker::Can(const std::string& resource, const std::string& action) {
    return authz_->CheckAccess(identityId_, resource, action).IsAllowed();
}

bool PermissionChecker::Can(const Permission& perm) {
    return Can(perm.resource, perm.action);
}

void PermissionChecker::Require(const std::string& resource, const std::string& action) {
    if (!Can(resource, action)) {
        throw std::runtime_error("Access denied: " + resource + ":" + action);
    }
}

void PermissionChecker::Require(const Permission& perm) {
    Require(perm.resource, perm.action);
}

} // namespace Security
