// RawrXD Access Control System Implementation
// Phase Q.2: RBAC, ABAC, and policy-based access control

#include "AccessControlSystem.hpp"
#include "AuditLogger.hpp"

#include <algorithm>
#include <regex>
#include <sstream>

namespace RawrXD {
namespace Security {

// ============================================================================
// AccessControlSystem Implementation
// ============================================================================

AccessControlSystem::AccessControlSystem(AuditLogger* auditLogger)
    : auditLogger_(auditLogger)
    , running_(false)
    , initialized_(false) {
}

AccessControlSystem::~AccessControlSystem() {
    if (running_) {
        shutdown();
    }
}

bool AccessControlSystem::initialize(const AccessControlConfig& config) {
    if (initialized_) {
        return true;
    }
    
    config_ = config;
    
    // Create default roles
    Role adminRole;
    adminRole.id = "role-admin";
    adminRole.name = "Administrator";
    adminRole.description = "Full system access";
    adminRole.isActive = true;
    adminRole.createdAt = std::chrono::system_clock::now();
    roles_[adminRole.id] = adminRole;
    
    Role userRole;
    userRole.id = "role-user";
    userRole.name = "User";
    userRole.description = "Standard user access";
    userRole.permissions = {
        Permission::MODEL_READ,
        Permission::INFERENCE_REQUEST,
        Permission::DATA_READ
    };
    userRole.isActive = true;
    userRole.createdAt = std::chrono::system_clock::now();
    roles_[userRole.id] = userRole;
    
    Role readonlyRole;
    readonlyRole.id = "role-readonly";
    readonlyRole.name = "Read Only";
    readonlyRole.description = "Read-only access";
    readonlyRole.permissions = {
        Permission::MODEL_READ,
        Permission::DATA_READ
    };
    readonlyRole.isActive = true;
    readonlyRole.createdAt = std::chrono::system_clock::now();
    roles_[readonlyRole.id] = readonlyRole;
    
    running_ = true;
    initialized_ = true;
    return true;
}

bool AccessControlSystem::shutdown() {
    if (!initialized_) {
        return true;
    }
    
    running_ = false;
    
    // Clear all sessions
    sessions_.clear();
    sessionExpiry_.clear();
    impersonations_.clear();
    
    initialized_ = false;
    return true;
}

// ============================================================================
// Authorization
// ============================================================================

AccessDecision AccessControlSystem::authorize(const AccessRequest& request) {
    auto start = std::chrono::steady_clock::now();
    
    AccessDecision decision;
    decision.allowed = false;
    
    // Check cache first
    if (config_.enableCaching) {
        CacheKey key;
        key.subjectId = request.subject.id;
        key.permission = request.permission;
        key.resourceId = request.resource.id;
        
        auto cacheIt = cache_.find(key);
        if (cacheIt != cache_.end()) {
            auto age = std::chrono::steady_clock::now() - cacheIt->second.second;
            if (age < std::chrono::seconds(config_.cacheTTLSeconds)) {
                decision.allowed = cacheIt->second.first;
                decision.reason = "Cache hit";
                cacheHits_++;
                
                auto end = std::chrono::steady_clock::now();
                decision.evaluationTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
                
                return decision;
            }
        }
        cacheMisses_++;
    }
    
    // Get subject with all roles
    Subject subject = request.subject;
    auto subjectRoles = getSubjectRoles(subject.id);
    for (const auto& roleId : subjectRoles) {
        auto role = getRole(roleId);
        if (role.isActive) {
            subject.roles.push_back(roleId);
        }
    }
    
    // Check direct permissions
    if (subject.directPermissions.count(request.permission)) {
        decision.allowed = true;
        decision.reason = "Direct permission";
    }
    
    // Check role permissions
    if (!decision.allowed) {
        for (const auto& roleId : subject.roles) {
            auto role = getRole(roleId);
            if (role.permissions.count(request.permission)) {
                // Check resource constraints
                bool resourceAllowed = true;
                auto it = role.resourceConstraints.find(resourceTypeToString(request.resource.type));
                if (it != role.resourceConstraints.end()) {
                    std::regex pattern(it->second);
                    resourceAllowed = std::regex_match(request.resource.id, pattern);
                }
                
                if (resourceAllowed) {
                    decision.allowed = true;
                    decision.matchedRoles.push_back(roleId);
                    decision.reason = "Role permission: " + roleId;
                    break;
                }
            }
        }
    }
    
    // Evaluate ABAC policies
    if (decision.allowed || !config_.defaultDeny) {
        auto policies = getActivePolicies();
        
        // Sort by priority (highest first)
        std::sort(policies.begin(), policies.end(),
                  [](const PolicyRule& a, const PolicyRule& b) {
                      return a.priority > b.priority;
                  });
        
        for (const auto& policy : policies) {
            // Check if policy applies to this action
            bool actionMatches = std::find(policy.actions.begin(), policy.actions.end(),
                                            request.permission) != policy.actions.end();
            if (!actionMatches) continue;
            
            // Check resource type
            bool resourceMatches = std::find(policy.resourceTypes.begin(), policy.resourceTypes.end(),
                                            request.resource.type) != policy.resourceTypes.end();
            if (!resourceMatches && !policy.resourceTypes.empty()) continue;
            
            // Check resource pattern
            if (!policy.resourcePatterns.empty()) {
                bool patternMatches = false;
                for (const auto& pattern : policy.resourcePatterns) {
                    std::regex regexPattern(pattern);
                    if (std::regex_match(request.resource.path, regexPattern)) {
                        patternMatches = true;
                        break;
                    }
                }
                if (!patternMatches) continue;
            }
            
            // Evaluate conditions
            bool conditionsMet = evaluatePolicy(policy, request);
            
            if (conditionsMet) {
                decision.matchedPolicies.push_back(policy.id);
                
                if (policy.effect == PolicyRule::Effect::DENY) {
                    decision.allowed = false;
                    decision.reason = "Denied by policy: " + policy.name;
                    break;
                } else if (policy.effect == PolicyRule::Effect::ALLOW) {
                    decision.allowed = true;
                    decision.reason = "Allowed by policy: " + policy.name;
                }
            }
        }
    }
    
    // Apply default deny if no policy matched
    if (decision.reason.empty() && config_.defaultDeny) {
        decision.allowed = false;
        decision.reason = "Default deny";
    }
    
    // Update stats
    totalRequests_++;
    if (decision.allowed) {
        allowedRequests_++;
    } else {
        deniedRequests_++;
    }
    
    // Update cache
    if (config_.enableCaching) {
        CacheKey key;
        key.subjectId = request.subject.id;
        key.permission = request.permission;
        key.resourceId = request.resource.id;
        cache_[key] = {decision.allowed, std::chrono::steady_clock::now()};
        
        // Trim cache if too large
        if (cache_.size() > config_.maxCacheSize) {
            auto oldest = cache_.begin();
            cache_.erase(oldest);
        }
    }
    
    // Audit log
    if (auditLogger_ && (config_.auditAllRequests || (!decision.allowed && config_.auditDeniedOnly))) {
        // Would log to audit system
    }
    
    auto end = std::chrono::steady_clock::now();
    decision.evaluationTime = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
    
    return decision;
}

bool AccessControlSystem::checkPermission(const Subject& subject, Permission permission) {
    AccessRequest request;
    request.subject = subject;
    request.permission = permission;
    request.timestamp = std::chrono::system_clock::now();
    
    auto decision = authorize(request);
    return decision.allowed;
}

bool AccessControlSystem::checkPermission(const Subject& subject, Permission permission, 
                                          const Resource& resource) {
    AccessRequest request;
    request.subject = subject;
    request.permission = permission;
    request.resource = resource;
    request.timestamp = std::chrono::system_clock::now();
    
    auto decision = authorize(request);
    return decision.allowed;
}

// ============================================================================
// Role Management
// ============================================================================

std::string AccessControlSystem::createRole(const Role& role) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string id = role.id.empty() ? "role-" + std::to_string(roles_.size() + 1) : role.id;
    Role newRole = role;
    newRole.id = id;
    newRole.createdAt = std::chrono::system_clock::now();
    
    roles_[id] = newRole;
    return id;
}

bool AccessControlSystem::updateRole(const std::string& roleId, const Role& role) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = roles_.find(roleId);
    if (it == roles_.end()) {
        return false;
    }
    
    Role updated = role;
    updated.id = roleId;
    it->second = updated;
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

bool AccessControlSystem::deleteRole(const std::string& roleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Remove role from all subjects
    for (auto& [subjectId, subject] : subjects_) {
        auto& roles = subject.roles;
        roles.erase(std::remove(roles.begin(), roles.end(), roleId), roles.end());
    }
    
    // Invalidate cache
    cache_.clear();
    
    return roles_.erase(roleId) > 0;
}

Role AccessControlSystem::getRole(const std::string& roleId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = roles_.find(roleId);
    if (it != roles_.end()) {
        return it->second;
    }
    
    return Role{};
}

std::vector<Role> AccessControlSystem::getAllRoles() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Role> result;
    for (const auto& [id, role] : roles_) {
        result.push_back(role);
    }
    return result;
}

std::vector<Role> AccessControlSystem::getRolesForSubject(const std::string& subjectId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Role> result;
    auto subjectIt = subjects_.find(subjectId);
    if (subjectIt != subjects_.end()) {
        for (const auto& roleId : subjectIt->second.roles) {
            auto roleIt = roles_.find(roleId);
            if (roleIt != roles_.end()) {
                result.push_back(roleIt->second);
            }
        }
    }
    return result;
}

// ============================================================================
// Role Assignment
// ============================================================================

bool AccessControlSystem::assignRole(const std::string& subjectId, const std::string& roleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto subjectIt = subjects_.find(subjectId);
    auto roleIt = roles_.find(roleId);
    
    if (subjectIt == subjects_.end() || roleIt == roles_.end()) {
        return false;
    }
    
    // Check if already assigned
    auto& roles = subjectIt->second.roles;
    if (std::find(roles.begin(), roles.end(), roleId) != roles.end()) {
        return true; // Already assigned
    }
    
    roles.push_back(roleId);
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

bool AccessControlSystem::revokeRole(const std::string& subjectId, const std::string& roleId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto subjectIt = subjects_.find(subjectId);
    if (subjectIt == subjects_.end()) {
        return false;
    }
    
    auto& roles = subjectIt->second.roles;
    roles.erase(std::remove(roles.begin(), roles.end(), roleId), roles.end());
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

std::vector<std::string> AccessControlSystem::getSubjectRoles(const std::string& subjectId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = subjects_.find(subjectId);
    if (it != subjects_.end()) {
        return it->second.roles;
    }
    
    return {};
}

// ============================================================================
// Policy Management
// ============================================================================

std::string AccessControlSystem::createPolicy(const PolicyRule& policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::string id = policy.id.empty() ? "policy-" + std::to_string(policies_.size() + 1) : policy.id;
    PolicyRule newPolicy = policy;
    newPolicy.id = id;
    
    policies_[id] = newPolicy;
    
    // Invalidate cache
    cache_.clear();
    
    return id;
}

bool AccessControlSystem::updatePolicy(const std::string& policyId, const PolicyRule& policy) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }
    
    PolicyRule updated = policy;
    updated.id = policyId;
    it->second = updated;
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

bool AccessControlSystem::deletePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Invalidate cache
    cache_.clear();
    
    return policies_.erase(policyId) > 0;
}

PolicyRule AccessControlSystem::getPolicy(const std::string& policyId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = policies_.find(policyId);
    if (it != policies_.end()) {
        return it->second;
    }
    
    return PolicyRule{};
}

std::vector<PolicyRule> AccessControlSystem::getAllPolicies() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PolicyRule> result;
    for (const auto& [id, policy] : policies_) {
        result.push_back(policy);
    }
    return result;
}

std::vector<PolicyRule> AccessControlSystem::getActivePolicies() const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<PolicyRule> result;
    for (const auto& [id, policy] : policies_) {
        if (policy.isActive) {
            result.push_back(policy);
        }
    }
    return result;
}

bool AccessControlSystem::enablePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }
    
    it->second.isActive = true;
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

bool AccessControlSystem::disablePolicy(const std::string& policyId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = policies_.find(policyId);
    if (it == policies_.end()) {
        return false;
    }
    
    it->second.isActive = false;
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

// ============================================================================
// Subject Management
// ============================================================================

bool AccessControlSystem::registerSubject(const Subject& subject) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    if (subjects_.count(subject.id)) {
        return false; // Already exists
    }
    
    subjects_[subject.id] = subject;
    return true;
}

bool AccessControlSystem::updateSubject(const std::string& subjectId, const Subject& subject) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = subjects_.find(subjectId);
    if (it == subjects_.end()) {
        return false;
    }
    
    Subject updated = subject;
    updated.id = subjectId;
    it->second = updated;
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

bool AccessControlSystem::unregisterSubject(const std::string& subjectId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Terminate all sessions
    terminateAllSessions(subjectId);
    
    // Invalidate cache
    cache_.clear();
    
    return subjects_.erase(subjectId) > 0;
}

Subject AccessControlSystem::getSubject(const std::string& subjectId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = subjects_.find(subjectId);
    if (it != subjects_.end()) {
        return it->second;
    }
    
    return Subject{};
}

bool AccessControlSystem::subjectExists(const std::string& subjectId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    return subjects_.count(subjectId) > 0;
}

// ============================================================================
// Direct Permissions
// ============================================================================

bool AccessControlSystem::grantPermission(const std::string& subjectId, Permission permission) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = subjects_.find(subjectId);
    if (it == subjects_.end()) {
        return false;
    }
    
    it->second.directPermissions.insert(permission);
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

bool AccessControlSystem::revokePermission(const std::string& subjectId, Permission permission) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = subjects_.find(subjectId);
    if (it == subjects_.end()) {
        return false;
    }
    
    it->second.directPermissions.erase(permission);
    
    // Invalidate cache
    cache_.clear();
    
    return true;
}

// ============================================================================
// Permission Queries
// ============================================================================

std::set<Permission> AccessControlSystem::getEffectivePermissions(const std::string& subjectId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = subjects_.find(subjectId);
    if (it == subjects_.end()) {
        return {};
    }
    
    return computeEffectivePermissions(it->second);
}

std::set<Permission> AccessControlSystem::getEffectivePermissions(const std::string& subjectId,
                                                                  const Resource& resource) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = subjects_.find(subjectId);
    if (it == subjects_.end()) {
        return {};
    }
    
    return computeEffectivePermissions(it->second, resource);
}

std::vector<Subject> AccessControlSystem::getSubjectsWithPermission(Permission permission) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<Subject> result;
    for (const auto& [id, subject] : subjects_) {
        auto perms = computeEffectivePermissions(subject);
        if (perms.count(permission)) {
            result.push_back(subject);
        }
    }
    return result;
}

// ============================================================================
// Session Management
// ============================================================================

std::string AccessControlSystem::createSession(const Subject& subject, uint32_t durationMinutes) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Check max concurrent sessions
    uint32_t sessionCount = 0;
    for (const auto& [sid, subId] : sessions_) {
        if (subId == subject.id) {
            sessionCount++;
        }
    }
    
    if (sessionCount >= config_.maxConcurrentSessions) {
        return ""; // Max sessions reached
    }
    
    // Generate session ID
    std::string sessionId = "session-" + std::to_string(sessions_.size() + 1);
    
    sessions_[sessionId] = subject.id;
    sessionExpiry_[sessionId] = std::chrono::system_clock::now() + 
                                 std::chrono::minutes(durationMinutes);
    
    return sessionId;
}

bool AccessControlSystem::validateSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = sessionExpiry_.find(sessionId);
    if (it == sessionExpiry_.end()) {
        return false;
    }
    
    if (it->second < std::chrono::system_clock::now()) {
        // Session expired
        sessions_.erase(sessionId);
        sessionExpiry_.erase(it);
        return false;
    }
    
    return true;
}

bool AccessControlSystem::terminateSession(const std::string& sessionId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    sessions_.erase(sessionId);
    sessionExpiry_.erase(sessionId);
    
    return true;
}

void AccessControlSystem::terminateAllSessions(const std::string& subjectId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> sessionsToRemove;
    for (const auto& [sessionId, subId] : sessions_) {
        if (subId == subjectId) {
            sessionsToRemove.push_back(sessionId);
        }
    }
    
    for (const auto& sessionId : sessionsToRemove) {
        sessions_.erase(sessionId);
        sessionExpiry_.erase(sessionId);
    }
}

std::vector<std::string> AccessControlSystem::getActiveSessions(const std::string& subjectId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    std::vector<std::string> result;
    auto now = std::chrono::system_clock::now();
    
    for (const auto& [sessionId, subId] : sessions_) {
        if (subId == subjectId) {
            auto expiryIt = sessionExpiry_.find(sessionId);
            if (expiryIt != sessionExpiry_.end() && expiryIt->second > now) {
                result.push_back(sessionId);
            }
        }
    }
    
    return result;
}

// ============================================================================
// Impersonation
// ============================================================================

bool AccessControlSystem::impersonate(const std::string& adminId, const std::string& targetSubjectId) {
    std::lock_guard<std::mutex> lock(mutex_);
    
    // Verify admin has impersonation permission
    auto adminIt = subjects_.find(adminId);
    if (adminIt == subjects_.end()) {
        return false;
    }
    
    auto adminPerms = computeEffectivePermissions(adminIt->second);
    if (!adminPerms.count(Permission::SECURITY_ADMIN)) {
        return false;
    }
    
    // Verify target exists
    if (!subjects_.count(targetSubjectId)) {
        return false;
    }
    
    impersonations_[adminId] = targetSubjectId;
    return true;
}

bool AccessControlSystem::stopImpersonation(const std::string& adminId) {
    std::lock_guard<std::mutex> lock(mutex_);
    return impersonations_.erase(adminId) > 0;
}

std::string AccessControlSystem::getImpersonatedSubject(const std::string& adminId) const {
    std::lock_guard<std::mutex> lock(mutex_);
    
    auto it = impersonations_.find(adminId);
    if (it != impersonations_.end()) {
        return it->second;
    }
    
    return "";
}

// ============================================================================
// Statistics
// ============================================================================

AccessControlSystem::AuthStats AccessControlSystem::getStats() const {
    AuthStats stats;
    stats.totalRequests = totalRequests_.load();
    stats.allowedRequests = allowedRequests_.load();
    stats.deniedRequests = deniedRequests_.load();
    stats.cacheHits = cacheHits_.load();
    stats.cacheMisses = cacheMisses_.load();
    stats.avgEvaluationTimeMs = 0.0; // Would track timing
    return stats;
}

// ============================================================================
// Configuration
// ============================================================================

bool AccessControlSystem::updateConfig(const AccessControlConfig& config) {
    std::lock_guard<std::mutex> lock(mutex_);
    config_ = config;
    return true;
}

// ============================================================================
// Internal Methods
// ============================================================================

bool AccessControlSystem::evaluatePolicy(const PolicyRule& policy, const AccessRequest& request) {
    for (const auto& condition : policy.conditions) {
        if (!evaluateCondition(condition, request)) {
            return false;
        }
    }
    return true;
}

bool AccessControlSystem::evaluateCondition(const PolicyRule::Condition& condition,
                                            const AccessRequest& request) {
    std::string value;
    
    // Extract value from request
    if (condition.attribute.find("subject.") == 0) {
        std::string attr = condition.attribute.substr(8);
        auto it = request.subject.attributes.find(attr);
        if (it != request.subject.attributes.end()) {
            value = it->second;
        }
    } else if (condition.attribute.find("resource.") == 0) {
        std::string attr = condition.attribute.substr(9);
        auto it = request.resource.attributes.find(attr);
        if (it != request.resource.attributes.end()) {
            value = it->second;
        }
    } else if (condition.attribute.find("context.") == 0) {
        std::string attr = condition.attribute.substr(8);
        auto it = request.context.find(attr);
        if (it != request.context.end()) {
            value = it->second;
        }
    }
    
    // Evaluate operator
    if (condition.operator_ == "==") {
        return value == condition.value;
    } else if (condition.operator_ == "!=") {
        return value != condition.value;
    } else if (condition.operator_ == "in") {
        return value.find(condition.value) != std::string::npos;
    } else if (condition.operator_ == "contains") {
        return condition.value.find(value) != std::string::npos;
    } else if (condition.operator_ == "regex") {
        std::regex pattern(condition.value);
        return std::regex_match(value, pattern);
    }
    
    return false;
}

std::set<Permission> AccessControlSystem::computeEffectivePermissions(const Subject& subject) const {
    std::set<Permission> result = subject.directPermissions;
    
    for (const auto& roleId : subject.roles) {
        auto it = roles_.find(roleId);
        if (it != roles_.end()) {
            result.insert(it->second.permissions.begin(), it->second.permissions.end());
        }
    }
    
    return result;
}

std::set<Permission> AccessControlSystem::computeEffectivePermissions(const Subject& subject,
                                                                    const Resource& resource) const {
    // For now, same as without resource
    // In production, would check resource constraints
    return computeEffectivePermissions(subject);
}

// ============================================================================
// Permission Helpers
// ============================================================================

std::string permissionToString(Permission permission) {
    switch (permission) {
        case Permission::MODEL_READ: return "model:read";
        case Permission::MODEL_WRITE: return "model:write";
        case Permission::MODEL_DELETE: return "model:delete";
        case Permission::MODEL_EXECUTE: return "model:execute";
        case Permission::MODEL_ADMIN: return "model:admin";
        case Permission::INFERENCE_REQUEST: return "inference:request";
        case Permission::INFERENCE_BATCH: return "inference:batch";
        case Permission::INFERENCE_STREAMING: return "inference:streaming";
        case Permission::INFERENCE_ADMIN: return "inference:admin";
        case Permission::DATA_READ: return "data:read";
        case Permission::DATA_WRITE: return "data:write";
        case Permission::DATA_DELETE: return "data:delete";
        case Permission::DATA_EXPORT: return "data:export";
        case Permission::DATA_ADMIN: return "data:admin";
        case Permission::SYSTEM_READ: return "system:read";
        case Permission::SYSTEM_WRITE: return "system:write";
        case Permission::SYSTEM_CONFIGURE: return "system:configure";
        case Permission::SYSTEM_ADMIN: return "system:admin";
        case Permission::USER_READ: return "user:read";
        case Permission::USER_WRITE: return "user:write";
        case Permission::USER_DELETE: return "user:delete";
        case Permission::USER_ADMIN: return "user:admin";
        case Permission::SECURITY_READ: return "security:read";
        case Permission::SECURITY_WRITE: return "security:write";
        case Permission::SECURITY_AUDIT: return "security:audit";
        case Permission::SECURITY_ADMIN: return "security:admin";
        default: return "unknown";
    }
}

Permission permissionFromString(const std::string& str) {
    static const std::map<std::string, Permission> mapping = {
        {"model:read", Permission::MODEL_READ},
        {"model:write", Permission::MODEL_WRITE},
        {"model:delete", Permission::MODEL_DELETE},
        {"model:execute", Permission::MODEL_EXECUTE},
        {"model:admin", Permission::MODEL_ADMIN},
        {"inference:request", Permission::INFERENCE_REQUEST},
        {"inference:batch", Permission::INFERENCE_BATCH},
        {"inference:streaming", Permission::INFERENCE_STREAMING},
        {"inference:admin", Permission::INFERENCE_ADMIN},
        {"data:read", Permission::DATA_READ},
        {"data:write", Permission::DATA_WRITE},
        {"data:delete", Permission::DATA_DELETE},
        {"data:export", Permission::DATA_EXPORT},
        {"data:admin", Permission::DATA_ADMIN},
        {"system:read", Permission::SYSTEM_READ},
        {"system:write", Permission::SYSTEM_WRITE},
        {"system:configure", Permission::SYSTEM_CONFIGURE},
        {"system:admin", Permission::SYSTEM_ADMIN},
        {"user:read", Permission::USER_READ},
        {"user:write", Permission::USER_WRITE},
        {"user:delete", Permission::USER_DELETE},
        {"user:admin", Permission::USER_ADMIN},
        {"security:read", Permission::SECURITY_READ},
        {"security:write", Permission::SECURITY_WRITE},
        {"security:audit", Permission::SECURITY_AUDIT},
        {"security:admin", Permission::SECURITY_ADMIN}
    };
    
    auto it = mapping.find(str);
    if (it != mapping.end()) {
        return it->second;
    }
    
    return Permission::MODEL_READ; // Default
}

std::string resourceTypeToString(ResourceType type) {
    switch (type) {
        case ResourceType::MODEL: return "model";
        case ResourceType::DATASET: return "dataset";
        case ResourceType::ENDPOINT: return "endpoint";
        case ResourceType::API_KEY: return "api_key";
        case ResourceType::USER: return "user";
        case ResourceType::ROLE: return "role";
        case ResourceType::POLICY: return "policy";
        case ResourceType::SYSTEM_CONFIG: return "system_config";
        case ResourceType::LOG: return "log";
        case ResourceType::SECRET: return "secret";
        default: return "unknown";
    }
}

ResourceType resourceTypeFromString(const std::string& str) {
    static const std::map<std::string, ResourceType> mapping = {
        {"model", ResourceType::MODEL},
        {"dataset", ResourceType::DATASET},
        {"endpoint", ResourceType::ENDPOINT},
        {"api_key", ResourceType::API_KEY},
        {"user", ResourceType::USER},
        {"role", ResourceType::ROLE},
        {"policy", ResourceType::POLICY},
        {"system_config", ResourceType::SYSTEM_CONFIG},
        {"log", ResourceType::LOG},
        {"secret", ResourceType::SECRET}
    };
    
    auto it = mapping.find(str);
    if (it != mapping.end()) {
        return it->second;
    }
    
    return ResourceType::MODEL; // Default
}

} // namespace Security
} // namespace RawrXD
