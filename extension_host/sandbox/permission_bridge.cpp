// permission_bridge.cpp — Permission Bridge Implementation
#include "permission_bridge.hpp"

namespace RawrXD {
namespace ExtensionHost {

PermissionBridge& PermissionBridge::Get() {
    static PermissionBridge instance;
    return instance;
}

PermissionResult PermissionBridge::CheckPermission(const std::string& extensionId, const std::string& operation, const std::string& resource) {
    // Check enterprise policy first
    auto policyIt = m_enterprisePolicies.find(operation);
    if (policyIt != m_enterprisePolicies.end()) {
        return policyIt->second ? PermissionResult::Granted : PermissionResult::Denied;
    }

    // Check if already granted
    auto extIt = m_grantedPermissions.find(extensionId);
    if (extIt != m_grantedPermissions.end()) {
        auto opIt = extIt->second.find(operation);
        if (opIt != extIt->second.end() && opIt->second) {
            return PermissionResult::Granted;
        }
    }

    // Not yet granted - needs approval
    return PermissionResult::PendingUserApproval;
}

PermissionResult PermissionBridge::RequestPermission(const PermissionRequest& request) {
    // Check enterprise policy
    auto policyIt = m_enterprisePolicies.find(request.operation);
    if (policyIt != m_enterprisePolicies.end()) {
        return policyIt->second ? PermissionResult::Granted : PermissionResult::Denied;
    }

    // Ask for user approval
    if (m_approvalCallback) {
        if (m_approvalCallback(request)) {
            GrantPermission(request.extensionId, request.operation);
            return PermissionResult::Granted;
        }
        return PermissionResult::Denied;
    }

    // Auto-deny if no callback
    return PermissionResult::Denied;
}

void PermissionBridge::GrantPermission(const std::string& extensionId, const std::string& operation) {
    m_grantedPermissions[extensionId][operation] = true;
}

void PermissionBridge::RevokePermission(const std::string& extensionId, const std::string& operation) {
    auto extIt = m_grantedPermissions.find(extensionId);
    if (extIt != m_grantedPermissions.end()) {
        extIt->second.erase(operation);
    }
}

std::vector<std::string> PermissionBridge::GetGrantedPermissions(const std::string& extensionId) const {
    std::vector<std::string> result;
    auto extIt = m_grantedPermissions.find(extensionId);
    if (extIt != m_grantedPermissions.end()) {
        for (const auto& [op, granted] : extIt->second) {
            if (granted) result.push_back(op);
        }
    }
    return result;
}

void PermissionBridge::SetEnterprisePolicy(const std::string& operation, bool allowed) {
    m_enterprisePolicies[operation] = allowed;
}

} // namespace ExtensionHost
} // namespace RawrXD
