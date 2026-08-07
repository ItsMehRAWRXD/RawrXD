// permission_bridge.hpp — Permission Bridge for Extension Sandbox
#pragma once
#include <string>
#include <map>
#include <functional>

namespace RawrXD {
namespace ExtensionHost {

// ============================================================================
// Permission Request
// ============================================================================
struct PermissionRequest {
    std::string extensionId;
    std::string operation;
    std::string resource;
    std::string reason;
};

// ============================================================================
// Permission Response
// ============================================================================
enum class PermissionResult {
    Granted,
    Denied,
    PendingUserApproval,
    PendingAdminApproval
};

// ============================================================================
// Permission Bridge
// ============================================================================
class PermissionBridge {
public:
    static PermissionBridge& Get();

    // Check if operation is allowed
    PermissionResult CheckPermission(const std::string& extensionId, const std::string& operation, const std::string& resource = "");

    // Request permission (may prompt user)
    PermissionResult RequestPermission(const PermissionRequest& request);

    // Grant permission
    void GrantPermission(const std::string& extensionId, const std::string& operation);

    // Revoke permission
    void RevokePermission(const std::string& extensionId, const std::string& operation);

    // Get granted permissions for extension
    std::vector<std::string> GetGrantedPermissions(const std::string& extensionId) const;

    // Enterprise policy override
    void SetEnterprisePolicy(const std::string& operation, bool allowed);

    // User approval callback
    using ApprovalCallback = std::function<bool(const PermissionRequest&)>;
    void SetApprovalCallback(ApprovalCallback callback) { m_approvalCallback = callback; }

private:
    PermissionBridge() = default;
    std::map<std::string, std::map<std::string, bool>> m_grantedPermissions;
    std::map<std::string, bool> m_enterprisePolicies;
    ApprovalCallback m_approvalCallback;
};

} // namespace ExtensionHost
} // namespace RawrXD
