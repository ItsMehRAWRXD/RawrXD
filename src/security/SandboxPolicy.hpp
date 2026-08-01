#pragma once
#include "CapabilityToken.hpp"

enum class PolicyDecision {
    Allow,
    Deny,
    Audit
};

class SandboxPolicy {
public:
    PolicyDecision CheckOperation(const CapabilityToken& token, const std::string& operation, PermissionScope scope) {
        if (HasPermission(token.grantedPermissions, PermissionScope::Admin)) return PolicyDecision::Allow;
        if (!token.IsAllowed(scope)) return PolicyDecision::Deny;
        return PolicyDecision::Allow;
    }
};
