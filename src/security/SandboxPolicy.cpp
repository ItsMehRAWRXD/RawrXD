// src/security/SandboxPolicy.cpp
// Enforces capability tokens against every backend operation.
// Every call through BackendManager is checked here first.

#include "CapabilityToken.hpp"
#include <iostream>
#include <string>
#include <vector>
#include <algorithm>

// ---------------------------------------------------------------------------
// Policy decision
// ---------------------------------------------------------------------------
enum class PolicyDecision {
    Allow,
    Deny,
    AuditOnly  // Allowed but logged
};

// ---------------------------------------------------------------------------
// Policy rule — maps a backend + operation to a decision
// ---------------------------------------------------------------------------
struct PolicyRule {
    std::string     backendName;
    std::string     operation;       // "build", "audit", "network", "gpu", etc.
    PermissionScope requiredPermission;
    PolicyDecision  decision;
    std::string     reason;
};

// ---------------------------------------------------------------------------
// Sandbox policy engine
// ---------------------------------------------------------------------------
class SandboxPolicy {
private:
    std::vector<PolicyRule> m_rules;
    bool m_enforceStrict = true;

public:
    SandboxPolicy() {
        // Default rules
        m_rules.push_back({"PowerShell", "build",  PermissionScope::Build,  PolicyDecision::Allow,     "PowerShell build allowed"});
        m_rules.push_back({"PowerShell", "network", PermissionScope::Network, PolicyDecision::Deny,  "PowerShell: network blocked by policy"});
        m_rules.push_back({"PowerShell", "admin",   PermissionScope::Admin,   PolicyDecision::Deny,  "PowerShell: elevation blocked"});
        m_rules.push_back({"BareMetal",  "build",   PermissionScope::Build,  PolicyDecision::Allow,  "BareMetal build allowed"});
        m_rules.push_back({"BareMetal",  "gpu",     PermissionScope::GpuAccess, PolicyDecision::Allow, "BareMetal GPU access allowed"});
        m_rules.push_back({"BareMetal",  "network", PermissionScope::Network, PolicyDecision::Deny,  "BareMetal: network blocked"});
        m_rules.push_back({"RemoteAgent","network", PermissionScope::Network, PolicyDecision::Allow,  "RemoteAgent network allowed"});
        m_rules.push_back({"RemoteAgent","filesystem", PermissionScope::Filesystem, PolicyDecision::Deny, "RemoteAgent: no local FS"});
        m_rules.push_back({"Sandbox",    "build",   PermissionScope::Build,  PolicyDecision::Allow,  "Sandbox build allowed"});
        m_rules.push_back({"Sandbox",    "filesystem", PermissionScope::Filesystem, PolicyDecision::Deny, "Sandbox: FS blocked"});
        m_rules.push_back({"Sandbox",    "network", PermissionScope::Network, PolicyDecision::Deny,  "Sandbox: network blocked"});
    }

    // -----------------------------------------------------------------------
    // Check an operation against the policy + token
    // -----------------------------------------------------------------------
    PolicyDecision CheckOperation(const CapabilityToken& token,
                                   const std::string& operation,
                                   PermissionScope requiredPerm) {
        // 1. Check token expiry
        if (token.IsExpired()) {
            std::cerr << "[SandboxPolicy] Token expired: " << token.tokenId << "\n";
            return PolicyDecision::Deny;
        }

        // 2. Check token permissions
        if (!token.IsAllowed(requiredPerm)) {
            std::cerr << "[SandboxPolicy] Token lacks permission: "
                      << token.backendName << " / " << operation << "\n";
            return PolicyDecision::Deny;
        }

        // 3. Check policy rules
        for (const auto& rule : m_rules) {
            if (rule.backendName == token.backendName && rule.operation == operation) {
                if (rule.decision == PolicyDecision::Deny) {
                    std::cerr << "[SandboxPolicy] Rule blocked: " << rule.reason << "\n";
                }
                return rule.decision;
            }
        }

        // 4. Default: strict mode denies, permissive allows
        if (m_enforceStrict) {
            std::cerr << "[SandboxPolicy] No matching rule, strict mode denies: "
                      << token.backendName << " / " << operation << "\n";
            return PolicyDecision::Deny;
        }
        return PolicyDecision::Allow;
    }

    // -----------------------------------------------------------------------
    // Quick-check helper for BackendManager
    // -----------------------------------------------------------------------
    bool IsBuildAllowed(const CapabilityToken& token) {
        return CheckOperation(token, "build", PermissionScope::Build) != PolicyDecision::Deny;
    }

    bool IsNetworkAllowed(const CapabilityToken& token) {
        return CheckOperation(token, "network", PermissionScope::Network) != PolicyDecision::Deny;
    }

    bool IsGpuAllowed(const CapabilityToken& token) {
        return CheckOperation(token, "gpu", PermissionScope::GpuAccess) != PolicyDecision::Deny;
    }

    // -----------------------------------------------------------------------
    // Configuration
    // -----------------------------------------------------------------------
    void SetStrictMode(bool strict) { m_enforceStrict = strict; }
    bool IsStrict() const { return m_enforceStrict; }

    // -----------------------------------------------------------------------
    // Dump all rules for audit
    // -----------------------------------------------------------------------
    void PrintRules() const {
        std::cout << "[SandboxPolicy] Active rules:\n";
        for (const auto& rule : m_rules) {
            std::cout << "  " << rule.backendName << " / " << rule.operation
                      << " -> " << (rule.decision == PolicyDecision::Allow ? "ALLOW" :
                                    rule.decision == PolicyDecision::Deny ? "DENY" : "AUDIT")
                      << " (" << rule.reason << ")\n";
        }
    }
};
