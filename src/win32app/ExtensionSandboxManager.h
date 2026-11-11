// ExtensionSandboxManager.h — AF04 path/command sandbox (fail-closed)
#pragma once

#include <mutex>
#include <string>
#include <vector>

namespace ExtensionSandbox {

enum class RiskTier { Auto, Confirm, Block };

class ExtensionSandboxManager {
public:
    static ExtensionSandboxManager& Instance();

    // Fail-closed until at least one workspace root is configured.
    bool PolicyReady() const;
    void ClearPolicy();
    void AddWorkspaceRoot(const std::string& root);
    void AddDeniedPathPrefix(const std::string& prefix);
    void SetAuditLogPath(const std::string& path);
    void SetInteractive(bool interactive); // false => RequestApproval denies
    void SetAutoApproveConfirm(bool allow); // probe/CI only; default false

    bool IsPathAllowed(const std::string& path) const;
    bool IsCommandAllowed(const std::string& command) const;
    bool RequestApproval(const std::string& action);
    bool RequestRiskApproval(RiskTier tier, const std::string& tool,
                             const std::string& detail);

    // Path/command only (no UI). Fail closed when policy missing.
    bool CheckPathAndCommand(const std::string& toolName,
                             const std::string& pathArg,
                             const std::string& commandArg,
                             std::string& denyReason);

    // Full choke: path/command then risk-tier approval before mutate/shell.
    bool GateToolDispatch(const std::string& toolName, RiskTier tier,
                          const std::string& pathArg,
                          const std::string& commandArg,
                          std::string& denyReason);

    void AppendAudit(const std::string& decision, const std::string& tool,
                     const std::string& detail, const std::string& reason);

private:
    ExtensionSandboxManager() = default;
    std::string Normalize(const std::string& p) const;
    bool PathUnderRoot(const std::string& absPath) const;
    bool PathDenied(const std::string& absPath) const;
    bool CommandMatchesDanger(const std::string& lower) const;

    mutable std::mutex m_mu;
    std::vector<std::string> m_roots;
    std::vector<std::string> m_denyPrefixes;
    std::string m_auditPath;
    bool m_interactive = true;
    bool m_autoApproveConfirm = false;
};

} // namespace ExtensionSandbox
