// ============================================================================
// workspace_trust_integration.cpp — Workspace Trust Manager Implementation
// ============================================================================
// Architecture: C++20 | Win32 | Security-first | Trust by exception
// Rule: NO SOURCE FILE IS TO BE SIMPLIFIED
// ============================================================================

#include "workspace_trust_integration.h"

#include <windows.h>
#include <algorithm>
#include <fstream>
#include <cctype>
#include <nlohmann/json.hpp>

using json = nlohmann::json;

namespace RawrXD {
namespace Extensions {

// ============================================================================
// Global Instance
// ============================================================================

static WorkspaceTrustManager* g_trustManager = nullptr;

WorkspaceTrustManager& GetWorkspaceTrustManager() {
    if (!g_trustManager) {
        g_trustManager = new WorkspaceTrustManager();
    }
    return *g_trustManager;
}

// ============================================================================
// WorkspaceTrustManager Implementation
// ============================================================================

WorkspaceTrustManager::WorkspaceTrustManager() {
    InitializeCapabilityPolices();
}

WorkspaceTrustManager::~WorkspaceTrustManager() {
}

void WorkspaceTrustManager::InitializeCapabilityPolices() {
    // Define what capabilities are allowed in each trust state
    
    // In trusted workspaces: all capabilities allowed
    m_allowedCapabilities[WorkspaceTrustState::Trusted] = {
        GuardedCapability::ExecuteCommand,
        GuardedCapability::TerminalAccess,
        GuardedCapability::ProcessSpawn,
        GuardedCapability::FileWrite,
        GuardedCapability::NetworkRequest,
        GuardedCapability::ExtensionScripting,
        GuardedCapability::TaskExecution,
        GuardedCapability::DebuggerAccess,
    };

    // In untrusted workspaces: very limited capabilities
    m_allowedCapabilities[WorkspaceTrustState::Untrusted] = {
        GuardedCapability::TerminalAccess,  // Read-only
        GuardedCapability::NetworkRequest,   // Limited to HTTPS
        // Most other capabilities blocked
    };

    // In restricted mode: minimal capabilities
    m_allowedCapabilities[WorkspaceTrustState::RestrictedMode] = {
        GuardedCapability::NetworkRequest,   // HTTPS only
        // Almost everything blocked
    };
}

WorkspaceTrustState WorkspaceTrustManager::GetWorkspaceTrustState(
    const std::string& workspacePath
) {
    if (workspacePath.empty()) {
        return WorkspaceTrustState::Unknown;
    }

    if (m_restrictedMode) {
        return WorkspaceTrustState::RestrictedMode;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto normalizedPath = NormalizePath(workspacePath);
    auto it = m_trustDecisions.find(normalizedPath);

    if (it != m_trustDecisions.end()) {
        return it->second.state;
    }

    return WorkspaceTrustState::Unknown;
}

bool WorkspaceTrustManager::IsWorkspaceTrusted(const std::string& workspacePath) const {
    if (workspacePath.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    if (m_restrictedMode) {
        return false;
    }

    auto normalizedPath = NormalizePath(workspacePath);
    auto it = m_trustDecisions.find(normalizedPath);

    if (it != m_trustDecisions.end()) {
        return it->second.state == WorkspaceTrustState::Trusted;
    }

    return false;
}

bool WorkspaceTrustManager::IsRestrictedMode() const {
    return m_restrictedMode.load();
}

bool WorkspaceTrustManager::TrustWorkspace(const std::string& workspacePath) {
    if (workspacePath.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto normalizedPath = NormalizePath(workspacePath);
    auto& decision = m_trustDecisions[normalizedPath];
    decision.workspacePath = normalizedPath;
    decision.state = WorkspaceTrustState::Trusted;
    decision.decisionTimeMs = ::GetTickCount64();
    decision.rememberDecision = true;

    return true;
}

bool WorkspaceTrustManager::UntrustWorkspace(const std::string& workspacePath) {
    if (workspacePath.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto normalizedPath = NormalizePath(workspacePath);
    auto& decision = m_trustDecisions[normalizedPath];
    decision.workspacePath = normalizedPath;
    decision.state = WorkspaceTrustState::Untrusted;
    decision.decisionTimeMs = ::GetTickCount64();
    decision.rememberDecision = true;

    return true;
}

bool WorkspaceTrustManager::ResetWorkspaceTrust(const std::string& workspacePath) {
    if (workspacePath.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto normalizedPath = NormalizePath(workspacePath);
    m_trustDecisions.erase(normalizedPath);

    return true;
}

TrustVerificationResult WorkspaceTrustManager::VerifyCapability(
    const std::string& workspacePath,
    GuardedCapability capability,
    const std::string& extensionId
) {
    TrustVerificationResult result;
    result.capability = capability;

    // Check if extension is blacklisted in untrusted workspaces
    if (!extensionId.empty()) {
        std::lock_guard<std::mutex> lock(m_lock);
        if (m_blacklistedExtensions.find(extensionId) != m_blacklistedExtensions.end()) {
            auto state = GetWorkspaceTrustState(workspacePath);
            if (state != WorkspaceTrustState::Trusted) {
                result.allowed = false;
                result.reason = "Extension is not allowed in untrusted workspaces";
                result.workspaceState = state;
                return result;
            }
        }
    }

    auto state = GetWorkspaceTrustState(workspacePath);
    result.workspaceState = state;

    std::lock_guard<std::mutex> lock(m_lock);

    auto it = m_allowedCapabilities.find(state);
    if (it != m_allowedCapabilities.end()) {
        result.allowed = it->second.find(capability) != it->second.end();
    }

    if (!result.allowed) {
        result.reason = "Capability not allowed in this workspace trust state";
    }

    return result;
}

bool WorkspaceTrustManager::CanCapabilityBeAllowed(
    const std::string& workspacePath,
    GuardedCapability capability
) const {
    if (workspacePath.empty()) {
        return false;
    }

    auto state = GetWorkspaceTrustState(workspacePath);
    if (state == WorkspaceTrustState::Trusted) {
        return true;  // All capabilities allowed in trusted workspaces
    }

    return false;
}

void WorkspaceTrustManager::RequestWorkspaceTrust(
    const std::string& workspacePath,
    std::function<void(bool trusted)> callback
) {
    if (workspacePath.empty() || !callback) {
        return;
    }

    // TODO: Show UI prompt to user asking for workspace trust
    // For MVP, call callback with false
    callback(false);
}

void WorkspaceTrustManager::RequestCapabilityPermission(
    const std::string& workspacePath,
    GuardedCapability capability,
    const std::string& extensionId,
    std::function<void(bool allowed)> callback
) {
    if (workspacePath.empty() || !callback) {
        return;
    }

    // TODO: Show UI prompt to user requesting capability permission
    // For MVP, call callback with false
    callback(false);
}

void WorkspaceTrustManager::SetExtensionTrustPolicy(const std::string& extensionId,
                                                    bool requiresWorkspaceTrust) {
    if (extensionId.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_lock);
    m_extensionTrustRequirements[extensionId] = requiresWorkspaceTrust;
}

bool WorkspaceTrustManager::ExtensionRequiresWorkspaceTrust(
    const std::string& extensionId
) const {
    if (extensionId.empty()) {
        return false;
    }

    std::lock_guard<std::mutex> lock(m_lock);

    auto it = m_extensionTrustRequirements.find(extensionId);
    if (it != m_extensionTrustRequirements.end()) {
        return it->second;
    }

    return false;
}

void WorkspaceTrustManager::BlacklistExtensionInUntrustedWorkspaces(
    const std::string& extensionId
) {
    if (extensionId.empty()) {
        return;
    }

    std::lock_guard<std::mutex> lock(m_lock);
    m_blacklistedExtensions.insert(extensionId);
}

bool WorkspaceTrustManager::LoadTrustDecisions(const std::string& storagePath) {
    if (storagePath.empty()) {
        return false;
    }

    try {
        std::ifstream file(storagePath);
        if (!file.is_open()) {
            return true;  // File doesn't exist yet
        }

        json data;
        file >> data;
        file.close();

        std::lock_guard<std::mutex> lock(m_lock);

        if (data.contains("trust_decisions") && data["trust_decisions"].is_object()) {
            for (auto& [path, decision] : data["trust_decisions"].items()) {
                TrustDecision td;
                td.workspacePath = path;
                // TODO: Deserialize state from JSON
                m_trustDecisions[path] = td;
            }
        }

        return true;
    } catch (...) {
        return false;
    }
}

bool WorkspaceTrustManager::SaveTrustDecisions(const std::string& storagePath) {
    if (storagePath.empty()) {
        return false;
    }

    try {
        json data;
        data["trust_decisions"] = json::object();

        {
            std::lock_guard<std::mutex> lock(m_lock);

            for (const auto& [path, decision] : m_trustDecisions) {
                json item;
                // TODO: Serialize decision to JSON
                data["trust_decisions"][path] = item;
            }
        }

        std::ofstream file(storagePath);
        if (!file.is_open()) {
            return false;
        }

        file << data.dump(2);
        file.close();

        return true;
    } catch (...) {
        return false;
    }
}

std::vector<std::string> WorkspaceTrustManager::GetTrustedWorkspaces() const {
    std::vector<std::string> trusted;

    {
        std::lock_guard<std::mutex> lock(m_lock);

        for (const auto& [path, decision] : m_trustDecisions) {
            if (decision.state == WorkspaceTrustState::Trusted) {
                trusted.push_back(path);
            }
        }
    }

    return trusted;
}

std::vector<std::string> WorkspaceTrustManager::GetUntrustedWorkspaces() const {
    std::vector<std::string> untrusted;

    {
        std::lock_guard<std::mutex> lock(m_lock);

        for (const auto& [path, decision] : m_trustDecisions) {
            if (decision.state == WorkspaceTrustState::Untrusted) {
                untrusted.push_back(path);
            }
        }
    }

    return untrusted;
}

void WorkspaceTrustManager::EnterRestrictedMode() {
    m_restrictedMode = true;
}

void WorkspaceTrustManager::ExitRestrictedMode() {
    m_restrictedMode = false;
}

std::string WorkspaceTrustManager::NormalizePath(const std::string& path) const {
    if (path.empty()) {
        return "";
    }

    // Convert to lowercase and normalize separators
    std::string normalized = path;
    for (auto& c : normalized) {
        if (c >= 'A' && c <= 'Z') {
            c = c - 'A' + 'a';
        } else if (c == '/') {
            c = '\\';
        }
    }

    return normalized;
}

bool WorkspaceTrustManager::MatchesPath(const std::string& pattern,
                                        const std::string& path) const {
    // Simple path matching: check if path starts with pattern
    return path.find(NormalizePath(pattern)) == 0;
}

// ============================================================================
// WorkspaceTrustGuard Implementation
// ============================================================================

WorkspaceTrustGuard::WorkspaceTrustGuard(const std::string& workspacePath,
                                         GuardedCapability capability,
                                         const std::string& extensionId)
    : m_workspacePath(workspacePath)
    , m_capability(capability)
    , m_extensionId(extensionId) {

    auto result = GetWorkspaceTrustManager().VerifyCapability(
        workspacePath, capability, extensionId
    );

    m_allowed = result.allowed;
    m_reason = result.reason;
}

WorkspaceTrustGuard::~WorkspaceTrustGuard() {
}

bool WorkspaceTrustGuard::IsAllowed() const {
    return m_allowed;
}

std::string WorkspaceTrustGuard::GetReason() const {
    return m_reason;
}

// ============================================================================
// Global Helpers
// ============================================================================

bool VerifyWorkspaceTrustForCapability(const std::string& workspacePath,
                                       GuardedCapability capability) {
    auto result = GetWorkspaceTrustManager().VerifyCapability(workspacePath, capability);
    return result.allowed;
}

WorkspaceTrustState GetCurrentWorkspaceTrustState(const std::string& workspacePath) {
    return GetWorkspaceTrustManager().GetWorkspaceTrustState(workspacePath);
}

}  // namespace Extensions
}  // namespace RawrXD

// ============================================================================
// End of workspace_trust_integration.cpp
// ============================================================================
