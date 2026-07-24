// ============================================================================
// WorkspaceTrust.hpp - Workspace Trust Model
// ============================================================================

#pragma once
#include <string>
#include <vector>
#include <functional>
#include <unordered_map>

namespace Sovereign {

enum class TrustLevel { UNTRUSTED, PARTIAL, TRUSTED, FULL };

struct WorkspaceTrustConfig {
    std::string path;
    TrustLevel level;
    std::vector<std::string> allowedOperations;
    std::vector<std::string> blockedOperations;
    bool allowExecution;
    bool allowFileWrite;
    bool allowNetwork;
    bool allowExtensions;
};

class WorkspaceTrust {
public:
    WorkspaceTrust();
    ~WorkspaceTrust();

    void SetTrust(const std::string& path, TrustLevel level);
    TrustLevel GetTrust(const std::string& path) const;
    bool IsOperationAllowed(const std::string& path, const std::string& operation) const;
    void SetDefaultTrust(TrustLevel level) { defaultTrust_ = level; }
    
    void AddRestrictedPath(const std::string& path);
    void RemoveRestrictedPath(const std::string& path);
    std::vector<std::string> GetRestrictedPaths() const;

private:
    std::unordered_map<std::string, WorkspaceTrustConfig> trustConfigs_;
    std::vector<std::string> restrictedPaths_;
    TrustLevel defaultTrust_ = TrustLevel::UNTRUSTED;
    mutable std::mutex mutex_;
};

} // namespace Sovereign
