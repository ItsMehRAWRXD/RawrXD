// ExtensionSandboxManager.h — Extension Isolation (Batch 5 X03)
#pragma once

#include <string>

namespace ExtensionSandbox {

class ExtensionSandboxManager {
public:
    static ExtensionSandboxManager& Instance();

    bool IsPathAllowed(const std::string& path) const;
    bool IsCommandAllowed(const std::string& command) const;
    bool RequestApproval(const std::string& action);

private:
    ExtensionSandboxManager() = default;
};

} // namespace ExtensionSandbox
