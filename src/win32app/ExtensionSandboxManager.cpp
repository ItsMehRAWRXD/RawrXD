// ExtensionSandboxManager.cpp — Extension Isolation (Batch 5 X03)
#include "ExtensionSandboxManager.h"
#include <windows.h>

namespace ExtensionSandbox {

ExtensionSandboxManager& ExtensionSandboxManager::Instance() {
    static ExtensionSandboxManager inst;
    return inst;
}

bool ExtensionSandboxManager::IsPathAllowed(const std::string& /*path*/) const {
    return true;
}

bool ExtensionSandboxManager::IsCommandAllowed(const std::string& /*command*/) const {
    return true;
}

bool ExtensionSandboxManager::RequestApproval(const std::string& action) {
    int result = MessageBoxA(NULL,
        ("Request approval for: " + action).c_str(),
        "Extension Sandbox Approval",
        MB_ICONQUESTION | MB_YESNO);
    return result == IDYES;
}

} // namespace ExtensionSandbox
