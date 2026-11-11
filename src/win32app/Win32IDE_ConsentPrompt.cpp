#include "ConsentPrompt.h"
#include "ExtensionSandboxManager.h"
#include "Win32IDE.h"
#include <string>

bool ShowConsentPrompt(HWND hwndParent, const std::string& status) {
    int result = MessageBoxA(hwndParent, status.c_str(), "AI Consent Prompt",
                             MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
    return result == IDYES;
}

bool RequestToolConsent(HWND hwndParent, ConsentRiskTier tier,
                        const std::string& toolName,
                        const std::string& detail) {
    using ExtensionSandbox::RiskTier;
    RiskTier rt = RiskTier::Confirm;
    if (tier == ConsentRiskTier::Auto) rt = RiskTier::Auto;
    else if (tier == ConsentRiskTier::Block) rt = RiskTier::Block;
    // Prefer sandbox manager (audit + headless policy).
    auto& sb = ExtensionSandbox::ExtensionSandboxManager::Instance();
    (void)hwndParent;
    return sb.RequestRiskApproval(rt, toolName, detail);
}

void HandleConsentPrompt(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    if (!ide) return;
    std::string statusText =
        "Consent Prompt Active\n\n"
        "Tool-dispatch approval gate is wired through ExtensionSandboxManager.\n"
        "Mutating / shell tools require Confirm; Block tiers are always denied.\n"
        "CERTIFIED=0 PROMOTE=0";
    if (!ShowConsentPrompt(ide->getMainWindow(), statusText)) {
        MessageBoxA(NULL, "Consent was not granted by user", "Consent Prompt",
                    MB_ICONWARNING | MB_OK);
    }
}
