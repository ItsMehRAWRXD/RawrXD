#pragma once
// Consent Prompt — user approval gate for AI / agent tool actions.
#include <windows.h>
#include <string>

enum class ConsentRiskTier {
    Auto = 0,
    Confirm = 1,
    Block = 2
};

// Returns true if user grants consent (MessageBox Yes). Default button = No.
bool ShowConsentPrompt(HWND hwndParent, const std::string& status);

// Risk-tier gate used by tool-dispatch choke point (not demo-only).
// Auto: allow; Confirm: prompt (or headless deny); Block: always deny.
bool RequestToolConsent(HWND hwndParent, ConsentRiskTier tier,
                        const std::string& toolName,
                        const std::string& detail);

void HandleConsentPrompt(void* idePtr);
