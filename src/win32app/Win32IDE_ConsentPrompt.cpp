#include "Win32IDE.h"
#include "ConsentPrompt.h"
#include <windows.h>
#include <string>

// Consent Prompt implementation - user approval gate for AI actions
bool ShowConsentPrompt(HWND hwndParent, const std::string& status) {
    // Simple consent dialog - returns true if user grants consent
    int result = MessageBoxA(hwndParent, status.c_str(), "AI Consent Prompt",
                             MB_ICONQUESTION | MB_YESNO | MB_DEFBUTTON2);
    return result == IDYES;
}

// Handler for Consent Prompt feature
void HandleConsentPrompt(void* idePtr) {
    Win32IDE* ide = static_cast<Win32IDE*>(idePtr);
    if (!ide) return;

    // Show consent status
    std::string statusText = "Consent Prompt Active\n\n";
    statusText += "User consent and privacy management:\n";
    statusText += "- Data collection consent\n";
    statusText += "- Privacy policy acknowledgment\n";
    statusText += "- Feature usage permissions\n";
    statusText += "- Telemetry opt-in/opt-out\n";
    statusText += "- Security policy compliance\n";

    if (!ShowConsentPrompt(ide->getMainWindow(), statusText)) {
        MessageBoxA(NULL, "Consent was not granted by user", "Consent Prompt", MB_ICONWARNING | MB_OK);
    }
}
