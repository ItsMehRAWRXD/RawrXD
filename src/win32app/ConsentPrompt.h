#pragma once

#include "Win32IDE.h"

// Consent Prompt - user approval gate for AI actions
bool ShowConsentPrompt(HWND hwndParent, const std::string& status);
