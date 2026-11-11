#pragma once

#include <windows.h>

// Simple dialog box with text input - returns true if user pressed OK
bool DialogBoxWithInput(LPCWSTR title, LPCWSTR prompt, LPWSTR buffer, int bufferSize);
