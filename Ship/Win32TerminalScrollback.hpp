#pragma once
// Shared RichEdit scrollback cap for integrated terminal + PowerShell panel (VS Code–class buffers).

#include <cstdint>
#include <cstdlib>
#include <windows.h>
#include <richedit.h>

inline void RawrXD_ApplyTerminalRichEditScrollback(HWND hwnd, uint32_t settingsCapChars)
{
    if (!hwnd || !IsWindow(hwnd))
        return;
    uint32_t capChars = settingsCapChars;
    char envCap[32]{};
    if (GetEnvironmentVariableA("RAWRXD_TERMINAL_SCROLLBACK_CHARS", envCap, sizeof(envCap)) > 0)
        capChars = static_cast<uint32_t>(strtoul(envCap, nullptr, 10));
    if (capChars < 262144u)
        capChars = 262144u;
    if (capChars > 16777216u)
        capChars = 16777216u;
    SendMessage(hwnd, EM_EXLIMITTEXT, 0, static_cast<LPARAM>(capChars));
}
