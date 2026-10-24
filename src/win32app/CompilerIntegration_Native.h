#pragma once

// Native compiler integration boundary used by the Win32 IDE shell.
// The implementation lives in CompilerIntegration_Real.cpp so the IDE does
// not duplicate compiler discovery, build, or fallback logic.

#include <windows.h>

#ifndef RAWRXD_WM_COMPILER_DETECTED
#define RAWRXD_WM_COMPILER_DETECTED (WM_USER + 1001)
#endif

namespace RawrXD::Win32App {
extern "C" {
    void CompilerIntegration_Init(HWND main_window);
    void CompilerIntegration_Shutdown();
    void CompilerIntegration_BuildMenu(HMENU menu_bar);
    void CompilerIntegration_RefreshMenu();
    BOOL CompilerIntegration_HandleCommand(WORD command_id);
    void CompilerIntegration_OnFileOpened(const char* file_path);
    void CompilerIntegration_OnFileSaved(const char* file_path);
    void CompilerIntegration_CompileCurrentFile();
    void CompilerIntegration_BuildProject();
    BOOL CompilerIntegration_IsBuilding();
    void CompilerIntegration_ShowOutput();
    int CompilerIntegration_GetAvailableCompilerCount();
    void CompilerIntegration_GetCompilerName(int index, char* buffer, int buffer_size);
}
} // namespace RawrXD::Win32App
