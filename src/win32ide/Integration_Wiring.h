// Auto-generated GUI wiring for Win32IDE
// Generated: 2026-07-08 08:27:40

#pragma once
#include <windows.h>
#include <string>

namespace RawrXD {
namespace Integration {

// Toolchain paths
const wchar_t* TOOLCHAIN_PATH = L"D:/rawrxd/native_toolchain";
const wchar_t* COMPILER_PATH = L"D:/rawrxd/native_toolchain/universal_compiler.exe";
const wchar_t* ASSEMBLER_PATH = L"D:/rawrxd/native_toolchain/minimal_assembler_v7.exe";
const wchar_t* LINKER_PATH = L"D:/rawrxd/native_toolchain/linker_fixed.exe";
const wchar_t* ANALYZER_PATH = L"D:/rawrxd/native_toolchain/analyze_pe.ps1";
const wchar_t* PATCHER_PATH = L"D:/rawrxd/native_toolchain/binary_patch_pipeline.c";

// Build system integration
class BuildSystem {
public:
    static bool CompileFile(const wchar_t* sourceFile, const wchar_t* outputFile);
    static bool AssembleFile(const wchar_t* sourceFile, const wchar_t* outputFile);
    static bool LinkObject(const wchar_t* objectFile, const wchar_t* outputFile);
    static bool BuildProject(const wchar_t* projectFile);
    static bool RunExecutable(const wchar_t* executable);
    static bool DebugExecutable(const wchar_t* executable);
};

// Analysis integration
class AnalysisTools {
public:
    static bool AnalyzePE(const wchar_t* executable);
    static bool FixImports(const wchar_t* executable);
    static bool PatchBinary(const wchar_t* executable, const wchar_t* patchFile);
};

// Execution wrapper
class ProcessRunner {
public:
    static DWORD RunProcess(const wchar_t* executable, const wchar_t* args, bool wait = true);
    static DWORD RunCompiler(const wchar_t* sourceFile);
    static DWORD RunWithOutput(const wchar_t* executable, std::wstring& output);
};

// Debug system integration (DAP)
class DebugSystem {
public:
    static bool StartDebugging(const wchar_t* executable, const wchar_t* args = nullptr);
    static bool StopDebugging();
    static bool SetBreakpoint(const wchar_t* file, int line);
    static bool ClearBreakpoint(const wchar_t* file, int line);
    static bool Continue();
    static bool Pause();
    static bool StepInto();
    static bool StepOver();
    static bool StepOut();
    static bool IsDebugging();
    static bool IsPaused();
};

// Settings persistence
class Settings {
public:
    static bool Initialize();
    static bool Save();
    
    // Generic getters/setters
    static bool GetString(const wchar_t* section, const wchar_t* key, wchar_t* value, size_t valueSize);
    static bool SetString(const wchar_t* section, const wchar_t* key, const wchar_t* value);
    static int GetInt(const wchar_t* section, const wchar_t* key, int defaultValue = 0);
    static bool SetInt(const wchar_t* section, const wchar_t* key, int value);
    static bool GetBool(const wchar_t* section, const wchar_t* key, bool defaultValue = false);
    static bool SetBool(const wchar_t* section, const wchar_t* key, bool value);
    
    // Editor settings
    static std::wstring GetEditorFont();
    static int GetEditorFontSize();
    static int GetTabSize();
    static bool UseSpacesForTabs();
    static bool GetWordWrap();
    static void SetWordWrap(bool wrap);
    
    // Window settings
    static void GetWindowSize(int& width, int& height);
    static void SetWindowSize(int width, int height);
    static bool GetWindowMaximized();
    static void SetWindowMaximized(bool maximized);
    
    // Recent files
    static void AddRecentFile(const wchar_t* filePath);
    static int GetRecentFileCount();
    static bool GetRecentFile(int index, wchar_t* filePath, size_t pathSize);
    
    // Theme
    static std::wstring GetTheme();
    static void SetTheme(const wchar_t* theme);
    
    // Build settings
    static std::wstring GetCompilerPath();
    static std::wstring GetAssemblerPath();
    static std::wstring GetLinkerPath();
};

} // namespace Integration
} // namespace RawrXD
