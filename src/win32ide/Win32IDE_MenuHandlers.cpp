// Win32IDE_MenuHandlers.cpp
// ACTUAL implementation of menu handlers - NO MORE SCAFFOLDING
// This file wires the Integration_Wiring to REAL Win32IDE menus

#include "../win32app/Win32IDE.h"  // Existing Win32IDE header
#include "Integration_Wiring.h"
#include "Win32IDE_Resource.h"
#include "Win32IDE_Helpers.h"
#include "Win32IDE_Project.h"
#include <windows.h>
#include <commctrl.h>
#include <commdlg.h>
#include <string>
#include <cstring>

// Force Unicode APIs
#undef GetFileAttributes
#define GetFileAttributes GetFileAttributesW
#undef MessageBox
#define MessageBox MessageBoxW
#undef OPENFILENAME
#define OPENFILENAME OPENFILENAMEW
#undef GetOpenFileName
#define GetOpenFileName GetOpenFileNameW
#undef GetSaveFileName
#define GetSaveFileName GetSaveFileNameW
#undef SetDlgItemText
#define SetDlgItemText SetDlgItemTextW
#undef GetDlgItemText
#define GetDlgItemText GetDlgItemTextW
#undef DeleteFile
#define DeleteFile DeleteFileW

// Forward declarations
INT_PTR CALLBACK NewProjectDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam);

// External globals (defined in Win32IDE_Helpers.cpp)
extern HWND g_hWndMain;
extern HWND g_hWndEditor;
extern HWND g_hWndStatusBar;
extern HWND g_hWndOutput;

// Menu command IDs - make sure these match your .rc file
#define ID_FILE_NEW_PROJECT     40001
#define ID_FILE_OPEN_PROJECT    40002
#define ID_FILE_SAVE_PROJECT    40003
#define ID_FILE_EXIT            40004

#define ID_BUILD_COMPILE        40101
#define ID_BUILD_RUN            40102
#define ID_BUILD_DEBUG          40103
#define ID_BUILD_CLEAN          40104

#define ID_TOOLS_ANALYZE        40201
#define ID_TOOLS_PATCH          40202
#define ID_TOOLS_OPTIONS        40203

// Output window helper
void LogOutput(const wchar_t* format, ...) {
    wchar_t buffer[4096];
    va_list args;
    va_start(args, format);
    vswprintf_s(buffer, format, args);
    va_end(args);
    
    AppendOutputText(buffer);
    AppendOutputText(L"\r\n");
}

// =============================================================================
// FILE MENU HANDLERS
// =============================================================================

void OnFileNewProject() {
    // Show New Project dialog
    wchar_t projectName[MAX_PATH] = {0};
    
    // Simple input dialog for project name
    // In production, this would be a proper dialog with templates
    if (DialogBoxParam(GetModuleHandle(nullptr), 
                       MAKEINTRESOURCE(IDD_NEW_PROJECT), 
                       g_hWndMain, 
                       NewProjectDlgProc, 
                       (LPARAM)projectName) == IDOK) {
        
        // Create project directory
        std::wstring projectDir = std::wstring(L"projects\\") + projectName;
        CreateDirectoryW(projectDir.c_str(), nullptr);
        
        // Create default main.c
        std::wstring mainFile = projectDir + L"\\main.c";
        HANDLE hFile = CreateFileW(mainFile.c_str(), GENERIC_WRITE, 0, nullptr, 
                                    CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            const char* defaultCode = "#include <stdio.h>\n\nint main() {\n    printf(\"Hello, RawrXD!\\n\");\n    return 0;\n}\n";
            DWORD written;
            WriteFile(hFile, defaultCode, strlen(defaultCode), &written, nullptr);
            CloseHandle(hFile);
        }
        
        // Create .rxproj file
        std::wstring projFile = projectDir + L"\\" + projectName + L".rxproj";
        hFile = CreateFileW(projFile.c_str(), GENERIC_WRITE, 0, nullptr,
                            CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, nullptr);
        if (hFile != INVALID_HANDLE_VALUE) {
            std::string json = "{\n  \"name\": \"" + std::string(projectName, projectName + wcslen(projectName)) + "\",\n  \"sources\": [\"main.c\"]\n}";
            DWORD written;
            WriteFile(hFile, json.c_str(), json.length(), &written, nullptr);
            CloseHandle(hFile);
        }
        
        // Open the new project
        SetEditorText(L"");
        SetActiveDocumentPath(projFile.c_str());
        SetCurrentProjectName(projectName);
        SetStatusBarText((L"New project created: " + std::wstring(projectName)).c_str());
        LogOutput(L"✅ Created project '%s' in %s", projectName, projectDir.c_str());
    }
}

void OnFileOpenProject() {
    wchar_t fileName[MAX_PATH] = {0};
    
    OPENFILENAME ofn = {0};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = g_hWndMain;
    ofn.lpstrFilter = L"RawrXD Projects (*.rxproj)\0*.rxproj\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = fileName;
    ofn.nMaxFile = MAX_PATH;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST;
    ofn.lpstrDefExt = L"rxproj";
    
    if (GetOpenFileName(&ofn)) {
        // Load project using Win32IDE_Project
        RxProject project;
        if (project.LoadFromFile(fileName)) {
            SetStatusBarText(L"Project opened");
            LogOutput(L"📂 Opened project: %s", fileName);
            
            // Load first source file into editor
            if (project.GetSourceCount() > 0) {
                std::wstring firstSource = project.GetSource(0);
                SetActiveDocumentPath(firstSource.c_str());
                SetEditorText(firstSource.c_str());
            }
        } else {
            MessageBoxW(g_hWndMain, L"Failed to load project", L"Error", MB_OK | MB_ICONERROR);
        }
    }
}

void OnFileSaveProject() {
    // Get current project path
    std::wstring currentProject = GetActiveDocumentPath();
    if (currentProject.empty()) {
        // No project open, show save dialog
        wchar_t fileName[MAX_PATH] = {0};
        
        OPENFILENAME ofn = {0};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = g_hWndMain;
        ofn.lpstrFilter = L"RawrXD Projects (*.rxproj)\0*.rxproj\0";
        ofn.lpstrFile = fileName;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_OVERWRITEPROMPT;
        ofn.lpstrDefExt = L"rxproj";
        
        if (!GetSaveFileName(&ofn)) {
            return; // User cancelled
        }
        currentProject = fileName;
    }
    
    // Save project
    RxProject project;
    project.SetName(L"Untitled"); // TODO: Get actual project name
    project.AddSource(GetActiveDocumentPath().c_str());
    
    if (project.SaveToFile(currentProject.c_str())) {
        SetStatusBarText(L"Project saved");
        LogOutput(L"💾 Saved project: %s", currentProject.c_str());
    } else {
        MessageBoxW(g_hWndMain, L"Failed to save project", L"Error", MB_OK | MB_ICONERROR);
    }
}

// =============================================================================
// BUILD MENU HANDLERS - ACTUALLY WIRED TO TOOLCHAIN
// =============================================================================

void OnBuildCompile() {
    // Get current file from editor
    std::wstring sourceFile = GetActiveDocumentPath();
    
    if (sourceFile.empty()) {
        ShowErrorMessage(L"No file open. Please open or create a file first.");
        return;
    }
    
    // Determine output file
    std::wstring outputFile = sourceFile;
    size_t dotPos = outputFile.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        outputFile = outputFile.substr(0, dotPos) + L".exe";
    } else {
        outputFile += L".exe";
    }
    
    // Clear output window
    ClearOutputWindow();
    LogOutput(L"🔨 Building %s...", sourceFile.c_str());
    SetStatusBarText(L"Building...");
    
    // ACTUALLY call the compiler
    bool success = RawrXD::Integration::BuildSystem::CompileFile(
        sourceFile.c_str(),
        outputFile.c_str()
    );
    
    if (success) {
        LogOutput(L"✅ Build successful!");
        LogOutput(L"Output: %s", outputFile.c_str());
        SetStatusBarText(L"Build successful");
        EnableMenuItemByID(ID_BUILD_RUN, TRUE);  // Enable Run menu
    } else {
        LogOutput(L"❌ Build failed");
        SetStatusBarText(L"Build failed");
    }
}

void OnBuildRun() {
    // Get output executable
    std::wstring sourceFile = GetActiveDocumentPath();
    if (sourceFile.empty()) {
        ShowErrorMessage(L"No file open. Please open or create a file first.");
        return;
    }
    
    std::wstring exeFile = sourceFile;
    size_t dotPos = exeFile.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        exeFile = exeFile.substr(0, dotPos) + L".exe";
    } else {
        exeFile += L".exe";
    }
    
    // Check if executable exists
    if (GetFileAttributes(exeFile.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ShowErrorMessage(L"Executable not found. Please build first.");
        return;
    }
    
    LogOutput(L"🏃 Running %s...", exeFile.c_str());
    SetStatusBarText(L"Running...");
    
    // ACTUALLY run the executable
    bool success = RawrXD::Integration::BuildSystem::RunExecutable(exeFile.c_str());
    
    if (success) {
        LogOutput(L"✅ Program completed");
        SetStatusBarText(L"Run completed");
    } else {
        LogOutput(L"❌ Run failed");
        SetStatusBarText(L"Run failed");
    }
}

void OnBuildDebug() {
    std::wstring sourceFile = GetActiveDocumentPath();
    if (sourceFile.empty()) {
        ShowErrorMessage(L"No file open. Please open or create a file first.");
        return;
    }
    
    std::wstring exeFile = sourceFile;
    size_t dotPos = exeFile.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        exeFile = exeFile.substr(0, dotPos) + L".exe";
    } else {
        exeFile += L".exe";
    }
    
    // Check if executable exists
    if (GetFileAttributes(exeFile.c_str()) == INVALID_FILE_ATTRIBUTES) {
        ShowErrorMessage(L"Executable not found. Please build first.");
        return;
    }
    
    LogOutput(L"🐛 Starting debugger for %s...", exeFile.c_str());
    SetStatusBarText(L"Debugging...");
    
    // ACTUALLY start debugging
    bool success = RawrXD::Integration::DebugSystem::StartDebugging(exeFile.c_str());
    
    if (success) {
        LogOutput(L"✅ Debugger started");
        SetStatusBarText(L"Debugging started");
    } else {
        LogOutput(L"❌ Failed to start debugger");
        SetStatusBarText(L"Debug failed");
    }
}

void OnBuildClean() {
    std::wstring sourceFile = GetActiveDocumentPath();
    if (sourceFile.empty()) {
        ShowErrorMessage(L"No file open. Please open or create a file first.");
        return;
    }

    std::wstring exeFile = sourceFile;
    size_t dotPos = exeFile.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        exeFile = exeFile.substr(0, dotPos) + L".exe";
    } else {
        exeFile += L".exe";
    }

    // Ask for confirmation
    if (!AskYesNoQuestion(L"Are you sure you want to clean the build output?")) {
        return;
    }

    // Delete executable
    if (DeleteFileW(exeFile.c_str())) {
        LogOutput(L"🧹 Cleaned %s", exeFile.c_str());
        SetStatusBarText(L"Clean completed");
        EnableMenuItemByID(ID_BUILD_RUN, FALSE);  // Disable Run menu
    } else {
        LogOutput(L"⚠️ Nothing to clean (or access denied)");
        SetStatusBarText(L"Clean completed");
    }
}

// =============================================================================
// TOOLS MENU HANDLERS
// =============================================================================

void OnToolsAnalyze() {
    std::wstring sourceFile = GetActiveDocumentPath();
    if (sourceFile.empty()) {
        MessageBoxW(g_hWndMain, L"No file open", L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    std::wstring exeFile = sourceFile;
    size_t dotPos = exeFile.find_last_of(L'.');
    if (dotPos != std::wstring::npos) {
        exeFile = exeFile.substr(0, dotPos) + L".exe";
    } else {
        exeFile += L".exe";
    }
    
    if (GetFileAttributes(exeFile.c_str()) == INVALID_FILE_ATTRIBUTES) {
        MessageBoxW(g_hWndMain, L"Executable not found. Build first.", 
                   L"Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    LogOutput(L"🔍 Analyzing %s...", exeFile.c_str());
    SetStatusBarText(L"Analyzing...");
    
    // ACTUALLY analyze the PE
    bool success = RawrXD::Integration::AnalysisTools::AnalyzePE(exeFile.c_str());
    
    if (success) {
        LogOutput(L"✅ Analysis complete");
        SetStatusBarText(L"Analysis complete");
    } else {
        LogOutput(L"❌ Analysis failed");
        SetStatusBarText(L"Analysis failed");
    }
}

void OnToolsPatch() {
    MessageBox(g_hWndMain,
        L"Binary patching requires a patch file.\n"
        L"Use CLI: rx patch <exe> <patch.json>",
        L"Patch", MB_OK | MB_ICONINFORMATION);
}

void OnToolsOptions() {
    // Initialize settings system
    RawrXD::Integration::Settings::Initialize();
    
    // Get current settings
    std::wstring theme = RawrXD::Integration::Settings::GetTheme();
    int fontSize = RawrXD::Integration::Settings::GetEditorFontSize();
    bool wordWrap = RawrXD::Integration::Settings::GetWordWrap();
    
    // Build info message
    wchar_t msg[512];
    swprintf_s(msg, L"Current Settings:\n"
                    L"Theme: %s\n"
                    L"Font Size: %d\n"
                    L"Word Wrap: %s\n\n"
                    L"Settings saved to: %%APPDATA%%\\RawrXD\\settings.ini",
                    theme.c_str(), fontSize, wordWrap ? L"On" : L"Off");
    
    MessageBoxW(g_hWndMain, msg, L"Options", MB_OK | MB_ICONINFORMATION);
}

// =============================================================================
// COMMAND ROUTER - Wire menu IDs to handlers
// =============================================================================

BOOL HandleMenuCommand(HWND hwnd, int id) {
    switch (id) {
        // File menu
        case ID_FILE_NEW_PROJECT:
            OnFileNewProject();
            return TRUE;
        case ID_FILE_OPEN_PROJECT:
            OnFileOpenProject();
            return TRUE;
        case ID_FILE_SAVE_PROJECT:
            OnFileSaveProject();
            return TRUE;
        case ID_FILE_EXIT:
            PostQuitMessage(0);
            return TRUE;
            
        // Build menu - ACTUALLY WIRED
        case ID_BUILD_COMPILE:
            OnBuildCompile();
            return TRUE;
        case ID_BUILD_RUN:
            OnBuildRun();
            return TRUE;
        case ID_BUILD_DEBUG:
            OnBuildDebug();
            return TRUE;
        case ID_BUILD_CLEAN:
            OnBuildClean();
            return TRUE;
            
        // Tools menu
        case ID_TOOLS_ANALYZE:
            OnToolsAnalyze();
            return TRUE;
        case ID_TOOLS_PATCH:
            OnToolsPatch();
            return TRUE;
        case ID_TOOLS_OPTIONS:
            OnToolsOptions();
            return TRUE;
            
        default:
            return FALSE;
    }
}

// =============================================================================
// INITIALIZATION
// =============================================================================

void InitializeMenuHandlers() {
    // Disable Run menu initially (until build succeeds)
    EnableMenuItemByID(ID_BUILD_RUN, FALSE);

    LogOutput(L"✅ Menu handlers initialized");
    LogOutput(L"Ready to build!");
}

// =============================================================================
// DIALOG PROCEDURES
// =============================================================================

INT_PTR CALLBACK NewProjectDlgProc(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam) {
    static wchar_t* projectName;
    
    switch (message) {
        case WM_INITDIALOG:
            projectName = (wchar_t*)lParam;
            SetDlgItemText(hDlg, IDC_EDIT_PROJECT_NAME, L"MyProject");
            return TRUE;
            
        case WM_COMMAND:
            if (LOWORD(wParam) == IDOK) {
                GetDlgItemText(hDlg, IDC_EDIT_PROJECT_NAME, projectName, MAX_PATH);
                EndDialog(hDlg, IDOK);
                return TRUE;
            } else if (LOWORD(wParam) == IDCANCEL) {
                EndDialog(hDlg, IDCANCEL);
                return TRUE;
            }
            break;
    }
    return FALSE;
}
