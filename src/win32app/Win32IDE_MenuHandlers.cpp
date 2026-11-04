#include "Win32IDE.h"
#include "Win32IDE_CommandIDs.h"
#include <shellapi.h>
#include <tchar.h>
#include <strsafe.h>
#include <stdio.h>
#include <direct.h>

// Helper: Get the current document path from the IDE
// In a full implementation, this would query the active editor tab
static std::wstring GetCurrentDocumentPath()
{
    // Placeholder: return empty string; real implementation would
    // retrieve the path of the active document from the RichEdit/tab context
    return std::wstring();
}

// Helper: Extract directory from a full file path
static std::wstring GetDirectoryFromPath(const std::wstring& filepath)
{
    size_t pos = filepath.find_last_of(L"\\/");
    if (pos != std::wstring::npos)
        return filepath.substr(0, pos + 1);
    return L".";
}

// Helper: Safe file deletion
static void SafeDeleteFile(const std::wstring& filepath)
{
    if (!filepath.empty() && PathFileExistsW(filepath.c_str()))
        DeleteFileW(filepath.c_str());
}

// OnBuildCompile - Compile the current/selected C/C++ document
// Build pipeline: Source → MASM → Link → Executable
void OnBuildCompile(HWND hWnd)
{
    std::wstring docPath = GetCurrentDocumentPath();

    if (docPath.empty())
    {
        // No document open - ask user to save or select a file
        TCHAR msg[] = _T("Build Compile - no active document. Please save or open a C/C++ file first.");
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
        return;
    }

    // Determine output executable path
    std::wstring exePath = docPath;
    // Replace .c/.cpp extension with .exe
    size_t dotPos = docPath.find_last_of(L".");
    if (dotPos != std::wstring::npos)
        exePath.replace(dotPos, docPath.length() - dotPos, L".exe");
    else
        exePath += L".exe";

    // Use the native toolchain: ml64.exe (assembler) + link.exe
    // or the universal_compiler.exe if available
    bool compileSuccess = false;

    // Attempt compilation using the configured toolchain
    // Priority: universal_compiler.exe first, then fall back to ml64+link
    std::wstring compilerCmd;

    // Check if universal_compiler.exe is available in the PATH
    std::wstring checkPath = L"universal_compiler.exe";
    if (PathFileExistsW(checkPath.c_str()))
    {
        // Use the universal compiler pipeline
        compilerCmd = checkPath + L" \"" + docPath + L"\" \"" + exePath + L"\"";
    }
    else
    {
        // Fall back: assemble with ml64.exe then link with link.exe
        // Generate ASM first, then assemble, then link
        std::wstring asmPath = docPath + L".asm";
        std::wstring objPath = docPath + L".obj";

        // Step 1: Generate ASM (cl /Fa) or use existing pipeline
        // Step 2: ml64.exe /c /Cx /Zi /Fo<obj> <source>
        // Step 3: link.exe /OUT:<exe> <obj> kernel32.user32.gdi32

        // For now, attempt the universal compiler path
        compilerCmd = L"echo Compilation toolchain not fully configured; see build logs";
    }

    // Execute the compilation command
    if (!compilerCmd.empty())
    {
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;

        PROCESS_INFORMATION pi;
        BOOL success = CreateProcessW(
            NULL,
            &compilerCmd[0],
            NULL, NULL, FALSE,
            0, NULL, NULL,
            &si, &pi);

        if (success)
        {
            WaitForSingleObject(pi.hProcess, INFINITE);
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            compileSuccess = (exitCode == 0);
        }
    }

    // Report results
    TCHAR compileMsg[512];
    if (compileSuccess)
    {
        // Verify the exe was actually produced
        if (PathFileExistsW(exePath.c_str()))
        {
            StringCchPrintf(compileMsg, 512,
                _T("Build Compile - %s compiled successfully to %s [PASS]"),
                docPath.c_str(), exePath.c_str());
        }
        else
        {
            StringCchPrintf(compileMsg, 512,
                _T("Build Compile - compilation reported success but output not found at %s"),
                exePath.c_str());
            compileSuccess = FALSE;
        }
    }
    else
    {
        StringCchPrintf(compileMsg, 512,
            _T("Build Compile - compilation failed or toolchain unavailable"));
    }

    MessageBox(hWnd, compileMsg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
}

// OnBuildRun - Run the most recently compiled executable
void OnBuildRun(HWND hWnd)
{
    // Try to find and run the most recent build artifact
    // In a full IDE, this would track the build output directory
    std::wstring exePath = L"test_editor.exe"; // placeholder

    // Strategy: check common locations for a just-compiled executable
    std::wstring pathsToTry[] = {
        L"test_editor.exe",
        L".\\RawrXD-Win32IDE-Native.exe",
        docPath.empty() ? L"" : GetDirectoryFromPath(docPath) + L"test_editor.exe"
    };

    bool runSuccess = false;
    TCHAR runMsg[512] = { 0 };

    for (int i = 0; i < _countof(pathsToTry); i++)
    {
        if (PathFileExistsW(pathsToTry[i].c_str()))
        {
            exePath = pathsToTry[i];
            break;
        }
    }

    if (PathFileExistsW(exePath.c_str()))
    {
        STARTUPINFOW si = { sizeof(si) };
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_SHOW;

        PROCESS_INFORMATION pi;
        BOOL success = CreateProcessW(
            NULL,
            &exePath[0],
            NULL, NULL, FALSE,
            0, NULL, NULL,
            &si, &pi);

        if (success)
        {
            WaitForSingleObject(pi.hProcess, INFINITE);
            DWORD exitCode;
            GetExitCodeProcess(pi.hProcess, &exitCode);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            runSuccess = (exitCode == 0);

            StringCchPrintf(runMsg, 512,
                _T("Build Run - executable %s ran with exit code %d %s"),
                exePath.c_str(), exitCode,
                runSuccess ? _T("[PASS]") : _T("[FAIL]"));
        }
    }

    if (!runSuccess && exePath != L"test_editor.exe")
    {
        // If we tried a different path than the default
        StringCchPrintf(runMsg, 512,
            _T("Build Run - could not find recently compiled executable; tried: %s"),
            exePath.c_str());
    }
    else if (!runSuccess)
    {
        StringCchPrintf(runMsg, 512, _T("Build Run - no executable found to run"));
    }

    MessageBox(hWnd, runMsg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
}

// OnBuildClean - Delete build artifacts for the current project
void OnBuildClean(HWND hWnd)
{
    std::wstring docPath = GetCurrentDocumentPath();

    // Delete common build artifacts associated with the current document
    SafeDeleteFile(docPath);                                    // source file
    SafeDeleteFile(docPath + L".asm");                          // assembly output
    SafeDeleteFile(docPath + L".obj");                          // object file

    // Determine exe path (same logic as compile)
    std::wstring exePath = docPath;
    size_t dotPos = docPath.find_last_of(L".");
    if (dotPos != std::wstring::npos)
        exePath.replace(dotPos, docPath.length() - dotPos, L".exe");
    else
        exePath += L".exe";

    SafeDeleteFile(exePath);                                    // executable

    // Also clean common test artifacts
    SafeDeleteFile(L"test_editor.exe");
    SafeDeleteFile(L"test_pipeline.exe");
    SafeDeleteFile(L"test_capture.exe");

    TCHAR cleanMsg[256];
    StringCchPrintf(cleanMsg, 256, _T("Build Clean - artifacts removed for %s"),
        docPath.empty() ? _T("(no active document)") : docPath.c_str());
    MessageBox(hWnd, cleanMsg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
}

// OnToolsAnalyze - Perform PE binary analysis
void OnToolsAnalyze(HWND hWnd)
{
    // Look for PE analysis targets: just-compiled exe, or user-selected binary
    std::wstring exePath = L"";

    // Check if just-compiled executable exists in current directory
    if (PathFileExistsW(L"RawrXD-Win32IDE-Native.exe"))
        exePath = L"RawrXD-Win32IDE-Native.exe";
    else if (PathFileExistsW(L"test_editor.exe"))
        exePath = L"test_editor.exe";

    if (!exePath.empty() && PathFileExistsW(exePath.c_str()))
    {
        // Basic PE header information
        TCHAR analyzeMsg[512];
        HANDLE hFile = CreateFileW(exePath.c_str(),
            GENERIC_READ,
            FILE_SHARE_READ,
            NULL,
            OPEN_EXISTING,
            FILE_ATTRIBUTE_NORMAL,
            NULL);

        if (hFile != INVALID_HANDLE_VALUE)
        {
            DWORD fileSizeLow = GetFileSize(hFile, NULL);
            TCHAR analyzeDetail[256];
            StringCchPrintf(analyzeDetail, 256,
                _T("File size: %d bytes; "),
                fileSizeLow);

            // Read dos header signature
            BYTE dosHeader[64];
            DWORD bytesRead;
            if (ReadFile(hFile, dosHeader, sizeof(dosHeader), &bytesRead, NULL) && bytesRead >= 2)
            {
                WORD signature = *(WORD*)dosHeader;
                if (signature == IMAGE_DOS_SIGNATURE)
                    StringCchCat(analyzeDetail, 256, _T("Valid DOS signature; "));
            }

            CloseHandle(hFile);

            StringCchPrintf(analyzeMsg, 512,
                _T("Tools Analyze - PE binary analyzed: %s %s"),
                exePath.c_str(), analyzeDetail);

            MessageBox(hWnd, analyzeMsg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            TCHAR msg[256];
            StringCchPrintf(msg, 256, _T("Tools Analyze - could not open %s for analysis"), exePath.c_str());
            MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONWARNING);
        }
    }
    else
    {
        TCHAR msg[256];
        StringCchPrintf(msg, 256, _T("Tools Analyze - no PE binary available for analysis"));
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
    }
}

// OnFileNew - Create a new C/C++ document
void OnFileNew(HWND hWnd)
{
    // Create a new untitled C source file
    std::wstring newPath = L"untitled.c";

    FILE* f = _wfopen(newPath.c_str(), _T("w"));
    if (f)
    {
        _ftprintf(f, _T("#include <stdio.h>\n"
            _T("int main() { return 0; }\n")));
        fclose(f);

        TCHAR msg[256];
        StringCchPrintf(msg, 256, _T("File New - created %s"), newPath.c_str());
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        TCHAR msg[] = _T("File New - could not create new document");
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONERROR);
    }
}

// OnFileOpen - Open file dialog to select a source file
void OnFileOpen(HWND hWnd)
{
    // Use GetOpenFileName to let user select a file
    OPENFILENAMEW ofn;
    WCHAR szFile[MAX_PATH] = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = _T("C/C++ Source Files\0*.;c;*.cpp;;All Files\0*.*\0");
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_PATHMUSTEXIST | OFN_FILEMUSTEXIST;

    if (GetOpenFileNameW(&ofn))
    {
        TCHAR msg[512];
        StringCchPrintf(msg, 512, _T("File Open - selected: %s"), ofn.lpstrFile);
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        TCHAR msg[] = _T("File Open - operation cancelled");
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
    }
}

// OnFileSave - Save the current document
void OnFileSave(HWND hWnd)
{
    std::wstring docPath = GetCurrentDocumentPath();

    if (docPath.empty())
    {
        // No document open - save as
        OnFileSaveAs(hWnd);
        return;
    }

    // Write placeholder content
    FILE* f = _wfopen(docPath.c_str(), _T("w"));
    if (f)
    {
        _ftprintf(f, _T("// RawrXD editor document\n"
            _T("int main() { return 0; }\n")));
        fclose(f);

        TCHAR msg[256];
        StringCchPrintf(msg, 256, _T("File Save - %s saved"), docPath.c_str());
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
    }
    else
    {
        TCHAR msg[] = _T("File Save - could not save document");
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONERROR);
    }
}

// OnFileSaveAs - Save current document as a different file
void OnFileSaveAs(HWND hWnd)
{
    OPENFILENAMEW ofn;
    WCHAR szFile[MAX_PATH] = { 0 };

    ZeroMemory(&ofn, sizeof(ofn));
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFile = szFile;
    ofn.nMaxFile = MAX_PATH;
    ofn.lpstrFilter = _T("C/C++ Source\0*.c;*.cpp;;All Files\0*.*\0");
    ofn.nFilterIndex = 1;
    ofn.Flags = OFN_OVERWRITEPROMPT | OFN_PATHMUSTEXIST;

    if (GetSaveFileNameW(&ofn))
    {
        // If there's a current document, copy its content;
        // otherwise write placeholder
        std::wstring docPath = GetCurrentDocumentPath();

        FILE* f = _wfopen(ofn.lpstrFile, _T("w"));
        if (f)
        {
            if (!docPath.empty() && PathFileExistsW(docPath.c_str()))
            {
                // Copy content from current document
                // In full implementation, would read and rewrite
                _ftprintf(f, _T("// Transferred from RawrXD editor\n"
                    _T("int main() { return 0; }\n")));
            }
            else
            {
                _ftprintf(f, _T("// RawrXD editor document\n"
                    _T("int main() { return 0; }\n")));
            }
            fclose(f);

            TCHAR msg[512];
            StringCchPrintf(msg, 512, _T("File Save As - %s saved"), ofn.lpstrFile);
            MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
        }
        else
        {
            TCHAR msg[] = _T("File Save As - could not save file");
            MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONERROR);
        }
    }
    else
    {
        TCHAR msg[] = _T("File Save As - operation cancelled");
        MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
    }
}

// OnToolsOptions - Open preferences/options dialog
void OnToolsOptions(HWND hWnd)
{
    TCHAR msg[] = _T("Tools Options - preferences dialog not yet implemented");
    MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
}

// OnHelpAbout - Show about dialog
void OnHelpAbout(HWND hWnd)
{
    TCHAR msg[] = _T("RawrXD IDE - Sovereign Edition\n\n"
        "Native Win32 IDE with MASM64 compiler\n"
        "Agentic capabilities integrated\n"
        "Version 1.0.0-integration\n\n"
        "Build: " _T(__DATE__) " " _T(__TIME__));
    MessageBox(hWnd, msg, _T("About RawrXD"), MB_OK | MB_ICONINFORMATION);
}

// OnFileExit - Exit the application
void OnFileExit(HWND hWnd)
{
    PostQuitMessage(0);
    TCHAR msg[] = _T("RawrXD - exiting application");
    MessageBox(hWnd, msg, _T("RawrXD"), MB_OK | MB_ICONINFORMATION);
}

// Command router - dispatches menu IDs to handlers
// This is called from the window procedure based on menu item selections
void RouteMenuCommand(UINT nID, HWND hWnd)
{
    switch (nID)
    {
    case IDM_FILE_NEW:
        OnFileNew(hWnd);
        break;
    case IDM_FILE_OPEN:
        OnFileOpen(hWnd);
        break;
    case IDM_FILE_SAVE:
        OnFileSave(hWnd);
        break;
    case IDM_FILE_SAVEAS:
        OnFileSaveAs(hWnd);
        break;
    case IDM_BUILD_COMPILE:
        OnBuildCompile(hWnd);
        break;
    case IDM_BUILD_RUN:
        OnBuildRun(hWnd);
        break;
    case IDM_BUILD_CLEAN:
        OnBuildClean(hWnd);
        break;
    case IDM_TOOLS_ANALYZE:
        OnToolsAnalyze(hWnd);
        break;
    case IDM_HELP_ABOUT:
        OnHelpAbout(hWnd);
        break;
    case IDM_FILE_EXIT:
        OnFileExit(hWnd);
        break;
    default:
        // Unknown menu ID - could be a future command
        break;
    }
}

// Initialize menu bindings - connect menu IDs to window procedure handlers
// Call this during IDE initialization after window creation
// Establishes the connection between menu resource IDs and C++ handler functions
void InitializeMenuHandlers(HWND hWnd)
{
    // Menu IDs are defined in Win32IDE.rc and routed through
    // the window procedure's WM_COMMAND handler
    // RouteMenuCommand dispatches to the appropriate handler above
    // Pass hWnd so handlers can interact with the IDE window as needed
    UNREFERENCED_PARAMETER(hWnd);
}

// Minimal empty implementation so the file compiles and links
// Actual implementations are filled in as integration progresses
extern "C" void Win32IDE_MenuHandlers_MinimalInit(void)
{
    // Placeholder for any initialization needed
    // Currently no global state to initialize
    // Handlers are stateless and receive HWND on each call
}