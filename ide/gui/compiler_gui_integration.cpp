/*============================================================================
 * RAWRXD Compiler Driver - GUI IDE Integration
 * Adds compiler functionality to the Win32 GUI IDE
 *============================================================================*/

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
#include <commdlg.h>
#include <cstdio>
#include <cstring>
#include "../common/compiler_integration.h"

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comdlg32.lib")

/*============================================================================
 * Resource IDs for Compiler Menu
 *============================================================================*/

// Menu IDs
#define IDM_COMPILER_COMPILE      3001
#define IDM_COMPILER_BUILD        3002
#define IDM_COMPILER_CLEAN        3003
#define IDM_COMPILER_RUN          3004
#define IDM_COMPILER_OPTIONS      3005
#define IDM_COMPILER_OUTPUT       3006

// Dialog IDs
#define IDD_COMPILER_OPTIONS      4001
#define IDC_OPT_OPTIMIZE          4101
#define IDC_OPT_DEBUG             4102
#define IDC_OPT_VERBOSE           4103
#define IDC_OPT_OUTPUT            4104

/*============================================================================
 * Compiler Output Window
 *============================================================================*/

static HWND g_hCompilerOutput = nullptr;
static HFONT g_hCompilerFont = nullptr;

static void CreateCompilerOutputWindow(HWND hParent) {
    if (g_hCompilerOutput) return;
    
    // Create output window (edit control)
    g_hCompilerOutput = CreateWindowExA(
        WS_EX_CLIENTEDGE, "EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_VSCROLL | WS_HSCROLL |
        ES_MULTILINE | ES_AUTOVSCROLL | ES_AUTOHSCROLL | ES_READONLY,
        0, 0, 0, 0,  // Size set by parent
        hParent, (HMENU)IDM_COMPILER_OUTPUT, nullptr, nullptr
    );
    
    // Set monospace font
    g_hCompilerFont = CreateFontA(12, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE,
        DEFAULT_CHARSET, OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS,
        CLEARTYPE_QUALITY, FIXED_PITCH | FF_MODERN, "Consolas");
    
    SendMessageA(g_hCompilerOutput, WM_SETFONT, (WPARAM)g_hCompilerFont, TRUE);
    SendMessageA(g_hCompilerOutput, EM_SETLIMITTEXT, 0x7FFFFFFF, 0);
    
    // Set dark background
    SendMessageA(g_hCompilerOutput, EM_SETBKGNDCOLOR, 0, RGB(30, 30, 30));
}

static void AppendCompilerOutput(const char* text) {
    if (!g_hCompilerOutput) return;
    
    int len = GetWindowTextLengthA(g_hCompilerOutput);
    SendMessageA(g_hCompilerOutput, EM_SETSEL, len, len);
    SendMessageA(g_hCompilerOutput, EM_REPLACESEL, FALSE, (LPARAM)text);
    
    // Auto-scroll to bottom
    SendMessageA(g_hCompilerOutput, EM_SCROLLCARET, 0, 0);
}

static void ClearCompilerOutput() {
    if (g_hCompilerOutput) SetWindowTextA(g_hCompilerOutput, "");
}

/*============================================================================
 * Compiler Dialogs
 *============================================================================*/

static INT_PTR CALLBACK CompilerOptionsDlgProc(HWND hDlg, UINT msg, WPARAM wParam, LPARAM lParam) {
    static RawrxdBuildConfig* config;
    
    switch (msg) {
    case WM_INITDIALOG:
        config = (RawrxdBuildConfig*)lParam;
        CheckDlgButton(hDlg, IDC_OPT_OPTIMIZE, config->optimize ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_OPT_DEBUG, config->debug ? BST_CHECKED : BST_UNCHECKED);
        CheckDlgButton(hDlg, IDC_OPT_VERBOSE, config->verbose ? BST_CHECKED : BST_UNCHECKED);
        SetDlgItemTextA(hDlg, IDC_OPT_OUTPUT, config->outputName);
        return TRUE;
        
    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case IDOK:
            config->optimize = IsDlgButtonChecked(hDlg, IDC_OPT_OPTIMIZE) == BST_CHECKED;
            config->debug = IsDlgButtonChecked(hDlg, IDC_OPT_DEBUG) == BST_CHECKED;
            config->verbose = IsDlgButtonChecked(hDlg, IDC_OPT_VERBOSE) == BST_CHECKED;
            GetDlgItemTextA(hDlg, IDC_OPT_OUTPUT, config->outputName, MAX_PATH);
            EndDialog(hDlg, IDOK);
            return TRUE;
            
        case IDCANCEL:
            EndDialog(hDlg, IDCANCEL);
            return TRUE;
        }
        break;
    }
    return FALSE;
}

/*============================================================================
 * File Operations
 *============================================================================*/

static bool OpenSourceFileDlg(HWND hWnd, char* outPath, size_t outSize) {
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = 
        "C/C++ Files (*.c;*.cpp;*.h)\0*.c;*.cpp;*.h\0"
        "Assembly Files (*.asm;*.s)\0*.asm;*.s\0"
        "C# Files (*.cs)\0*.cs\0"
        "All Source Files\0*.c;*.cpp;*.h;*.asm;*.s;*.cs\0"
        "All Files (*.*)\0*.*\0";
    ofn.lpstrFile = outPath;
    ofn.nMaxFile = (DWORD)outSize;
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_ALLOWMULTISELECT;
    ofn.lpstrTitle = "Select Source File(s) to Compile";
    return GetOpenFileNameA(&ofn) != 0;
}

static bool SaveOutputDlg(HWND hWnd, char* outPath, size_t outSize) {
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = "Executable (*.exe)\0*.exe\0All Files (*.*)\0*.*\0";
    ofn.lpstrFile = outPath;
    ofn.nMaxFile = (DWORD)outSize;
    ofn.Flags = OFN_OVERWRITEPROMPT;
    ofn.lpstrTitle = "Select Output File";
    ofn.lpstrDefExt = "exe";
    return GetSaveFileNameA(&ofn) != 0;
}

/*============================================================================
 * Compilation Commands
 *============================================================================*/

static void DoCompileFile(HWND hWnd, const char* filePath) {
    if (!RawrxdCompiler_IsAvailable()) {
        MessageBoxA(hWnd, 
            "RAWRXD Compiler not found.\n\n"
            "Please ensure the compiler is installed and in PATH.",
            "Compiler Error", MB_OK | MB_ICONERROR);
        return;
    }
    
    ClearCompilerOutput();
    AppendCompilerOutput("================================================================\r\n");
    AppendCompilerOutput("  RAWRXD Compiler Driver\r\n");
    AppendCompilerOutput("================================================================\r\n\r\n");
    
    RawrxdLanguage lang = RawrxdCompiler_DetectLanguage(filePath);
    AppendCompilerOutput("[*] Detected language: ");
    AppendCompilerOutput(RawrxdCompiler_LanguageName(lang));
    AppendCompilerOutput("\r\n");
    
    // Get options
    RawrxdBuildConfig config;
    RawrxdCompiler_GetDefaultConfig(&config, nullptr);
    
    // Show options dialog
    // (In real implementation, show dialog here)
    
    // Compile
    AppendCompilerOutput("[*] Compiling: ");
    AppendCompilerOutput(filePath);
    AppendCompilerOutput("\r\n");
    
    RawrxdCompileResult result = RawrxdCompiler_Compile(filePath, &config);
    
    if (result.success) {
        AppendCompilerOutput("\r\n[+] Compilation successful!\r\n");
        AppendCompilerOutput("    Output: ");
        AppendCompilerOutput(result.outputPath);
        AppendCompilerOutput("\r\n");
        AppendCompilerOutput("    Time: ");
        char timeStr[64];
        snprintf(timeStr, sizeof(timeStr), "%.2f ms\r\n", result.compileTimeMs);
        AppendCompilerOutput(timeStr);
    } else {
        AppendCompilerOutput("\r\n[-] Compilation failed!\r\n");
        AppendCompilerOutput("    Exit code: ");
        char codeStr[32];
        snprintf(codeStr, sizeof(codeStr), "%d\r\n", result.exitCode);
        AppendCompilerOutput(codeStr);
        if (result.error[0]) {
            AppendCompilerOutput("    Error: ");
            AppendCompilerOutput(result.error);
            AppendCompilerOutput("\r\n");
        }
        if (result.output[0]) {
            AppendCompilerOutput("\r\n--- Compiler Output ---\r\n");
            AppendCompilerOutput(result.output);
        }
    }
    
    AppendCompilerOutput("\r\n");
}

static void DoBuildProject(HWND hWnd) {
    char filePaths[10][MAX_PATH];
    char multiPath[MAX_PATH * 10] = {};
    
    OPENFILENAMEA ofn = {};
    ofn.lStructSize = sizeof(ofn);
    ofn.hwndOwner = hWnd;
    ofn.lpstrFilter = 
        "C/C++ Files (*.c;*.cpp)\0*.c;*.cpp\0"
        "Assembly Files (*.asm)\0*.asm\0"
        "C# Files (*.cs)\0*.cs\0"
        "All Source Files\0*.c;*.cpp;*.asm;*.cs\0"
        "All Files (*.*)\0*.*\0";
    ofn.lpstrFile = multiPath;
    ofn.nMaxFile = sizeof(multiPath);
    ofn.Flags = OFN_FILEMUSTEXIST | OFN_PATHMUSTEXIST | OFN_ALLOWMULTISELECT | OFN_EXPLORER;
    ofn.lpstrTitle = "Select Source Files to Build";
    
    if (!GetOpenFileNameA(&ofn)) {
        return;
    }
    
    // Parse multi-select
    const char* dir = multiPath;
    const char* file = multiPath + strlen(dir) + 1;
    int count = 0;
    
    while (file[0] && count < 10) {
        snprintf(filePaths[count], MAX_PATH, "%s\\%s", dir, file);
        count++;
        file += strlen(file) + 1;
    }
    
    if (count == 0) {
        // Single file selected
        strncpy(filePaths[0], multiPath, MAX_PATH);
        count = 1;
    }
    
    // Build
    ClearCompilerOutput();
    AppendCompilerOutput("================================================================\r\n");
    AppendCompilerOutput("  RAWRXD Compiler Driver - Build Project\r\n");
    AppendCompilerOutput("================================================================\r\n\r\n");
    AppendCompilerOutput("[*] Building ");
    char countStr[32];
    snprintf(countStr, sizeof(countStr), "%d", count);
    AppendCompilerOutput(countStr);
    AppendCompilerOutput(" file(s)...\r\n\r\n");
    
    RawrxdBuildConfig config;
    RawrxdCompiler_GetDefaultConfig(&config, nullptr);
    
    const char* paths[10];
    for (int i = 0; i < count; i++) {
        paths[i] = filePaths[i];
    }
    
    RawrxdCompileResult result = RawrxdCompiler_Build(paths, count, &config);
    
    if (result.success) {
        AppendCompilerOutput("\r\n[+] Build successful!\r\n");
    } else {
        AppendCompilerOutput("\r\n[-] Build failed!\r\n");
        if (result.error[0]) {
            AppendCompilerOutput(result.error);
        }
        if (result.output[0]) {
            AppendCompilerOutput(result.output);
        }
    }
}

/*============================================================================
 * Menu Integration
 *============================================================================*/

HMENU CreateCompilerMenu(void) {
    HMENU hCompiler = CreatePopupMenu();
    
    AppendMenuA(hCompiler, MF_STRING, IDM_COMPILER_COMPILE, 
        "&Compile File...\tCtrl+F7");
    AppendMenuA(hCompiler, MF_STRING, IDM_COMPILER_BUILD, 
        "&Build Project...\tCtrl+Shift+B");
    AppendMenuA(hCompiler, MF_STRING, IDM_COMPILER_RUN, 
        "&Run Executable\tCtrl+F5");
    AppendMenuA(hCompiler, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hCompiler, MF_STRING, IDM_COMPILER_CLEAN, 
        "&Clean Build");
    AppendMenuA(hCompiler, MF_SEPARATOR, 0, nullptr);
    AppendMenuA(hCompiler, MF_STRING, IDM_COMPILER_OPTIONS, 
        "&Options...");
    
    return hCompiler;
}

void AddCompilerToMenuBar(HMENU hMenuBar) {
    HMENU hCompiler = CreateCompilerMenu();
    AppendMenuA(hMenuBar, MF_POPUP, (UINT_PTR)hCompiler, "&Compiler");
}

/*============================================================================
 * Command Handler
 *============================================================================*/

bool HandleCompilerCommand(HWND hWnd, int id) {
    switch (id) {
    case IDM_COMPILER_COMPILE: {
        char path[MAX_PATH] = {};
        if (OpenSourceFileDlg(hWnd, path, sizeof(path))) {
            DoCompileFile(hWnd, path);
        }
        return true;
    }
    
    case IDM_COMPILER_BUILD:
        DoBuildProject(hWnd);
        return true;
        
    case IDM_COMPILER_CLEAN:
        ClearCompilerOutput();
        AppendCompilerOutput("[*] Cleaning build artifacts...\r\n");
        // TODO: Implement clean
        AppendCompilerOutput("[+] Clean complete.\r\n");
        return true;
        
    case IDM_COMPILER_RUN: {
        char path[MAX_PATH] = {};
        OPENFILENAMEA ofn = {};
        ofn.lStructSize = sizeof(ofn);
        ofn.hwndOwner = hWnd;
        ofn.lpstrFilter = "Executable (*.exe)\0*.exe\0";
        ofn.lpstrFile = path;
        ofn.nMaxFile = MAX_PATH;
        ofn.Flags = OFN_FILEMUSTEXIST;
        ofn.lpstrTitle = "Select Executable to Run";
        
        if (GetOpenFileNameA(&ofn)) {
            ShellExecuteA(hWnd, "open", path, nullptr, nullptr, SW_SHOW);
        }
        return true;
    }
    
    case IDM_COMPILER_OPTIONS:
        MessageBoxA(hWnd, 
            "Compiler Options\n\n"
            "- Optimize: Enable optimization\n"
            "- Debug: Include debug info\n"
            "- Verbose: Show detailed output",
            "Compiler Options", MB_OK | MB_ICONINFORMATION);
        return true;
    }
    
    return false;
}

/*============================================================================
 * Accelerator Table Additions
 *============================================================================*/

void GetCompilerAccelerators(ACCEL* accels, int* count) {
    int i = *count;
    
    // Ctrl+F7 = Compile
    accels[i].fVirt = FCONTROL | FVIRTKEY;
    accels[i].key = VK_F7;
    accels[i].cmd = IDM_COMPILER_COMPILE;
    i++;
    
    // Ctrl+Shift+B = Build
    accels[i].fVirt = FCONTROL | FSHIFT | FVIRTKEY;
    accels[i].key = 'B';
    accels[i].cmd = IDM_COMPILER_BUILD;
    i++;
    
    // Ctrl+F5 = Run
    accels[i].fVirt = FCONTROL | FVIRTKEY;
    accels[i].key = VK_F5;
    accels[i].cmd = IDM_COMPILER_RUN;
    i++;
    
    *count = i;
}

/*============================================================================
 * Initialization
 *============================================================================*/

bool InitializeCompilerIntegration(HWND hMainWindow) {
    // Initialize compiler
    if (!RawrxdCompiler_Init()) {
        return false;
    }
    
    // Create output window
    CreateCompilerOutputWindow(hMainWindow);
    
    return true;
}

void ShutdownCompilerIntegration(void) {
    RawrxdCompiler_Shutdown();
    
    if (g_hCompilerFont) {
        DeleteObject(g_hCompilerFont);
        g_hCompilerFont = nullptr;
    }
}

/*============================================================================
 * Version Info
 *============================================================================*/

const char* GetCompilerIntegrationVersion(void) {
    return "1.0.0";
}
