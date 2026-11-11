//=============================================================================
// NativeToolchainUI.cpp - GUI Integration for Native Toolchain in Win32IDE
// Provides dialogs and menu integration for the native toolchain
//=============================================================================

#include <windows.h>
#include <commctrl.h>
#include <string>
#include <vector>
#include <sstream>

#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")

//=============================================================================
// Resource IDs
//=============================================================================

#define IDD_NATIVE_COMPILE      100
#define IDD_NATIVE_PATCH        101
#define IDD_NATIVE_DISASM       102
#define IDD_NATIVE_SETTINGS     103

#define IDC_INPUT_FILE          1001
#define IDC_OUTPUT_FILE         1002
#define IDC_OUTPUT_FORMAT       1003
#define IDC_BROWSE_INPUT        1004
#define IDC_BROWSE_OUTPUT       1005
#define IDC_STATUS_TEXT         1006
#define IDC_PROGRESS_BAR        1007
#define IDC_LOG_EDIT            1008

#define ID_NATIVE_COMPILE       2001
#define ID_NATIVE_PATCH         2002
#define ID_NATIVE_DISASM        2003
#define ID_NATIVE_SETTINGS      2004
#define ID_NATIVE_ABOUT         2005

//=============================================================================
// Utility Functions
//=============================================================================

// Convert wide string to UTF-8
std::string WideToUtf8(const wchar_t* wide) {
    if (!wide) return "";
    int size = WideCharToMultiByte(CP_UTF8, 0, wide, -1, nullptr, 0, nullptr, nullptr);
    if (size <= 0) return "";
    std::string result(size - 1, 0);
    WideCharToMultiByte(CP_UTF8, 0, wide, -1, &result[0], size, nullptr, nullptr);
    return result;
}

// Convert UTF-8 to wide string
std::wstring Utf8ToWide(const std::string& utf8) {
    if (utf8.empty()) return L"";
    int size = MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, nullptr, 0);
    if (size <= 0) return L"";
    std::wstring result(size - 1, 0);
    MultiByteToWideChar(CP_UTF8, 0, utf8.c_str(), -1, &result[0], size);
    return result;
}

// Execute command and capture output
std::string ExecuteCommand(const char* cmd) {
    std::string result;
    SECURITY_ATTRIBUTES sa = { sizeof(sa), nullptr, TRUE };
    
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) return "";
    
    STARTUPINFOA si = { sizeof(si) };
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    si.hStdInput = nullptr;
    
    PROCESS_INFORMATION pi = {};
    
    if (CreateProcessA(nullptr, (LPSTR)cmd, nullptr, nullptr, TRUE, 
                       CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi)) {
        CloseHandle(hWrite);
        
        char buffer[4096];
        DWORD bytesRead;
        while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &bytesRead, nullptr) && bytesRead > 0) {
            buffer[bytesRead] = '\0';
            result += buffer;
        }
        
        WaitForSingleObject(pi.hProcess, INFINITE);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    } else {
        CloseHandle(hWrite);
    }
    
    CloseHandle(hRead);
    return result;
}

//=============================================================================
// Native Compile Dialog
//=============================================================================

class NativeCompileDialog {
public:
    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_INITDIALOG: {
            // Center dialog
            RECT rcDlg, rcOwner;
            GetWindowRect(hwnd, &rcDlg);
            GetWindowRect(GetDesktopWindow(), &rcOwner);
            int x = rcOwner.left + (rcOwner.right - rcOwner.left - rcDlg.right + rcDlg.left) / 2;
            int y = rcOwner.top + (rcOwner.bottom - rcOwner.top - rcDlg.bottom + rcDlg.top) / 2;
            SetWindowPos(hwnd, nullptr, x, y, 0, 0, SWP_NOSIZE | SWP_NOZORDER);
            
            // Initialize format combo
            HWND hFormat = GetDlgItem(hwnd, IDC_OUTPUT_FORMAT);
            SendMessage(hFormat, CB_ADDSTRING, 0, (LPARAM)L"Assembly (MASM syntax)");
            SendMessage(hFormat, CB_ADDSTRING, 0, (LPARAM)L"Assembly (AT&T syntax)");
            SendMessage(hFormat, CB_ADDSTRING, 0, (LPARAM)L"COFF Object (.obj)");
            SendMessage(hFormat, CB_ADDSTRING, 0, (LPARAM)L"PE Executable (.exe)");
            SendMessage(hFormat, CB_SETCURSEL, 0, 0);
            
            // Set default output name
            SetDlgItemText(hwnd, IDC_OUTPUT_FILE, L"output.asm");
            
            return TRUE;
        }
        
        case WM_COMMAND: {
            switch (LOWORD(wParam)) {
            case IDOK: {
                wchar_t input[MAX_PATH] = {0};
                wchar_t output[MAX_PATH] = {0};
                GetDlgItemText(hwnd, IDC_INPUT_FILE, input, MAX_PATH);
                GetDlgItemText(hwnd, IDC_OUTPUT_FILE, output, MAX_PATH);
                
                if (wcslen(input) == 0) {
                    MessageBox(hwnd, L"Please select an input file.", 
                              L"Input Required", MB_OK | MB_ICONWARNING);
                    return TRUE;
                }
                
                // Execute compilation
                ExecuteCompilation(hwnd, input, output);
                return TRUE;
            }
            
            case IDCANCEL:
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
                
            case IDC_BROWSE_INPUT: {
                wchar_t file[MAX_PATH] = {0};
                OPENFILENAME ofn = { sizeof(ofn) };
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = file;
                ofn.nMaxFile = MAX_PATH;
                ofn.lpstrFilter = L"JSON Files\0*.json\0ASM Files\0*.asm\0C Files\0*.c\0All Files\0*.*\0";
                ofn.lpstrTitle = L"Select Input File";
                ofn.Flags = OFN_FILEMUSTEXIST | OFN_HIDEREADONLY;
                
                if (GetOpenFileName(&ofn)) {
                    SetDlgItemText(hwnd, IDC_INPUT_FILE, file);
                    
                    // Auto-generate output name
                    wchar_t output[MAX_PATH];
                    wcscpy_s(output, file);
                    wchar_t* ext = wcsrchr(output, L'.');
                    if (ext) {
                        wcscpy_s(ext, MAX_PATH - (ext - output), L".asm");
                        SetDlgItemText(hwnd, IDC_OUTPUT_FILE, output);
                    }
                }
                return TRUE;
            }
            
            case IDC_BROWSE_OUTPUT: {
                wchar_t file[MAX_PATH] = L"output.asm";
                OPENFILENAME ofn = { sizeof(ofn) };
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = file;
                ofn.nMaxFile = MAX_PATH;
                ofn.lpstrFilter = L"Assembly Files\0*.asm\0Object Files\0*.obj\0Executable Files\0*.exe\0All Files\0*.*\0";
                ofn.lpstrTitle = L"Select Output File";
                ofn.Flags = OFN_OVERWRITEPROMPT | OFN_HIDEREADONLY;
                
                if (GetSaveFileName(&ofn)) {
                    SetDlgItemText(hwnd, IDC_OUTPUT_FILE, file);
                }
                return TRUE;
            }
            }
            break;
        }
        }
        return FALSE;
    }
    
private:
    static void ExecuteCompilation(HWND hwnd, const wchar_t* input, const wchar_t* output) {
        // Show progress
        HWND hStatus = GetDlgItem(hwnd, IDC_STATUS_TEXT);
        SetWindowText(hStatus, L"Compiling...");
        
        // Convert paths
        std::string input_c = WideToUtf8(input);
        std::string output_c = WideToUtf8(output);
        
        // Determine file type and build command
        std::string cmd;
        const wchar_t* ext = wcsrchr(input, L'.');
        
        if (ext && _wcsicmp(ext, L".json") == 0) {
            // JSON to ASM
            cmd = "codex_native_bridge.exe /convert \"" + input_c + "\" \"" + output_c + "\"";
        } else if (ext && _wcsicmp(ext, L".c") == 0) {
            // C to ASM
            cmd = "c_compiler_enhanced.exe \"" + input_c + "\" -o \"" + output_c + "\"";
        } else if (ext && _wcsicmp(ext, L".asm") == 0) {
            // ASM to OBJ
            std::string obj_out = output_c;
            size_t dot = obj_out.rfind('.');
            if (dot != std::string::npos) obj_out = obj_out.substr(0, dot) + ".obj";
            cmd = "minimal_assembler_v2.exe \"" + input_c + "\" \"" + obj_out + "\"";
        } else {
            MessageBox(hwnd, L"Unsupported input file type.", L"Error", MB_OK | MB_ICONERROR);
            return;
        }
        
        // Execute
        std::string result = ExecuteCommand(cmd.c_str());
        
        // Show result
        if (result.find("SUCCESS") != std::string::npos || 
            result.find("Created") != std::string::npos ||
            GetFileAttributes(output) != INVALID_FILE_ATTRIBUTES) {
            SetWindowText(hStatus, L"Compilation successful!");
            MessageBox(hwnd, L"Compilation completed successfully!", 
                      L"Success", MB_OK | MB_ICONINFORMATION);
            EndDialog(hwnd, IDOK);
        } else {
            SetWindowText(hStatus, L"Compilation failed.");
            std::wstring msg = L"Compilation failed.\n\n" + Utf8ToWide(result);
            MessageBox(hwnd, msg.c_str(), L"Error", MB_OK | MB_ICONERROR);
        }
    }
};

//=============================================================================
// Native Patch Dialog
//=============================================================================

class NativePatchDialog {
public:
    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_INITDIALOG:
            SetDlgItemText(hwnd, IDC_INPUT_FILE, L"");
            SetDlgItemText(hwnd, IDC_OUTPUT_FILE, L"patched.exe");
            return TRUE;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case IDOK: {
                wchar_t input[MAX_PATH], output[MAX_PATH];
                GetDlgItemText(hwnd, IDC_INPUT_FILE, input, MAX_PATH);
                GetDlgItemText(hwnd, IDC_OUTPUT_FILE, output, MAX_PATH);
                
                if (wcslen(input) == 0) {
                    MessageBox(hwnd, L"Please select a binary file to patch.",
                              L"Input Required", MB_OK | MB_ICONWARNING);
                    return TRUE;
                }
                
                ExecutePatch(hwnd, input, output);
                return TRUE;
            }
            case IDCANCEL:
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            case IDC_BROWSE_INPUT: {
                wchar_t file[MAX_PATH] = {0};
                OPENFILENAME ofn = { sizeof(ofn) };
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = file;
                ofn.nMaxFile = MAX_PATH;
                ofn.lpstrFilter = L"Executable Files\0*.exe\0DLL Files\0*.dll\0All Files\0*.*\0";
                ofn.lpstrTitle = L"Select Binary to Patch";
                ofn.Flags = OFN_FILEMUSTEXIST;
                
                if (GetOpenFileName(&ofn)) {
                    SetDlgItemText(hwnd, IDC_INPUT_FILE, file);
                }
                return TRUE;
            }
            }
            break;
        }
        return FALSE;
    }
    
private:
    static void ExecutePatch(HWND hwnd, const wchar_t* input, const wchar_t* output) {
        std::string input_c = WideToUtf8(input);
        std::string output_c = WideToUtf8(output);
        
        // Create a simple patch (NOP sled at entry point)
        std::string cmd = "binary_patch_pipeline.exe /add-nop 0x1000 5 "
                         "/patch \"" + input_c + "\" \"" + output_c + "\" /verify";
        
        std::string result = ExecuteCommand(cmd.c_str());
        
        if (GetFileAttributes(output) != INVALID_FILE_ATTRIBUTES) {
            MessageBox(hwnd, L"Binary patched successfully!", 
                      L"Success", MB_OK | MB_ICONINFORMATION);
            EndDialog(hwnd, IDOK);
        } else {
            MessageBox(hwnd, L"Patching failed. Check console output.",
                      L"Error", MB_OK | MB_ICONERROR);
        }
    }
};

//=============================================================================
// Native Disassembly Dialog
//=============================================================================

class NativeDisasmDialog {
public:
    static INT_PTR CALLBACK DialogProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
        switch (msg) {
        case WM_INITDIALOG:
            SetDlgItemText(hwnd, IDC_INPUT_FILE, L"");
            return TRUE;
            
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
            case IDOK: {
                wchar_t input[MAX_PATH];
                GetDlgItemText(hwnd, IDC_INPUT_FILE, input, MAX_PATH);
                
                if (wcslen(input) == 0) {
                    MessageBox(hwnd, L"Please select a binary file to disassemble.",
                              L"Input Required", MB_OK | MB_ICONWARNING);
                    return TRUE;
                }
                
                ExecuteDisasm(hwnd, input);
                return TRUE;
            }
            case IDCANCEL:
                EndDialog(hwnd, IDCANCEL);
                return TRUE;
            case IDC_BROWSE_INPUT: {
                wchar_t file[MAX_PATH] = {0};
                OPENFILENAME ofn = { sizeof(ofn) };
                ofn.hwndOwner = hwnd;
                ofn.lpstrFile = file;
                ofn.nMaxFile = MAX_PATH;
                ofn.lpstrFilter = L"Executable Files\0*.exe\0Object Files\0*.obj\0All Files\0*.*\0";
                ofn.lpstrTitle = L"Select Binary to Disassemble";
                ofn.Flags = OFN_FILEMUSTEXIST;
                
                if (GetOpenFileName(&ofn)) {
                    SetDlgItemText(hwnd, IDC_INPUT_FILE, file);
                }
                return TRUE;
            }
            }
            break;
        }
        return FALSE;
    }
    
private:
    static void ExecuteDisasm(HWND hwnd, const wchar_t* input) {
        std::string input_c = WideToUtf8(input);
        std::string output_c = input_c + ".disasm.json";
        
        std::string cmd = "binary_patch_pipeline.exe /disasm \"" + 
                         input_c + "\" \"" + output_c + "\"";
        
        std::string result = ExecuteCommand(cmd.c_str());
        
        // Show result in a message box or open in editor
        std::wstring msg = L"Disassembly complete.\n\nOutput: " + Utf8ToWide(output_c);
        MessageBox(hwnd, msg.c_str(), L"Disassembly", MB_OK | MB_ICONINFORMATION);
    }
};

//=============================================================================
// Menu Integration
//=============================================================================

void AddNativeToolchainMenu(HMENU hMenu) {
    HMENU hNativeMenu = CreatePopupMenu();
    
    AppendMenu(hNativeMenu, MF_STRING, ID_NATIVE_COMPILE, 
               L"&Compile...\tCtrl+Shift+C");
    AppendMenu(hNativeMenu, MF_STRING, ID_NATIVE_PATCH, 
               L"&Patch Binary...\tCtrl+Shift+P");
    AppendMenu(hNativeMenu, MF_STRING, ID_NATIVE_DISASM, 
               L"&Disassemble...\tCtrl+Shift+D");
    AppendMenu(hNativeMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenu(hNativeMenu, MF_STRING, ID_NATIVE_SETTINGS, 
               L"&Settings...");
    AppendMenu(hNativeMenu, MF_SEPARATOR, 0, nullptr);
    AppendMenu(hNativeMenu, MF_STRING, ID_NATIVE_ABOUT, 
               L"&About Native Toolchain");
    
    AppendMenu(hMenu, MF_POPUP, (UINT_PTR)hNativeMenu, L"&Native Toolchain");
}

void HandleNativeCommand(HWND hwnd, int cmd) {
    switch (cmd) {
    case ID_NATIVE_COMPILE:
        DialogBox(GetModuleHandle(nullptr), MAKEINTRESOURCE(IDD_NATIVE_COMPILE),
                 hwnd, NativeCompileDialog::DialogProc);
        break;
    case ID_NATIVE_PATCH:
        DialogBox(GetModuleHandle(nullptr), MAKEINTRESOURCE(IDD_NATIVE_PATCH),
                 hwnd, NativePatchDialog::DialogProc);
        break;
    case ID_NATIVE_DISASM:
        DialogBox(GetModuleHandle(nullptr), MAKEINTRESOURCE(IDD_NATIVE_DISASM),
                 hwnd, NativeDisasmDialog::DialogProc);
        break;
    case ID_NATIVE_SETTINGS:
        MessageBox(hwnd, L"Settings dialog - TODO", L"Settings", MB_OK);
        break;
    case ID_NATIVE_ABOUT:
        MessageBox(hwnd, 
            L"RawrXD Native Toolchain v1.0\n\n"
            L"Components:\n"
            L"  • Native Assembler (no ML64)\n"
            L"  • Native Linker (no LINK)\n"
            L"  • C Compiler Frontend\n"
            L"  • Binary Patch Pipeline\n\n"
            L"Self-hosting capable toolchain for RawrXD.",
            L"About", MB_OK | MB_ICONINFORMATION);
        break;
    }
}

//=============================================================================
// Toolbar Integration
//=============================================================================

void AddNativeToolchainToolbar(HWND hToolbar) {
    TBBUTTON buttons[] = {
        { 0, ID_NATIVE_COMPILE, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Compile" },
        { 1, ID_NATIVE_PATCH, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Patch" },
        { 2, ID_NATIVE_DISASM, TBSTATE_ENABLED, BTNS_BUTTON, {0}, 0, (INT_PTR)L"Disasm" },
    };
    
    SendMessage(hToolbar, TB_ADDBUTTONS, (WPARAM)3, (LPARAM)&buttons);
}

//=============================================================================
// Context Menu Integration
//=============================================================================

void ShowNativeContextMenu(HWND hwnd, HMENU hMenu, int x, int y) {
    HMENU hContext = CreatePopupMenu();
    
    AppendMenu(hContext, MF_STRING, ID_NATIVE_COMPILE, L"Compile with Native Toolchain");
    AppendMenu(hContext, MF_STRING, ID_NATIVE_PATCH, L"Patch Binary");
    AppendMenu(hContext, MF_SEPARATOR, 0, nullptr);
    AppendMenu(hContext, MF_STRING, ID_NATIVE_DISASM, L"Disassemble");
    
    TrackPopupMenu(hContext, TPM_LEFTALIGN | TPM_RIGHTBUTTON, x, y, 0, hwnd, nullptr);
    DestroyMenu(hContext);
}

//=============================================================================
// Export Functions for Win32IDE Integration
//=============================================================================

extern "C" {
    __declspec(dllexport) void InitializeNativeToolchain(HMENU hMainMenu) {
        AddNativeToolchainMenu(hMainMenu);
    }
    
    __declspec(dllexport) void ProcessNativeCommand(HWND hwnd, int cmd) {
        HandleNativeCommand(hwnd, cmd);
    }
    
    __declspec(dllexport) void ShowNativeCompileDialog(HWND hwnd) {
        DialogBox(GetModuleHandle(nullptr), MAKEINTRESOURCE(IDD_NATIVE_COMPILE),
                 hwnd, NativeCompileDialog::DialogProc);
    }
    
    __declspec(dllexport) void ShowNativePatchDialog(HWND hwnd) {
        DialogBox(GetModuleHandle(nullptr), MAKEINTRESOURCE(IDD_NATIVE_PATCH),
                 hwnd, NativePatchDialog::DialogProc);
    }
    
    __declspec(dllexport) void ShowNativeDisasmDialog(HWND hwnd) {
        DialogBox(GetModuleHandle(nullptr), MAKEINTRESOURCE(IDD_NATIVE_DISASM),
                 hwnd, NativeDisasmDialog::DialogProc);
    }
}

//=============================================================================
// Standalone Test Entry Point
//=============================================================================

#ifdef TEST_NATIVE_TOOLCHAIN_UI

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, LPWSTR, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = { sizeof(iccex), ICC_WIN95_CLASSES };
    InitCommonControlsEx(&iccex);
    
    // Create main window
    HWND hwnd = CreateWindowEx(0, L"STATIC", L"Native Toolchain UI Test",
                               WS_OVERLAPPEDWINDOW | WS_VISIBLE,
                               CW_USEDEFAULT, CW_USEDEFAULT, 800, 600,
                               nullptr, nullptr, hInstance, nullptr);
    
    // Create menu
    HMENU hMenu = CreateMenu();
    AddNativeToolchainMenu(hMenu);
    SetMenu(hwnd, hMenu);
    
    // Message loop
    MSG msg;
    while (GetMessage(&msg, nullptr, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }
    
    return 0;
}

#endif
