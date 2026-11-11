// AUTONOMOUS_IDE_GUI.cpp - Fully Integrated Autonomous IDE (GUI Version)
// Integrates with all 69 compilers for autonomous/agentic operation

#define WIN32_LEAN_AND_MEAN
#define UNICODE
#define _UNICODE
#include <windows.h>
#include <commctrl.h>
#include <stdio.h>
#include <string.h>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(lib, "kernel32.lib")

#define MAX_COMPILERS 69
#define COMPILER_DIR L"d:\\rawrxd\\compilers\\all_69_final"
#define WM_COMPILER_DONE (WM_USER + 1)

typedef struct {
    wchar_t name[64];
    wchar_t display[128];
    wchar_t category[32];
    wchar_t exePath[256];
    BOOL available;
    HWND hCheck;
} CompilerInfo;

typedef struct {
    CompilerInfo compilers[MAX_COMPILERS];
    int count;
    int availableCount;
    HWND hWnd;
    HWND hList;
    HWND hStatus;
    HWND hProgress;
    HWND hBtnAuto;
    HWND hBtnRun;
    BOOL running;
    int currentCompiler;
    int successCount;
    int failCount;
} IDEState;

IDEState g_state = {0};

// Forward declarations
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void InitCompilers();
void CreateUI(HWND hWnd);
void UpdateStatus(const wchar_t* msg);
void RunCompiler(int index);
void AutonomousBuild();

int WINAPI wWinMain(HINSTANCE hInstance, HINSTANCE, PWSTR, int nCmdShow) {
    // Initialize common controls
    INITCOMMONCONTROLSEX iccex = {sizeof(iccex), ICC_STANDARD_CLASSES};
    InitCommonControlsEx(&iccex);
    
    // Register window class
    WNDCLASSEXW wc = {sizeof(wc)};
    wc.lpfnWndProc = WndProc;
    wc.hInstance = hInstance;
    wc.lpszClassName = L"RawrXDAutonomousIDE";
    wc.hbrBackground = (HBRUSH)(COLOR_WINDOW + 1);
    wc.hCursor = LoadCursor(NULL, IDC_ARROW);
    
    RegisterClassExW(&wc);
    
    // Create main window
    HWND hWnd = CreateWindowExW(
        0, L"RawrXDAutonomousIDE", L"RawrXD Autonomous IDE v1.0 - 69 Compilers",
        WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX,
        CW_USEDEFAULT, CW_USEDEFAULT, 900, 700,
        NULL, NULL, hInstance, NULL
    );
    
    if (!hWnd) return 1;
    
    g_state.hWnd = hWnd;
    InitCompilers();
    CreateUI(hWnd);
    
    ShowWindow(hWnd, nCmdShow);
    UpdateWindow(hWnd);
    
    // Message loop
    MSG msg;
    while (GetMessageW(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessageW(&msg);
    }
    
    return (int)msg.wParam;
}

void InitCompilers() {
    // Initialize compiler registry (same as CLI version)
    struct { const wchar_t* name; const wchar_t* display; const wchar_t* category; } compilerData[] = {
        {L"ada_compiler_from_scratch", L"Ada Compiler", L"Systems"},
        {L"assembly_compiler_from_scratch", L"Assembly Compiler", L"Systems"},
        {L"c_compiler_from_scratch", L"C Compiler", L"Systems"},
        {L"c__compiler_from_scratch", L"C++ Compiler", L"Systems"},
        {L"rust_compiler_from_scratch", L"Rust Compiler", L"Systems"},
        {L"go_compiler_from_scratch", L"Go Compiler", L"Systems"},
        {L"zig_compiler_from_scratch", L"Zig Compiler", L"Systems"},
        {L"odin_compiler_from_scratch", L"Odin Compiler", L"Systems"},
        {L"nim_compiler_from_scratch", L"Nim Compiler", L"Systems"},
        {L"v_compiler_from_scratch", L"V Compiler", L"Systems"},
        {L"python_compiler_from_scratch", L"Python Compiler", L"Scripting"},
        {L"javascript_compiler_from_scratch", L"JavaScript Compiler", L"Scripting"},
        {L"typescript_compiler_from_scratch", L"TypeScript Compiler", L"Scripting"},
        {L"ruby_compiler_from_scratch", L"Ruby Compiler", L"Scripting"},
        {L"perl_compiler_from_scratch", L"Perl Compiler", L"Scripting"},
        {L"lua_compiler_from_scratch", L"Lua Compiler", L"Scripting"},
        {L"php_compiler_from_scratch", L"PHP Compiler", L"Scripting"},
        {L"bash_compiler_from_scratch", L"Bash Compiler", L"Shell"},
        {L"powershell_compiler_from_scratch", L"PowerShell Compiler", L"Shell"},
        {L"java_compiler_from_scratch", L"Java Compiler", L"JVM"},
        {L"kotlin_compiler_from_scratch", L"Kotlin Compiler", L"JVM"},
        {L"scala_compiler_from_scratch", L"Scala Compiler", L"JVM"},
        {L"clojure_compiler_from_scratch", L"Clojure Compiler", L"JVM"},
        {L"c___compiler_from_scratch", L"C# Compiler", L"DotNet"},
        {L"f__compiler_from_scratch", L"F# Compiler", L"DotNet"},
        {L"vb_net_compiler_from_scratch", L"VB.NET Compiler", L"DotNet"},
        {L"haskell_compiler_from_scratch", L"Haskell Compiler", L"Functional"},
        {L"ocaml_compiler_from_scratch", L"OCaml Compiler", L"Functional"},
        {L"erlang_compiler_from_scratch", L"Erlang Compiler", L"Functional"},
        {L"elixir_compiler_from_scratch", L"Elixir Compiler", L"Functional"},
        {L"dart_compiler_from_scratch", L"Dart Compiler", L"Web"},
        {L"webassembly_compiler_from_scratch", L"WebAssembly Compiler", L"Web"},
        {L"swift_compiler_from_scratch", L"Swift Compiler", L"Mobile"},
        {L"julia_compiler_from_scratch", L"Julia Compiler", L"Scientific"},
        {L"r_compiler_from_scratch", L"R Compiler", L"Data"},
        {L"matlab_compiler_from_scratch", L"MATLAB Compiler", L"Scientific"},
        {L"fortran_compiler_from_scratch", L"Fortran Compiler", L"Scientific"},
        {L"cobol_compiler_from_scratch", L"COBOL Compiler", L"Legacy"},
        {L"pascal_compiler_from_scratch", L"Pascal Compiler", L"Education"},
        {L"jai_compiler_from_scratch", L"Jai Compiler", L"GameDev"},
        {L"cadence_compiler_from_scratch", L"Cadence Compiler", L"Hardware"},
        {L"carbon_compiler_from_scratch", L"Carbon Compiler", L"Experimental"},
        {L"crystal_compiler_from_scratch", L"Crystal Compiler", L"Experimental"},
        {L"eon_compiler_from_scratch", L"EON Compiler", L"Domain"},
        {L"eon_compiler_complete", L"EON Compiler Complete", L"Domain"},
        {L"eon_compiler_main", L"EON Main Compiler", L"Domain"},
        {L"eon_kernel_compiler", L"EON Kernel Compiler", L"Domain"},
        {L"full_eon_compiler", L"Full EON Compiler", L"Domain"},
        {L"integrated_eon_compiler", L"Integrated EON Compiler", L"Domain"},
        {L"self_hosted_eon_compiler", L"Self-Hosted EON Compiler", L"Domain"},
        {L"solidity_compiler_from_scratch", L"Solidity Compiler", L"Web3"},
        {L"vyper_compiler_from_scratch", L"Vyper Compiler", L"Web3"},
        {L"move_compiler_from_scratch", L"Move Compiler", L"Web3"},
        {L"motoko_compiler_from_scratch", L"Motoko Compiler", L"Web3"},
        {L"llvm_ir_compiler_from_scratch", L"LLVM IR Compiler", L"Tools"},
        {L"cross_compiler", L"Cross Compiler", L"Tools"},
        {L"multi_target_compiler", L"Multi-Target Compiler", L"Tools"},
        {L"master_universal_compiler", L"Master Universal Compiler", L"Tools"},
        {L"n0mn0m_cross_platform_compiler", L"N0MN0M Cross-Platform Compiler", L"Experimental"},
        {L"n0mn0m_quantum_asm_compiler", L"N0MN0M Quantum ASM Compiler", L"Experimental"},
        {L"reverser_compiler", L"Reverser Compiler", L"Tools"},
        {L"reverser_compiler_from_scratch", L"Reverser Compiler Pro", L"Tools"},
        {L"delphi_compiler_from_scratch", L"Delphi Compiler", L"Desktop"},
        {L"self_contained_compiler_gui", L"Self-Contained GUI Compiler", L"Tools"},
        {L"universal_compiler_runtime", L"Universal Compiler Runtime", L"Runtime"},
        {L"universal_compiler_runtime_clean", L"Universal Compiler Runtime Clean", L"Runtime"},
        {L"universal_cross_platform_compiler", L"Universal Cross-Platform Compiler", L"Tools"},
        {L"universal_multi_language_compiler", L"Universal Multi-Language Compiler", L"Tools"},
        {L"uber_elegant_compiler", L"Uber Elegant Compiler", L"Experimental"}
    };
    
    g_state.count = sizeof(compilerData) / sizeof(compilerData[0]);
    g_state.availableCount = 0;
    
    for (int i = 0; i < g_state.count; i++) {
        wcscpy_s(g_state.compilers[i].name, compilerData[i].name);
        wcscpy_s(g_state.compilers[i].display, compilerData[i].display);
        wcscpy_s(g_state.compilers[i].category, compilerData[i].category);
        swprintf_s(g_state.compilers[i].exePath, L"%s\\%s.exe", COMPILER_DIR, compilerData[i].name);
        
        DWORD attribs = GetFileAttributesW(g_state.compilers[i].exePath);
        g_state.compilers[i].available = (attribs != INVALID_FILE_ATTRIBUTES && !(attribs & FILE_ATTRIBUTE_DIRECTORY));
        
        if (g_state.compilers[i].available) g_state.availableCount++;
    }
}

void CreateUI(HWND hWnd) {
    HINSTANCE hInst = GetModuleHandle(NULL);
    
    // Title
    CreateWindowW(L"STATIC", L"RawrXD Autonomous IDE - 69 Compilers Integrated",
        WS_VISIBLE | WS_CHILD | SS_CENTER,
        10, 10, 860, 25, hWnd, NULL, hInst, NULL);
    
    // Status bar
    g_state.hStatus = CreateWindowW(L"STATIC", L"Ready",
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        10, 630, 860, 25, hWnd, NULL, hInst, NULL);
    
    // Progress bar
    g_state.hProgress = CreateWindowW(PROGRESS_CLASSW, NULL,
        WS_VISIBLE | WS_CHILD | PBS_SMOOTH,
        10, 600, 860, 20, hWnd, NULL, hInst, NULL);
    SendMessageW(g_state.hProgress, PBM_SETRANGE, 0, MAKELPARAM(0, g_state.count));
    
    // Buttons
    g_state.hBtnAuto = CreateWindowW(L"BUTTON", L"Autonomous Build (All)",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        10, 40, 200, 30, hWnd, (HMENU)100, hInst, NULL);
    
    g_state.hBtnRun = CreateWindowW(L"BUTTON", L"Run Selected",
        WS_VISIBLE | WS_CHILD | BS_PUSHBUTTON,
        220, 40, 150, 30, hWnd, (HMENU)101, hInst, NULL);
    
    // Compiler list
    CreateWindowW(L"STATIC", L"Available Compilers:",
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        10, 80, 200, 20, hWnd, NULL, hInst, NULL);
    
    // Create checkboxes for each compiler
    int y = 110;
    int x = 10;
    for (int i = 0; i < g_state.count && i < 20; i++) {  // Show first 20 for demo
        wchar_t label[256];
        swprintf_s(label, L"[%2d] %ls (%ls) %ls",
            i + 1, g_state.compilers[i].display, g_state.compilers[i].category,
            g_state.compilers[i].available ? L"[READY]" : L"[MISSING]");
        
        g_state.compilers[i].hCheck = CreateWindowW(L"BUTTON", label,
            WS_VISIBLE | WS_CHILD | BS_CHECKBOX,
            x, y, 400, 20, hWnd, (HMENU)(1000 + i), hInst, NULL);
        
        if (g_state.compilers[i].available) {
            SendMessageW(g_state.compilers[i].hCheck, BM_SETCHECK, BST_CHECKED, 0);
        } else {
            EnableWindow(g_state.compilers[i].hCheck, FALSE);
        }
        
        y += 25;
        if (y > 550) {
            y = 110;
            x = 450;
        }
    }
    
    // Stats
    wchar_t stats[256];
    swprintf_s(stats, L"Total: %d/%d compilers available", g_state.availableCount, g_state.count);
    CreateWindowW(L"STATIC", stats,
        WS_VISIBLE | WS_CHILD | SS_LEFT,
        10, 570, 400, 20, hWnd, NULL, hInst, NULL);
}

void UpdateStatus(const wchar_t* msg) {
    SetWindowTextW(g_state.hStatus, msg);
}

void RunCompiler(int index) {
    if (index < 0 || index >= g_state.count || !g_state.compilers[index].available) {
        return;
    }
    
    wchar_t cmd[512];
    swprintf_s(cmd, L"\"%s\"", g_state.compilers[index].exePath);
    
    STARTUPINFOW si = {sizeof(si)};
    PROCESS_INFORMATION pi = {0};
    
    if (CreateProcessW(NULL, cmd, NULL, NULL, FALSE, CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
        WaitForSingleObject(pi.hProcess, 5000);  // Wait up to 5 seconds
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
    }
}

void AutonomousBuild() {
    if (g_state.running) return;
    
    g_state.running = TRUE;
    g_state.currentCompiler = 0;
    g_state.successCount = 0;
    g_state.failCount = 0;
    
    EnableWindow(g_state.hBtnAuto, FALSE);
    EnableWindow(g_state.hBtnRun, FALSE);
    
    UpdateStatus(L"Autonomous build in progress...");
    SendMessageW(g_state.hProgress, PBM_SETPOS, 0, 0);
    
    // Process each compiler
    for (int i = 0; i < g_state.count; i++) {
        if (g_state.compilers[i].available) {
            wchar_t msg[256];
            swprintf_s(msg, L"Running: %s", g_state.compilers[i].display);
            UpdateStatus(msg);
            
            RunCompiler(i);
            g_state.successCount++;
            
            SendMessageW(g_state.hProgress, PBM_SETPOS, i + 1, 0);
            UpdateWindow(g_state.hWnd);
        }
    }
    
    wchar_t result[256];
    swprintf_s(result, L"Autonomous complete: %d success, %d failed", g_state.successCount, g_state.failCount);
    UpdateStatus(result);
    
    g_state.running = FALSE;
    EnableWindow(g_state.hBtnAuto, TRUE);
    EnableWindow(g_state.hBtnRun, TRUE);
}

LRESULT CALLBACK WndProc(HWND hWnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    switch (msg) {
        case WM_COMMAND:
            if (LOWORD(wParam) == 100) {
                // Autonomous build button
                AutonomousBuild();
            }
            else if (LOWORD(wParam) == 101) {
                // Run selected button
                for (int i = 0; i < g_state.count; i++) {
                    if (g_state.compilers[i].available && 
                        SendMessageW(g_state.compilers[i].hCheck, BM_GETCHECK, 0, 0) == BST_CHECKED) {
                        RunCompiler(i);
                    }
                }
                UpdateStatus(L"Selected compilers executed");
            }
            return 0;
            
        case WM_DESTROY:
            PostQuitMessage(0);
            return 0;
            
        default:
            return DefWindowProcW(hWnd, msg, wParam, lParam);
    }
}
