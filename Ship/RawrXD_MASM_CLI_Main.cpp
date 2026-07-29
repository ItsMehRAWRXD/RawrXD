#include <windows.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <wchar.h>

// RawrXD MASM x64 CLI
// Pure command-line interface for assembling MASM x64 code
// Integrates with Win32 IDE's split-pane terminal

#pragma comment(lib, "kernel32.lib")
#pragma comment(lib, "user32.lib")

#define MAX_CMD 512
#define MAX_PATH_STR 260

typedef struct {
    wchar_t command[MAX_CMD];
    wchar_t filename[MAX_PATH_STR];
    wchar_t options[MAX_CMD];
    int verbose;
    int optimize;
} MasmCommand;

void print_banner() {
    wprintf(L"RawrXD MASM x64 CLI v1.0\n");
    wprintf(L"Pure x64 Assembly Command Interface\n");
    wprintf(L"Type 'help' for available commands\n\n");
}

void print_prompt() {
    wprintf(L"[MASM]> ");
    fflush(stdout);
}

void print_help() {
    wprintf(L"\nAvailable Commands:\n");
    wprintf(L"  help              - Show this help message\n");
    wprintf(L"  version           - Display version information\n");
    wprintf(L"  asm FILE          - Assemble FILE.asm (auto-detects NASM vs MASM)\n");
    wprintf(L"  check FILE        - Syntax check (auto-detects format)\n");
    wprintf(L"  info FILE         - Show file information\n");
    wprintf(L"  path              - Display assembler search paths\n");
    wprintf(L"  exit              - Exit CLI\n");
    wprintf(L"\nFormat detection: asm/check peek at the file and use NASM for\n");
    wprintf(L"  section .text/data, bits 64, default rel, %%include; MASM for\n");
    wprintf(L"  .model, option casemap, invoke, includelib, .code/.data.\n");
    wprintf(L"\nExamples:\n");
    wprintf(L"  asm Titan_Kernel.asm\n");
    wprintf(L"  asm file_nasm_style.asm   (uses nasm -f win64 if NASM format detected)\n\n");
}

void print_version() {
    wprintf(L"RawrXD MASM CLI v1.0 (Windows x64)\n");
    wprintf(L"MASM Assembler Integration\n");
    wprintf(L"Microsoft Macro Assembler (ML64) support\n");
    wprintf(L"NASM fallback support\n\n");
}

// Detect assembly format by peeking at file content. Returns 1=MASM, 2=NASM, 0=unknown.
int detect_asm_format(const wchar_t* filename) {
    HANDLE h = CreateFileW(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (h == INVALID_HANDLE_VALUE) return 0;
    enum { PEEK_SIZE = 4096 };
    char buf[PEEK_SIZE + 1];
    DWORD read = 0;
    ReadFile(h, buf, PEEK_SIZE, &read, NULL);
    CloseHandle(h);
    if (read == 0) return 0;
    buf[read] = '\0';
    // Normalize to lowercase for comparison
    for (DWORD i = 0; i < read; i++) {
        if (buf[i] >= 'A' && buf[i] <= 'Z') buf[i] += 32;
    }
    int nasm_score = 0, masm_score = 0;
    // NASM signatures
    if (strstr(buf, "section .text")) nasm_score++;
    if (strstr(buf, "section .data")) nasm_score++;
    if (strstr(buf, "section .bss")) nasm_score++;
    if (strstr(buf, "bits 64") || strstr(buf, "bits 32")) nasm_score++;
    if (strstr(buf, "default rel")) nasm_score++;
    if (strstr(buf, "%include")) nasm_score++;
    if (strstr(buf, "[rel ")) nasm_score++;
    // MASM signatures
    if (strstr(buf, ".model")) masm_score++;
    if (strstr(buf, "option casemap")) masm_score++;
    if (strstr(buf, "invoke ")) masm_score++;
    if (strstr(buf, "includelib")) masm_score++;
    if (strstr(buf, ".686") || strstr(buf, ".xmm")) masm_score++;
    if (strstr(buf, "option frame")) masm_score++;
    if (strstr(buf, " proc ") || strstr(buf, " endp ") || strstr(buf, "\tproc ") || strstr(buf, "\tendp ")) masm_score++;
    // .code / .data: MASM uses bare .code/.data; NASM uses "section .*"
    if (strstr(buf, ".code") && !strstr(buf, "section .code")) masm_score++;
    if (strstr(buf, ".data") && !strstr(buf, "section .data")) masm_score++;
    if (nasm_score > masm_score) return 2;
    if (masm_score > nasm_score) return 1;
    return 0;
}

// Find a specific assembler: type 1 = ML64, type 2 = NASM. Fills path, returns 1 if found else 0. No printf.
int find_assembler_ex(int type, wchar_t* path, size_t pathlen) {
    if (type == 1) {
        if (SearchPathW(NULL, L"ml64.exe", NULL, (DWORD)pathlen, path, NULL) > 0) return 1;
    } else if (type == 2) {
        if (SearchPathW(NULL, L"nasm.exe", NULL, (DWORD)pathlen, path, NULL) > 0) return 1;
    }
    return 0;
}

int find_assembler(wchar_t* path, size_t pathlen) {
    // Prefer ML64 then NASM (legacy behavior when no format detection)
    if (find_assembler_ex(1, path, pathlen)) {
        wprintf(L"Found: ml64.exe at %s\n", path);
        return 1;
    }
    if (find_assembler_ex(2, path, pathlen)) {
        wprintf(L"Found: nasm.exe at %s\n", path);
        return 2;
    }
    return 0;
}

int cmd_build(wchar_t* filename) {
    wchar_t asmPath[MAX_PATH_STR];
    int asmType = 0;
    int format = detect_asm_format(filename);
    if (format == 2) {
        if (find_assembler_ex(2, asmPath, MAX_PATH_STR)) asmType = 2;
        else if (find_assembler_ex(1, asmPath, MAX_PATH_STR)) { asmType = 1; wprintf(L"[WARN] NASM format detected but only ML64 found. Using ML64 (may fail).\n"); }
    } else if (format == 1) {
        if (find_assembler_ex(1, asmPath, MAX_PATH_STR)) asmType = 1;
        else if (find_assembler_ex(2, asmPath, MAX_PATH_STR)) { asmType = 2; wprintf(L"[WARN] MASM format detected but only NASM found. Using NASM (may fail).\n"); }
    }
    if (asmType == 0) asmType = find_assembler(asmPath, MAX_PATH_STR);
    if (asmType == 0) {
        wprintf(L"[ERROR] No assembler found. Install ML64 or NASM.\n");
        return 1;
    }
    if (format != 0) wprintf(L"Detected format: %s -> using %s\n", format == 2 ? L"NASM" : L"MASM", asmType == 2 ? L"nasm" : L"ml64");
    wchar_t cmd[1024];
    wchar_t objfile[MAX_PATH_STR];
    wcscpy_s(objfile, MAX_PATH_STR, filename);
    size_t len = wcslen(objfile);
    if (len > 4 && wcscmp(&objfile[len-4], L".asm") == 0) {
        wcscpy_s(&objfile[len-4], 5, L".obj");
    }
    if (asmType == 1) {
        swprintf_s(cmd, 1024, L"\"%s\" /c /Zs /Fo\"%s\" \"%s\"",
                   asmPath, objfile, filename);
    } else {
        swprintf_s(cmd, 1024, L"\"%s\" -f win64 -o \"%s\" \"%s\"",
                   asmPath, objfile, filename);
    }
    wprintf(L"Building: %s -> %s\n", filename, objfile);
    wprintf(L"Command: %s\n", cmd);
    
    // Execute
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                        NULL, NULL, &si, &pi)) {
        wprintf(L"[ERROR] Failed to execute assembler\n");
        return 1;
    }
    
    wprintf(L"[MASM] Assembling...\n");
    WaitForSingleObject(pi.hProcess, 30000);  // Wait up to 30 seconds
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (exitCode == 0) {
        wprintf(L"[MASM] Assembly complete. Output: %s\n", objfile);
    } else {
        wprintf(L"[MASM] Assembly failed with exit code: %u\n", exitCode);
    }
    
    return (int)exitCode;
}

int cmd_check(wchar_t* filename) {
    wchar_t asmPath[MAX_PATH_STR];
    int asmType = 0;
    int format = detect_asm_format(filename);
    if (format == 2) {
        if (find_assembler_ex(2, asmPath, MAX_PATH_STR)) asmType = 2;
        else if (find_assembler_ex(1, asmPath, MAX_PATH_STR)) asmType = 1;
    } else if (format == 1) {
        if (find_assembler_ex(1, asmPath, MAX_PATH_STR)) asmType = 1;
        else if (find_assembler_ex(2, asmPath, MAX_PATH_STR)) asmType = 2;
    }
    if (asmType == 0) asmType = find_assembler(asmPath, MAX_PATH_STR);
    if (asmType == 0) {
        wprintf(L"[ERROR] No assembler found.\n");
        return 1;
    }
    wchar_t cmd[1024];
    wchar_t tmpObj[MAX_PATH_STR] = { 0 };
    if (asmType == 1) {
        swprintf_s(cmd, 1024, L"\"%s\" /c /Zs \"%s\"", asmPath, filename);
    } else {
        wchar_t tmpDir[MAX_PATH_STR];
        if (GetTempPathW(MAX_PATH_STR, tmpDir)) {
            wcscpy_s(tmpObj, MAX_PATH_STR, tmpDir);
            wcscat_s(tmpObj, MAX_PATH_STR, L"rawrxd_nasm_check.obj");
            swprintf_s(cmd, 1024, L"\"%s\" -f win64 -o \"%s\" \"%s\"", asmPath, tmpObj, filename);
        } else {
            swprintf_s(cmd, 1024, L"\"%s\" -f win64 -o \"%s\" \"%s\"", asmPath, L"nasm_check.obj", filename);
        }
    }
    wprintf(L"Checking: %s (%s)\n", filename, format == 2 ? L"NASM" : format == 1 ? L"MASM" : L"auto");
    
    STARTUPINFOW si = { sizeof(si) };
    PROCESS_INFORMATION pi = {};
    
    if (!CreateProcessW(NULL, cmd, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW | CREATE_NEW_PROCESS_GROUP,
                        NULL, NULL, &si, &pi)) {
        wprintf(L"[ERROR] Failed to execute assembler\n");
        return 1;
    }
    
    WaitForSingleObject(pi.hProcess, 30000);
    
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    
    if (exitCode == 0) {
        wprintf(L"[MASM] Syntax OK: %s\n", filename);
    } else {
        wprintf(L"[MASM] Syntax errors found (code %u)\n", exitCode);
    }
    if (tmpObj[0]) DeleteFileW(tmpObj);
    return (int)exitCode;
}

void cmd_info(wchar_t* filename) {
    WIN32_FILE_ATTRIBUTE_DATA fad = {};
    if (!GetFileAttributesExW(filename, GetFileExInfoStandard, &fad)) {
        wprintf(L"[ERROR] File not found: %s\n", filename);
        return;
    }
    
    ULARGE_INTEGER fileSize;
    fileSize.LowPart = fad.nFileSizeLow;
    fileSize.HighPart = fad.nFileSizeHigh;
    
    wprintf(L"File: %s\n", filename);
    wprintf(L"Size: %llu bytes\n", fileSize.QuadPart);
    
    SYSTEMTIME st;
    FileTimeToSystemTime(&fad.ftLastWriteTime, &st);
    wprintf(L"Modified: %04u-%02u-%02u %02u:%02u:%02u\n",
            st.wYear, st.wMonth, st.wDay,
            st.wHour, st.wMinute, st.wSecond);
}

int main() {
    SetConsoleCP(CP_UTF8);
    SetConsoleOutputCP(CP_UTF8);
    
    print_banner();
    
    wchar_t inputLine[MAX_CMD];
    wchar_t cmd[100];
    wchar_t arg1[MAX_PATH_STR];
    wchar_t arg2[MAX_CMD];
    
    while (1) {
        print_prompt();
        
        if (!fgetws(inputLine, MAX_CMD, stdin)) {
            break;
        }
        
        // Parse input
        int parsed = swscanf_s(inputLine, L"%99s %259s %511s[^\n]",
                               cmd, (unsigned)sizeof(cmd),
                               arg1, (unsigned)sizeof(arg1),
                               arg2, (unsigned)sizeof(arg2));
        
        if (parsed < 1) continue;
        
        // Process commands
        if (wcscmp(cmd, L"exit") == 0) {
            wprintf(L"Exiting RawrXD MASM CLI.\n");
            break;
        }
        else if (wcscmp(cmd, L"help") == 0) {
            print_help();
        }
        else if (wcscmp(cmd, L"version") == 0) {
            print_version();
        }
        else if (wcscmp(cmd, L"asm") == 0 || wcscmp(cmd, L"assemble") == 0) {
            if (parsed > 1) {
                cmd_build(arg1);
            } else {
                wprintf(L"Usage: asm <filename.asm>\n");
            }
        }
        else if (wcscmp(cmd, L"check") == 0) {
            if (parsed > 1) {
                cmd_check(arg1);
            } else {
                wprintf(L"Usage: check <filename.asm>\n");
            }
        }
        else if (wcscmp(cmd, L"info") == 0) {
            if (parsed > 1) {
                cmd_info(arg1);
            } else {
                wprintf(L"Usage: info <filename>\n");
            }
        }
        else if (wcscmp(cmd, L"path") == 0) {
            wchar_t asmPath[MAX_PATH_STR];
            int type = find_assembler(asmPath, MAX_PATH_STR);
            if (type == 0) {
                wprintf(L"No assembler found in PATH\n");
                wprintf(L"Install ML64 (MSVC) or NASM\n");
            }
        }
        else {
            wprintf(L"Unknown command: %s\n", cmd);
            wprintf(L"Type 'help' for available commands\n");
        }
        
        wprintf(L"\n");
    }
    
    return 0;
}
