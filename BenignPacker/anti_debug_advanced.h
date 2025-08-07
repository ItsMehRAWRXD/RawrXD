#pragma once

#include <iostream>
#include <thread>
#include <chrono>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#pragma comment(lib, "ntdll.lib")
#else
#include <sys/ptrace.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <cstring>
#include <signal.h>
#endif

class AntiDebugAdvanced {
private:
    std::mt19937 rng{std::random_device{}()};
    
    // Add random delays to confuse timing analysis
    void randomMicroDelay() {
        std::uniform_int_distribution<> dist(10, 1000);
        std::this_thread::sleep_for(std::chrono::microseconds(dist(rng)));
    }

public:
    // Master check function with obfuscated name (from test_embedded_final.cpp)
    bool procComponent519() {
#ifdef _WIN32
        return checkWindowsDebuggers();
#else
        return checkLinuxDebuggers();
#endif
    }

#ifdef _WIN32
    bool checkWindowsDebuggers() {
        randomMicroDelay();
        
        // 1. IsDebuggerPresent check
        if (IsDebuggerPresent()) return true;
        
        // 2. CheckRemoteDebuggerPresent
        BOOL debugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
        if (debugged) return true;
        
        randomMicroDelay();
        
        // 3. Check PEB BeingDebugged flag manually
        PPEB pPeb = (PPEB)__readgsqword(0x60); // x64
        if (pPeb->BeingDebugged) return true;
        
        // 4. Check NtGlobalFlag
        if (pPeb->NtGlobalFlag & 0x70) return true;
        
        randomMicroDelay();
        
        // 5. Check for debug privileges
        HANDLE hToken;
        if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)) {
            DWORD dwSize = 0;
            GetTokenInformation(hToken, TokenPrivileges, NULL, 0, &dwSize);
            
            if (dwSize > 0) {
                PTOKEN_PRIVILEGES pPrivs = (PTOKEN_PRIVILEGES)malloc(dwSize);
                if (GetTokenInformation(hToken, TokenPrivileges, pPrivs, dwSize, &dwSize)) {
                    for (DWORD i = 0; i < pPrivs->PrivilegeCount; i++) {
                        if (pPrivs->Privileges[i].Attributes & SE_PRIVILEGE_ENABLED) {
                            WCHAR szPrivName[256];
                            DWORD dwPrivNameSize = 256;
                            if (LookupPrivilegeNameW(NULL, &pPrivs->Privileges[i].Luid, szPrivName, &dwPrivNameSize)) {
                                if (wcscmp(szPrivName, L"SeDebugPrivilege") == 0) {
                                    free(pPrivs);
                                    CloseHandle(hToken);
                                    return true;
                                }
                            }
                        }
                    }
                }
                free(pPrivs);
            }
            CloseHandle(hToken);
        }
        
        randomMicroDelay();
        
        // 6. Hardware breakpoint detection
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        if (GetThreadContext(GetCurrentThread(), &ctx)) {
            if (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3) return true;
        }
        
        // 7. Check for common debugger processes
        const wchar_t* debuggers[] = {
            L"ollydbg.exe", L"x64dbg.exe", L"x32dbg.exe", L"windbg.exe",
            L"idaq.exe", L"idaq64.exe", L"ida.exe", L"ida64.exe",
            L"Debugger.exe", L"devenv.exe", L"procmon.exe", L"procmon64.exe",
            L"processhacker.exe", L"perfmon.exe", L"winapi32.exe"
        };
        
        PROCESSENTRY32W pe32;
        pe32.dwSize = sizeof(PROCESSENTRY32W);
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    for (const auto& debugger : debuggers) {
                        if (_wcsicmp(pe32.szExeFile, debugger) == 0) {
                            CloseHandle(hSnapshot);
                            return true;
                        }
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        
        randomMicroDelay();
        
        // 8. Timing check
        LARGE_INTEGER frequency, start, end;
        QueryPerformanceFrequency(&frequency);
        QueryPerformanceCounter(&start);
        
        // Some dummy operations
        volatile int dummy = 0;
        for (int i = 0; i < 1000; i++) dummy += i;
        
        QueryPerformanceCounter(&end);
        double elapsed = (double)(end.QuadPart - start.QuadPart) / frequency.QuadPart;
        
        // If execution took too long, likely being debugged
        if (elapsed > 0.01) return true;
        
        return false;
    }
#else
    bool checkLinuxDebuggers() {
        randomMicroDelay();
        
        // 1. Check TracerPid in /proc/self/status
        FILE* f = fopen("/proc/self/status", "r");
        if (!f) return false;
        
        char line[256];
        while (fgets(line, sizeof(line), f)) {
            if (strncmp(line, "TracerPid:", 10) == 0) {
                fclose(f);
                return atoi(line + 10) != 0;
            }
        }
        fclose(f);
        
        randomMicroDelay();
        
        // 2. Try ptrace - if we're being debugged, this will fail
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
            return true;
        }
        
        // 3. Check for GDB via environment
        if (getenv("LINES") || getenv("COLUMNS")) {
            return true;
        }
        
        // 4. Check parent process name
        char path[256];
        char name[256];
        snprintf(path, sizeof(path), "/proc/%d/comm", getppid());
        
        f = fopen(path, "r");
        if (f) {
            if (fgets(name, sizeof(name), f)) {
                fclose(f);
                if (strstr(name, "gdb") || strstr(name, "lldb") || 
                    strstr(name, "strace") || strstr(name, "ltrace")) {
                    return true;
                }
            }
        }
        
        randomMicroDelay();
        
        // 5. Check /proc/self/exe for modifications
        struct stat st1, st2;
        if (stat("/proc/self/exe", &st1) == 0) {
            randomMicroDelay();
            if (stat("/proc/self/exe", &st2) == 0) {
                if (st1.st_ino != st2.st_ino) return true;
            }
        }
        
        return false;
    }
#endif

    // Anti-VM detection
    bool isVirtualMachine() {
#ifdef _WIN32
        // Check for VM-specific registry keys
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            WCHAR szBuffer[256];
            DWORD dwSize = sizeof(szBuffer);
            if (RegQueryValueExW(hKey, L"0", NULL, NULL, (LPBYTE)szBuffer, &dwSize) == ERROR_SUCCESS) {
                if (wcsstr(szBuffer, L"VMware") || wcsstr(szBuffer, L"VBOX") || 
                    wcsstr(szBuffer, L"Virtual") || wcsstr(szBuffer, L"QEMU")) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
            RegCloseKey(hKey);
        }
        
        // Check CPU info
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 0x40000000);
        if (cpuInfo[1] == 0x61774D56 || // "VMwa"
            cpuInfo[1] == 0x4D566572 || // "VBox"
            cpuInfo[1] == 0x65726177) { // "ware"
            return true;
        }
#else
        // Check DMI info on Linux
        FILE* f = fopen("/sys/class/dmi/id/product_name", "r");
        if (f) {
            char buffer[256];
            if (fgets(buffer, sizeof(buffer), f)) {
                fclose(f);
                if (strstr(buffer, "VMware") || strstr(buffer, "VirtualBox") || 
                    strstr(buffer, "QEMU") || strstr(buffer, "Virtual")) {
                    return true;
                }
            }
        }
#endif
        return false;
    }
    
    // Advanced sandbox detection
    bool isSandboxed() {
        randomMicroDelay();
        
#ifdef _WIN32
        // Check for low number of processes (typical in sandboxes)
        DWORD processes[1024], cbNeeded;
        if (EnumProcesses(processes, sizeof(processes), &cbNeeded)) {
            DWORD processCount = cbNeeded / sizeof(DWORD);
            if (processCount < 50) return true;
        }
        
        // Check for small screen resolution (common in sandboxes)
        if (GetSystemMetrics(SM_CXSCREEN) < 1024 || 
            GetSystemMetrics(SM_CYSCREEN) < 768) {
            return true;
        }
        
        // Check for suspicious usernames
        WCHAR username[256];
        DWORD size = sizeof(username) / sizeof(WCHAR);
        if (GetUserNameW(username, &size)) {
            if (wcsstr(username, L"sandbox") || wcsstr(username, L"virus") || 
                wcsstr(username, L"malware") || wcsstr(username, L"sample")) {
                return true;
            }
        }
#endif
        
        return false;
    }
    
    // Comprehensive security check
    bool performSecurityCheck() {
        // Check debuggers
        if (procComponent519()) {
            std::cout << "Security check failed: Debugger detected" << std::endl;
            return false;
        }
        
        randomMicroDelay();
        
        // Check VM
        if (isVirtualMachine()) {
            std::cout << "Security check warning: Virtual machine detected" << std::endl;
            // Don't fail on VM, just warn
        }
        
        randomMicroDelay();
        
        // Check sandbox
        if (isSandboxed()) {
            std::cout << "Security check failed: Sandbox environment detected" << std::endl;
            return false;
        }
        
        return true;
    }
};