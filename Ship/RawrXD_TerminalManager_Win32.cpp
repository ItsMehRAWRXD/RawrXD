/*
 * RawrXD_TerminalManager_Win32.cpp
 * Pure Win32 replacement for Qt QProcess/terminal widgets
 * Uses: CreateProcessW, pipes, console API
 */

#define WIN32_LEAN_AND_MEAN
#include <windows.h>
<<<<<<< HEAD

#ifndef RAWRXD_WIN32_STATIC_BUILD
#define RAWRXD_SHIP_EXPORT __declspec(dllexport)
#else
#define RAWRXD_SHIP_EXPORT
#endif
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
#include <vector>
#include <string>
#include <map>
#include <queue>
#include <memory>

struct ProcessInfo {
    HANDLE hProcess;
    HANDLE hThread;
    HANDLE hStdOut;
    HANDLE hStdErr;
<<<<<<< HEAD
    HANDLE hStdInWrite;
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
    DWORD dwProcessId;
    bool running;
};

class RawrXDTerminalManager {
private:
    std::map<DWORD, ProcessInfo> m_processes;
    mutable CRITICAL_SECTION m_criticalSection;
    
public:
    RawrXDTerminalManager() {
        InitializeCriticalSection(&m_criticalSection);
    }
    
    ~RawrXDTerminalManager() {
        EnterCriticalSection(&m_criticalSection);
        for (auto& pair : m_processes) {
            if (pair.second.hProcess) {
                ::TerminateProcess(pair.second.hProcess, 1);
                CloseHandle(pair.second.hProcess);
            }
            if (pair.second.hThread) CloseHandle(pair.second.hThread);
            if (pair.second.hStdOut) CloseHandle(pair.second.hStdOut);
            if (pair.second.hStdErr) CloseHandle(pair.second.hStdErr);
<<<<<<< HEAD
            if (pair.second.hStdInWrite) CloseHandle(pair.second.hStdInWrite);
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        }
        LeaveCriticalSection(&m_criticalSection);
        DeleteCriticalSection(&m_criticalSection);
    }
    
    DWORD ExecuteCommand(const wchar_t* command, const wchar_t* workingDir = nullptr) {
<<<<<<< HEAD
        SECURITY_ATTRIBUTES sa = {sizeof(sa), nullptr, TRUE};
        HANDLE hStdoutRead = nullptr, hStdoutWrite = nullptr;
        HANDLE hStdinRead = nullptr, hStdinWrite = nullptr;
        
        if (!CreatePipe(&hStdoutRead, &hStdoutWrite, &sa, 0)) return 0;
        if (!CreatePipe(&hStdinRead, &hStdinWrite, &sa, 0)) {
            CloseHandle(hStdoutRead); CloseHandle(hStdoutWrite);
            return 0;
        }
        SetHandleInformation(hStdoutRead, HANDLE_FLAG_INHERIT, 0);
        SetHandleInformation(hStdinWrite, HANDLE_FLAG_INHERIT, 0);
        
        STARTUPINFOW si = {0};
        si.cb = sizeof(STARTUPINFOW);
        si.dwFlags = STARTF_USESTDHANDLES | STARTF_USESHOWWINDOW;
        si.hStdOutput = hStdoutWrite;
        si.hStdError = hStdoutWrite;
        si.hStdInput = hStdinRead;
        si.wShowWindow = SW_HIDE;
        
        PROCESS_INFORMATION pi = {0};
=======
        // Simplified - just launch the process without output redirection for now
        STARTUPINFOW si = {0};
        si.cb = sizeof(STARTUPINFOW);
        si.dwFlags = STARTF_USESHOWWINDOW;
        si.wShowWindow = SW_HIDE;
        
        PROCESS_INFORMATION pi = {0};
        
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        wchar_t cmdLine[32768];
        wcscpy_s(cmdLine, sizeof(cmdLine) / sizeof(wchar_t), L"cmd.exe /c ");
        wcscat_s(cmdLine, sizeof(cmdLine) / sizeof(wchar_t), command);
        
<<<<<<< HEAD
        if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, TRUE,
            CREATE_NO_WINDOW, nullptr, workingDir, &si, &pi)) {
            CloseHandle(hStdoutRead); CloseHandle(hStdoutWrite);
            CloseHandle(hStdinRead); CloseHandle(hStdinWrite);
            return 0;
        }
        
        CloseHandle(hStdoutWrite);
        CloseHandle(hStdinRead);
        
        ProcessInfo pinfo;
        pinfo.hProcess = pi.hProcess;
        pinfo.hThread = pi.hThread;
        pinfo.hStdOut = hStdoutRead;
        pinfo.hStdErr = nullptr;
        pinfo.hStdInWrite = hStdinWrite;
=======
        if (!CreateProcessW(nullptr, cmdLine, nullptr, nullptr, FALSE,
            CREATE_NO_WINDOW, nullptr, workingDir, &si, &pi)) {
            return 0;
        }
        
        ProcessInfo pinfo;
        pinfo.hProcess = pi.hProcess;
        pinfo.hThread = pi.hThread;
        pinfo.hStdOut = nullptr;
        pinfo.hStdErr = nullptr;
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        pinfo.dwProcessId = pi.dwProcessId;
        pinfo.running = true;
        
        EnterCriticalSection(&m_criticalSection);
        m_processes[pi.dwProcessId] = pinfo;
        LeaveCriticalSection(&m_criticalSection);
        
        return pi.dwProcessId;
    }
    
    bool ReadOutput(DWORD processId, char* buffer, size_t bufSize, size_t& bytesRead) {
        EnterCriticalSection(&m_criticalSection);
        
        auto it = m_processes.find(processId);
        if (it == m_processes.end()) {
            LeaveCriticalSection(&m_criticalSection);
            return false;
        }
        
        HANDLE hPipe = it->second.hStdOut;
        LeaveCriticalSection(&m_criticalSection);
        
        DWORD dwRead;
        if (!ReadFile(hPipe, buffer, (DWORD)bufSize, &dwRead, nullptr)) {
            return false;
        }
        
        bytesRead = dwRead;
        return true;
    }
    
    bool IsProcessRunning(DWORD processId) {
        EnterCriticalSection(&m_criticalSection);
        
        auto it = m_processes.find(processId);
        if (it == m_processes.end()) {
            LeaveCriticalSection(&m_criticalSection);
            return false;
        }
        
        DWORD dwExitCode;
        bool running = GetExitCodeProcess(it->second.hProcess, &dwExitCode) &&
            (dwExitCode == STILL_ACTIVE);
        
        LeaveCriticalSection(&m_criticalSection);
        return running;
    }
    
    DWORD GetExitCode(DWORD processId) {
        EnterCriticalSection(&m_criticalSection);
        
        auto it = m_processes.find(processId);
        if (it == m_processes.end()) {
            LeaveCriticalSection(&m_criticalSection);
            return -1;
        }
        
        DWORD dwExitCode;
        GetExitCodeProcess(it->second.hProcess, &dwExitCode);
        
        LeaveCriticalSection(&m_criticalSection);
        return dwExitCode;
    }
    
    bool TerminateProcess(DWORD processId) {
        EnterCriticalSection(&m_criticalSection);
        
        auto it = m_processes.find(processId);
        if (it == m_processes.end()) {
            LeaveCriticalSection(&m_criticalSection);
            return false;
        }
        
        bool result = ::TerminateProcess(it->second.hProcess, 1);
        
        LeaveCriticalSection(&m_criticalSection);
        return result;
    }
    
    void KillAllProcesses() {
        EnterCriticalSection(&m_criticalSection);
        
        for (auto& pair : m_processes) {
            if (pair.second.hProcess) {
                ::TerminateProcess(pair.second.hProcess, 1);
            }
        }
        
        LeaveCriticalSection(&m_criticalSection);
    }
};

static RawrXDTerminalManager* g_terminalManager = nullptr;

extern "C" {
<<<<<<< HEAD
    RAWRXD_SHIP_EXPORT void* __stdcall CreateTerminalManager() {
=======
    __declspec(dllexport) void* __stdcall CreateTerminalManager() {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        if (!g_terminalManager) {
            g_terminalManager = new RawrXDTerminalManager();
        }
        return g_terminalManager;
    }
    
<<<<<<< HEAD
    RAWRXD_SHIP_EXPORT void __stdcall DestroyTerminalManager(void* mgr) {
=======
    __declspec(dllexport) void __stdcall DestroyTerminalManager(void* mgr) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        if (mgr && mgr == g_terminalManager) {
            delete g_terminalManager;
            g_terminalManager = nullptr;
        }
    }
    
<<<<<<< HEAD
    RAWRXD_SHIP_EXPORT DWORD __stdcall Terminal_ExecuteCommand(void* mgr, const wchar_t* command, const wchar_t* workingDir) {
=======
    __declspec(dllexport) DWORD __stdcall Terminal_ExecuteCommand(void* mgr, const wchar_t* command, const wchar_t* workingDir) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        RawrXDTerminalManager* m = static_cast<RawrXDTerminalManager*>(mgr);
        return m ? m->ExecuteCommand(command, workingDir) : 0;
    }
    
<<<<<<< HEAD
    RAWRXD_SHIP_EXPORT bool __stdcall Terminal_ReadOutput(void* mgr, DWORD processId, char* buffer, size_t bufSize, size_t* bytesRead) {
=======
    __declspec(dllexport) bool __stdcall Terminal_ReadOutput(void* mgr, DWORD processId, char* buffer, size_t bufSize, size_t* bytesRead) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        RawrXDTerminalManager* m = static_cast<RawrXDTerminalManager*>(mgr);
        size_t read = 0;
        bool result = m ? m->ReadOutput(processId, buffer, bufSize, read) : false;
        if (bytesRead) *bytesRead = read;
        return result;
    }
    
<<<<<<< HEAD
    RAWRXD_SHIP_EXPORT bool __stdcall Terminal_IsProcessRunning(void* mgr, DWORD processId) {
=======
    __declspec(dllexport) bool __stdcall Terminal_IsProcessRunning(void* mgr, DWORD processId) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        RawrXDTerminalManager* m = static_cast<RawrXDTerminalManager*>(mgr);
        return m ? m->IsProcessRunning(processId) : false;
    }
    
<<<<<<< HEAD
    RAWRXD_SHIP_EXPORT DWORD __stdcall Terminal_GetExitCode(void* mgr, DWORD processId) {
=======
    __declspec(dllexport) DWORD __stdcall Terminal_GetExitCode(void* mgr, DWORD processId) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        RawrXDTerminalManager* m = static_cast<RawrXDTerminalManager*>(mgr);
        return m ? m->GetExitCode(processId) : -1;
    }
    
<<<<<<< HEAD
    RAWRXD_SHIP_EXPORT bool __stdcall Terminal_TerminateProcess(void* mgr, DWORD processId) {
=======
    __declspec(dllexport) bool __stdcall Terminal_TerminateProcess(void* mgr, DWORD processId) {
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
        RawrXDTerminalManager* m = static_cast<RawrXDTerminalManager*>(mgr);
        return m ? m->TerminateProcess(processId) : false;
    }
}

<<<<<<< HEAD
#ifndef RAWRXD_WIN32_STATIC_BUILD
=======
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
BOOL WINAPI DllMain(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpReserved) {
    if (fdwReason == DLL_PROCESS_ATTACH) {
        OutputDebugStringW(L"RawrXD_TerminalManager_Win32 loaded\n");
    } else if (fdwReason == DLL_PROCESS_DETACH && g_terminalManager) {
        g_terminalManager->KillAllProcesses();
        delete g_terminalManager;
<<<<<<< HEAD
        g_terminalManager = nullptr;
    }
    return TRUE;
}
#endif
=======
    }
    return TRUE;
}
>>>>>>> 99cf6bb9afc974435d8bd1fc140968c0301b26f9
