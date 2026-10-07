// Win32GitPipe.cpp - Production Implementation
// Provides Git command execution via named pipes for Win32IDE
// ============================================================================

#include <windows.h>
#include <cstdint>
#include <cstring>
#include <cstdio>

#define MAX_PIPE_OUTPUT   4096
#define MAX_GIT_CMDS      32

struct GitCommand {
    volatile LONG active;
    uint32_t cmdId;
    char cmd[256];
    char output[MAX_PIPE_OUTPUT];
    uint32_t exitCode;
    uint64_t execTime;
};

static volatile LONG g_initialized = 0;
static GitCommand g_cmds[MAX_GIT_CMDS];
static volatile LONG g_nextCmdId = 1;

extern "C" __declspec(dllexport) int Win32GitPipe_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    InterlockedExchange(&g_nextCmdId, 1);
    memset(g_cmds, 0, sizeof(g_cmds));
    return 1;
}

extern "C" __declspec(dllexport) int Win32GitPipe_Shutdown() {
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int Win32GitPipe_Execute(const char* cmd, char* outOutput, uint32_t maxLen, uint32_t* outExitCode) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!cmd || !outOutput || !outExitCode) return 0;
    
    // Find free slot
    int slot = -1;
    for (int i = 0; i < MAX_GIT_CMDS; ++i) {
        if (InterlockedCompareExchange(&g_cmds[i].active, 0, 0) == 0) { slot = i; break; }
    }
    if (slot < 0) return 0;
    
    GitCommand* entry = &g_cmds[slot];
    entry->cmdId = InterlockedIncrement(&g_nextCmdId);
    size_t cmdLen = strlen(cmd);
    if (cmdLen >= 256) cmdLen = 255;
    memcpy(entry->cmd, cmd, cmdLen);
    entry->cmd[cmdLen] = 0;
    
    // Execute via CreateProcess with pipe
    SECURITY_ATTRIBUTES sa;
    sa.nLength = sizeof(sa);
    sa.lpSecurityDescriptor = nullptr;
    sa.bInheritHandle = TRUE;
    
    HANDLE hRead, hWrite;
    if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
        InterlockedExchange(&entry->active, 0);
        return 0;
    }
    
    STARTUPINFOA si;
    memset(&si, 0, sizeof(si));
    si.cb = sizeof(si);
    si.dwFlags = STARTF_USESTDHANDLES;
    si.hStdOutput = hWrite;
    si.hStdError = hWrite;
    
    PROCESS_INFORMATION pi;
    memset(&pi, 0, sizeof(pi));
    
    char fullCmd[512];
    snprintf(fullCmd, sizeof(fullCmd), "cmd.exe /c %s", cmd);
    
    BOOL created = CreateProcessA(nullptr, fullCmd, nullptr, nullptr, TRUE, CREATE_NO_WINDOW, nullptr, nullptr, &si, &pi);
    CloseHandle(hWrite);
    
    if (!created) {
        CloseHandle(hRead);
        InterlockedExchange(&entry->active, 0);
        return 0;
    }
    
    // Read output
    DWORD read = 0;
    DWORD totalRead = 0;
    char buffer[1024];
    while (ReadFile(hRead, buffer, sizeof(buffer) - 1, &read, nullptr) && read > 0) {
        if (totalRead + read >= MAX_PIPE_OUTPUT - 1) {
            read = MAX_PIPE_OUTPUT - 1 - totalRead;
        }
        if (read > 0) {
            memcpy(entry->output + totalRead, buffer, read);
            totalRead += read;
        }
    }
    entry->output[totalRead] = 0;
    
    WaitForSingleObject(pi.hProcess, 5000);
    DWORD exitCode = 0;
    GetExitCodeProcess(pi.hProcess, &exitCode);
    
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    CloseHandle(hRead);
    
    entry->exitCode = exitCode;
    entry->execTime = GetTickCount64();
    InterlockedExchange(&entry->active, 1);
    
    size_t outLen = totalRead;
    if (outLen >= maxLen) outLen = maxLen - 1;
    memcpy(outOutput, entry->output, outLen);
    outOutput[outLen] = 0;
    *outExitCode = exitCode;
    
    return 1;
}

extern "C" __declspec(dllexport) int Win32GitPipe_GetLastOutput(uint32_t cmdId, char* outOutput, uint32_t maxLen) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    for (int i = 0; i < MAX_GIT_CMDS; ++i) {
        if (InterlockedCompareExchange(&g_cmds[i].active, 0, 0) == 1 && g_cmds[i].cmdId == cmdId) {
            size_t len = strlen(g_cmds[i].output);
            if (len >= maxLen) len = maxLen - 1;
            memcpy(outOutput, g_cmds[i].output, len);
            outOutput[len] = 0;
            return 1;
        }
    }
    return 0;
}
