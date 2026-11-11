// RawrXD_Debugger_Core.cpp - Native Debugger Implementation
// Zero dependencies, pure Win32 debugging API

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <dbghelp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

#pragma comment(lib, "dbghelp.lib")

#define MAX_BREAKPOINTS 256
#define MAX_THREADS 64
#define MAX_MODULES 128
#define MAX_STACK_FRAMES 128

// Breakpoint types
enum BreakpointType {
    BP_SOFTWARE = 0,
    BP_HARDWARE,
    BP_MEMORY
};

// Breakpoint structure
struct Breakpoint {
    BOOL bActive;
    BreakpointType type;
    DWORD_PTR dwAddress;
    BYTE bOriginalByte;
    DWORD dwThreadId;
    SIZE_T nHitCount;
    BOOL bConditional;
    char szCondition[256];
};

// Thread context
struct ThreadContext {
    DWORD dwThreadId;
    HANDLE hThread;
    CONTEXT ctx;
    BOOL bSuspended;
    char szName[64];
};

// Module info
struct ModuleInfo {
    DWORD_PTR dwBase;
    DWORD dwSize;
    char szName[MAX_PATH];
    char szPath[MAX_PATH];
    BOOL bSymbolsLoaded;
};

// Stack frame
struct StackFrame {
    DWORD_PTR dwAddress;
    DWORD_PTR dwReturnAddress;
    DWORD_PTR dwFramePointer;
    DWORD_PTR dwStackPointer;
    char szFunction[256];
    char szFile[MAX_PATH];
    DWORD dwLine;
};

// Variable info
struct VariableInfo {
    char szName[128];
    char szType[128];
    char szValue[512];
    DWORD_PTR dwAddress;
    BOOL bExpanded;
};

// Debugger state
struct DebuggerState {
    BOOL bActive;
    BOOL bRunning;
    BOOL bAttached;
    DWORD dwProcessId;
    HANDLE hProcess;
    HANDLE hDebugThread;
    
    Breakpoint breakpoints[MAX_BREAKPOINTS];
    int nBreakpointCount;
    
    ThreadContext threads[MAX_THREADS];
    int nThreadCount;
    int nCurrentThread;
    
    ModuleInfo modules[MAX_MODULES];
    int nModuleCount;
    
    StackFrame stackFrames[MAX_STACK_FRAMES];
    int nStackFrameCount;
    int nCurrentFrame;
    
    VariableInfo locals[256];
    int nLocalCount;
    
    VariableInfo watches[64];
    int nWatchCount;
    
    char szCurrentFile[MAX_PATH];
    DWORD dwCurrentLine;
    DWORD_PTR dwInstructionPointer;
    
    char szOutput[65536];
    int nOutputLen;
    
    CRITICAL_SECTION cs;
};

static DebuggerState g_Dbg = {0};
static BOOL g_bDebuggerInitialized = FALSE;

// Function prototypes
BOOL Debugger_Init(void);
void Debugger_Shutdown(void);
BOOL Debugger_StartProcess(const char* szExePath, const char* szArgs, const char* szWorkingDir);
BOOL Debugger_AttachProcess(DWORD dwProcessId);
void Debugger_Detach(void);
void Debugger_Stop(void);

BOOL Debugger_Continue(void);
BOOL Debugger_StepInto(void);
BOOL Debugger_StepOver(void);
BOOL Debugger_StepOut(void);
BOOL Debugger_Break(void);

int Debugger_SetBreakpoint(DWORD_PTR dwAddress);
BOOL Debugger_RemoveBreakpoint(int nBpId);
BOOL Debugger_EnableBreakpoint(int nBpId, BOOL bEnable);
BOOL Debugger_SetBreakpointCondition(int nBpId, const char* szCondition);

BOOL Debugger_ReadMemory(DWORD_PTR dwAddress, void* pBuffer, SIZE_T nSize);
BOOL Debugger_WriteMemory(DWORD_PTR dwAddress, const void* pBuffer, SIZE_T nSize);

BOOL Debugger_GetCallStack(int nThreadId);
BOOL Debugger_GetLocals(void);
BOOL Debugger_GetWatches(void);
BOOL Debugger_EvaluateExpression(const char* szExpr, char* szResult, size_t nResultSize);

void Debugger_AddOutput(const char* szText);
void Debugger_ClearOutput(void);

DWORD WINAPI Debugger_DebugThread(LPVOID lpParam);
void Debugger_HandleEvent(DEBUG_EVENT* pEvent);
void Debugger_UpdateState(void);

// Initialize debugger
BOOL Debugger_Init(void) {
    if (g_bDebuggerInitialized) return TRUE;
    
    ZeroMemory(&g_Dbg, sizeof(g_Dbg));
    InitializeCriticalSection(&g_Dbg.cs);
    
    // Initialize DbgHelp
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS | SYMOPT_LOAD_LINES);
    
    g_bDebuggerInitialized = TRUE;
    return TRUE;
}

// Shutdown debugger
void Debugger_Shutdown(void) {
    if (!g_bDebuggerInitialized) return;
    
    if (g_Dbg.bActive) {
        Debugger_Stop();
    }
    
    DeleteCriticalSection(&g_Dbg.cs);
    g_bDebuggerInitialized = FALSE;
}

// Start process under debugger
BOOL Debugger_StartProcess(const char* szExePath, const char* szArgs, const char* szWorkingDir) {
    if (!g_bDebuggerInitialized) return FALSE;
    if (g_Dbg.bActive) return FALSE;
    
    char szCmdLine[4096];
    _snprintf_s(szCmdLine, sizeof(szCmdLine), _TRUNCATE, "\"%s\" %s", szExePath, szArgs ? szArgs : "");
    
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    
    PROCESS_INFORMATION pi = {0};
    
    DWORD dwCreationFlags = DEBUG_ONLY_THIS_PROCESS | CREATE_NEW_CONSOLE;
    
    if (!CreateProcessA(NULL, szCmdLine, NULL, NULL, FALSE, dwCreationFlags,
        NULL, szWorkingDir, &si, &pi)) {
        return FALSE;
    }
    
    g_Dbg.dwProcessId = pi.dwProcessId;
    g_Dbg.hProcess = pi.hProcess;
    g_Dbg.bActive = TRUE;
    g_Dbg.bRunning = TRUE;
    g_Dbg.bAttached = FALSE;
    
    // Initialize DbgHelp for this process
    SymInitialize(g_Dbg.hProcess, NULL, FALSE);
    
    // Start debug event thread
    g_Dbg.hDebugThread = CreateThread(NULL, 0, Debugger_DebugThread, NULL, 0, NULL);
    
    CloseHandle(pi.hThread);
    
    return TRUE;
}

// Attach to running process
BOOL Debugger_AttachProcess(DWORD dwProcessId) {
    if (!g_bDebuggerInitialized) return FALSE;
    if (g_Dbg.bActive) return FALSE;
    
    if (!DebugActiveProcess(dwProcessId)) {
        return FALSE;
    }
    
    g_Dbg.dwProcessId = dwProcessId;
    g_Dbg.hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, dwProcessId);
    if (!g_Dbg.hProcess) {
        DebugActiveProcessStop(dwProcessId);
        return FALSE;
    }
    
    g_Dbg.bActive = TRUE;
    g_Dbg.bRunning = TRUE;
    g_Dbg.bAttached = TRUE;
    
    // Initialize DbgHelp
    SymInitialize(g_Dbg.hProcess, NULL, TRUE);
    
    // Start debug event thread
    g_Dbg.hDebugThread = CreateThread(NULL, 0, Debugger_DebugThread, NULL, 0, NULL);
    
    return TRUE;
}

// Detach from process
void Debugger_Detach(void) {
    if (!g_Dbg.bActive) return;
    if (!g_Dbg.bAttached) return;
    
    DebugActiveProcessStop(g_Dbg.dwProcessId);
    g_Dbg.bActive = FALSE;
    g_Dbg.bRunning = FALSE;
    
    if (g_Dbg.hDebugThread) {
        WaitForSingleObject(g_Dbg.hDebugThread, 5000);
        CloseHandle(g_Dbg.hDebugThread);
    }
    
    SymCleanup(g_Dbg.hProcess);
    CloseHandle(g_Dbg.hProcess);
}

// Stop debugging
void Debugger_Stop(void) {
    if (!g_Dbg.bActive) return;
    
    // Terminate process if we started it
    if (!g_Dbg.bAttached) {
        TerminateProcess(g_Dbg.hProcess, 1);
    }
    
    g_Dbg.bActive = FALSE;
    g_Dbg.bRunning = FALSE;
    
    if (g_Dbg.hDebugThread) {
        WaitForSingleObject(g_Dbg.hDebugThread, 5000);
        CloseHandle(g_Dbg.hDebugThread);
    }
    
    SymCleanup(g_Dbg.hProcess);
    CloseHandle(g_Dbg.hProcess);
}

// Continue execution
BOOL Debugger_Continue(void) {
    if (!g_Dbg.bActive) return FALSE;
    g_Dbg.bRunning = TRUE;
    return TRUE;
}

// Step into
BOOL Debugger_StepInto(void) {
    if (!g_Dbg.bActive) return FALSE;
    if (g_Dbg.nCurrentThread < 0 || g_Dbg.nCurrentThread >= g_Dbg.nThreadCount) return FALSE;
    
    ThreadContext* pThread = &g_Dbg.threads[g_Dbg.nCurrentThread];
    pThread->ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(pThread->hThread, &pThread->ctx);
    
    // Set trap flag for single step
    pThread->ctx.EFlags |= 0x100;
    SetThreadContext(pThread->hThread, &pThread->ctx);
    
    g_Dbg.bRunning = TRUE;
    return TRUE;
}

// Step over (skip function calls)
BOOL Debugger_StepOver(void) {
    if (!g_Dbg.bActive) return FALSE;
    if (g_Dbg.nCurrentThread < 0 || g_Dbg.nCurrentThread >= g_Dbg.nThreadCount) return FALSE;
    
    ThreadContext* pThread = &g_Dbg.threads[g_Dbg.nCurrentThread];
    pThread->ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(pThread->hThread, &pThread->ctx);
    
    // Check if current instruction is a call
    BYTE bInstr[16];
    SIZE_T nRead = 0;
    if (ReadProcessMemory(g_Dbg.hProcess, (LPCVOID)pThread->ctx.Rip, bInstr, sizeof(bInstr), &nRead)) {
        if (bInstr[0] == 0xE8 || bInstr[0] == 0xFF) {
            // It's a call - set breakpoint at return address
            DWORD_PTR dwReturnAddr = pThread->ctx.Rip + nRead;
            Debugger_SetBreakpoint(dwReturnAddr);
            g_Dbg.bRunning = TRUE;
            return TRUE;
        }
    }
    
    // Not a call - just step into
    return Debugger_StepInto();
}

// Step out of current function
BOOL Debugger_StepOut(void) {
    if (!g_Dbg.bActive) return FALSE;
    if (g_Dbg.nCurrentThread < 0 || g_Dbg.nCurrentThread >= g_Dbg.nThreadCount) return FALSE;
    
    ThreadContext* pThread = &g_Dbg.threads[g_Dbg.nCurrentThread];
    pThread->ctx.ContextFlags = CONTEXT_CONTROL;
    GetThreadContext(pThread->hThread, &pThread->ctx);
    
    // Get return address from stack
    DWORD_PTR dwReturnAddr = 0;
    SIZE_T nRead = 0;
    if (ReadProcessMemory(g_Dbg.hProcess, (LPCVOID)pThread->ctx.Rsp, &dwReturnAddr, sizeof(dwReturnAddr), &nRead)) {
        // Set breakpoint at return address
        Debugger_SetBreakpoint(dwReturnAddr);
        g_Dbg.bRunning = TRUE;
        return TRUE;
    }
    
    return FALSE;
}

// Break execution
BOOL Debugger_Break(void) {
    if (!g_Dbg.bActive) return FALSE;
    
    // Suspend all threads
    for (int i = 0; i < g_Dbg.nThreadCount; i++) {
        SuspendThread(g_Dbg.threads[i].hThread);
        g_Dbg.threads[i].bSuspended = TRUE;
    }
    
    g_Dbg.bRunning = FALSE;
    return TRUE;
}

// Set software breakpoint
int Debugger_SetBreakpoint(DWORD_PTR dwAddress) {
    if (!g_Dbg.bActive) return -1;
    if (g_Dbg.nBreakpointCount >= MAX_BREAKPOINTS) return -1;
    
    // Find free slot
    int nSlot = -1;
    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
        if (!g_Dbg.breakpoints[i].bActive) {
            nSlot = i;
            break;
        }
    }
    
    if (nSlot == -1) return -1;
    
    Breakpoint* pBp = &g_Dbg.breakpoints[nSlot];
    
    // Read original byte
    SIZE_T nRead = 0;
    if (!ReadProcessMemory(g_Dbg.hProcess, (LPCVOID)dwAddress, &pBp->bOriginalByte, 1, &nRead)) {
        return -1;
    }
    
    // Write INT3 (0xCC)
    BYTE bInt3 = 0xCC;
    SIZE_T nWritten = 0;
    if (!WriteProcessMemory(g_Dbg.hProcess, (LPVOID)dwAddress, &bInt3, 1, &nWritten)) {
        return -1;
    }
    
    // Flush instruction cache
    FlushInstructionCache(g_Dbg.hProcess, (LPCVOID)dwAddress, 1);
    
    pBp->bActive = TRUE;
    pBp->type = BP_SOFTWARE;
    pBp->dwAddress = dwAddress;
    pBp->nHitCount = 0;
    pBp->bConditional = FALSE;
    
    g_Dbg.nBreakpointCount++;
    
    return nSlot;
}

// Remove breakpoint
BOOL Debugger_RemoveBreakpoint(int nBpId) {
    if (!g_Dbg.bActive) return FALSE;
    if (nBpId < 0 || nBpId >= MAX_BREAKPOINTS) return FALSE;
    if (!g_Dbg.breakpoints[nBpId].bActive) return FALSE;
    
    Breakpoint* pBp = &g_Dbg.breakpoints[nBpId];
    
    // Restore original byte
    SIZE_T nWritten = 0;
    WriteProcessMemory(g_Dbg.hProcess, (LPVOID)pBp->dwAddress, &pBp->bOriginalByte, 1, &nWritten);
    FlushInstructionCache(g_Dbg.hProcess, (LPCVOID)pBp->dwAddress, 1);
    
    pBp->bActive = FALSE;
    g_Dbg.nBreakpointCount--;
    
    return TRUE;
}

// Enable/disable breakpoint
BOOL Debugger_EnableBreakpoint(int nBpId, BOOL bEnable) {
    if (!g_Dbg.bActive) return FALSE;
    if (nBpId < 0 || nBpId >= MAX_BREAKPOINTS) return FALSE;
    if (!g_Dbg.breakpoints[nBpId].bActive) return FALSE;
    
    Breakpoint* pBp = &g_Dbg.breakpoints[nBpId];
    
    if (bEnable) {
        // Write INT3
        BYTE bInt3 = 0xCC;
        SIZE_T nWritten = 0;
        WriteProcessMemory(g_Dbg.hProcess, (LPVOID)pBp->dwAddress, &bInt3, 1, &nWritten);
    } else {
        // Restore original
        SIZE_T nWritten = 0;
        WriteProcessMemory(g_Dbg.hProcess, (LPVOID)pBp->dwAddress, &pBp->bOriginalByte, 1, &nWritten);
    }
    
    FlushInstructionCache(g_Dbg.hProcess, (LPCVOID)pBp->dwAddress, 1);
    return TRUE;
}

// Read process memory
BOOL Debugger_ReadMemory(DWORD_PTR dwAddress, void* pBuffer, SIZE_T nSize) {
    if (!g_Dbg.bActive) return FALSE;
    
    SIZE_T nRead = 0;
    return ReadProcessMemory(g_Dbg.hProcess, (LPCVOID)dwAddress, pBuffer, nSize, &nRead);
}

// Write process memory
BOOL Debugger_WriteMemory(DWORD_PTR dwAddress, const void* pBuffer, SIZE_T nSize) {
    if (!g_Dbg.bActive) return FALSE;
    
    SIZE_T nWritten = 0;
    BOOL bResult = WriteProcessMemory(g_Dbg.hProcess, (LPVOID)dwAddress, pBuffer, nSize, &nWritten);
    if (bResult) {
        FlushInstructionCache(g_Dbg.hProcess, (LPCVOID)dwAddress, nSize);
    }
    return bResult;
}

// Get call stack
BOOL Debugger_GetCallStack(int nThreadId) {
    if (!g_Dbg.bActive) return FALSE;
    if (nThreadId < 0 || nThreadId >= g_Dbg.nThreadCount) return FALSE;
    
    ThreadContext* pThread = &g_Dbg.threads[nThreadId];
    
    // Get thread context
    pThread->ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(pThread->hThread, &pThread->ctx)) {
        return FALSE;
    }
    
    // Initialize stack frame
    STACKFRAME64 stackFrame = {0};
    stackFrame.AddrPC.Offset = pThread->ctx.Rip;
    stackFrame.AddrPC.Mode = AddrModeFlat;
    stackFrame.AddrFrame.Offset = pThread->ctx.Rbp;
    stackFrame.AddrFrame.Mode = AddrModeFlat;
    stackFrame.AddrStack.Offset = pThread->ctx.Rsp;
    stackFrame.AddrStack.Mode = AddrModeFlat;
    
    // Walk stack
    g_Dbg.nStackFrameCount = 0;
    while (StackWalk64(IMAGE_FILE_MACHINE_AMD64, g_Dbg.hProcess, pThread->hThread,
        &stackFrame, &pThread->ctx, NULL, SymFunctionTableAccess64, SymGetModuleBase64, NULL)) {
        
        if (g_Dbg.nStackFrameCount >= MAX_STACK_FRAMES) break;
        
        StackFrame* pFrame = &g_Dbg.stackFrames[g_Dbg.nStackFrameCount];
        pFrame->dwAddress = stackFrame.AddrPC.Offset;
        pFrame->dwReturnAddress = stackFrame.AddrReturn.Offset;
        pFrame->dwFramePointer = stackFrame.AddrFrame.Offset;
        pFrame->dwStackPointer = stackFrame.AddrStack.Offset;
        
        // Get symbol info
        BYTE symbolBuffer[sizeof(SYMBOL_INFO) + 256] = {0};
        PSYMBOL_INFO pSymbol = (PSYMBOL_INFO)symbolBuffer;
        pSymbol->SizeOfStruct = sizeof(SYMBOL_INFO);
        pSymbol->MaxNameLen = 255;
        
        DWORD64 dwDisplacement = 0;
        if (SymFromAddr(g_Dbg.hProcess, stackFrame.AddrPC.Offset, &dwDisplacement, pSymbol)) {
            strncpy_s(pFrame->szFunction, sizeof(pFrame->szFunction), pSymbol->Name, _TRUNCATE);
        } else {
            strcpy_s(pFrame->szFunction, sizeof(pFrame->szFunction), "???");
        }
        
        // Get line info
        IMAGEHLP_LINE64 line = {0};
        line.SizeOfStruct = sizeof(line);
        DWORD dwLineDisplacement = 0;
        if (SymGetLineFromAddr64(g_Dbg.hProcess, stackFrame.AddrPC.Offset, &dwLineDisplacement, &line)) {
            strncpy_s(pFrame->szFile, sizeof(pFrame->szFile), line.FileName, _TRUNCATE);
            pFrame->dwLine = line.LineNumber;
        } else {
            strcpy_s(pFrame->szFile, sizeof(pFrame->szFile), "???");
            pFrame->dwLine = 0;
        }
        
        g_Dbg.nStackFrameCount++;
    }
    
    return g_Dbg.nStackFrameCount > 0;
}

// Debug event thread
DWORD WINAPI Debugger_DebugThread(LPVOID lpParam) {
    (void)lpParam;
    
    DEBUG_EVENT debugEvent = {0};
    BOOL bContinue = TRUE;
    
    while (g_Dbg.bActive && bContinue) {
        if (!WaitForDebugEvent(&debugEvent, 100)) {
            continue;
        }
        
        EnterCriticalSection(&g_Dbg.cs);
        
        switch (debugEvent.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT: {
                EXCEPTION_DEBUG_INFO* pException = &debugEvent.u.Exception;
                
                if (pException->ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT ||
                    pException->ExceptionRecord.ExceptionCode == STATUS_WX86_BREAKPOINT) {
                    
                    // Handle breakpoint
                    g_Dbg.dwInstructionPointer = (DWORD_PTR)pException->ExceptionRecord.ExceptionAddress;
                    g_Dbg.bRunning = FALSE;
                    
                    // Check if it's one of our breakpoints
                    for (int i = 0; i < MAX_BREAKPOINTS; i++) {
                        if (g_Dbg.breakpoints[i].bActive &&
                            g_Dbg.breakpoints[i].dwAddress == g_Dbg.dwInstructionPointer) {
                            g_Dbg.breakpoints[i].nHitCount++;
                            
                            // Restore original byte and step over
                            SIZE_T nWritten = 0;
                            WriteProcessMemory(g_Dbg.hProcess, (LPVOID)g_Dbg.dwInstructionPointer,
                                &g_Dbg.breakpoints[i].bOriginalByte, 1, &nWritten);
                            FlushInstructionCache(g_Dbg.hProcess, (LPCVOID)g_Dbg.dwInstructionPointer, 1);
                            
                            // Set single step to re-enable breakpoint
                            // TODO: Implement
                            
                            break;
                        }
                    }
                    
                    // Update state
                    Debugger_UpdateState();
                    
                    // Notify UI
                    char szMsg[256];
                    _snprintf_s(szMsg, sizeof(szMsg), _TRUNCATE, "Breakpoint hit at 0x%p\n",
                        pException->ExceptionRecord.ExceptionAddress);
                    Debugger_AddOutput(szMsg);
                    
                } else if (pException->ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                    // Single step completed
                    g_Dbg.dwInstructionPointer = (DWORD_PTR)pException->ExceptionRecord.ExceptionAddress;
                    g_Dbg.bRunning = FALSE;
                    Debugger_UpdateState();
                    
                } else {
                    // Other exception
                    char szMsg[256];
                    _snprintf_s(szMsg, sizeof(szMsg), _TRUNCATE, "Exception 0x%08X at 0x%p\n",
                        pException->ExceptionRecord.ExceptionCode,
                        pException->ExceptionRecord.ExceptionAddress);
                    Debugger_AddOutput(szMsg);
                }
                
                bContinue = TRUE;
                break;
            }
            
            case CREATE_THREAD_DEBUG_EVENT: {
                if (g_Dbg.nThreadCount < MAX_THREADS) {
                    ThreadContext* pThread = &g_Dbg.threads[g_Dbg.nThreadCount];
                    pThread->dwThreadId = debugEvent.dwThreadId;
                    pThread->hThread = debugEvent.u.CreateThread.hThread;
                    pThread->bSuspended = FALSE;
                    g_Dbg.nThreadCount++;
                }
                bContinue = TRUE;
                break;
            }
            
            case CREATE_PROCESS_DEBUG_EVENT: {
                // Initial thread
                if (g_Dbg.nThreadCount < MAX_THREADS) {
                    ThreadContext* pThread = &g_Dbg.threads[g_Dbg.nThreadCount];
                    pThread->dwThreadId = debugEvent.dwThreadId;
                    pThread->hThread = debugEvent.u.CreateProcessInfo.hThread;
                    pThread->bSuspended = FALSE;
                    g_Dbg.nThreadCount++;
                }
                
                // Close file handle
                CloseHandle(debugEvent.u.CreateProcessInfo.hFile);
                
                bContinue = TRUE;
                break;
            }
            
            case EXIT_THREAD_DEBUG_EVENT: {
                // Remove thread
                for (int i = 0; i < g_Dbg.nThreadCount; i++) {
                    if (g_Dbg.threads[i].dwThreadId == debugEvent.dwThreadId) {
                        // Shift remaining threads
                        memmove(&g_Dbg.threads[i], &g_Dbg.threads[i + 1],
                            (g_Dbg.nThreadCount - i - 1) * sizeof(ThreadContext));
                        g_Dbg.nThreadCount--;
                        break;
                    }
                }
                bContinue = TRUE;
                break;
            }
            
            case EXIT_PROCESS_DEBUG_EVENT: {
                g_Dbg.bActive = FALSE;
                g_Dbg.bRunning = FALSE;
                bContinue = FALSE;
                Debugger_AddOutput("Process exited\n");
                break;
            }
            
            case LOAD_DLL_DEBUG_EVENT: {
                // Add module
                if (g_Dbg.nModuleCount < MAX_MODULES) {
                    ModuleInfo* pModule = &g_Dbg.modules[g_Dbg.nModuleCount];
                    pModule->dwBase = (DWORD_PTR)debugEvent.u.LoadDll.lpBaseOfDll;
                    
                    // Get module name
                    IMAGE_DOS_HEADER dosHeader = {0};
                    SIZE_T nRead = 0;
                    if (ReadProcessMemory(g_Dbg.hProcess, debugEvent.u.LoadDll.lpBaseOfDll,
                        &dosHeader, sizeof(dosHeader), &nRead)) {
                        // TODO: Get module name from export table
                    }
                    
                    strcpy_s(pModule->szName, sizeof(pModule->szName), "???");
                    pModule->bSymbolsLoaded = FALSE;
                    g_Dbg.nModuleCount++;
                }
                
                CloseHandle(debugEvent.u.LoadDll.hFile);
                bContinue = TRUE;
                break;
            }
            
            case UNLOAD_DLL_DEBUG_EVENT: {
                // Remove module
                for (int i = 0; i < g_Dbg.nModuleCount; i++) {
                    if (g_Dbg.modules[i].dwBase == (DWORD_PTR)debugEvent.u.UnloadDll.lpBaseOfDll) {
                        memmove(&g_Dbg.modules[i], &g_Dbg.modules[i + 1],
                            (g_Dbg.nModuleCount - i - 1) * sizeof(ModuleInfo));
                        g_Dbg.nModuleCount--;
                        break;
                    }
                }
                bContinue = TRUE;
                break;
            }
            
            case OUTPUT_DEBUG_STRING_EVENT: {
                // Read debug string
                char szBuffer[512] = {0};
                SIZE_T nRead = 0;
                ReadProcessMemory(g_Dbg.hProcess,
                    debugEvent.u.DebugString.lpDebugStringData,
                    szBuffer,
                    min(debugEvent.u.DebugString.nDebugStringLength, sizeof(szBuffer) - 1),
                    &nRead);
                Debugger_AddOutput(szBuffer);
                bContinue = TRUE;
                break;
            }
            
            default:
                bContinue = TRUE;
                break;
        }
        
        LeaveCriticalSection(&g_Dbg.cs);
        
        if (bContinue) {
            ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, DBG_CONTINUE);
        }
    }
    
    return 0;
}

// Update debugger state
void Debugger_UpdateState(void) {
    if (g_Dbg.nCurrentThread >= 0 && g_Dbg.nCurrentThread < g_Dbg.nThreadCount) {
        ThreadContext* pThread = &g_Dbg.threads[g_Dbg.nCurrentThread];
        
        // Get instruction pointer
        pThread->ctx.ContextFlags = CONTEXT_CONTROL;
        GetThreadContext(pThread->hThread, &pThread->ctx);
        g_Dbg.dwInstructionPointer = pThread->ctx.Rip;
        
        // Get call stack
        Debugger_GetCallStack(g_Dbg.nCurrentThread);
        
        // Update current location
        if (g_Dbg.nStackFrameCount > 0) {
            strncpy_s(g_Dbg.szCurrentFile, sizeof(g_Dbg.szCurrentFile),
                g_Dbg.stackFrames[0].szFile, _TRUNCATE);
            g_Dbg.dwCurrentLine = g_Dbg.stackFrames[0].dwLine;
        }
    }
}

// Add output
void Debugger_AddOutput(const char* szText) {
    EnterCriticalSection(&g_Dbg.cs);
    
    size_t nLen = strlen(szText);
    if (g_Dbg.nOutputLen + nLen < sizeof(g_Dbg.szOutput) - 1) {
        strcat_s(g_Dbg.szOutput + g_Dbg.nOutputLen,
            sizeof(g_Dbg.szOutput) - g_Dbg.nOutputLen, szText);
        g_Dbg.nOutputLen += (int)nLen;
    }
    
    LeaveCriticalSection(&g_Dbg.cs);
}

// Clear output
void Debugger_ClearOutput(void) {
    EnterCriticalSection(&g_Dbg.cs);
    g_Dbg.szOutput[0] = '\0';
    g_Dbg.nOutputLen = 0;
    LeaveCriticalSection(&g_Dbg.cs);
}

// Public API
extern "C" __declspec(dllexport) BOOL RawrXD_Debug_Init(void) {
    return Debugger_Init();
}

extern "C" __declspec(dllexport) void RawrXD_Debug_Shutdown(void) {
    Debugger_Shutdown();
}

extern "C" __declspec(dllexport) BOOL RawrXD_Debug_Start(const char* szExe, const char* szArgs, const char* szDir) {
    return Debugger_StartProcess(szExe, szArgs, szDir);
}

extern "C" __declspec(dllexport) BOOL RawrXD_Debug_Attach(DWORD dwPid) {
    return Debugger_AttachProcess(dwPid);
}

extern "C" __declspec(dllexport) void RawrXD_Debug_Stop(void) {
    Debugger_Stop();
}

extern "C" __declspec(dllexport) BOOL RawrXD_Debug_Continue(void) {
    return Debugger_Continue();
}

extern "C" __declspec(dllexport) BOOL RawrXD_Debug_StepInto(void) {
    return Debugger_StepInto();
}

extern "C" __declspec(dllexport) BOOL RawrXD_Debug_StepOver(void) {
    return Debugger_StepOver();
}

extern "C" __declspec(dllexport) int RawrXD_Debug_SetBreakpoint(DWORD_PTR addr) {
    return Debugger_SetBreakpoint(addr);
}

extern "C" __declspec(dllexport) BOOL RawrXD_Debug_RemoveBreakpoint(int id) {
    return Debugger_RemoveBreakpoint(id);
}

// End of RawrXD_Debugger_Core.cpp
