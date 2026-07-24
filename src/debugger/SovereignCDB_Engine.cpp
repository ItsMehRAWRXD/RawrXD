/*===========================================================================
 * SovereignCDB_Engine.cpp
 * RawrXD IDE Debugger Backend Implementation
 * 
 * Bare-metal Windows debugging using direct kernel32.dll APIs
 * No COM, no DbgEng, minimal dependencies
 * 
 * Key APIs used:
 * - WaitForDebugEventEx / ContinueDebugEvent
 * - DebugActiveProcess / DebugActiveProcessStop
 * - CreateProcessA (with DEBUG_PROCESS flag)
 * - ReadProcessMemory / WriteProcessMemory
 * - GetThreadContext / SetThreadContext
 *===========================================================================*/

#include "SovereignCDB_Engine.h"
#include <string>
#include <cstdio>
#include <vector>
#include <queue>
#include <mutex>
#include <thread>
#include <atomic>

#ifdef _WIN32
    #include <windows.h>
    #include <tlhelp32.h>
    #include <dbghelp.h>
    #pragma comment(lib, "dbghelp.lib")
#endif

/*===========================================================================
 * INTERNAL STATE
 *===========================================================================*/

typedef struct CDB_Internal {
    // Engine state
    bool                    initialized;
    CDB_State               state;
    CDB_Config              config;
    char                    lastError[512];
    
    // Process info
    HANDLE                  hProcess;
    uint32_t                processId;
    HANDLE                  hMainThread;
    uint32_t                mainThreadId;
    bool                    attached;
    bool                    created;
    
    // Event handling
    CDB_EventCallback       eventCallback;
    void*                   eventUserData;
    std::thread             eventPumpThread;
    std::atomic<bool>       eventPumpRunning;
    std::queue<CDB_DebugEvent> eventQueue;
    std::mutex              eventQueueMutex;
    
    // Breakpoints
    std::vector<CDB_Breakpoint> breakpoints;
    uint32_t                nextBreakpointId;
    std::mutex              breakpointMutex;
    
    // Threads
    std::vector<CDB_ThreadContext> threads;
    std::mutex              threadsMutex;
    
    // Modules
    std::vector<CDB_Module> modules;
    std::mutex              modulesMutex;
    
} CDB_Internal;

static CDB_Internal g_CDB = {0};

/*===========================================================================
 * HELPER FUNCTIONS
 *===========================================================================*/

static void CDB_SetLastError(const char* msg) {
    strncpy(g_CDB.lastError, msg, sizeof(g_CDB.lastError) - 1);
    g_CDB.lastError[sizeof(g_CDB.lastError) - 1] = '\0';
}

static void CDB_SetLastErrorWin32(const char* context) {
    DWORD error = GetLastError();
    char msg[512];
    snprintf(msg, sizeof(msg), "%s: Win32 error %lu", context, error);
    CDB_SetLastError(msg);
}

static uint64_t CDB_GetTimestamp(void) {
    LARGE_INTEGER freq, count;
    QueryPerformanceFrequency(&freq);
    QueryPerformanceCounter(&count);
    return (count.QuadPart * 1000000) / freq.QuadPart; // Microseconds
}

static void CDB_PostEvent(const CDB_DebugEvent* event) {
    std::lock_guard<std::mutex> lock(g_CDB.eventQueueMutex);
    
    if (g_CDB.eventQueue.size() < g_CDB.config.eventQueueSize) {
        g_CDB.eventQueue.push(*event);
    }
    
    // Also call callback directly if set
    if (g_CDB.eventCallback) {
        g_CDB.eventCallback(event, g_CDB.eventUserData);
    }
}

/*===========================================================================
 * EVENT PUMP THREAD
 *===========================================================================*/

static void CDB_EventPumpThreadProc(void) {
    DEBUG_EVENT debugEvent;
    
    while (g_CDB.eventPumpRunning) {
        // Wait for debug event (100ms timeout for responsive shutdown)
        if (!WaitForDebugEvent(&debugEvent, 100)) {
            continue; // Timeout or error
        }
        
        // Process the event
        CDB_DebugEvent cdbEvent = {0};
        cdbEvent.processId = debugEvent.dwProcessId;
        cdbEvent.threadId = debugEvent.dwThreadId;
        cdbEvent.timestamp = CDB_GetTimestamp();
        
        switch (debugEvent.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT:
                cdbEvent.type = CDB_EVENT_PROCESS_CREATE;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "Process created: PID=%lu", debugEvent.dwProcessId);
                g_CDB.processId = debugEvent.dwProcessId;
                g_CDB.hProcess = debugEvent.u.CreateProcessInfo.hProcess;
                break;
                
            case EXIT_PROCESS_DEBUG_EVENT:
                cdbEvent.type = CDB_EVENT_PROCESS_EXIT;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "Process exited: code=%lu", debugEvent.u.ExitProcess.dwExitCode);
                g_CDB.state = CDB_STATE_TERMINATED;
                g_CDB.eventPumpRunning = false;
                break;
                
            case CREATE_THREAD_DEBUG_EVENT:
                cdbEvent.type = CDB_EVENT_THREAD_CREATE;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "Thread created: TID=%lu", debugEvent.dwThreadId);
                break;
                
            case EXIT_THREAD_DEBUG_EVENT:
                cdbEvent.type = CDB_EVENT_THREAD_EXIT;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "Thread exited: code=%lu", debugEvent.u.ExitThread.dwExitCode);
                break;
                
            case LOAD_DLL_DEBUG_EVENT:
                cdbEvent.type = CDB_EVENT_MODULE_LOAD;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "DLL loaded");
                break;
                
            case UNLOAD_DLL_DEBUG_EVENT:
                cdbEvent.type = CDB_EVENT_MODULE_UNLOAD;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "DLL unloaded");
                break;
                
            case EXCEPTION_DEBUG_EVENT: {
                EXCEPTION_RECORD* exc = &debugEvent.u.Exception.ExceptionRecord;
                cdbEvent.type = CDB_EVENT_EXCEPTION;
                cdbEvent.address = (uint64_t)exc->ExceptionAddress;
                cdbEvent.exceptionCode = exc->ExceptionCode;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "Exception 0x%08X at 0x%016llX", exc->ExceptionCode, cdbEvent.address);
                
                // Check if it's a breakpoint (int3)
                if (exc->ExceptionCode == EXCEPTION_BREAKPOINT ||
                    exc->ExceptionCode == 0x80000003) {
                    cdbEvent.type = CDB_EVENT_BREAKPOINT;
                    g_CDB.state = CDB_STATE_BREAKPOINT;
                }
                break;
            }
                
            case OUTPUT_DEBUG_STRING_EVENT: {
                cdbEvent.type = CDB_EVENT_OUTPUT;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "Debug output");
                break;
            }
                
            default:
                cdbEvent.type = CDB_EVENT_NONE;
                snprintf(cdbEvent.description, sizeof(cdbEvent.description),
                    "Unknown event: %lu", debugEvent.dwDebugEventCode);
                break;
        }
        
        // Post event to queue
        CDB_PostEvent(&cdbEvent);
        
        // Continue execution (unless it's a breakpoint we want to stop at)
        DWORD continueStatus = DBG_CONTINUE;
        if (cdbEvent.type == CDB_EVENT_BREAKPOINT || cdbEvent.type == CDB_EVENT_EXCEPTION) {
            // Don't auto-continue on breakpoints - let user handle it
            continueStatus = DBG_EXCEPTION_NOT_HANDLED;
        }
        
        ContinueDebugEvent(debugEvent.dwProcessId, debugEvent.dwThreadId, continueStatus);
    }
}

/*===========================================================================
 * LIFECYCLE
 *===========================================================================*/

bool CDB_Initialize(const CDB_Config* config) {
    if (g_CDB.initialized) {
        return true;
    }
    
    memset(&g_CDB, 0, sizeof(g_CDB));
    
    // Copy configuration
    if (config) {
        memcpy(&g_CDB.config, config, sizeof(CDB_Config));
    } else {
        // Default config
        g_CDB.config.breakOnEntry = true;
        g_CDB.config.breakOnException = true;
        g_CDB.config.eventQueueSize = CDB_EVENT_QUEUE_SIZE;
        strcpy(g_CDB.config.symbolPath, "srv*C:\\Symbols*https://msdl.microsoft.com/download/symbols");
    }
    
    // Initialize DbgHelp for symbol resolution
    SymSetOptions(SYMOPT_UNDNAME | SYMOPT_DEFERRED_LOADS);
    
    g_CDB.initialized = true;
    g_CDB.state = CDB_STATE_IDLE;
    g_CDB.nextBreakpointId = 1;
    
    return true;
}

void CDB_Shutdown(void) {
    if (!g_CDB.initialized) {
        return;
    }
    
    // Stop event pump
    if (g_CDB.eventPumpRunning) {
        g_CDB.eventPumpRunning = false;
        if (g_CDB.eventPumpThread.joinable()) {
            g_CDB.eventPumpThread.join();
        }
    }
    
    // Detach or terminate process
    if (g_CDB.attached) {
        CDB_Detach();
    } else if (g_CDB.created && g_CDB.state != CDB_STATE_TERMINATED) {
        CDB_Terminate(0);
    }
    
    // Cleanup breakpoints
    {
        std::lock_guard<std::mutex> lock(g_CDB.breakpointMutex);
        g_CDB.breakpoints.clear();
    }
    
    memset(&g_CDB, 0, sizeof(g_CDB));
}

bool CDB_IsReady(void) {
    return g_CDB.initialized;
}

/*===========================================================================
 * DEBUG SESSION
 *===========================================================================*/

bool CDB_LaunchProcess(
    const char* exePath,
    const char* cmdLine,
    const char* workingDir,
    const char* envVars
) {
    if (!g_CDB.initialized) {
        CDB_SetLastError("CDB not initialized");
        return false;
    }
    
    if (g_CDB.state != CDB_STATE_IDLE) {
        CDB_SetLastError("Already debugging a process");
        return false;
    }
    
    // Build command line
    char fullCmdLine[4096];
    if (cmdLine && *cmdLine) {
        snprintf(fullCmdLine, sizeof(fullCmdLine), "\"%s\" %s", exePath, cmdLine);
    } else {
        snprintf(fullCmdLine, sizeof(fullCmdLine), "\"%s\"", exePath);
    }
    
    // Setup startup info
    STARTUPINFOA si = {0};
    si.cb = sizeof(si);
    
    PROCESS_INFORMATION pi = {0};
    
    // Create process suspended with debug flag
    DWORD creationFlags = CREATE_SUSPENDED | DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS;
    
    if (!CreateProcessA(
        exePath,                    // Application name
        fullCmdLine,                // Command line
        NULL,                       // Process security attributes
        NULL,                       // Thread security attributes
        FALSE,                      // Inherit handles
        creationFlags,              // Creation flags
        (LPVOID)envVars,            // Environment
        workingDir,                 // Current directory
        &si,                        // Startup info
        &pi                         // Process info
    )) {
        CDB_SetLastErrorWin32("CreateProcessA failed");
        return false;
    }
    
    // Store handles
    g_CDB.hProcess = pi.hProcess;
    g_CDB.processId = pi.dwProcessId;
    g_CDB.hMainThread = pi.hThread;
    g_CDB.mainThreadId = pi.dwThreadId;
    g_CDB.created = true;
    g_CDB.attached = false;
    g_CDB.state = CDB_STATE_STARTING;
    
    // Initialize symbol handler for this process
    SymInitialize(g_CDB.hProcess, g_CDB.config.symbolPath, TRUE);
    
    // Start event pump
    g_CDB.eventPumpRunning = true;
    g_CDB.eventPumpThread = std::thread(CDB_EventPumpThreadProc);
    
    // Resume main thread
    ResumeThread(g_CDB.hMainThread);
    
    g_CDB.state = CDB_STATE_RUNNING;
    
    return true;
}

bool CDB_AttachProcess(uint32_t processId) {
    if (!g_CDB.initialized) {
        CDB_SetLastError("CDB not initialized");
        return false;
    }
    
    if (g_CDB.state != CDB_STATE_IDLE) {
        CDB_SetLastError("Already debugging a process");
        return false;
    }
    
    // Open process for debugging
    HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, processId);
    if (!hProcess) {
        CDB_SetLastErrorWin32("OpenProcess failed");
        return false;
    }
    
    // Attach debugger
    if (!DebugActiveProcess(processId)) {
        CDB_SetLastErrorWin32("DebugActiveProcess failed");
        CloseHandle(hProcess);
        return false;
    }
    
    g_CDB.hProcess = hProcess;
    g_CDB.processId = processId;
    g_CDB.attached = true;
    g_CDB.created = false;
    g_CDB.state = CDB_STATE_RUNNING;
    
    // Initialize symbol handler
    SymInitialize(g_CDB.hProcess, g_CDB.config.symbolPath, TRUE);
    
    // Start event pump
    g_CDB.eventPumpRunning = true;
    g_CDB.eventPumpThread = std::thread(CDB_EventPumpThreadProc);
    
    return true;
}

void CDB_Detach(void) {
    if (!g_CDB.attached || !g_CDB.hProcess) {
        return;
    }
    
    // Stop event pump
    g_CDB.eventPumpRunning = false;
    if (g_CDB.eventPumpThread.joinable()) {
        g_CDB.eventPumpThread.join();
    }
    
    // Detach debugger
    DebugActiveProcessStop(g_CDB.processId);
    
    // Cleanup
    SymCleanup(g_CDB.hProcess);
    CloseHandle(g_CDB.hProcess);
    
    g_CDB.hProcess = NULL;
    g_CDB.processId = 0;
    g_CDB.attached = false;
    g_CDB.state = CDB_STATE_IDLE;
}

void CDB_Terminate(uint32_t exitCode) {
    if (!g_CDB.hProcess) {
        return;
    }
    
    // Stop event pump
    g_CDB.eventPumpRunning = false;
    if (g_CDB.eventPumpThread.joinable()) {
        g_CDB.eventPumpThread.join();
    }
    
    // Terminate process
    TerminateProcess(g_CDB.hProcess, exitCode);
    
    // Cleanup
    SymCleanup(g_CDB.hProcess);
    CloseHandle(g_CDB.hProcess);
    if (g_CDB.hMainThread) {
        CloseHandle(g_CDB.hMainThread);
    }
    
    g_CDB.hProcess = NULL;
    g_CDB.hMainThread = NULL;
    g_CDB.processId = 0;
    g_CDB.state = CDB_STATE_TERMINATED;
}

CDB_State CDB_GetState(void) {
    return g_CDB.state;
}

const char* CDB_GetLastError(void) {
    return g_CDB.lastError[0] ? g_CDB.lastError : "No error";
}

/*===========================================================================
 * EXECUTION CONTROL
 *===========================================================================*/

void CDB_Continue(uint32_t threadId, bool singleStep) {
    if (!g_CDB.hProcess) {
        return;
    }
    
    if (singleStep) {
        g_CDB.state = CDB_STATE_STEPPING;
        
        // Set single-step flag in EFLAGS
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, 
                                   FALSE, threadId ? threadId : g_CDB.mainThreadId);
        if (hThread) {
            CONTEXT ctx;
            ctx.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(hThread, &ctx);
            ctx.EFlags |= 0x100; // Trap flag for single-step
            SetThreadContext(hThread, &ctx);
            CloseHandle(hThread);
        }
    } else {
        g_CDB.state = CDB_STATE_RUNNING;
    }
}

void CDB_StepInto(uint32_t threadId) {
    CDB_Continue(threadId, true);
}

void CDB_StepOver(uint32_t threadId) {
    // TODO: Implement step-over (set breakpoint on next instruction, run)
    CDB_StepInto(threadId);
}

void CDB_StepOut(uint32_t threadId) {
    // TODO: Implement step-out (set breakpoint on return address, run)
    CDB_Continue(threadId, false);
}

void CDB_Break(void) {
    if (!g_CDB.hProcess) {
        return;
    }
    
    // Inject breakpoint exception into main thread
    DebugBreakProcess(g_CDB.hProcess);
}

/*===========================================================================
 * BREAKPOINTS
 *===========================================================================*/

uint32_t CDB_SetBreakpoint(uint64_t address, const char* symbolName) {
    if (!g_CDB.hProcess) {
        return 0;
    }
    
    std::lock_guard<std::mutex> lock(g_CDB.breakpointMutex);
    
    // Check if breakpoint already exists at this address
    for (auto& bp : g_CDB.breakpoints) {
        if (bp.address == address && bp.enabled) {
            return bp.id;
        }
    }
    
    // Read original byte
    uint8_t originalByte;
    SIZE_T read;
    if (!ReadProcessMemory(g_CDB.hProcess, (LPVOID)address, &originalByte, 1, &read)) {
        return 0;
    }
    
    // Write int3 (0xCC)
    uint8_t int3 = 0xCC;
    SIZE_T written;
    if (!WriteProcessMemory(g_CDB.hProcess, (LPVOID)address, &int3, 1, &written)) {
        return 0;
    }
    
    // Flush instruction cache
    FlushInstructionCache(g_CDB.hProcess, (LPVOID)address, 1);
    
    // Create breakpoint record
    CDB_Breakpoint bp = {0};
    bp.id = g_CDB.nextBreakpointId++;
    bp.address = address;
    bp.enabled = true;
    bp.originalByte = originalByte;
    if (symbolName) {
        strncpy(bp.symbolName, symbolName, sizeof(bp.symbolName) - 1);
    }
    
    g_CDB.breakpoints.push_back(bp);
    
    return bp.id;
}

uint32_t CDB_SetBreakpointByName(const char* symbolName) {
    // TODO: Resolve symbol to address using DbgHelp
    // Implementation pending - returns 0
    (void)symbolName;
    return 0;
}

void CDB_RemoveBreakpoint(uint32_t bpId) {
    std::lock_guard<std::mutex> lock(g_CDB.breakpointMutex);
    
    for (auto it = g_CDB.breakpoints.begin(); it != g_CDB.breakpoints.end(); ++it) {
        if (it->id == bpId) {
            // Restore original byte
            if (g_CDB.hProcess) {
                SIZE_T written;
                WriteProcessMemory(g_CDB.hProcess, (LPVOID)it->address, 
                                  &it->originalByte, 1, &written);
                FlushInstructionCache(g_CDB.hProcess, (LPVOID)it->address, 1);
            }
            
            g_CDB.breakpoints.erase(it);
            return;
        }
    }
}

void CDB_EnableBreakpoint(uint32_t bpId, bool enable) {
    std::lock_guard<std::mutex> lock(g_CDB.breakpointMutex);
    
    for (auto& bp : g_CDB.breakpoints) {
        if (bp.id == bpId) {
            if (bp.enabled != enable) {
                bp.enabled = enable;
                
                if (g_CDB.hProcess) {
                    SIZE_T written;
                    if (enable) {
                        uint8_t int3 = 0xCC;
                        WriteProcessMemory(g_CDB.hProcess, (LPVOID)bp.address, 
                                          &int3, 1, &written);
                    } else {
                        WriteProcessMemory(g_CDB.hProcess, (LPVOID)bp.address, 
                                          &bp.originalByte, 1, &written);
                    }
                    FlushInstructionCache(g_CDB.hProcess, (LPVOID)bp.address, 1);
                }
            }
            return;
        }
    }
}

bool CDB_GetBreakpoint(uint32_t bpId, CDB_Breakpoint* outBp) {
    std::lock_guard<std::mutex> lock(g_CDB.breakpointMutex);
    
    for (const auto& bp : g_CDB.breakpoints) {
        if (bp.id == bpId) {
            if (outBp) {
                *outBp = bp;
            }
            return true;
        }
    }
    
    return false;
}

void CDB_EnumBreakpoints(
    bool (*callback)(const CDB_Breakpoint* bp, void* userData),
    void* userData
) {
    std::lock_guard<std::mutex> lock(g_CDB.breakpointMutex);
    
    for (const auto& bp : g_CDB.breakpoints) {
        if (!callback(&bp, userData)) {
            break;
        }
    }
}

/*===========================================================================
 * MEMORY & REGISTERS
 *===========================================================================*/

size_t CDB_ReadMemory(uint64_t address, void* buffer, size_t size) {
    if (!g_CDB.hProcess || !buffer) {
        return 0;
    }
    
    SIZE_T read;
    if (ReadProcessMemory(g_CDB.hProcess, (LPCVOID)address, buffer, size, &read)) {
        return read;
    }
    
    return 0;
}

size_t CDB_WriteMemory(uint64_t address, const void* buffer, size_t size) {
    if (!g_CDB.hProcess || !buffer) {
        return 0;
    }
    
    SIZE_T written;
    if (WriteProcessMemory(g_CDB.hProcess, (LPVOID)address, buffer, size, &written)) {
        return written;
    }
    
    return 0;
}

bool CDB_GetThreadContext(uint32_t threadId, CDB_ThreadContext* context) {
    if (!context) {
        return false;
    }
    
    HANDLE hThread = OpenThread(THREAD_GET_CONTEXT, FALSE, 
                                threadId ? threadId : g_CDB.mainThreadId);
    if (!hThread) {
        return false;
    }
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    
    if (!GetThreadContext(hThread, &ctx)) {
        CloseHandle(hThread);
        return false;
    }
    
    CloseHandle(hThread);
    
    // Convert to our format
    context->threadId = threadId ? threadId : g_CDB.mainThreadId;
    context->rip = ctx.Rip;
    context->rsp = ctx.Rsp;
    context->rbp = ctx.Rbp;
    context->rax = ctx.Rax;
    context->rbx = ctx.Rbx;
    context->rcx = ctx.Rcx;
    context->rdX = ctx.Rdx;
    context->rsi = ctx.Rsi;
    context->rdi = ctx.Rdi;
    context->r8 = ctx.R8;
    context->r9 = ctx.R9;
    context->r10 = ctx.R10;
    context->r11 = ctx.R11;
    context->r12 = ctx.R12;
    context->r13 = ctx.R13;
    context->r14 = ctx.R14;
    context->r15 = ctx.R15;
    context->eflags = ctx.EFlags;
    context->suspended = false;
    
    return true;
}

bool CDB_SetThreadContext(uint32_t threadId, const CDB_ThreadContext* context) {
    if (!context) {
        return false;
    }
    
    HANDLE hThread = OpenThread(THREAD_SET_CONTEXT, FALSE, 
                                threadId ? threadId : g_CDB.mainThreadId);
    if (!hThread) {
        return false;
    }
    
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    ctx.Rip = context->rip;
    ctx.Rsp = context->rsp;
    ctx.Rbp = context->rbp;
    ctx.Rax = context->rax;
    ctx.Rbx = context->rbx;
    ctx.Rcx = context->rcx;
    ctx.Rdx = context->rdX;
    ctx.Rsi = context->rsi;
    ctx.Rdi = context->rdi;
    ctx.R8 = context->r8;
    ctx.R9 = context->r9;
    ctx.R10 = context->r10;
    ctx.R11 = context->r11;
    ctx.R12 = context->r12;
    ctx.R13 = context->r13;
    ctx.R14 = context->r14;
    ctx.R15 = context->r15;
    ctx.EFlags = context->eflags;
    
    BOOL result = SetThreadContext(hThread, &ctx);
    CloseHandle(hThread);
    
    return result == TRUE;
}

void CDB_SuspendThread(uint32_t threadId) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, 
                                threadId ? threadId : g_CDB.mainThreadId);
    if (hThread) {
        SuspendThread(hThread);
        CloseHandle(hThread);
    }
}

void CDB_ResumeThread(uint32_t threadId) {
    HANDLE hThread = OpenThread(THREAD_SUSPEND_RESUME, FALSE, 
                                threadId ? threadId : g_CDB.mainThreadId);
    if (hThread) {
        ResumeThread(hThread);
        CloseHandle(hThread);
    }
}

/*===========================================================================
 * EVENTS
 *===========================================================================*/

void CDB_SetEventCallback(CDB_EventCallback callback, void* userData) {
    g_CDB.eventCallback = callback;
    g_CDB.eventUserData = userData;
}

bool CDB_PollEvents(void) {
    // Events are handled by the event pump thread
    // This function just checks if there are queued events
    std::lock_guard<std::mutex> lock(g_CDB.eventQueueMutex);
    return !g_CDB.eventQueue.empty();
}

bool CDB_WaitForEvent(uint32_t timeoutMs) {
    // Simple implementation: poll with sleep
    uint32_t elapsed = 0;
    while (elapsed < timeoutMs) {
        if (CDB_PollEvents()) {
            return true;
        }
        Sleep(10);
        elapsed += 10;
    }
    return false;
}

bool CDB_GetNextEvent(CDB_DebugEvent* outEvent) {
    std::lock_guard<std::mutex> lock(g_CDB.eventQueueMutex);
    
    if (g_CDB.eventQueue.empty()) {
        return false;
    }
    
    if (outEvent) {
        *outEvent = g_CDB.eventQueue.front();
    }
    
    g_CDB.eventQueue.pop();
    return true;
}

/*===========================================================================
 * UTILITY
 *===========================================================================*/

void CDB_FormatAddress(uint64_t address, char* outBuffer, size_t bufferSize) {
    snprintf(outBuffer, bufferSize, "0x%016llX", address);
}

const char* CDB_GetExceptionName(uint32_t exceptionCode) {
    switch (exceptionCode) {
        case EXCEPTION_ACCESS_VIOLATION:         return "Access Violation";
        case EXCEPTION_BREAKPOINT:              return "Breakpoint";
        case EXCEPTION_DATATYPE_MISALIGNMENT:   return "Datatype Misalignment";
        case EXCEPTION_SINGLE_STEP:             return "Single Step";
        case EXCEPTION_ARRAY_BOUNDS_EXCEEDED:   return "Array Bounds Exceeded";
        case EXCEPTION_FLT_DENORMAL_OPERAND:    return "Float Denormal Operand";
        case EXCEPTION_FLT_DIVIDE_BY_ZERO:      return "Float Divide by Zero";
        case EXCEPTION_INT_DIVIDE_BY_ZERO:      return "Integer Divide by Zero";
        case EXCEPTION_INT_OVERFLOW:            return "Integer Overflow";
        case EXCEPTION_PRIV_INSTRUCTION:          return "Privileged Instruction";
        case EXCEPTION_STACK_OVERFLOW:          return "Stack Overflow";
        default:                                return "Unknown Exception";
    }
}

const char* CDB_GetRegisterName(uint32_t regIndex) {
    static const char* names[] = {
        "RAX", "RBX", "RCX", "RDX", "RSI", "RDI", "RBP", "RSP",
        "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP"
    };
    
    if (regIndex < sizeof(names) / sizeof(names[0])) {
        return names[regIndex];
    }
    
    return "UNKNOWN";
}

uint64_t CDB_GetRegisterValue(const CDB_ThreadContext* ctx, const char* regName) {
    if (!ctx || !regName) return 0;
    
    if (_stricmp(regName, "RAX") == 0) return ctx->rax;
    if (_stricmp(regName, "RBX") == 0) return ctx->rbx;
    if (_stricmp(regName, "RCX") == 0) return ctx->rcx;
    if (_stricmp(regName, "RDX") == 0) return ctx->rdX;
    if (_stricmp(regName, "RSI") == 0) return ctx->rsi;
    if (_stricmp(regName, "RDI") == 0) return ctx->rdi;
    if (_stricmp(regName, "RBP") == 0) return ctx->rbp;
    if (_stricmp(regName, "RSP") == 0) return ctx->rsp;
    if (_stricmp(regName, "R8") == 0) return ctx->r8;
    if (_stricmp(regName, "R9") == 0) return ctx->r9;
    if (_stricmp(regName, "R10") == 0) return ctx->r10;
    if (_stricmp(regName, "R11") == 0) return ctx->r11;
    if (_stricmp(regName, "R12") == 0) return ctx->r12;
    if (_stricmp(regName, "R13") == 0) return ctx->r13;
    if (_stricmp(regName, "R14") == 0) return ctx->r14;
    if (_stricmp(regName, "R15") == 0) return ctx->r15;
    if (_stricmp(regName, "RIP") == 0) return ctx->rip;
    
    return 0;
}

void CDB_SetRegisterValue(CDB_ThreadContext* ctx, const char* regName, uint64_t value) {
    if (!ctx || !regName) return;
    
    if (_stricmp(regName, "RAX") == 0) ctx->rax = value;
    else if (_stricmp(regName, "RBX") == 0) ctx->rbx = value;
    else if (_stricmp(regName, "RCX") == 0) ctx->rcx = value;
    else if (_stricmp(regName, "RDX") == 0) ctx->rdX = value;
    else if (_stricmp(regName, "RSI") == 0) ctx->rsi = value;
    else if (_stricmp(regName, "RDI") == 0) ctx->rdi = value;
    else if (_stricmp(regName, "RBP") == 0) ctx->rbp = value;
    else if (_stricmp(regName, "RSP") == 0) ctx->rsp = value;
    else if (_stricmp(regName, "R8") == 0) ctx->r8 = value;
    else if (_stricmp(regName, "R9") == 0) ctx->r9 = value;
    else if (_stricmp(regName, "R10") == 0) ctx->r10 = value;
    else if (_stricmp(regName, "R11") == 0) ctx->r11 = value;
    else if (_stricmp(regName, "R12") == 0) ctx->r12 = value;
    else if (_stricmp(regName, "R13") == 0) ctx->r13 = value;
    else if (_stricmp(regName, "R14") == 0) ctx->r14 = value;
    else if (_stricmp(regName, "R15") == 0) ctx->r15 = value;
    else if (_stricmp(regName, "RIP") == 0) ctx->rip = value;
}

/* E> End of SovereignCDB_Engine.cpp <3 */
