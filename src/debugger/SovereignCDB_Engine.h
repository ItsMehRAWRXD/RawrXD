/*===========================================================================
 * SovereignCDB_Engine.h
 * RawrXD IDE Debugger Backend
 * 
 * Bare-metal Windows debugging without heavy DbgEng dependencies
 * Uses kernel32.dll WaitForDebugEventEx/ContinueDebugEvent directly
 * 
 * Architecture:
 * - Lightweight: No COM, no heavy debugger frameworks
 * - Event-driven: Dedicated debug event pump thread
 * - State-sync: Bridge register/memory state to IDE UI
 * - No-deps: Direct Win32 API calls only
 *===========================================================================*/

#pragma once

#include <windows.h>
#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/*===========================================================================
 * CONSTANTS
 *===========================================================================*/
#define CDB_MAX_BREAKPOINTS         256
#define CDB_MAX_THREADS             256
#define CDB_MAX_MODULES             128
#define CDB_EVENT_QUEUE_SIZE        1024
#define CDB_SYMBOL_NAME_LEN         256
#define CDB_PATH_LEN                MAX_PATH

/*===========================================================================
 * DEBUG STATE
 *===========================================================================*/
typedef enum CDB_State {
    CDB_STATE_IDLE = 0,
    CDB_STATE_STARTING,
    CDB_STATE_RUNNING,
    CDB_STATE_BREAKPOINT,
    CDB_STATE_STEPPING,
    CDB_STATE_EXCEPTION,
    CDB_STATE_TERMINATED,
    CDB_STATE_ERROR
} CDB_State;

/*===========================================================================
 * BREAKPOINT
 *===========================================================================*/
typedef struct CDB_Breakpoint {
    uint64_t    address;
    uint32_t    id;
    uint32_t    threadId;
    bool        enabled;
    bool        hit;
    char        symbolName[CDB_SYMBOL_NAME_LEN];
    uint8_t     originalByte;     // For software breakpoints (0xCC)
} CDB_Breakpoint;

/*===========================================================================
 * THREAD CONTEXT
 *===========================================================================*/
typedef struct CDB_ThreadContext {
    uint32_t    threadId;
    uint64_t    rip;                // Instruction pointer
    uint64_t    rsp;                // Stack pointer
    uint64_t    rbp;                // Base pointer
    uint64_t    rax, rbx, rcx, rdx; // General purpose
    uint64_t    rsi, rdi;
    uint64_t    r8, r9, r10, r11;
    uint64_t    r12, r13, r14, r15;
    uint32_t    eflags;
    bool        suspended;
} CDB_ThreadContext;

/*===========================================================================
 * MODULE INFO
 *===========================================================================*/
typedef struct CDB_Module {
    uint64_t    baseAddress;
    uint64_t    size;
    char        name[CDB_PATH_LEN];
    char        path[CDB_PATH_LEN];
    bool        symbolsLoaded;
} CDB_Module;

/*===========================================================================
 * DEBUG EVENT
 *===========================================================================*/
typedef enum CDB_EventType {
    CDB_EVENT_NONE = 0,
    CDB_EVENT_BREAKPOINT,
    CDB_EVENT_STEP,
    CDB_EVENT_EXCEPTION,
    CDB_EVENT_THREAD_CREATE,
    CDB_EVENT_THREAD_EXIT,
    CDB_EVENT_PROCESS_CREATE,
    CDB_EVENT_PROCESS_EXIT,
    CDB_EVENT_MODULE_LOAD,
    CDB_EVENT_MODULE_UNLOAD,
    CDB_EVENT_OUTPUT
} CDB_EventType;

typedef struct CDB_DebugEvent {
    CDB_EventType   type;
    uint32_t        processId;
    uint32_t        threadId;
    uint64_t        address;
    uint32_t        exceptionCode;
    char            description[256];
    uint64_t        timestamp;
} CDB_DebugEvent;

/*===========================================================================
 * EVENT CALLBACK
 *===========================================================================*/
typedef void (*CDB_EventCallback)(
    const CDB_DebugEvent* event,
    void* userData
);

/*===========================================================================
 * ENGINE CONFIGURATION
 *===========================================================================*/
typedef struct CDB_Config {
    bool        breakOnEntry;       // Break at process entry point
    bool        breakOnDllLoad;     // Break when DLLs load
    bool        breakOnException;   // Break on first-chance exceptions
    bool        symbolPathsEnabled; // Use symbol server
    char        symbolPath[CDB_PATH_LEN * 4];
    uint32_t    eventQueueSize;
} CDB_Config;

/*===========================================================================
 * LIFECYCLE
 *===========================================================================*/

/* Initialize the CDB engine
 * Must be called before any other functions
 * Returns: TRUE on success, FALSE on error */
bool CDB_Initialize(const CDB_Config* config);

/* Shutdown and cleanup the CDB engine
 * Terminates any active debugging session */
void CDB_Shutdown(void);

/* Check if CDB engine is initialized and ready */
bool CDB_IsReady(void);

/*===========================================================================
 * DEBUG SESSION MANAGEMENT
 *===========================================================================*/

/* Start debugging a process by path
 * Launches process suspended, then begins debugging
 * 
 * Parameters:
 *   exePath     - Path to executable
 *   cmdLine     - Command line arguments (can be NULL)
 *   workingDir  - Working directory (can be NULL)
 *   envVars     - Environment variables (can be NULL)
 * 
 * Returns: TRUE on success, FALSE on error */
bool CDB_LaunchProcess(
    const char* exePath,
    const char* cmdLine,
    const char* workingDir,
    const char* envVars
);

/* Attach to an existing process
 * 
 * Parameters:
 *   processId   - Process ID to attach to
 * 
 * Returns: TRUE on success, FALSE on error */
bool CDB_AttachProcess(uint32_t processId);

/* Detach from current process
 * Process continues running normally */
void CDB_Detach(void);

/* Terminate debugged process */
void CDB_Terminate(uint32_t exitCode);

/* Get current debug state */
CDB_State CDB_GetState(void);

/* Get last error message */
const char* CDB_GetLastError(void);

/*===========================================================================
 * EXECUTION CONTROL
 *===========================================================================*/

/* Continue execution after a breakpoint/event
 * 
 * Parameters:
 *   threadId    - Thread to continue (0 = all threads)
 *   singleStep  - TRUE for single-step, FALSE for run */
void CDB_Continue(uint32_t threadId, bool singleStep);

/* Step into (single step) */
void CDB_StepInto(uint32_t threadId);

/* Step over (skip function calls) */
void CDB_StepOver(uint32_t threadId);

/* Step out (run until return) */
void CDB_StepOut(uint32_t threadId);

/* Break execution (inject breakpoint) */
void CDB_Break(void);

/*===========================================================================
 * BREAKPOINT MANAGEMENT
 *===========================================================================*/

/* Set a breakpoint at address
 * 
 * Parameters:
 *   address     - Virtual address for breakpoint
 *   symbolName  - Optional symbol name (can be NULL)
 * 
 * Returns: breakpoint ID (>0) on success, 0 on error */
uint32_t CDB_SetBreakpoint(uint64_t address, const char* symbolName);

/* Set breakpoint by symbol name
 * 
 * Parameters:
 *   symbolName  - Symbol name (e.g., "main", "MyClass::Method")
 * 
 * Returns: breakpoint ID (>0) on success, 0 on error */
uint32_t CDB_SetBreakpointByName(const char* symbolName);

/* Remove a breakpoint
 * 
 * Parameters:
 *   bpId        - Breakpoint ID from SetBreakpoint */
void CDB_RemoveBreakpoint(uint32_t bpId);

/* Enable/disable breakpoint */
void CDB_EnableBreakpoint(uint32_t bpId, bool enable);

/* Get breakpoint info */
bool CDB_GetBreakpoint(uint32_t bpId, CDB_Breakpoint* outBp);

/* Enumerate all breakpoints
 * Callback receives each breakpoint, return FALSE to stop */
void CDB_EnumBreakpoints(
    bool (*callback)(const CDB_Breakpoint* bp, void* userData),
    void* userData
);

/*===========================================================================
 * MEMORY & REGISTERS
 *===========================================================================*/

/* Read memory from debugged process
 * 
 * Parameters:
 *   address     - Virtual address to read
 *   buffer      - Output buffer
 *   size        - Number of bytes to read
 * 
 * Returns: Number of bytes actually read */
size_t CDB_ReadMemory(uint64_t address, void* buffer, size_t size);

/* Write memory to debugged process
 * 
 * Parameters:
 *   address     - Virtual address to write
 *   buffer      - Data to write
 *   size        - Number of bytes to write
 * 
 * Returns: Number of bytes actually written */
size_t CDB_WriteMemory(uint64_t address, const void* buffer, size_t size);

/* Get thread context (registers)
 * 
 * Parameters:
 *   threadId    - Thread ID (0 = current thread)
 *   context     - Output context
 * 
 * Returns: TRUE on success */
bool CDB_GetThreadContext(uint32_t threadId, CDB_ThreadContext* context);

/* Set thread context (registers)
 * 
 * Parameters:
 *   threadId    - Thread ID (0 = current thread)
 *   context     - New context
 * 
 * Returns: TRUE on success */
bool CDB_SetThreadContext(uint32_t threadId, const CDB_ThreadContext* context);

/* Suspend thread */
void CDB_SuspendThread(uint32_t threadId);

/* Resume thread */
void CDB_ResumeThread(uint32_t threadId);

/*===========================================================================
 * MODULE & SYMBOL INFO
 *===========================================================================*/

/* Enumerate loaded modules
 * Callback receives each module, return FALSE to stop */
void CDB_EnumModules(
    bool (*callback)(const CDB_Module* module, void* userData),
    void* userData
);

/* Get module by address */
bool CDB_GetModuleByAddress(uint64_t address, CDB_Module* outModule);

/* Resolve symbol name to address
 * 
 * Parameters:
 *   symbolName  - Symbol name
 *   outAddress  - Output address
 * 
 * Returns: TRUE if symbol found */
bool CDB_ResolveSymbol(const char* symbolName, uint64_t* outAddress);

/* Get symbol name by address
 * 
 * Parameters:
 *   address     - Virtual address
 *   outName     - Output buffer
 *   nameSize    - Buffer size
 * 
 * Returns: TRUE if symbol found */
bool CDB_GetSymbolByAddress(uint64_t address, char* outName, size_t nameSize);

/*===========================================================================
 * EVENT PUMP & CALLBACKS
 *===========================================================================*/

/* Set event callback
 * Called for every debug event (breakpoint, exception, etc.) */
void CDB_SetEventCallback(CDB_EventCallback callback, void* userData);

/* Poll for events (non-blocking)
 * Returns: TRUE if event processed, FALSE if no events */
bool CDB_PollEvents(void);

/* Wait for event (blocking)
 * Returns: TRUE on success, FALSE on timeout/error */
bool CDB_WaitForEvent(uint32_t timeoutMs);

/* Get next event from queue (non-blocking)
 * Returns: TRUE if event retrieved, FALSE if queue empty */
bool CDB_GetNextEvent(CDB_DebugEvent* outEvent);

/*===========================================================================
 * UTILITY
 *===========================================================================*/

/* Format address as string */
void CDB_FormatAddress(uint64_t address, char* outBuffer, size_t bufferSize);

/* Get exception name from code */
const char* CDB_GetExceptionName(uint32_t exceptionCode);

/* Get register name from index */
const char* CDB_GetRegisterName(uint32_t regIndex);

/* Get register value from context by name */
uint64_t CDB_GetRegisterValue(const CDB_ThreadContext* ctx, const char* regName);

/* Set register value in context by name */
void CDB_SetRegisterValue(CDB_ThreadContext* ctx, const char* regName, uint64_t value);

#ifdef __cplusplus
}
#endif

/* E> End of SovereignCDB_Engine.h <3 */
