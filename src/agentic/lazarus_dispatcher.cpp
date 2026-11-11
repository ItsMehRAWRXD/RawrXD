// lazarus_dispatcher.cpp - Production Implementation
// Task dispatcher with worker thread pool for agentic operations
// ============================================================================

#include <windows.h>
#include <process.h>

// ============================================================================
// Constants
// ============================================================================
#define MAX_WORKERS     8
#define MAX_TASKS       128
#define TASK_MAGIC      0x4C415A00  // 'LAZ'

// ============================================================================
// Task States
// ============================================================================
enum TaskState {
    TASK_IDLE = 0,
    TASK_QUEUED = 1,
    TASK_RUNNING = 2,
    TASK_COMPLETED = 3,
    TASK_FAILED = 4
};

// ============================================================================
// Task Structure
// ============================================================================
struct Task {
    volatile LONG magic;
    volatile LONG state;
    DWORD taskId;
    DWORD priority;
    void (*func)(void*);
    void* context;
    DWORD result;
    DWORD errorCode;
};

// ============================================================================
// Worker Context
// ============================================================================
struct WorkerContext {
    HANDLE hThread;
    HANDLE hEvent;
    volatile LONG active;
    DWORD workerId;
};

// ============================================================================
// State
// ============================================================================
static volatile LONG g_initialized = 0;
static Task g_taskPool[MAX_TASKS];
static WorkerContext g_workers[MAX_WORKERS];
static volatile LONG g_taskHead = 0;
static volatile LONG g_taskTail = 0;
static volatile LONG g_taskCount = 0;
static volatile LONG g_nextTaskId = 1;
static HANDLE g_hDispatchEvent = nullptr;
static CRITICAL_SECTION g_cs;

// ============================================================================
// Worker Thread
// ============================================================================
static unsigned int __stdcall WorkerThread(void* param) {
    WorkerContext* ctx = static_cast<WorkerContext*>(param);
    
    while (InterlockedCompareExchange(&ctx->active, 0, 0) == 1) {
        WaitForSingleObject(g_hDispatchEvent, 100);
        
        if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) break;
        
        EnterCriticalSection(&g_cs);
        
        LONG head = g_taskHead;
        LONG tail = g_taskTail;
        
        if (head < tail) {
            LONG idx = head % MAX_TASKS;
            Task* task = &g_taskPool[idx];
            
            if (InterlockedCompareExchange(&task->state, TASK_IDLE, TASK_QUEUED) == TASK_QUEUED) {
                InterlockedExchange(&task->state, TASK_RUNNING);
                g_taskHead++;
                g_taskCount--;
                
                LeaveCriticalSection(&g_cs);
                
                // Execute task
                __try {
                    if (task->func) {
                        task->func(task->context);
                    }
                    InterlockedExchange(&task->state, TASK_COMPLETED);
                    task->result = 1;
                } __except (EXCEPTION_EXECUTE_HANDLER) {
                    InterlockedExchange(&task->state, TASK_FAILED);
                    task->errorCode = GetExceptionCode();
                    task->result = 0;
                }
                
                InterlockedExchange(&task->magic, 0);
                continue;
            }
        }
        
        LeaveCriticalSection(&g_cs);
    }
    
    return 0;
}

// ============================================================================
// Exported API
// ============================================================================
extern "C" __declspec(dllexport) int lazarus_dispatcher_Init() {
    LONG was = InterlockedCompareExchange(&g_initialized, 1, 0);
    if (was != 0) return 1;
    
    InitializeCriticalSection(&g_cs);
    g_hDispatchEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
    
    InterlockedExchange(&g_taskHead, 0);
    InterlockedExchange(&g_taskTail, 0);
    InterlockedExchange(&g_taskCount, 0);
    InterlockedExchange(&g_nextTaskId, 1);
    
    for (int i = 0; i < MAX_TASKS; ++i) {
        InterlockedExchange(&g_taskPool[i].magic, 0);
        InterlockedExchange(&g_taskPool[i].state, TASK_IDLE);
        g_taskPool[i].taskId = 0;
        g_taskPool[i].func = nullptr;
        g_taskPool[i].context = nullptr;
    }
    
    for (int i = 0; i < MAX_WORKERS; ++i) {
        g_workers[i].hEvent = CreateEventA(nullptr, FALSE, FALSE, nullptr);
        InterlockedExchange(&g_workers[i].active, 1);
        g_workers[i].workerId = i;
        g_workers[i].hThread = reinterpret_cast<HANDLE>(_beginthreadex(nullptr, 0, WorkerThread, &g_workers[i], 0, nullptr));
    }
    
    return 1;
}

extern "C" __declspec(dllexport) int lazarus_dispatcher_Shutdown() {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    
    // Signal workers to stop
    for (int i = 0; i < MAX_WORKERS; ++i) {
        InterlockedExchange(&g_workers[i].active, 0);
    }
    
    // Wake all workers
    if (g_hDispatchEvent) {
        for (int i = 0; i < MAX_WORKERS * 2; ++i) {
            SetEvent(g_hDispatchEvent);
        }
    }
    
    // Wait for threads
    HANDLE threads[MAX_WORKERS];
    for (int i = 0; i < MAX_WORKERS; ++i) {
        threads[i] = g_workers[i].hThread;
    }
    WaitForMultipleObjects(MAX_WORKERS, threads, TRUE, 5000);
    
    // Cleanup
    for (int i = 0; i < MAX_WORKERS; ++i) {
        if (g_workers[i].hThread) CloseHandle(g_workers[i].hThread);
        if (g_workers[i].hEvent) CloseHandle(g_workers[i].hEvent);
    }
    if (g_hDispatchEvent) CloseHandle(g_hDispatchEvent);
    DeleteCriticalSection(&g_cs);
    
    InterlockedExchange(&g_initialized, 0);
    return 0;
}

extern "C" __declspec(dllexport) int lazarus_dispatcher_Dispatch(
    void (*func)(void*), 
    void* context, 
    DWORD priority,
    DWORD* outTaskId
) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    if (!func) return 0;
    
    EnterCriticalSection(&g_cs);
    
    LONG count = g_taskCount;
    if (count >= MAX_TASKS) {
        LeaveCriticalSection(&g_cs);
        return 0; // Queue full
    }
    
    LONG idx = g_taskTail % MAX_TASKS;
    Task* task = &g_taskPool[idx];
    
    if (InterlockedCompareExchange(&task->magic, 0, 0) != 0) {
        LeaveCriticalSection(&g_cs);
        return 0; // Slot in use
    }
    
    DWORD taskId = InterlockedIncrement(&g_nextTaskId);
    task->taskId = taskId;
    task->func = func;
    task->context = context;
    task->priority = priority;
    task->result = 0;
    task->errorCode = 0;
    InterlockedExchange(&task->state, TASK_QUEUED);
    InterlockedExchange(&task->magic, TASK_MAGIC);
    
    g_taskTail++;
    g_taskCount++;
    
    LeaveCriticalSection(&g_cs);
    
    if (outTaskId) *outTaskId = taskId;
    SetEvent(g_hDispatchEvent);
    
    return 1;
}

extern "C" __declspec(dllexport) int lazarus_dispatcher_GetTaskStatus(DWORD taskId, DWORD* outState, DWORD* outResult) {
    if (InterlockedCompareExchange(&g_initialized, 0, 0) == 0) return 0;
    
    for (int i = 0; i < MAX_TASKS; ++i) {
        if (g_taskPool[i].taskId == taskId) {
            if (outState) *outState = static_cast<DWORD>(InterlockedCompareExchange(&g_taskPool[i].state, 0, 0));
            if (outResult) *outResult = g_taskPool[i].result;
            return 1;
        }
    }
    return 0;
}

extern "C" __declspec(dllexport) int lazarus_dispatcher_GetQueueDepth() {
    return static_cast<int>(InterlockedCompareExchange(&g_taskCount, 0, 0));
}
