/**
 * @file multiwindow_kernel.h
 * @brief Minimal C ABI declarations for the MultiWindow Kernel.
 *
 * Provides the typedefs, enums, and export function prototypes required by
 * multiwindow_scheduler.hpp/cpp and by the MASM64 implementation in
 * RawrXD_MultiWindow_Kernel.asm.
 */

#pragma once

#ifndef MULTIWINDOW_KERNEL_H
#define MULTIWINDOW_KERNEL_H

#include <stdint.h>
#include <stdbool.h>

#ifdef __cplusplus
extern "C" {
#endif

/* ------------------------------------------------------------------ */
/* Primitive typedefs                                                 */
/* ------------------------------------------------------------------ */
typedef uint32_t MW_WINDOW_ID;
typedef uint32_t MW_TASK_ID;
typedef uint8_t  MW_TASK_TYPE;
typedef uint8_t  MW_PRIORITY;
typedef uint32_t MW_MSG_TYPE;

/* ------------------------------------------------------------------ */
/* Constants                                                          */
/* ------------------------------------------------------------------ */
enum {
    MW_TASK_CHAT        = 0,
    MW_TASK_COMPLETION  = 1,
    MW_TASK_EMBED       = 2,
    MW_TASK_TOOL_CALL   = 3,
};

enum {
    MW_PRIORITY_LOW     = 0,
    MW_PRIORITY_NORMAL  = 1,
    MW_PRIORITY_HIGH    = 2,
    MW_PRIORITY_URGENT  = 3,
};

enum {
    MW_SHM_REPLAY_BASE  = 0x00000001,
    MW_IPC_SHARED_SIZE  = 65536,
};

/* ------------------------------------------------------------------ */
/* Stats structure                                                    */
/* ------------------------------------------------------------------ */
typedef struct MW_KernelStats {
    uint64_t tasksSubmitted;
    uint64_t tasksCompleted;
    uint64_t tasksFailed;
    uint64_t tasksCancelled;
    uint64_t windowsActive;
    uint64_t uptimeMs;
    uint64_t totalCpuTimeUs;
    uint32_t maxQueueDepth;
    uint32_t peakWorkers;
} MW_KernelStats;

/* ------------------------------------------------------------------ */
/* Task callback                                                      */
/* ------------------------------------------------------------------ */
typedef void (*MW_TaskCallback)(MW_TASK_ID taskId, bool success);

/* ------------------------------------------------------------------ */
/* Replay entry                                                       */
/* ------------------------------------------------------------------ */
typedef struct MW_ReplayEntry {
    uint64_t timestampUs;
    MW_TASK_ID taskId;
    MW_WINDOW_ID windowId;
    uint8_t  type;
    uint8_t  outcome;
    uint16_t payloadSize;
} MW_ReplayEntry;

/* ------------------------------------------------------------------ */
/* Kernel exports (C ABI)                                             */
/* ------------------------------------------------------------------ */

__declspec(dllimport) bool KernelInit(uint32_t workers);
__declspec(dllimport) void KernelShutdown(void);

__declspec(dllimport) MW_TASK_ID SubmitTask(MW_TASK_TYPE type,
                                              MW_PRIORITY priority,
                                              MW_WINDOW_ID windowId,
                                              uint64_t modelId,
                                              MW_TASK_ID dependsOn,
                                              MW_TaskCallback callback,
                                              void* userData);

__declspec(dllimport) bool CancelTask(MW_TASK_ID taskId);
__declspec(dllimport) bool IsTaskComplete(MW_TASK_ID taskId);

__declspec(dllimport) MW_WINDOW_ID RegisterWindow(uint32_t type,
                                                   int32_t x,
                                                   int32_t y,
                                                   uint32_t w,
                                                   uint32_t h);

__declspec(dllimport) void UnregisterWindow(MW_WINDOW_ID windowId);

__declspec(dllimport) bool SendIPCMessage(MW_MSG_TYPE msgType,
                                            MW_WINDOW_ID src,
                                            MW_WINDOW_ID dst,
                                            const void* payload,
                                            uint32_t payloadSize);

__declspec(dllimport) void GetKernelStats(MW_KernelStats* outStats);

__declspec(dllimport) uint32_t SwarmBroadcast(MW_TASK_TYPE type,
                                               const void* payload,
                                               uint32_t payloadSize,
                                               uint32_t modelCount);

__declspec(dllimport) MW_TASK_ID ChainOfThought(MW_WINDOW_ID windowId,
                                                  const MW_TaskCallback* steps,
                                                  uint32_t stepCount);

__declspec(dllimport) uint64_t GetMicroseconds(void);

#ifdef __cplusplus
} // extern "C"
#endif

#endif // MULTIWINDOW_KERNEL_H
