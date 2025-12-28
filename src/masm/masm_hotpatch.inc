;=====================================================================
; masm_hotpatch.inc - Shared Structure Definitions and Constants
; PURE MASM x64 HOTPATCH SYSTEM DEFINITIONS
;=====================================================================
; This include file defines all structures, constants, and external
; function declarations used across the MASM hotpatch system.
;=====================================================================

; ==== SIGNAL IDs for Event Coordination ====
SIGNAL_PATCH_APPLIED            EQU 1000
SIGNAL_PATCH_FAILED             EQU 1001
SIGNAL_OPTIMIZATION_COMPLETE    EQU 1002
SIGNAL_ERROR_OCCURRED           EQU 1003
SIGNAL_FAILURE_DETECTED         EQU 1004

; ==== Failure Type Constants ====
FAILURE_NONE                    EQU 0
FAILURE_REFUSAL                 EQU 1
FAILURE_HALLUCINATION           EQU 2
FAILURE_TIMEOUT                 EQU 3
FAILURE_RESOURCE_EXHAUSTION     EQU 4
FAILURE_SAFETY_VIOLATION        EQU 5
FAILURE_FORMAT_ERROR            EQU 6

; ==== Agentic Mode Constants ====
MODE_PLAN                       EQU 0
MODE_AGENT                      EQU 1
MODE_ASK                        EQU 2
MODE_CUSTOM                     EQU 3

; ==== Correction Strategy Constants ====
STRATEGY_RETRY                  EQU 0
STRATEGY_TRANSFORM              EQU 1
STRATEGY_FALLBACK               EQU 2

; ==== Patch Layer Constants ====
PATCH_LAYER_MEMORY              EQU 0
PATCH_LAYER_BYTE                EQU 1
PATCH_LAYER_SERVER              EQU 2

; ==== Injection Point Constants ====
INJECTION_PRE_REQUEST           EQU 0
INJECTION_POST_REQUEST          EQU 1
INJECTION_PRE_RESPONSE          EQU 2
INJECTION_POST_RESPONSE         EQU 3
INJECTION_STREAM_CHUNK          EQU 4

; ==== Structure Size Constants ====
SIZEOF_PATCH_RESULT             EQU 64
SIZEOF_MEMORY_PATCH             EQU 128
SIZEOF_BYTE_PATCH               EQU 256
SIZEOF_SERVER_HOTPATCH          EQU 512
SIZEOF_PROXY_HOTPATCH           EQU 512
SIZEOF_UNIFIED_RESULT           EQU 128
SIZEOF_FAILURE_DETECTION_RESULT EQU 256
SIZEOF_CORRECTION_RESULT        EQU 256
SIZEOF_EVENT_RECORD             EQU 64
SIZEOF_EVENT_LOOP_HANDLE        EQU 256
SIZEOF_UNIFIED_MANAGER          EQU 1024

; ==== External Runtime Functions (from asm_memory.asm) ====
EXTERN asm_malloc:PROC
EXTERN asm_free:PROC
EXTERN asm_realloc:PROC

; ==== External Sync Functions (from asm_sync.asm) ====
EXTERN asm_mutex_create:PROC
EXTERN asm_mutex_lock:PROC
EXTERN asm_mutex_unlock:PROC
EXTERN asm_mutex_destroy:PROC

EXTERN asm_event_create:PROC
EXTERN asm_event_set:PROC
EXTERN asm_event_wait:PROC
EXTERN asm_event_destroy:PROC

EXTERN asm_atomic_increment:PROC
EXTERN asm_atomic_decrement:PROC
EXTERN asm_atomic_cmpxchg:PROC

; ==== External String Functions (from asm_string.asm) ====
EXTERN asm_str_create:PROC
EXTERN asm_str_length:PROC
EXTERN asm_str_concat:PROC
EXTERN asm_str_compare:PROC
EXTERN asm_str_find:PROC
EXTERN asm_str_destroy:PROC

; ==== External Event Loop Functions (from asm_events.asm) ====
EXTERN asm_event_loop_create:PROC
EXTERN asm_event_loop_register_signal:PROC
EXTERN asm_event_loop_emit:PROC
EXTERN asm_event_loop_process_one:PROC
EXTERN asm_event_loop_process_all:PROC
EXTERN asm_event_loop_destroy:PROC

; ==== Memory Hotpatch Functions (from model_memory_hotpatch.asm) ====
EXTERN masm_hotpatch_apply_memory:PROC
EXTERN masm_hotpatch_rollback:PROC
EXTERN masm_hotpatch_get_stats:PROC

; ==== Byte-Level Hotpatch Functions (from byte_level_hotpatcher.asm) ====
EXTERN masm_byte_patch_open_file:PROC
EXTERN masm_byte_patch_find_pattern:PROC
EXTERN masm_byte_patch_apply:PROC
EXTERN masm_byte_patch_close:PROC
EXTERN masm_byte_patch_get_stats:PROC

; ==== Server Hotpatch Functions (from gguf_server_hotpatch.asm) ====
EXTERN masm_server_hotpatch_init:PROC
EXTERN masm_server_hotpatch_add:PROC
EXTERN masm_server_hotpatch_apply:PROC
EXTERN masm_server_hotpatch_enable:PROC
EXTERN masm_server_hotpatch_disable:PROC
EXTERN masm_server_hotpatch_get_stats:PROC
EXTERN masm_server_hotpatch_cleanup:PROC

; ==== Unified Manager Functions (from unified_hotpatch_manager.asm) ====
EXTERN masm_unified_manager_create:PROC
EXTERN masm_unified_apply_memory_patch:PROC
EXTERN masm_unified_apply_byte_patch:PROC
EXTERN masm_unified_add_server_hotpatch:PROC
EXTERN masm_unified_process_events:PROC
EXTERN masm_unified_get_stats:PROC
EXTERN masm_unified_destroy:PROC

; ==== Proxy Hotpatcher Functions (from proxy_hotpatcher.asm) ====
EXTERN masm_proxy_hotpatch_init:PROC
EXTERN masm_proxy_hotpatch_add:PROC
EXTERN masm_proxy_apply_logit_bias:PROC
EXTERN masm_proxy_inject_rst:PROC
EXTERN masm_proxy_transform_response:PROC
EXTERN masm_proxy_hotpatch_get_stats:PROC
EXTERN masm_proxy_hotpatch_cleanup:PROC

; ==== Agentic Failure Detector Functions (from agentic_failure_detector.asm) ====
EXTERN masm_detect_failure:PROC
EXTERN masm_detect_timeout:PROC
EXTERN masm_detect_resource_exhaustion:PROC
EXTERN masm_failure_detector_get_stats:PROC

; ==== Agentic Puppeteer Functions (from agentic_puppeteer.asm) ====
EXTERN masm_puppeteer_correct_response:PROC
EXTERN masm_puppeteer_get_stats:PROC

; ==== Logging (asm_log.asm) ====
EXTERN asm_log_init:PROC
EXTERN asm_log:PROC
LOG_ENABLED EQU 1

; ==== Win32 APIs (external from kernel32.dll) ====
EXTERN VirtualProtect:PROC
EXTERN GetLastError:PROC
EXTERN CreateFileA:PROC
EXTERN ReadFile:PROC
EXTERN WriteFile:PROC
EXTERN SetFilePointer:PROC
EXTERN CloseHandle:PROC
EXTERN GetSystemInfo:PROC
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC
EXTERN GetFileSizeEx:PROC
EXTERN FlushInstructionCache:PROC
EXTERN GetCurrentProcess:PROC
EXTERN OutputDebugStringA:PROC
EXTERN QueryPerformanceCounter:PROC

; ==== Useful Macros ====

; Macro: LOGA msgLabel -- emits debug log when LOG_ENABLED=1
LOGA MACRO msgLabel
IF LOG_ENABLED
    lea rcx, msgLabel
    call asm_log
ENDIF
ENDM

; Macro: LOCK_MUTEX mutex_handle
LOCK_MUTEX MACRO mutex_handle
    mov rcx, mutex_handle
    call asm_mutex_lock
ENDM

; Macro: UNLOCK_MUTEX mutex_handle
UNLOCK_MUTEX MACRO mutex_handle
    mov rcx, mutex_handle
    call asm_mutex_unlock
ENDM

; Macro: EMIT_SIGNAL event_loop, signal_id, p1, p2, p3
EMIT_SIGNAL MACRO event_loop, signal_id, p1, p2, p3
    mov rcx, event_loop
    mov edx, signal_id
    mov r8, p1
    mov r9, p2
    mov qword ptr [rsp + 40], p3
    call asm_event_loop_emit
ENDM

; Macro: ALLOC_STRUCT size, alignment
ALLOC_STRUCT MACRO size, alignment
    mov rcx, size
    mov rdx, alignment
    call asm_malloc
ENDM

; Macro: FREE_PTR ptr
FREE_PTR MACRO ptr
    mov rcx, ptr
    call asm_free
ENDM

;=====================================================================
; End of masm_hotpatch.inc
;=====================================================================
