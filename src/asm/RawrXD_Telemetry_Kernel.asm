; =============================================================================
; RawrXD_Telemetry_Kernel.asm — Pure x64 MASM Implementation
; High-performance, Lock-free Metrics & Logging
; =============================================================================
;
; Architecture:
;   - Wait-Free Atomic Ring Buffer for events (lock xadd slot reservation)
;   - Lock-Free 64-bit Counters via single-instruction lock inc
;   - Direct Win32 I/O (no CRT, no Qt, no std::ofstream)
;   - Sub-microsecond timestamps via GetSystemTimePreciseAsFileTime
;
; Exports:
;   UTC_IncrementCounter     — Thread-safe atomic increment of any counter
;   UTC_DecrementCounter     — Thread-safe atomic decrement
;   UTC_ReadCounter          — Acquire-fence read of a counter
;   UTC_ResetCounter         — Atomic exchange to zero
;   UTC_LogEvent             — Wait-free write to ring buffer
;   UTC_FlushToDisk          — Drain ring buffer to log file
;   UTC_InitTelemetry        — Open log file handle
;   UTC_ShutdownTelemetry    — Flush + close handle
;   UTC_GetMetricTableBase   — Returns pointer to METRIC_TABLE_START
;   UTC_GetEventBufferStats  — Returns head/tail indices
;
; Pattern: PatchResult (RAX=0 success, RAX=error code on failure)
; Rule:    NO CRT, NO Qt, NO std::, NO exceptions
; =============================================================================

include RawrXD_Common.inc

; Win32 APIs not in Common.inc
EXTERNDEF GetSystemTimePreciseAsFileTime:PROC
EXTERNDEF FileTimeToSystemTime:PROC
EXTERNDEF WriteFile:PROC
EXTERNDEF CreateFileA:PROC
EXTERNDEF FlushFileBuffers:PROC

INCLUDE P1PRA_UtcWitness.inc

; =============================================================================
;                              Data Segment
; =============================================================================

; Telemetry counters (g_MetricTableStart..g_MetricTableEnd, g_Counter_*)
; are now defined in rawr_globals.asm — accessed via EXTERNDEF (rawr_globals.inc)
INCLUDE rawr_globals.inc

; Ring buffer and other data (standard .data alignment)
.data

    ; =========================================================================
    ; Ring Buffer Configuration
    ; EVENT_BUFFER_SIZE must be a power of 2 for bitmask indexing.
    ; Each slot is EVENT_STRUCT_SIZE bytes (null-terminated string w/ timestamp).
    ; =========================================================================

    EVENT_BUFFER_SIZE       equ 8192    ; 8K slots (power of 2)
    EVENT_STRUCT_SIZE       equ 256     ; Max bytes per event entry
    EVENT_BUFFER_MASK       equ (EVENT_BUFFER_SIZE - 1)
    EVENT_STRUCT_SHIFT      equ 8       ; log2(256) = 8, used with shl

    align 16
    g_EventBuffer       db (EVENT_BUFFER_SIZE * EVENT_STRUCT_SIZE) dup(0)

    align 8
    g_HeadIdx           dq 0    ; Producer index (atomic xadd)
    g_TailIdx           dq 0    ; Consumer index (single-writer: flush thread)

    ; =========================================================================
    ; Win32 File Handle for log output
    ; =========================================================================
    g_hLogFile          dq -1   ; INVALID_HANDLE_VALUE initially
    g_bInitialized      dq 0    ; Boolean: telemetry subsystem ready

    ; Log file path (default)
    szLogPath           db "rawrxd_kernel.log", 0

    ; Timestamp format helpers
    szBracketOpen       db "[", 0
    szBracketClose      db "] ", 0
    szColon             db ":", 0
    szNewline           db 13, 10, 0     ; CRLF for Windows

    ; Status strings
    szTK_InitOk         db "[UTC] Telemetry kernel initialized", 13, 10, 0
    szFlushOk           db "[UTC] Buffer flushed to disk", 13, 10, 0
    szShutdownOk        db "[UTC] Telemetry kernel shutdown", 13, 10, 0

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    szUtcPathResolve    db "path_resolve", 0
    szUtcStatePub       db "state_publication", 0
    szUtcCounterReset   db "counter_ring_reset", 0
    szUtcInitBanner     db "init_banner_log", 0
    szUtcReturnSuccess  db "return_success", 0
    szUtcReturnError    db "return_error", 0
    szUtcLogSlotReserve db "log_slot_reserve", 0
    szUtcLogTimestamp   db "log_timestamp", 0
    szUtcLogMessageCopy db "log_message_copy", 0
    szUtcLogNewline     db "log_newline", 0
    szUtcCfShadow       db "cf_shadow_alloc", 0
    szUtcCfArgPath      db "cf_arg_path", 0
    szUtcCfArgAccess    db "cf_arg_access", 0
    szUtcCfArgShare     db "cf_arg_share", 0
    szUtcCfArgSecurity  db "cf_arg_security", 0
    szUtcCfStackParams  db "cf_stack_params", 0
    szUtcCfCall         db "cf_call", 0
    szUtcCfPostcall     db "cf_postcall", 0
    szUtcExportShutdown db "export_shutdown", 0
    szUtcExportFlush    db "export_flush", 0
    szUtcExportGetMetric db "export_get_metric_base", 0
    szUtcExportGetStats db "export_get_buffer_stats", 0
    szUtcExportLogEvent db "export_log_event", 0
    szUtcExportInc      db "export_inc_counter", 0
    szUtcExportDec      db "export_dec_counter", 0
    szUtcExportRead     db "export_read_counter", 0
    szUtcExportReset    db "export_reset_counter", 0
    szUtcTsFileTime     db "ts_get_filetime", 0
    szUtcTsSystemTime   db "ts_to_systemtime", 0
    szUtcTsFormat       db "ts_format_ascii", 0
    szUtcFlushInitGate  db "flush_init_gate", 0
    szUtcFlushLoopCmp   db "flush_loop_compare", 0
    szUtcFlushStrlen    db "flush_strlen_slot", 0
    szUtcFlushWrite     db "flush_write_file", 0
    szUtcFlushAdvance   db "flush_advance_tail", 0
    szUtcFlushOsBuf     db "flush_os_buffers", 0
    szUtcCfStackLayout  db "cf_stack_layout", 0
    szUtcCfResultHandle db "cf_result_handle", 0
    szUtcCfHandleCompare db "cf_handle_compare", 0
    szUtcCfHandleSuccess db "cf_handle_success", 0
    szUtcCfLastError    db "cf_last_error", 0
    szUtcShutdownFlush  db "shutdown_flush_call", 0
    szUtcShutdownHLoad  db "shutdown_handle_load", 0
    szUtcShutdownHGate  db "shutdown_handle_gate", 0
    szUtcShutdownClose  db "shutdown_close_call", 0
    szUtcShutdownClear  db "shutdown_state_clear", 0
    szUtcLogSlotAddr    db "log_slot_addr_calc", 0
    szUtcLogCopyBounds  db "log_copy_bounds", 0
    szUtcLogCopyEnter   db "log_copy_loop_enter", 0
    szUtcLogCopyDone    db "log_copy_loop_done", 0
    szUtcLogTsCall      db "log_ts_internal_call", 0
    szUtcCfShadowRspPre db "cf_shadow_rsp_pre", 0
    szUtcCfShadowSub56  db "cf_shadow_sub56", 0
    szUtcStatePubStore  db "state_pub_store_handle", 0
    szUtcStatePubInit   db "state_pub_set_init", 0
    szUtcCounterMetrics db "counter_reset_metrics", 0
    szUtcCounterRing    db "counter_reset_ring_idx", 0
    szUtcInitBannerLea  db "init_banner_lea_msg", 0
    szUtcInitBannerLog  db "init_banner_log_event", 0
    szUtcReturnSuccessZero db "return_success_zero", 0
    szUtcReturnErrorEnter db "return_error_enter", 0
    szUtcKernelReturn   db "utc_kernel_return", 0
    szUtcFlushCntInc    db "flush_counter_inc", 0
    szUtcFlushWriteShadow db "flush_write_shadow", 0
    szUtcTsAscii2Hour   db "ts_ascii2_hour", 0
    szUtcTsAscii2Minute db "ts_ascii2_minute", 0
    szUtcLogTsRspPre    db "log_timestamp_rsp_pre", 0
    szUtcLogTsArgs      db "log_timestamp_args", 0
    szUtcLogTsPost      db "log_timestamp_post", 0
    szUtcTsGetSysTime   db "ts_get_system_time", 0
    szUtcTsTimeFields   db "ts_time_to_fields", 0
    szUtcTsAscii2Year   db "ts_ascii2_year", 0
    szUtcTsAscii2Month  db "ts_ascii2_month", 0
    szUtcTsAscii2Day    db "ts_ascii2_day", 0
    szUtcTsAscii2Sec    db "ts_ascii2_sec", 0
    szUtcTsAscii2Msec   db "ts_ascii2_msec", 0
    szUtcLogCopyTsStr   db "log_copy_ts_string", 0
    szUtcLogCopyPayload db "log_copy_payload_loop", 0
    szUtcLogAppendNl    db "log_append_newline", 0
    szUtcLogCommitSlot  db "log_commit_slot", 0
    szUtcLogTsAlignTrap db "log_timestamp_align_trap", 0
    szUtcLogTsRspSnap   db "log_timestamp_rsp_snap", 0
    szUtcLogTsShadowChk db "log_timestamp_shadow_chk", 0
    g_debug_rsp_pre_ts  dq 0
    g_debug_rsp_shadow_chk dq 0
ENDIF

; =============================================================================
;                              Code Segment
; =============================================================================

.code

; =============================================================================
; UTC_InitTelemetry — Opens the log file and marks subsystem as ready
; RCX = Pointer to log file path (null-terminated), or NULL for default
; Returns: RAX = 0 on success, GetLastError on failure
; =============================================================================
UTC_InitTelemetry PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    sub  rsp, 48
    .allocstack 48
    .endprolog

    mov  rdi, rcx               ; preserve logFilePath arg (witnesses clobber RCX)

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    mov  r11, [rsp+64]
    mov  r10, rsp
    P1PRA_UtcWitnessEntry UTC_InitTelemetry, r10, r11
ENDIF

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcPathResolve, P1PRA_UtcEnterPathResolve
ENDIF
    test rdi, rdi
    jnz  @use_custom_path
    lea  rcx, szLogPath
    jmp  @path_ready
@use_custom_path:
    mov  rcx, rdi
@path_ready:
    mov  rbx, rcx               ; preserve path (witness exit clobbers RCX)
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcPathResolve
ENDIF
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    sub  rsp, 88
    mov  rcx, rbx
    mov  edx, GENERIC_WRITE
    mov  r8d, FILE_SHARE_READ
    xor  r9, r9
    mov  dword ptr [rsp+32], CREATE_ALWAYS
    mov  dword ptr [rsp+40], 80h
    mov  qword ptr [rsp+48], 0
    lea  rax, [rsp+88]
    mov  qword ptr [rsp+56], rax
    call P1PRA_UtcCfSnapAll
    add  rsp, 88
    mov  r11, rsp
    sub  rsp, 8
    mov  rcx, r11
    mov  edx, P1PRA_UtcCfShadowSub56
    call P1PRA_UtcRspSnapLight
    add  rsp, 8
ENDIF
    sub  rsp, 48h
    mov  dword ptr [rsp+32], CREATE_ALWAYS
    mov  dword ptr [rsp+40], 80h
    mov  qword ptr [rsp+48], 0
    mov  rcx, rbx
    mov  edx, GENERIC_WRITE
    mov  r8d, FILE_SHARE_READ
    xor  r9, r9
    call CreateFileA
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    mov  rcx, rax
    call P1PRA_UtcHandleSnap
ENDIF
    add  rsp, 48h
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcCfPostcall, P1PRA_UtcCfPostcall
    P1PRA_UtcWitnessExit szUtcCfPostcall
    P1PRA_UtcWitnessEnter szUtcCfHandleCompare, P1PRA_UtcCfHandleCompare
ENDIF

    cmp  rax, INVALID_HANDLE_VALUE
    je   @init_failed

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcCfHandleCompare
    P1PRA_UtcWitnessEnter szUtcCfHandleSuccess, P1PRA_UtcCfHandleSuccess
    P1PRA_UtcWitnessExit szUtcCfHandleSuccess
    P1PRA_UtcWitnessEnter szUtcStatePubStore, P1PRA_UtcStatePubStoreHandle
ENDIF
    mov  g_hLogFile, rax
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcStatePubStore
    P1PRA_UtcWitnessEnter szUtcStatePubInit, P1PRA_UtcStatePubSetInit
ENDIF
    mov  qword ptr g_bInitialized, 1
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcStatePubInit
    P1PRA_UtcWitnessEnter szUtcCounterMetrics, P1PRA_UtcCounterResetMetrics
ENDIF
    xor  eax, eax
    mov  g_Counter_Inference, rax
    mov  g_Counter_ScsiFails, rax
    mov  g_Counter_AgentLoop, rax
    mov  g_Counter_BytePatches, rax
    mov  g_Counter_MemPatches, rax
    mov  g_Counter_ServerPatches, rax
    mov  g_Counter_FlushOps, rax
    mov  g_Counter_Errors, rax
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcCounterMetrics
    P1PRA_UtcWitnessEnterFlat szUtcCounterRing, P1PRA_UtcCounterResetRingIdx
ENDIF
    xor  rax, rax
    mov  g_HeadIdx, rax
    mov  g_TailIdx, rax
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcCounterRing
    P1PRA_UtcWitnessEnterFlat szUtcInitBannerLea, P1PRA_UtcInitBannerLeaMsg
ENDIF
    lea  rcx, szTK_InitOk
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcInitBannerLea
    P1PRA_UtcWitnessEnterFlat szUtcInitBannerLog, P1PRA_UtcInitBannerLogEvent
ENDIF
    call UTC_LogEvent
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcInitBannerLog
    P1PRA_UtcWitnessEnterFlat szUtcReturnSuccessZero, P1PRA_UtcReturnSuccessZero
ENDIF
    xor  eax, eax
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcReturnSuccessZero
ENDIF
    jmp  @init_done

@init_failed:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcCfHandleCompare
    P1PRA_UtcWitnessEnter szUtcReturnErrorEnter, P1PRA_UtcReturnErrorEnter
ENDIF
    call GetLastError
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    mov  ecx, eax
    sub  rsp, 20h
    call P1PRA_UtcLastErrorSnap
    add  rsp, 20h
    P1PRA_UtcWitnessExit szUtcReturnErrorEnter
ENDIF

@init_done:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcKernelReturn, P1PRA_UtcKernelReturn
    mov  r11, [rsp+64]
    mov  r10, rsp
    P1PRA_UtcWitnessReturn r10, r11
    P1PRA_UtcWitnessExit szUtcKernelReturn
ENDIF
    add  rsp, 48
    pop  rdi
    pop  rbx
    ret
UTC_InitTelemetry ENDP

; =============================================================================
; UTC_ShutdownTelemetry — Flush remaining events, close handle
; Returns: RAX = 0 on success
; =============================================================================
UTC_ShutdownTelemetry PROC FRAME
    push rbx
    .pushreg rbx
    sub  rsp, 40
    .allocstack 40
    .endprolog

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcExportShutdown, P1PRA_UtcExportShutdown
    P1PRA_UtcWitnessEnter szUtcShutdownFlush, P1PRA_UtcShutdownFlushCall
ENDIF

    call UTC_FlushToDisk

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcShutdownFlush
    P1PRA_UtcWitnessEnter szUtcShutdownHLoad, P1PRA_UtcShutdownHandleLoad
ENDIF

    mov  rcx, g_hLogFile

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcShutdownHLoad
    P1PRA_UtcWitnessEnter szUtcShutdownHGate, P1PRA_UtcShutdownHandleGate
ENDIF

    cmp  rcx, INVALID_HANDLE_VALUE
    je   @skip_close

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcShutdownHGate
    P1PRA_UtcWitnessEnter szUtcShutdownClose, P1PRA_UtcShutdownCloseCall
ENDIF

    sub  rsp, 32
    call CloseHandle
    add  rsp, 32

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcShutdownClose
ENDIF
    jmp  @shutdown_clear

@skip_close:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcShutdownHGate
ENDIF

@shutdown_clear:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcShutdownClear, P1PRA_UtcShutdownStateClear
ENDIF
    mov  qword ptr g_hLogFile, INVALID_HANDLE_VALUE
    mov  qword ptr g_bInitialized, 0
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcShutdownClear
ENDIF

    xor  eax, eax
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcExportShutdown
ENDIF
    add  rsp, 40
    pop  rbx
    ret
UTC_ShutdownTelemetry ENDP

; =============================================================================
; UTC_IncrementCounter — Thread-safe atomic increment
; RCX = Pointer to the counter (e.g., offset g_Counter_Inference)
; Returns: RAX = new value after increment
; =============================================================================
UTC_IncrementCounter PROC
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    push rcx
    push rdx
    P1PRA_UtcWitnessEnter szUtcExportInc, P1PRA_UtcExportInc
ENDIF
    mov  rax, 1
    lock xadd qword ptr [rcx], rax  ; RAX = old value
    inc  rax                         ; RAX = new value
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcExportInc
    pop  rdx
    pop  rcx
ENDIF
    ret
UTC_IncrementCounter ENDP

; =============================================================================
; UTC_DecrementCounter — Thread-safe atomic decrement
; RCX = Pointer to the counter
; Returns: RAX = new value after decrement
; =============================================================================
UTC_DecrementCounter PROC
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    push rcx
    push rdx
    P1PRA_UtcWitnessEnter szUtcExportDec, P1PRA_UtcExportDec
ENDIF
    mov  rax, -1
    lock xadd qword ptr [rcx], rax  ; RAX = old value
    dec  rax                         ; RAX = new value
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcExportDec
    pop  rdx
    pop  rcx
ENDIF
    ret
UTC_DecrementCounter ENDP

; =============================================================================
; UTC_ReadCounter — Acquire-fence read of a 64-bit counter
; RCX = Pointer to the counter
; Returns: RAX = current value
; =============================================================================
UTC_ReadCounter PROC
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    push rcx
    push rdx
    P1PRA_UtcWitnessEnter szUtcExportRead, P1PRA_UtcExportRead
ENDIF
    mov  rax, qword ptr [rcx]
    lfence
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcExportRead
    pop  rdx
    pop  rcx
ENDIF
    ret
UTC_ReadCounter ENDP

; =============================================================================
; UTC_ResetCounter — Atomically zero a counter and return old value
; RCX = Pointer to the counter
; Returns: RAX = previous value
; =============================================================================
UTC_ResetCounter PROC
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    push rcx
    push rdx
    P1PRA_UtcWitnessEnter szUtcExportReset, P1PRA_UtcExportReset
ENDIF
    xor  eax, eax
    lock xchg qword ptr [rcx], rax
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcExportReset
    pop  rdx
    pop  rcx
ENDIF
    ret
UTC_ResetCounter ENDP

; =============================================================================
; UTC_LogEvent — Wait-free write to the ring buffer
; RCX = Pointer to null-terminated message string
; Returns: RAX = slot index used
; =============================================================================
; Strategy:
;   1. Atomically reserve a slot via lock xadd on g_HeadIdx
;   2. Compute buffer address: (slot & MASK) << SHIFT + base
;   3. Write [HH:MM:SS] timestamp prefix
;   4. Copy message bytes (up to EVENT_STRUCT_SIZE - timestamp overhead)
;   5. Return (no blocking, no mutex)
; =============================================================================
UTC_LogEvent PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub  rsp, 100h
    .allocstack 100h
    .endprolog

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcExportLogEvent, P1PRA_UtcExportLogEvent
ENDIF

    mov  rbx, rcx               ; Save message pointer

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcLogSlotReserve, P1PRA_UtcLogSlotReserve
ENDIF
    ; 1. Reserve slot in ring buffer via atomic exchange-add on Head
    mov  rax, 1
    lock xadd qword ptr [g_HeadIdx], rax
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcLogSlotReserve
    P1PRA_UtcWitnessExitFlat szUtcExportLogEvent
    mov  rcx, rsp
    test rcx, 0Fh
    jz   @log_ts_rsp_aligned
    call P1PRA_UtcAlignmentFault
@log_ts_rsp_aligned:
    P1PRA_UtcWitnessEnterFlat szUtcLogTimestamp, P1PRA_UtcLogTimestamp
    mov  rcx, rsp
    mov  qword ptr [g_debug_rsp_pre_ts], rcx
    mov  edx, P1PRA_UtcLogTsRspSnapLight
    call P1PRA_UtcRspSnapLight
ENDIF
    ; RAX = old Head (our reserved slot index)

    mov  qword ptr [rsp+0E0h], rax ; slot index (frame store, no push misalign)

    ; 2. Calculate destination address: g_EventBuffer + ((slot & MASK) << SHIFT)
    and  rax, EVENT_BUFFER_MASK
    shl  rax, EVENT_STRUCT_SHIFT
    lea  rdi, [g_EventBuffer + rax]

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcLogSlotAddr, P1PRA_UtcLogSlotAddrCalc87
    P1PRA_UtcWitnessExitFlat szUtcLogSlotAddr
    P1PRA_UtcWitnessEnterFlat szUtcLogTsArgs, P1PRA_UtcLogTsArgs
    P1PRA_UtcWitnessExitFlat szUtcLogTsArgs
    mov  rcx, rsp
    mov  rdx, rdi
    mov  qword ptr [g_debug_rsp_shadow_chk], rcx
    call P1PRA_UtcShadowSnapLight
ENDIF

    mov  rcx, rdi
    call UTC_Internal_GetTimestamp
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcLogTsPost, P1PRA_UtcLogTsPost
    P1PRA_UtcWitnessExitFlat szUtcLogTsPost
    P1PRA_UtcWitnessEnterFlat szUtcLogCopyTsStr, P1PRA_UtcLogCopyTsString
    P1PRA_UtcWitnessExitFlat szUtcLogCopyTsStr
    P1PRA_UtcWitnessExitFlat szUtcLogTimestamp
    P1PRA_UtcWitnessEnterFlat szUtcLogMessageCopy, P1PRA_UtcLogMessageCopy
ENDIF
    ; RAX = updated pointer past timestamp
    mov  rdi, rax

    ; 4. Copy message string (bounded by remaining space)
    mov  rsi, rbx               ; Source = message
    lea  rdx, [g_EventBuffer]
    ; Calculate end-of-slot boundary
    mov  rax, qword ptr [rsp+0E0h]
    and  rax, EVENT_BUFFER_MASK
    shl  rax, EVENT_STRUCT_SHIFT
    lea  rdx, [g_EventBuffer + rax]
    add  rdx, EVENT_STRUCT_SIZE
    sub  rdx, 2                 ; Leave room for CRLF terminator

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcLogCopyBounds, P1PRA_UtcLogCopyBounds
    P1PRA_UtcWitnessExitFlat szUtcLogCopyBounds
    P1PRA_UtcWitnessEnterFlat szUtcLogCopyPayload, P1PRA_UtcLogCopyPayloadLoop
ENDIF

@copy_loop:
    cmp  rdi, rdx               ; Bounds check
    jae  @copy_done
    lodsb
    test al, al
    jz   @copy_done
    stosb
    jmp  @copy_loop

@copy_done:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcLogCopyPayload
    P1PRA_UtcWitnessEnterFlat szUtcLogCopyDone, P1PRA_UtcLogCopyLoopDone
    P1PRA_UtcWitnessExitFlat szUtcLogCopyDone
    P1PRA_UtcWitnessExitFlat szUtcLogMessageCopy
    P1PRA_UtcWitnessEnterFlat szUtcLogAppendNl, P1PRA_UtcLogAppendNewline
ENDIF
    ; Append newline
    mov  byte ptr [rdi], 13     ; CR
    inc  rdi
    mov  byte ptr [rdi], 10     ; LF
    inc  rdi
    mov  byte ptr [rdi], 0      ; Null terminator
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcLogAppendNl
    P1PRA_UtcWitnessEnterFlat szUtcLogCommitSlot, P1PRA_UtcLogCommitSlot
    P1PRA_UtcWitnessExitFlat szUtcLogCommitSlot
ENDIF

    mov  rax, qword ptr [rsp+0E0h] ; Return slot index
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcExportLogEvent
ENDIF
    add  rsp, 100h
    pop  rdi
    pop  rsi
    pop  rbx
    ret
UTC_LogEvent ENDP

; =============================================================================
; UTC_FlushToDisk — Drains the ring buffer to the log file
; Single-consumer model: only one thread should call this.
; Returns: RAX = number of events flushed
; =============================================================================
UTC_FlushToDisk PROC FRAME
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    sub  rsp, 80
    .allocstack 80
    .endprolog

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcExportFlush, P1PRA_UtcExportFlush
ENDIF

    xor  r12d, r12d             ; r12 = events flushed count

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcFlushInitGate, P1PRA_UtcFlushInitGate
ENDIF
    cmp  qword ptr g_bInitialized, 0
    je   @flush_init_fail

    mov  rax, g_hLogFile
    cmp  rax, INVALID_HANDLE_VALUE
    je   @flush_init_fail
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushInitGate
ENDIF
    jmp  @flush_loop

@flush_init_fail:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushInitGate
ENDIF
    jmp  @flush_exit

@flush_loop:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcFlushLoopCmp, P1PRA_UtcFlushLoopCompare
ENDIF
    mov  rsi, g_TailIdx
    mov  rdi, g_HeadIdx
    cmp  rsi, rdi
    jge  @flush_done
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushLoopCmp
ENDIF

    mov  rax, rsi
    and  rax, EVENT_BUFFER_MASK
    shl  rax, EVENT_STRUCT_SHIFT
    lea  rbx, [g_EventBuffer + rax]

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcFlushStrlen, P1PRA_UtcFlushStrlenSlot
ENDIF
    mov  rcx, rbx
    xor  edx, edx
@strlen_loop:
    cmp  edx, EVENT_STRUCT_SIZE
    jge  @strlen_done
    cmp  byte ptr [rcx + rdx], 0
    je   @strlen_done
    inc  edx
    jmp  @strlen_loop
@strlen_done:

    test edx, edx
    jz   @strlen_empty

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushStrlen
    P1PRA_UtcWitnessEnter szUtcFlushWriteShadow, P1PRA_UtcFlushWriteShadow
ENDIF
    mov  r13d, edx
    sub  rsp, 32
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushWriteShadow
    P1PRA_UtcWitnessEnter szUtcFlushWrite, P1PRA_UtcFlushWriteFile
ENDIF
    mov  rcx, g_hLogFile        ; hFile
    mov  rdx, rbx               ; lpBuffer
    mov  r8d, r13d              ; nNumberOfBytesToWrite
    lea  r9, [rsp+64]           ; lpNumberOfBytesWritten (on stack)
    mov  qword ptr [rsp+32], 0  ; lpOverlapped = NULL
    call WriteFile
    add  rsp, 32
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushWrite
ENDIF
    jmp  @advance_tail

@strlen_empty:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushStrlen
ENDIF

@advance_tail:
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcFlushAdvance, P1PRA_UtcFlushAdvanceTail
ENDIF
    inc  qword ptr g_TailIdx
    inc  r12
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushAdvance
ENDIF
    jmp  @flush_loop

@flush_done:
    test r12d, r12d
    jz   @flush_exit

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnter szUtcFlushOsBuf, P1PRA_UtcFlushOsBuffers
ENDIF
    sub  rsp, 32
    mov  rcx, g_hLogFile
    call FlushFileBuffers
    add  rsp, 32
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushOsBuf
    P1PRA_UtcWitnessEnter szUtcFlushCntInc, P1PRA_UtcFlushCounterInc
ENDIF
    lea  rcx, g_Counter_FlushOps
    lock inc qword ptr [rcx]
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcFlushCntInc
ENDIF

@flush_exit:
    mov  rax, r12               ; Return events flushed
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcExportFlush
ENDIF

    add  rsp, 80
    pop  r13
    pop  r12
    pop  rdi
    pop  rsi
    pop  rbx
    ret
UTC_FlushToDisk ENDP

; =============================================================================
; UTC_GetMetricTableBase — Returns pointer to the metric table start
; Returns: RAX = address of g_MetricTableStart
; =============================================================================
UTC_GetMetricTableBase PROC
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    push rcx
    push rdx
    P1PRA_UtcWitnessEnter szUtcExportGetMetric, P1PRA_UtcExportGetMetricBase
ENDIF
    lea  rax, g_MetricTableStart
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcExportGetMetric
    pop  rdx
    pop  rcx
ENDIF
    ret
UTC_GetMetricTableBase ENDP

; =============================================================================
; UTC_GetEventBufferStats — Returns head and tail indices
; Returns: RAX = Head index, RDX = Tail index
; =============================================================================
UTC_GetEventBufferStats PROC
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    push rcx
    push rdx
    P1PRA_UtcWitnessEnter szUtcExportGetStats, P1PRA_UtcExportGetBufferStats
ENDIF
    mov  rax, g_HeadIdx
    mov  rdx, g_TailIdx
    lfence
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExit szUtcExportGetStats
    pop  rdx
    pop  rcx
ENDIF
    ret
UTC_GetEventBufferStats ENDP

; =============================================================================
; UTC_Internal_GetTimestamp — High-resolution timestamp formatter
; RCX = Destination buffer pointer
; Returns: RAX = updated pointer past the timestamp
;
; Writes "[HH:MM:SS.mmm] " format using GetSystemTimePreciseAsFileTime
; (Win8+ API, sub-microsecond precision)
; =============================================================================
UTC_Internal_GetTimestamp PROC FRAME
    push rbx
    .pushreg rbx
    push rdi
    .pushreg rdi
    sub  rsp, 80
    .allocstack 80
    .endprolog

    mov  rdi, rcx               ; Save destination buffer pointer

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcTsGetSysTime, P1PRA_UtcTsGetSystemTime
ENDIF
    lea  rcx, [rsp+48]         ; lpFileTime (8 bytes at rsp+48)
    sub  rsp, 32
    call GetSystemTimePreciseAsFileTime
    add  rsp, 32
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsGetSysTime
    P1PRA_UtcWitnessEnterFlat szUtcTsTimeFields, P1PRA_UtcTsTimeToFields
ENDIF

    lea  rcx, [rsp+48]         ; lpFileTime
    lea  rdx, [rsp+56]         ; lpSystemTime (16 bytes at rsp+56)
    sub  rsp, 32
    call FileTimeToSystemTime
    add  rsp, 32
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsTimeFields
    P1PRA_UtcWitnessEnterFlat szUtcTsFormat, P1PRA_UtcTsFormat
    P1PRA_UtcWitnessEnterFlat szUtcTsAscii2Year, P1PRA_UtcTsAscii2Year
ENDIF
    movzx eax, word ptr [rsp+56+0]
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsAscii2Year
    P1PRA_UtcWitnessEnterFlat szUtcTsAscii2Month, P1PRA_UtcTsAscii2Month
ENDIF
    movzx eax, word ptr [rsp+56+2]
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsAscii2Month
    P1PRA_UtcWitnessEnterFlat szUtcTsAscii2Day, P1PRA_UtcTsAscii2Day
ENDIF
    movzx eax, word ptr [rsp+56+6]
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsAscii2Day
ENDIF

    ; Format: [HH:MM:SS.mmm]
    mov  byte ptr [rdi], '['
    inc  rdi

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcTsAscii2Hour, P1PRA_UtcTsAscii2Hour
ENDIF
    movzx eax, word ptr [rsp+56+8]
    call UTC_Internal_U16ToAscii2
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsAscii2Hour
ENDIF
    mov  byte ptr [rdi], ':'
    inc  rdi

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcTsAscii2Minute, P1PRA_UtcTsAscii2Minute
ENDIF
    movzx eax, word ptr [rsp+56+10]
    call UTC_Internal_U16ToAscii2
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsAscii2Minute
ENDIF
    mov  byte ptr [rdi], ':'
    inc  rdi

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcTsAscii2Sec, P1PRA_UtcTsAscii2Sec
ENDIF
    movzx eax, word ptr [rsp+56+12]
    call UTC_Internal_U16ToAscii2
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsAscii2Sec
ENDIF
    mov  byte ptr [rdi], '.'
    inc  rdi

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessEnterFlat szUtcTsAscii2Msec, P1PRA_UtcTsAscii2Msec
ENDIF
    movzx eax, word ptr [rsp+56+14]
    call UTC_Internal_U16ToAscii3
IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsAscii2Msec
ENDIF

    mov  byte ptr [rdi], ']'
    inc  rdi
    mov  byte ptr [rdi], ' '
    inc  rdi

    mov  rax, rdi               ; Return updated pointer

IFDEF RAWRXD_P1_PRODUCT_RUNTIME_AUTHORITY
    P1PRA_UtcWitnessExitFlat szUtcTsFormat
ENDIF

    add  rsp, 80
    pop  rdi
    pop  rbx
    ret
UTC_Internal_GetTimestamp ENDP

; =============================================================================
; UTC_Internal_U16ToAscii2 — Convert 0-99 value to 2 zero-padded ASCII digits
; EAX = value (0-99), RDI = destination (advances RDI by 2)
; =============================================================================
UTC_Internal_U16ToAscii2 PROC
    ; Tens digit
    xor  edx, edx
    mov  ecx, 10
    div  ecx                    ; EAX = tens, EDX = ones
    add  al, '0'
    mov  byte ptr [rdi], al
    inc  rdi

    ; Ones digit
    add  dl, '0'
    mov  byte ptr [rdi], dl
    inc  rdi
    ret
UTC_Internal_U16ToAscii2 ENDP

; =============================================================================
; UTC_Internal_U16ToAscii3 — Convert 0-999 value to 3 zero-padded ASCII digits
; EAX = value (0-999), RDI = destination (advances RDI by 3)
; =============================================================================
UTC_Internal_U16ToAscii3 PROC
    ; Hundreds digit
    xor  edx, edx
    mov  ecx, 100
    div  ecx                    ; EAX = hundreds, EDX = remainder
    add  al, '0'
    mov  byte ptr [rdi], al
    inc  rdi

    ; Tens digit
    mov  eax, edx
    xor  edx, edx
    mov  ecx, 10
    div  ecx                    ; EAX = tens, EDX = ones
    add  al, '0'
    mov  byte ptr [rdi], al
    inc  rdi

    ; Ones digit
    add  dl, '0'
    mov  byte ptr [rdi], dl
    inc  rdi
    ret
UTC_Internal_U16ToAscii3 ENDP

END
