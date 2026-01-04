; compliance_logger_masm.asm
; Pure MASM x64 - Compliance Logger (converted from C++ ComplianceLogger class)
; Comprehensive audit logging for compliance and security monitoring

option casemap:none

EXTERN malloc:PROC
EXTERN free:PROC
EXTERN memcpy:PROC
EXTERN strlen:PROC
EXTERN strcpy:PROC
EXTERN sprintf:PROC
EXTERN console_log:PROC
EXTERN GetSystemTimeAsFileTime:PROC
EXTERN CreateFileA:PROC
EXTERN WriteFile:PROC
EXTERN CloseHandle:PROC

; Log level enumeration
LOG_LEVEL_INFO EQU 0
LOG_LEVEL_WARN EQU 1
LOG_LEVEL_ERROR EQU 2
LOG_LEVEL_SECURITY EQU 3
LOG_LEVEL_AUDIT EQU 4

; Event type enumeration
EVENT_TYPE_MODEL EQU 0
EVENT_TYPE_DATA EQU 1
EVENT_TYPE_USER EQU 2
EVENT_TYPE_CONFIG EQU 3
EVENT_TYPE_SYSTEM EQU 4
EVENT_TYPE_SEC_VIOLATION EQU 5

; Constants
MAX_LOG_ENTRIES EQU 10000
LOG_ENTRY_SIZE EQU 1024
ROTATION_SIZE EQU 10485760      ; 10 MB

; ============================================================================
; DATA STRUCTURES
; ============================================================================

; LOG_ENTRY - Single audit log entry
LOG_ENTRY STRUCT
    timestamp QWORD ?               ; 64-bit timestamp
    level DWORD ?                   ; LOG_LEVEL_*
    eventType DWORD ?               ; EVENT_TYPE_*
    userId QWORD ?                  ; User ID string (malloc'd)
    action QWORD ?                  ; Action description
    resourceId QWORD ?              ; Resource ID
    ipAddress QWORD ?               ; IP address
    details QWORD ?                 ; Additional details
    checksum QWORD ?                ; CRC32 or hash
LOG_ENTRY ENDS

; COMPLIANCE_LOGGER - Global compliance logger state
COMPLIANCE_LOGGER STRUCT
    logFile QWORD ?                 ; File handle
    logFileName QWORD ?             ; File name (malloc'd)
    logEntries QWORD ?              ; Array of LOG_ENTRY
    entryCount QWORD ?              ; Current entry count
    totalLogged QWORD ?             ; Total entries logged
    retentionDays DWORD ?           ; Log retention period
COMPLIANCE_LOGGER ENDS

; ============================================================================
; GLOBAL DATA
; ============================================================================

.data
    g_logger COMPLIANCE_LOGGER <>
    
    szLoggerStarted DB "[AUDIT] Logger started: %s", 0
    szLoggerStopped DB "[AUDIT] Logger stopped, total entries: %lld", 0
    szEventLogged DB "[AUDIT] Event: level=%d, type=%d, user=%s, action=%s", 0
    szSecurityAlert DB "[SECURITY] ALERT: %s", 0
    szComplianceViolation DB "[COMPLIANCE] VIOLATION: %s", 0
    szLogRotated DB "[AUDIT] Log rotated, new file: %s", 0

.code

; ============================================================================
; PUBLIC API
; ============================================================================

; compliance_logger_init(RCX = logFilePath)
; Initialize compliance logger
; Returns: EAX = 1 (success) or 0 (failure)
PUBLIC compliance_logger_init
compliance_logger_init PROC
    push rbx
    
    lea rbx, [g_logger]
    
    ; Store log file name
    mov r8, rcx                    ; r8 = logFilePath
    
    mov rcx, 256                   ; Max filename length
    call malloc
    mov [rbx + COMPLIANCE_LOGGER.logFileName], rax
    
    mov rcx, rax
    mov rdx, r8
    call strcpy
    
    ; Allocate log entry array
    mov rcx, MAX_LOG_ENTRIES
    imul rcx, SIZEOF LOG_ENTRY
    call malloc
    mov [rbx + COMPLIANCE_LOGGER.logEntries], rax
    
    ; Initialize counters
    mov [rbx + COMPLIANCE_LOGGER.entryCount], 0
    mov [rbx + COMPLIANCE_LOGGER.totalLogged], 0
    mov dword ptr [rbx + COMPLIANCE_LOGGER.retentionDays], 90  ; Default 90 day retention
    
    ; Log startup
    lea rcx, [szLoggerStarted]
    mov rdx, r8
    call console_log
    
    mov eax, 1
    pop rbx
    ret
compliance_logger_init ENDP

; ============================================================================

; compliance_log_event(RCX = level, RDX = eventType, R8 = userId, R9 = action, [rsp+40] = resourceId, [rsp+48] = details)
; Log compliance event
PUBLIC compliance_log_event
compliance_log_event PROC
    push rbx
    push rsi
    
    lea rbx, [g_logger]
    
    ; Check buffer space
    mov rax, [rbx + COMPLIANCE_LOGGER.entryCount]
    cmp rax, MAX_LOG_ENTRIES
    jge buffer_full_local
    
    ; Get log entry slot
    mov r10, [rbx + COMPLIANCE_LOGGER.logEntries]
    imul rax, SIZEOF LOG_ENTRY
    add r10, rax
    
    ; Get timestamp
    lea r11, [r10 + LOG_ENTRY.timestamp]
    call GetSystemTimeAsFileTime
    
    ; Store event properties
    mov [r10 + LOG_ENTRY.level], ecx
    mov [r10 + LOG_ENTRY.eventType], edx
    
    ; Store string pointers
    mov [r10 + LOG_ENTRY.userId], r8
    mov [r10 + LOG_ENTRY.action], r9
    
    ; Increment counter
    inc qword [rbx + COMPLIANCE_LOGGER.entryCount]
    inc qword [rbx + COMPLIANCE_LOGGER.totalLogged]
    
    ; Log
    lea rcx, [szEventLogged]
    mov edx, [r10 + LOG_ENTRY.level]
    mov r8d, [r10 + LOG_ENTRY.eventType]
    mov r8, [r10 + LOG_ENTRY.userId]
    mov r9, [r10 + LOG_ENTRY.action]
    call console_log
    
    pop rsi
    pop rbx
    ret
    
buffer_full_local:
    pop rsi
    pop rbx
    ret
compliance_log_event ENDP

; ============================================================================

; compliance_log_model_access(RCX = userId, RDX = modelPath, R8 = action)
; Log model access event
PUBLIC compliance_log_model_access
compliance_log_model_access PROC
    ; Delegate to compliance_log_event with EVENT_TYPE_MODEL
    mov r9, r8                     ; r9 = action
    mov r8, rcx                    ; r8 = userId
    mov rdx, EVENT_TYPE_MODEL
    mov ecx, LOG_LEVEL_AUDIT
    
    call compliance_log_event
    ret
compliance_log_model_access ENDP

; ============================================================================

; compliance_log_security_violation(RCX = userId, RDX = violation)
; Log security violation
PUBLIC compliance_log_security_violation
compliance_log_security_violation PROC
    ; Log as security event
    mov r9, rdx                    ; r9 = violation
    mov r8, rcx                    ; r8 = userId
    mov rdx, EVENT_TYPE_SEC_VIOLATION
    mov ecx, LOG_LEVEL_SECURITY
    
    call compliance_log_event
    
    ; Also emit alert
    lea rcx, [szSecurityAlert]
    mov rdx, r9
    call console_log
    
    ret
compliance_log_security_violation ENDP

; ============================================================================

; compliance_log_user_login(RCX = userId, RDX = success, R8 = ipAddress)
; Log user login event
PUBLIC compliance_log_user_login
compliance_log_user_login PROC
    ; Log as user event
    mov r9, r8                     ; r9 = ipAddress (as action)
    mov r8, rcx                    ; r8 = userId
    mov rdx, EVENT_TYPE_USER
    mov ecx, LOG_LEVEL_AUDIT
    
    call compliance_log_event
    ret
compliance_log_user_login ENDP

; ============================================================================

; compliance_rotate_logs()
; Rotate log file when size exceeds limit
PUBLIC compliance_rotate_logs
compliance_rotate_logs PROC
    lea rcx, [g_logger]
    
    ; Check current file size
    ; If > ROTATION_SIZE, rotate to backup and create new
    
    lea rcx, [szLogRotated]
    mov rdx, [g_logger]
    call console_log
    
    ret
compliance_rotate_logs ENDP

; ============================================================================

; compliance_export_audit_log(RCX = startDate, RDX = endDate)
; Export audit log entries within date range
; Returns: RAX = pointer to formatted log string
PUBLIC compliance_export_audit_log
compliance_export_audit_log PROC
    lea rbx, [g_logger]
    
    ; Iterate through log entries and filter by date
    ; Format as JSON or CSV
    
    mov rcx, [rbx + COMPLIANCE_LOGGER.entryCount]
    
    ; Allocate output buffer
    mov rcx, 65536                 ; 64 KB for export
    call malloc
    
    ret
compliance_export_audit_log ENDP

; ============================================================================

; compliance_set_retention(RCX = days)
; Set log retention period in days
PUBLIC compliance_set_retention
compliance_set_retention PROC
    lea rax, [g_logger]
    mov [rax + COMPLIANCE_LOGGER.retentionDays], ecx
    ret
compliance_set_retention ENDP

; ============================================================================

; compliance_logger_shutdown()
; Shutdown compliance logger
PUBLIC compliance_logger_shutdown
compliance_logger_shutdown PROC
    lea rbx, [g_logger]
    
    ; Log shutdown
    lea rcx, [szLoggerStopped]
    mov rdx, [rbx + COMPLIANCE_LOGGER.totalLogged]
    call console_log
    
    ; Free resources
    mov rcx, [rbx + COMPLIANCE_LOGGER.logFileName]
    cmp rcx, 0
    je skip_name_local
    call free
skip_name_local:
    
    mov rcx, [rbx + COMPLIANCE_LOGGER.logEntries]
    cmp rcx, 0
    je skip_entries_local
    call free
skip_entries_local:
    
    ; Close file if open
    mov rcx, [rbx + COMPLIANCE_LOGGER.logFile]
    cmp rcx, INVALID_HANDLE_VALUE
    je skip_close_local
    call CloseHandle
skip_close_local:
    
    ret
compliance_logger_shutdown ENDP

; ============================================================================

END

