;==============================================================================
; masm_agent_main.asm
; MASM Replacement for agent_main.cpp
; CLI Entry Point for Zero C++ Core Agentic IDE
;
; Replaces all Qt/C++ functionality with pure MASM x64
; No QCoreApplication, no C++ runtime, no Qt framework required
;==============================================================================

option casemap:none

include windows.inc
includelib kernel32.lib
includelib user32.lib
includelib advapi32.lib
includelib ws2_32.lib

; Import from unified bridge
EXTERN zero_cpp_bridge_initialize:PROC
EXTERN zero_cpp_bridge_process_wish:PROC
EXTERN zero_cpp_bridge_shutdown:PROC
EXTERN zero_cpp_bridge_get_status:PROC

; String Constants
.data

    ; Application Info
    szAppName           DB "RawrXD-Agent", 0
    szAppVersion        DB "1.0.0", 0
    szCmdLineUsage      DB "Usage: RawrXD-Agent [--wish ""<wish>""] [--timeout <ms>] [--priority <level>]", 0
    szCmdLineTip        DB "  Example: RawrXD-Agent --wish ""build and test project""", 0
    
    ; Status Messages
    szInitStatus        DB "Agent: Initializing zero C++ core...", 0
    szInitOk            DB "Agent: Initialization complete. Ready for wishes.", 0
    szInitFailed        DB "Agent: Initialization failed. Error: 0x%X", 0
    
    ; Wish Processing
    szWishPrefix        DB "Agent: Processing wish: ", 0
    szWishExecStart     DB "Agent: Execution started. This may take a while...", 0
    szWishExecComplete  DB "Agent: Wish complete in %d ms", 0
    szWishExecError     DB "Agent: Execution error: 0x%X", 0
    szWishCanceled      DB "Agent: Wish cancelled by user", 0
    
    ; Status Display
    szStatusPrefix      DB "Agent: System Status:", 0
    szStatusService     DB "  Service %d: %s (errors: %d)", 0
    szStatusUptime      DB "  Uptime: %d ms, Wishes: %d", 0
    
    ; Shutdown
    szShutdownStart     DB "Agent: Shutting down...", 0
    szShutdownOk        DB "Agent: Shutdown complete", 0
    
    ; Command Line Options
    szOptWish           DB "--wish", 0
    szOptTimeout        DB "--timeout", 0
    szOptPriority       DB "--priority", 0
    szOptStatus         DB "--status", 0
    szOptHelp           DB "--help", 0
    szOptVersion        DB "--version", 0
    
    ; Error Messages
    szErrNoWish         DB "Agent: No wish provided. Use --wish ""<your request>""", 0
    szErrInvalidOpt     DB "Agent: Invalid option: %s", 0
    szErrMemory         DB "Agent: Memory allocation failed", 0
    szErrInitFail       DB "Agent: Service initialization failed", 0

.data?
    ; Global state
    g_wish_text         QWORD ?
    g_wish_length       DWORD ?
    g_timeout_ms        DWORD 30000  ; 30 seconds default
    g_priority          DWORD 1      ; NORMAL priority
    g_show_status       DWORD 0
    g_exit_code         DWORD 0
    g_argc              DWORD ?
    g_argv_ptr          QWORD ?

;==============================================================================
; PUBLIC EXPORTS
;==============================================================================
PUBLIC main

;==============================================================================
; MAIN ENTRY POINT (Replaces C++ main)
;==============================================================================

.code

ALIGN 16
main PROC
    ; Standard C runtime: rcx = argc, rdx = argv
    
    push rbx
    push r12
    push r13
    sub rsp, 64
    
    mov g_argc, ecx
    mov g_argv_ptr, rdx
    
    ; =========================================================================
    ; PHASE 1: PARSE COMMAND LINE
    ; =========================================================================
    
    mov ecx, g_argc
    mov rdx, g_argv_ptr
    call parse_commandline
    
    ; If help was requested, just print help and exit
    test eax, eax
    jz parse_ok_local
    
    ; Error in parsing
    lea rcx, szCmdLineUsage
    call print_line
    lea rcx, szCmdLineTip
    call print_line
    mov g_exit_code, 1
    jmp cleanup_local
    
parse_ok_local:
    
    ; If --help was specified, print help and exit
    ; (parse_commandline returns 2 for help)
    cmp eax, 2
    je show_help_local
    
    ; If --status was specified, show status and exit
    cmp DWORD PTR g_show_status, 1
    jne skip_status_local
    
    call show_system_status
    jmp cleanup_local
    
skip_status_local:
    
    ; =========================================================================
    ; PHASE 2: INITIALIZE ZERO C++ CORE
    ; =========================================================================
    
    lea rcx, szInitStatus
    call print_line
    
    xor ecx, ecx        ; config_flags = 0 (default)
    xor edx, edx        ; callback_hwnd = NULL (CLI mode)
    call zero_cpp_bridge_initialize
    
    test eax, eax
    jz init_failed_local
    
    lea rcx, szInitOk
    call print_line
    
    ; =========================================================================
    ; PHASE 3: PROCESS WISH (if provided)
    ; =========================================================================
    
    ; Check if wish was provided
    cmp QWORD PTR g_wish_text, 0
    je no_wish_local
    
    ; Create wish context
    sub rsp, SIZEOF WISH_CONTEXT
    mov rbx, rsp
    
    mov rax, g_wish_text
    mov [rbx + WISH_CONTEXT.wish_text], rax
    mov eax, g_wish_length
    mov [rbx + WISH_CONTEXT.wish_length], eax
    mov DWORD PTR [rbx + WISH_CONTEXT.source], 0  ; TEXT_INPUT
    mov eax, g_priority
    mov [rbx + WISH_CONTEXT.priority], eax
    mov eax, g_timeout_ms
    mov [rbx + WISH_CONTEXT.timeout_ms], eax
    mov QWORD PTR [rbx + WISH_CONTEXT.callback_hwnd], 0  ; CLI mode
    
    ; Print execution start
    lea rcx, szWishExecStart
    call print_line
    
    ; Get start time for performance tracking
    call GetTickCount64
    mov r12, rax
    
    ; Process wish through unified bridge
    mov rcx, rbx
    call zero_cpp_bridge_process_wish
    
    test rax, rax
    jz wish_failed_local
    
    ; Calculate execution time
    call GetTickCount64
    mov r13, rax
    sub r13, r12
    
    ; Print results
    mov rcx, r13
    lea rdx, szWishExecComplete
    call format_and_print
    
    add rsp, SIZEOF WISH_CONTEXT
    jmp phase_local4
    
no_wish_local:
    lea rcx, szErrNoWish
    call print_line
    mov g_exit_code, 1
    jmp phase_local4
    
wish_failed_local:
    lea rcx, szWishExecError
    call print_line
    mov g_exit_code, 1
    jmp phase_local4
    
.phase4:
    
    ; =========================================================================
    ; PHASE 4: SHUTDOWN
    ; =========================================================================
    
    lea rcx, szShutdownStart
    call print_line
    
    call zero_cpp_bridge_shutdown
    
    lea rcx, szShutdownOk
    call print_line
    
    jmp cleanup_local
    
show_help_local:
    lea rcx, szCmdLineUsage
    call print_line
    lea rcx, szCmdLineTip
    call print_line
    xor g_exit_code, g_exit_code
    jmp cleanup_local
    
init_failed_local:
    lea rcx, szInitFailed
    call print_line
    mov g_exit_code, 1
    jmp cleanup_local
    
cleanup_local:
    mov eax, g_exit_code
    add rsp, 64
    pop r13
    pop r12
    pop rbx
    ret
ALIGN 16
main ENDP

;==============================================================================
; COMMAND LINE PARSING
;==============================================================================

ALIGN 16
parse_commandline PROC
    ; rcx = argc, rdx = argv
    ; Returns: eax = 0 (ok), 1 (error), 2 (help)
    
    push rbx
    push r12
    push r13
    sub rsp, 32
    
    mov r12d, ecx       ; argc
    mov r13, rdx        ; argv
    mov ebx, 1          ; Skip program name (argv[0])
    
parse_loop_local:
    cmp ebx, r12d
    jge parse_done_local
    
    ; Get current argument
    mov rax, r13
    add rax, rbx
    shl rbx, 3          ; *8 for pointer size
    mov rcx, [rax + rbx]
    
    ; Check for --help
    lea rdx, szOptHelp
    call compare_strings
    test eax, eax
    jz show_help_msg_local
    
    ; Check for --version
    lea rdx, szOptVersion
    call compare_strings
    test eax, eax
    jz show_version_msg_local
    
    ; Check for --status
    lea rdx, szOptStatus
    call compare_strings
    test eax, eax
    jz set_status_local
    
    ; Check for --wish
    lea rdx, szOptWish
    call compare_strings
    test eax, eax
    jz get_wish_local
    
    ; Check for --timeout
    lea rdx, szOptTimeout
    call compare_strings
    test eax, eax
    jz get_timeout_local
    
    ; Check for --priority
    lea rdx, szOptPriority
    call compare_strings
    test eax, eax
    jz get_priority_local
    
    ; Unknown option
    lea rdx, szErrInvalidOpt
    call format_and_print
    mov eax, 1
    jmp parse_exit_local
    
set_status_local:
    mov DWORD PTR g_show_status, 1
    inc ebx
    jmp parse_loop_local
    
get_wish_local:
    inc ebx
    cmp ebx, r12d
    jge missing_value_local
    
    ; Get next argument as wish
    mov rax, r13
    add rax, rbx
    shl rbx, 3
    mov rax, [rax + rbx]
    mov g_wish_text, rax
    
    ; Calculate wish length
    mov rsi, rax
    xor ecx, ecx
wish_len_loop_local:
    cmp BYTE PTR [rsi], 0
    je wish_len_done_local
    inc ecx
    inc rsi
    jmp wish_len_loop_local
wish_len_done_local:
    mov g_wish_length, ecx
    
    inc ebx
    jmp parse_loop_local
    
get_timeout_local:
    inc ebx
    cmp ebx, r12d
    jge missing_value_local
    
    ; Get next argument as timeout
    mov rax, r13
    add rax, rbx
    shl rbx, 3
    mov rax, [rax + rbx]
    
    ; Parse integer from string
    call string_to_int
    mov g_timeout_ms, eax
    
    inc ebx
    jmp parse_loop_local
    
get_priority_local:
    inc ebx
    cmp ebx, r12d
    jge missing_value_local
    
    ; Get next argument as priority
    mov rax, r13
    add rax, rbx
    shl rbx, 3
    mov rax, [rax + rbx]
    
    ; Parse priority level
    call string_to_int
    mov g_priority, eax
    
    inc ebx
    jmp parse_loop_local
    
parse_done_local:
    xor eax, eax      ; Success
    jmp parse_exit_local
    
show_help_msg_local:
    mov eax, 2        ; Help requested
    jmp parse_exit_local
    
show_version_msg_local:
    lea rcx, szAppVersion
    call print_line
    mov eax, 2
    jmp parse_exit_local
    
missing_value_local:
    lea rcx, szErrInvalidOpt
    call print_line
    mov eax, 1
    
parse_exit_local:
    add rsp, 32
    pop r13
    pop r12
    pop rbx
    ret
ALIGN 16
parse_commandline ENDP

;==============================================================================
; STRING UTILITIES
;==============================================================================

ALIGN 16
compare_strings PROC
    ; rcx = string1, rdx = string2
    ; Returns: eax = 0 if equal, non-zero if not
    
cmp_loop_local:
    mov al, BYTE PTR [rcx]
    mov bl, BYTE PTR [rdx]
    cmp al, bl
    jne cmp_fail_local
    test al, al
    jz cmp_ok_local
    inc rcx
    inc rdx
    jmp cmp_loop_local
    
cmp_ok_local:
    xor eax, eax
    ret
    
cmp_fail_local:
    mov eax, 1
    ret
ALIGN 16
compare_strings ENDP

ALIGN 16
string_to_int PROC
    ; rcx = string
    ; Returns: eax = integer value
    
    xor eax, eax
int_loop_local:
    mov bl, BYTE PTR [rcx]
    test bl, bl
    jz int_done_local
    
    cmp bl, '0'
    jl int_done_local
    cmp bl, '9'
    jg int_done_local
    
    imul eax, 10
    movzx ebx, bl
    sub ebx, '0'
    add eax, ebx
    
    inc rcx
    jmp int_loop_local
    
int_done_local:
    ret
ALIGN 16
string_to_int ENDP

;==============================================================================
; OUTPUT UTILITIES
;==============================================================================

ALIGN 16
print_line PROC
    ; rcx = string to print
    
    push rbx
    sub rsp, 32
    
    ; Get string length
    mov rsi, rcx
    xor edx, edx
len_loop_local:
    cmp BYTE PTR [rsi], 0
    je len_done_local
    inc edx
    inc rsi
    jmp len_loop_local
    
len_done_local:
    ; Write to stdout
    mov rsi, rcx          ; lpBuffer
    mov r8d, edx          ; nNumberOfBytesToWrite
    
    ; Get stdout handle
    mov ecx, -11          ; STD_OUTPUT_HANDLE
    call GetStdHandle
    mov rbx, rax
    
    ; WriteFile(stdout, string, length, &written, NULL)
    mov rcx, rbx          ; hFile
    mov rdx, rsi          ; lpBuffer
    mov r8d, r8d          ; nNumberOfBytesToWrite
    lea r9, [rsp]         ; lpNumberOfBytesWritten
    call WriteFile
    
    ; Write newline
    mov BYTE PTR [rsp], 13   ; CR
    mov BYTE PTR [rsp+1], 10 ; LF
    
    mov rcx, rbx
    mov rdx, rsp
    mov r8d, 2
    lea r9, [rsp+4]
    call WriteFile
    
    add rsp, 32
    pop rbx
    ret
ALIGN 16
print_line ENDP

ALIGN 16
format_and_print PROC
    ; rcx = format string, rdx = first parameter, r8 = second parameter
    
    ; For now, just print the format string
    call print_line
    ret
ALIGN 16
format_and_print ENDP

ALIGN 16
show_system_status PROC
    ; Display current system status
    
    call zero_cpp_bridge_get_status
    
    ; rax = status array, edx = count, ecx = overall health
    
    lea rcx, szStatusPrefix
    call print_line
    
    ; TODO: Print service statuses
    
    ret
ALIGN 16
show_system_status ENDP

END





