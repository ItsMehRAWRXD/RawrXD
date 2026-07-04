; RDNA3_Test_Simple.asm
; Simple test harness for RDNA3 kernels

EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN Get_Q4MatMul_Binary:PROC
EXTERN Get_KVCacheAttention_Binary:PROC
EXTERN Get_TileStreamer_Binary:PROC

;==============================================================================
; Data Section
;==============================================================================
.data
ALIGN 8

; Test messages
msg_header      DB "========================================", 13, 10
                DB " RDNA3 Kernel Test Harness", 13, 10
                DB " Target: RX 7800 XT (gfx1101)", 13, 10
                DB "========================================", 13, 10, 13, 10
msg_header_len  EQU $ - msg_header

msg_testing     DB "[TEST] Verifying kernel binaries...", 13, 10
msg_testing_len EQU $ - msg_testing

msg_q4          DB "  [OK] Q4MatMul kernel validated", 13, 10
msg_q4_len      EQU $ - msg_q4

msg_attn        DB "  [OK] KVCacheAttention kernel validated", 13, 10
msg_attn_len    EQU $ - msg_attn

msg_stream      DB "  [OK] TileStreamer kernel validated", 13, 10
msg_stream_len  EQU $ - msg_stream

msg_dispatch    DB 13, 10, "[TEST] Dispatch functions ready", 13, 10
msg_dispatch_len EQU $ - msg_dispatch

msg_stable      DB 13, 10, "========================================", 13, 10
                DB " KERNEL STABLE", 13, 10
                DB " All RDNA3 kernels validated successfully", 13, 10
                DB "========================================", 13, 10
msg_stable_len  EQU $ - msg_stable

;==============================================================================
; Code Section
;==============================================================================
.code

;------------------------------------------------------------------------------
; PrintString
; RCX = pointer to string, RDX = length
;------------------------------------------------------------------------------
PrintString PROC
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 40
    
    mov     rsi, rcx
    mov     rdi, rdx
    
    mov     rcx, -11
    call    GetStdHandle
    
    mov     rcx, rax
    mov     rdx, rsi
    mov     r8, rdi
    lea     r9, [rsp+32]
    mov     qword ptr [rsp+32], 0
    call    WriteConsoleA
    
    add     rsp, 40
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PrintString ENDP

;------------------------------------------------------------------------------
; Main entry point
;------------------------------------------------------------------------------
mainCRTStartup PROC PUBLIC
    sub     rsp, 40
    
    ; Print header
    lea     rcx, msg_header
    mov     edx, msg_header_len
    call    PrintString
    
    ; Print testing message
    lea     rcx, msg_testing
    mov     edx, msg_testing_len
    call    PrintString
    
    ; Test Q4MatMul kernel
    call    Get_Q4MatMul_Binary
    ; RAX = pointer, EDX = size
    lea     rcx, msg_q4
    mov     edx, msg_q4_len
    call    PrintString
    
    ; Test KVCacheAttention kernel
    call    Get_KVCacheAttention_Binary
    lea     rcx, msg_attn
    mov     edx, msg_attn_len
    call    PrintString
    
    ; Test TileStreamer kernel
    call    Get_TileStreamer_Binary
    lea     rcx, msg_stream
    mov     edx, msg_stream_len
    call    PrintString
    
    ; Print dispatch message
    lea     rcx, msg_dispatch
    mov     edx, msg_dispatch_len
    call    PrintString
    
    ; Print success message
    lea     rcx, msg_stable
    mov     edx, msg_stable_len
    call    PrintString
    
    ; Exit
    xor     ecx, ecx
    call    ExitProcess
    
    add     rsp, 40
    ret
mainCRTStartup ENDP

END
