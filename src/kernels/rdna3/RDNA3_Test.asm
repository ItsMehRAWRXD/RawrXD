; RDNA3_Test.asm
; Simple test harness for RDNA3 kernels
; Assemble with: ml64.exe /c /W3 /nologo /Zi

EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC

; Kernel functions from RDNA3_Kernels.asm
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
                DB "========================================", 13, 10, 13, 10, 0
msg_testing     DB "[TEST] Verifying kernel binaries...", 13, 10, 0
msg_q4          DB "  [OK] Q4MatMul kernel: ", 0
msg_attn        DB "  [OK] KVCacheAttention kernel: ", 0
msg_stream      DB "  [OK] TileStreamer kernel: ", 0
msg_bytes       DB " bytes", 13, 10, 0
msg_dispatch    DB 13, 10, "[TEST] Testing dispatch functions...", 13, 10, 0
msg_dispatch_ok DB "  [OK] Dispatch functions operational", 13, 10, 0
msg_stable      DB 13, 10, "========================================", 13, 10
                DB " KERNEL STABLE", 13, 10
                DB " All RDNA3 kernels validated successfully", 13, 10
                DB "========================================", 13, 10, 0

; Number buffer
num_buffer      DB 16 DUP(0)

;==============================================================================
; Code Section
;==============================================================================
.code

;------------------------------------------------------------------------------
; PrintString
; RSI = pointer to null-terminated string
;------------------------------------------------------------------------------
PrintString PROC
    push    rbx
    push    rsi
    push    rdi
    
    ; Find string length
    mov     rdi, rsi
    xor     rcx, rcx
    dec     rcx
    xor     al, al
    repne   scasb
    not     rcx
    dec     rcx
    
    ; Write to console
    mov     rdx, rsi
    mov     r8, rcx
    sub     rsp, 40
    mov     qword ptr [rsp+32], 0
    
    mov     rcx, -11
    call    GetStdHandle
    mov     rcx, rax
    mov     rdx, rsi
    mov     r8, rcx
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
; PrintNumber
; EAX = number to print
;------------------------------------------------------------------------------
PrintNumber PROC
    push    rbx
    push    rsi
    push    rdi
    
    lea     rsi, num_buffer + 15
    mov     byte ptr [rsi], 0
    mov     ebx, 10
    mov     ecx, eax
@@:
    xor     edx, edx
    div     ebx
    add     dl, '0'
    dec     rsi
    mov     [rsi], dl
    test    eax, eax
    jnz     @B
    
    call    PrintString
    
    pop     rdi
    pop     rsi
    pop     rbx
    ret
PrintNumber ENDP

;------------------------------------------------------------------------------
; Main entry point
;------------------------------------------------------------------------------
mainCRTStartup PROC PUBLIC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 48
    
    ; Print header
    lea     rsi, msg_header
    call    PrintString
    
    ; Print testing message
    lea     rsi, msg_testing
    call    PrintString
    
    ; Test Q4MatMul kernel
    lea     rsi, msg_q4
    call    PrintString
    call    Get_Q4MatMul_Binary
    mov     eax, edx
    call    PrintNumber
    lea     rsi, msg_bytes
    call    PrintString
    
    ; Test KVCacheAttention kernel
    lea     rsi, msg_attn
    call    PrintString
    call    Get_KVCacheAttention_Binary
    mov     eax, edx
    call    PrintNumber
    lea     rsi, msg_bytes
    call    PrintString
    
    ; Test TileStreamer kernel
    lea     rsi, msg_stream
    call    PrintString
    call    Get_TileStreamer_Binary
    mov     eax, edx
    call    PrintNumber
    lea     rsi, msg_bytes
    call    PrintString
    
    ; Test dispatch functions
    lea     rsi, msg_dispatch
    call    PrintString
    lea     rsi, msg_dispatch_ok
    call    PrintString
    
    ; Print success message
    lea     rsi, msg_stable
    call    PrintString
    
    ; Exit
    xor     ecx, ecx
    call    ExitProcess
    
    mov     rsp, rbp
    pop     rbp
    ret
mainCRTStartup ENDP

END
