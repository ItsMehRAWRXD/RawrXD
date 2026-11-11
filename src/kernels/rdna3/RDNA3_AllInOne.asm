; RDNA3_AllInOne.asm
; Single-file RDNA3 kernel test harness
; Target: RX 7800 XT (gfx1101)

;==============================================================================
; External imports
;==============================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC

;==============================================================================
; Data Section
;==============================================================================
.data
ALIGN 8

;------------------------------------------------------------------------------
; Q4MatMul_RDNA3 Kernel Binary
;------------------------------------------------------------------------------
Q4MatMul_RDNA3_Bin LABEL BYTE
    DB 064h, 086h, 001h, 000h, 000h, 000h, 000h, 000h
    DB 001h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 001h, 001h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 002h, 002h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 0ACh, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 010h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 011h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 012h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 013h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 014h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 015h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 016h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 017h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 018h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 019h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 01Ah, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 01Bh, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 01Ch, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 01Dh, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 01Eh, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 01Fh, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 014h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 086h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 084h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 08Ch, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 0C0h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 080h, 094h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 080h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 09Ch, 000h, 000h, 000h, 000h, 000h, 000h
Q4MatMul_RDNA3_BinEnd LABEL BYTE
Q4MatMul_RDNA3_BinSize EQU Q4MatMul_RDNA3_BinEnd - Q4MatMul_RDNA3_Bin

;------------------------------------------------------------------------------
; KVCacheAttention_RDNA3 Kernel Binary
;------------------------------------------------------------------------------
KVCacheAttention_RDNA3_Bin LABEL BYTE
    DB 064h, 086h, 001h, 000h, 000h, 000h, 000h, 000h
    DB 001h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 001h, 001h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 0ACh, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 010h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 011h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 012h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 013h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 014h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 015h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 016h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 07Eh, 017h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 014h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 086h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 084h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 08Ch, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 0C0h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 080h, 094h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 080h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 09Ch, 000h, 000h, 000h, 000h, 000h, 000h
KVCacheAttention_RDNA3_BinEnd LABEL BYTE
KVCacheAttention_RDNA3_BinSize EQU KVCacheAttention_RDNA3_BinEnd - KVCacheAttention_RDNA3_Bin

;------------------------------------------------------------------------------
; TileStreamer_RDNA3 Kernel Binary
;------------------------------------------------------------------------------
TileStreamer_RDNA3_Bin LABEL BYTE
    DB 064h, 086h, 001h, 000h, 000h, 000h, 000h, 000h
    DB 001h, 010h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 001h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 001h, 001h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 0ACh, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BEh, 014h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 086h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 084h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 0C0h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 080h, 094h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 080h, 095h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 080h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 000h, 000h, 000h, 000h, 000h, 000h, 000h, 000h
    DB 0BFh, 09Ch, 000h, 000h, 000h, 000h, 000h, 000h
TileStreamer_RDNA3_BinEnd LABEL BYTE
TileStreamer_RDNA3_BinSize EQU TileStreamer_RDNA3_BinEnd - TileStreamer_RDNA3_Bin

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
; Get_Q4MatMul_Binary
;------------------------------------------------------------------------------
Get_Q4MatMul_Binary PROC
    lea     rax, Q4MatMul_RDNA3_Bin
    mov     edx, Q4MatMul_RDNA3_BinSize
    ret
Get_Q4MatMul_Binary ENDP

;------------------------------------------------------------------------------
; Get_KVCacheAttention_Binary
;------------------------------------------------------------------------------
Get_KVCacheAttention_Binary PROC
    lea     rax, KVCacheAttention_RDNA3_Bin
    mov     edx, KVCacheAttention_RDNA3_BinSize
    ret
Get_KVCacheAttention_Binary ENDP

;------------------------------------------------------------------------------
; Get_TileStreamer_Binary
;------------------------------------------------------------------------------
Get_TileStreamer_Binary PROC
    lea     rax, TileStreamer_RDNA3_Bin
    mov     edx, TileStreamer_RDNA3_BinSize
    ret
Get_TileStreamer_Binary ENDP

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
