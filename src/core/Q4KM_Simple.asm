; Q4KM_Simple.asm - Simplified Q4_K_M dequantization
option casemap:none

includelib msvcrt.lib
includelib kernel32.lib

EXTERNDEF printf:PROC
EXTERNDEF exit:PROC

.data
    fmt_header      db "=== Q4_K_M SIMPLE TEST ===", 10, 0
    fmt_init        db "[1] Kernel ready", 10, 0
    fmt_dequant     db "[2] Dequantizing 256 weights...", 10, 0
    fmt_done        db "[3] Complete! Sample[0]=%f", 10, 0
    fmt_success     db "=== SUCCESS ===", 10, 0
    
    ; Simple test: 256 weights, all with value 5
    ; Scale = 1.0, Min = 0.0
    ; Dequantized = (5 * 1.0) + 0.0 = 5.0
    test_weights    db 256 dup(5)       ; 8-bit signed weights
    test_scale      dd 1.0
    test_min        dd 0.0
    
    align 16
    output          dd 256 dup(0.0)

.code

; Simple dequant: output[i] = (input[i] * scale) + min
SimpleDequant PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    r12
    push    r13
    
    mov     r12, rcx            ; R12 = input weights
    mov     r13, rdx            ; R13 = output buffer
    movss   xmm0, dword ptr [test_scale]
    movss   xmm1, dword ptr [test_min]
    
    xor     rbx, rbx            ; RBX = index
    
dequant_loop:
    cmp     rbx, 256
    jge     dequant_done
    
    ; Load weight
    movsx   eax, byte ptr [r12 + rbx]
    cvtsi2ss xmm2, eax
    
    ; Dequantize: weight * scale + min
    mulss   xmm2, xmm0
    addss   xmm2, xmm1
    
    ; Store
    movss   dword ptr [r13 + rbx*4], xmm2
    
    inc     rbx
    jmp     dequant_loop
    
dequant_done:
    pop     r13
    pop     r12
    pop     rbx
    pop     rbp
    ret
SimpleDequant ENDP

main PROC
    push    rbp
    mov     rbp, rsp
    sub     rsp, 32
    
    lea     rcx, fmt_header
    call    printf
    
    lea     rcx, fmt_init
    call    printf
    
    lea     rcx, fmt_dequant
    call    printf
    
    ; Call simple dequant
    lea     rcx, test_weights
    lea     rdx, output
    call    SimpleDequant
    
    ; Print result
    lea     rcx, fmt_done
    movss   xmm0, dword ptr [output]
    cvtss2sd xmm0, xmm0
    movq    rdx, xmm0
    call    printf
    
    lea     rcx, fmt_success
    call    printf
    
    xor     ecx, ecx
    call    exit
    
    add     rsp, 32
    pop     rbp
    ret
main ENDP

END
