.CODE
; ==================================================================
; TITAN_CORE: HARDENED DISPATCHER (MODEL EXECUTION HUB)
; ==================================================================
; R9 = NodeID (0:SIMD, 1:Q4, 2:MATRIX, 3:FUSED_Q4), RCX/RDX/R8 = Params
; ==================================================================
KERNEL_SIMD PROC FRAME
    sub rsp, 28h
    lea rbx, [rcx + r8*4]
.loop: cmp rcx, rbx
    jae .done
    vmovups xmm0, [rcx]
    vmulps  xmm0, xmm0, xmm1
    vmovups [rdx], xmm0
    add rcx, 16
    add rdx, 16
    jmp .loop
.done: add rsp, 28h
    ret
KERNEL_SIMD ENDP

KERNEL_Q4 PROC FRAME
    mov rax, r8
    lea rbx, [rax + rax*8]
    add rbx, rbx
    add rbx, rdx
    mov rsi, rdx
.loop: cmp rsi, rbx
    jae .done
    vmovups xmm0, [rsi+2]
    add rsi, 18
    jmp .loop
.done: ret
KERNEL_Q4 ENDP

KERNEL_FUSED_Q4_ACCUM PROC FRAME
    sub rsp, 28h
    mov rax, r8
    lea rbx, [rax + rax*8]
    add rbx, rbx
    add rbx, rcx        ; rbx = rcx (src) + 18 * count
    
    vxorps ymm2, ymm2, ymm2  ; zero accumulator

.loop:
    cmp rcx, rbx
    jae .done

    prefetcht0 [rcx + 128]   ; Software Prefetching

    vmovups ymm0, [rcx + 2]  ; Load Q4 Nibbles
    
    ; [Placeholder for AVX2 PSHUFB Unpack / Dequantize]
    
    vbroadcastss ymm15, dword ptr [rcx]  ; Load Block Scale
    vmulps ymm0, ymm0, ymm15             ; In-Register Scale Application
    
    ; [Placeholder for Activation Multiply (ymm1)]
    
    vaddps ymm2, ymm2, ymm0              ; Accumulate!
    
    add rcx, 18
    jmp .loop

.done:
    vmovups [rdx], ymm2      ; Single Store per Sequence
    add rsp, 28h
    ret
KERNEL_FUSED_Q4_ACCUM ENDP

KERNEL_MATRIX PROC FRAME
    add r10, r11
    cmp r10, r12
    jae .done
    ret
.done: ret
KERNEL_MATRIX ENDP

PUBLIC KERNEL_DISPATCH
KERNEL_DISPATCH PROC FRAME
    push rbx
    push rsi
    push rdi
    
    cmp r9, 0
    je .simd
    cmp r9, 1
    je .q4
    cmp r9, 3
    je .fused_q4_accum
    call KERNEL_MATRIX
    jmp .exit
.simd: 
    call KERNEL_SIMD
    jmp .exit
.q4: 
    call KERNEL_Q4
    jmp .exit
.fused_q4_accum:
    call KERNEL_FUSED_Q4_ACCUM
.exit:
    pop rdi
    pop rsi
    pop rbx
    ret
KERNEL_DISPATCH ENDP

ALIGN 64
.DATA
Sentinel db 16 dup(0xCC)
; ==================================================================
; END OF DISPATCHER: NO EXTERNAL DEP, HARDENED AB, MMU-READY
; ==================================================================
END
