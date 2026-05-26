; ==============================================================================
; Sovereign_SIMD_Scanner.asm - Hardware Audit + Pattern Scanner
; ==============================================================================

include Sovereign_Common.inc

EXTERN g_DispatchTable : DISPATCH_TABLE
EXTERN g_pGlobalRing   : QWORD
EXTERN DotProduct_F32_AVX512 : PROC
EXTERN DotProduct_F32_Scalar : PROC
EXTERN Ring_Push_Atomic : PROC

.CODE

; ----------------------------------------------------------------------------
; Sovereign_Hardware_Audit
; Populate g_DispatchTable based on CPUID
; ----------------------------------------------------------------------------
PUBLIC Sovereign_Hardware_Audit
Sovereign_Hardware_Audit PROC
    push rbx
    
    ; Default to Scalar
    lea rax, DotProduct_F32_Scalar
    mov [g_DispatchTable.pGemv_F32], rax

    ; Check for AVX-512 Foundation
    mov eax, 7
    xor ecx, ecx
    cpuid
    test ebx, 00010000h ; AVX-512 Foundation (bit 16)
    jz @Done

    ; Upgrade to AVX-512
    lea rax, DotProduct_F32_AVX512
    mov [g_DispatchTable.pGemv_F32], rax

@Done:
    pop rbx
    ret
Sovereign_Hardware_Audit ENDP

; --- Original Scanner Functions ---

PUBLIC Sovereign_AVX512_Tail_Scan
Sovereign_AVX512_Tail_Scan PROC
    mov rax, 1
    shlx rax, rax, rcx
    dec rax
    kmovq k1, rax
    vmovdqu8 zmm0 {k1}{z}, zmmword ptr [r8]
    vpcmpub k2 {k1}, zmm0, zmm1, 0
    kmovq rax, k2
    test rax, rax
    jz @NoMatch
    tzcnt rax, rax
    add rax, r8
    push rax
    mov rcx, g_pGlobalRing
    mov rdx, rax
    call Ring_Push_Atomic
    pop rax
    ret
@NoMatch:
    xor rax, rax
    ret
Sovereign_AVX512_Tail_Scan ENDP

PUBLIC Sovereign_ScanPattern
Sovereign_ScanPattern PROC
    push rbp
    mov rbp, rsp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    mov rsi, rcx
    mov rdi, r8
    mov r12, rdx
    mov r13, r9
    movzx eax, byte ptr [rdi]
    vpbroadcastb zmm1, eax
    xor rbx, rbx
_MainLoop:
    mov r14, r12
    sub r14, rbx
    cmp r14, 64
    jb _TailProcessing
    vmovdqu8 zmm0, [rsi + rbx]
    vpcmpeqb k1, zmm0, zmm1
    kmovq rax, k1
    test rax, rax
    jnz _PotentialMatches
_NextBlock:
    add rbx, 64
    jmp _MainLoop
_TailProcessing:
    test r14, r14
    jz _ScanEnd
    mov rcx, r14
    lea r8, [rsi + rbx]
    call Sovereign_AVX512_Tail_Scan
    jmp _ScanEnd
_PotentialMatches:
    lea rax, [rsi + rbx]
    jmp _ScanEnd
_ScanEnd:
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Sovereign_ScanPattern ENDP
END
