; ==================================================================================
; SOVEREIGN HARDWARE
; File: Sovereign_Hardware.asm
; Role: CPUID Feature Detection & Calibration
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc

.CODE

PUBLIC Sovereign_Check_Features
Sovereign_Check_Features PROC
    ENTER_FRAME
    push rbx
    
    ; 1. Check OSXSAVE (CPUID Leaf 1, ECX bit 27)
    mov eax, 1
    xor ecx, ecx
    cpuid
    bt ecx, 27
    jnc @@NoAVX512
    
    ; 2. Check XCR0 (XGETBV) for ZMM state (OPMASK bit 5, ZMM_Hi256 bit 6, Hi16_ZMM bit 7)
    xor ecx, ecx
    xgetbv
    mov edx, eax
    and edx, 11100110b         ; Check bits 1, 2, 5, 6, 7
    cmp edx, 11100110b
    jne @@NoAVX512
    
    ; 3. Check AVX512F (CPUID Leaf 7, EBX bit 16)
    mov eax, 7
    xor ecx, ecx
    cpuid
    bt ebx, 16
    jc @@HasAVX512
    
@@NoAVX512:
    xor rax, rax
    jmp @@Done
    
@@HasAVX512:
    mov rax, 1
    
@@Done:
    pop rbx
    EXIT_FRAME
    ret
Sovereign_Check_Features ENDP

PUBLIC Sovereign_Warmup_Core
Sovereign_Warmup_Core PROC
    ENTER_FRAME
    rdtscp
    shl rdx, 32
    or rax, rdx
    mov r9, rax
@@Loop:
    rdtscp
    shl rdx, 32
    or rax, rdx
    sub rax, r9
    cmp rax, 1000000
    jl @@Loop
    
    EXIT_FRAME
    ret
Sovereign_Warmup_Core ENDP

END
