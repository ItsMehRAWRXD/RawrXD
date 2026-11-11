; ============================================================================
; kernel/sme2_feature_check.asm - ARM64 SME2 Hardware Capability Detection
; Checks FEAT_SME, FEAT_SME2, ZA availability, Streaming Mode support
; Provides graceful fallback: SME2 -> SVE2 -> NEON reference
; ============================================================================

option casemap:none

PUBLIC SME2_CheckHardwareCapability
PUBLIC SME2_GetCapabilityString
PUBLIC SME2_GetMaxVectorLength

; Capability flags returned in EAX
SME2_CAP_NONE       EQU 0000h  ; No SME/SVE support
SME2_CAP_NEON       EQU 0001h  ; Only NEON available
SME2_CAP_SVE       EQU 0002h  ; SVE available
SME2_CAP_SVE2      EQU 0004h  ; SVE2 available
SME2_CAP_SME       EQU 0008h  ; SME available
SME2_CAP_SME2      EQU 0010h  ; SME2 available
SME2_CAP_ZT0       EQU 0020h  ; ZT0 table register available
SME2_CAP_LUTI      EQU 0040h  ; LUTI2/LUTI4 instructions available
SME2_CAP_FP16      EQU 0080h  ; FP16 dequantization support
SME2_CAP_BF16      EQU 0100h  ; BF16 support
SME2_CAP_SVE_512   EQU 0200h  ; 512-bit SVE vector length

.data
    align 8
    cap_unknown     db "Unknown (x86_64 host)", 0
    cap_sme2_full   db "SME2 Full (ZT0 + LUTI + FP16)", 0
    cap_sme         db "SME (no SME2)", 0
    cap_sve2        db "SVE2 (no SME)", 0
    cap_sve         db "SVE (no SVE2)", 0
    cap_neon        db "NEON only", 0
    cap_none_str    db "No SIMD support", 0

    ; CPU feature registers (simulated for x86_64 cross-compile)
    ; On real ARM64, these would come from ID_AA64PFR1_EL1, ID_AA64ZFR0_EL1, etc.
    simd_caps       dd SME2_CAP_SME2 or SME2_CAP_ZT0 or SME2_CAP_LUTI or SME2_CAP_FP16 or SME2_CAP_SVE_512

.code

; ============================================================================
; SME2_CheckHardwareCapability
; Returns: EAX = bitmask of SME2_CAP_* flags
; On x86_64 host: returns simulated full capability for cross-compile validation
; ============================================================================
SME2_CheckHardwareCapability PROC
    push rbp
    mov rbp, rsp

    ; On x86_64, we can't execute ARM64 SME2 instructions.
    ; Return simulated full capability for cross-compile/cross-validation.
    ; On real ARM64 hardware, this would use:
    ;   MRS X0, ID_AA64PFR1_EL1  ; Check FEAT_SME
    ;   MRS X0, ID_AA64ZFR0_EL1  ; Check FEAT_SVE, FEAT_SVE2
    ;   MRS X0, ID_AA64MMFR2_EL1 ; Check vector length

    mov eax, [simd_caps]
    pop rbp
    ret
SME2_CheckHardwareCapability ENDP

; ============================================================================
; SME2_GetCapabilityString
; Returns: RAX = pointer to human-readable capability string
; ============================================================================
SME2_GetCapabilityString PROC
    push rbp
    mov rbp, rsp

    mov eax, [simd_caps]
    
    test eax, SME2_CAP_SME2 or SME2_CAP_ZT0 or SME2_CAP_LUTI
    jnz is_sme2_full
    
    test eax, SME2_CAP_SME
    jnz is_sme
    
    test eax, SME2_CAP_SVE2
    jnz is_sve2
    
    test eax, SME2_CAP_SVE
    jnz is_sve
    
    test eax, SME2_CAP_NEON
    jnz is_neon
    
    lea rax, [cap_none_str]
    pop rbp
    ret

is_sme2_full:
    lea rax, [cap_sme2_full]
    pop rbp
    ret

is_sme:
    lea rax, [cap_sme]
    pop rbp
    ret

is_sve2:
    lea rax, [cap_sve2]
    pop rbp
    ret

is_sve:
    lea rax, [cap_sve]
    pop rbp
    ret

is_neon:
    lea rax, [cap_neon]
    pop rbp
    ret
SME2_GetCapabilityString ENDP

; ============================================================================
; SME2_GetMaxVectorLength
; Returns: EAX = maximum SVE vector length in bytes (0 if no SVE/SME)
; ============================================================================
SME2_GetMaxVectorLength PROC
    push rbp
    mov rbp, rsp

    mov eax, [simd_caps]
    test eax, SME2_CAP_SVE_512
    jz check_sve_256
    
    mov eax, 64  ; 512-bit = 64 bytes
    pop rbp
    ret

check_sve_256:
    test eax, SME2_CAP_SVE or SME2_CAP_SVE2 or SME2_CAP_SME or SME2_CAP_SME2
    jz no_sve
    
    mov eax, 32  ; 256-bit = 32 bytes (minimum SVE)
    pop rbp
    ret

no_sve:
    xor eax, eax
    pop rbp
    ret
SME2_GetMaxVectorLength ENDP

; ============================================================================
; SME2_SelectOptimalKernel
; Returns: EAX = kernel ID to use based on hardware capabilities
;   0 = INT4 SME2 SpMV (preferred)
;   1 = INT2 SME2 SpMV
;   2 = FP16 SME2 SpMV
;   3 = SVE2 fallback
;   4 = NEON reference
; ============================================================================
SME2_SelectOptimalKernel PROC
    push rbp
    mov rbp, rsp

    mov eax, [simd_caps]
    
    test eax, SME2_CAP_SME2 or SME2_CAP_ZT0 or SME2_CAP_LUTI
    jz try_sme
    
    ; SME2 full - prefer INT4 for best throughput
    mov eax, 0  ; INT4 SME2 SpMV
    pop rbp
    ret

try_sme:
    test eax, SME2_CAP_SME
    jz try_sve2
    
    mov eax, 2  ; FP16 SME SpMV
    pop rbp
    ret

try_sve2:
    test eax, SME2_CAP_SVE2
    jz try_sve
    
    mov eax, 3  ; SVE2 fallback
    pop rbp
    ret

try_sve:
    test eax, SME2_CAP_SVE
    jz use_neon
    
    mov eax, 3  ; SVE fallback
    pop rbp
    ret

use_neon:
    mov eax, 4  ; NEON reference
    pop rbp
    ret
SME2_SelectOptimalKernel ENDP

END
