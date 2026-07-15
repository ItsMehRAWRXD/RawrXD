;==============================================================================
; RAWRXD_CYLINDER.asm
; 6-Shot Execution Cylinder — Mask-Aware Vector Dispatch
; L1 cache-aligned (64 bytes). Lock-free atomic rotation with bit-test skip.
; Zero-CRT, compact, no scaffolding.
;==============================================================================
OPTION CASEMAP:NONE

.CODE

;------------------------------------------------------------------------------
; Cylinder_RotateAndFireMasked(pCylinder:rcx, pPayload:rdx, allowedMask:r8d)
; Atomically rotates to next chamber, skips disabled chambers via bit-test.
; If chamber bit is set and function pointer is non-null, calls it with pPayload.
; Clobbers: rax, r9, r10, r11
;------------------------------------------------------------------------------
Cylinder_RotateAndFireMasked PROC
    test rcx, rcx
    jz @@done
    test r8d, r8d
    jz @@done              ; Empty mask = nothing to do

    mov r11, rdx           ; r11 = payload pointer
    xor r10d, r10d         ; r10d = spin watchdog (max 6)

@@spin:
    inc r10d
    cmp r10d, 6
    jg @@done              ; Safety: all chambers masked or empty

    ; Atomically advance chamber index (0-5)
    mov eax, [rcx + 48]    ; currentChamber
    mov r9d, eax
    inc r9d
    cmp r9d, 6
    jne @@nowrap
    xor r9d, r9d
@@nowrap:
    lock cmpxchg [rcx + 48], r9d
    jnz @@spin             ; Lost race, retry with updated eax

    ; eax = confirmed chamber index (0-5)
    ; Test if this chamber is allowed
    bt r8d, eax
    jnc @@spin             ; Bit clear = skip to next chamber

    ; Load function pointer
    mov rax, [rcx + rax * 8]
    test rax, rax
    jz @@spin              ; Null pointer = skip

    ; Fire!
    mov rdx, r11           ; pPayload in RDX (Win64: arg2)
    call rax

    ; Increment lifetime fire counter
    lock inc qword ptr [rcx + 56]

@@done:
    ret
Cylinder_RotateAndFireMasked ENDP

END
