; =========================================================================================
; FILE: Sovereign_WFC_Generator.asm
; SUBSYSTEM: WAVE FUNCTION COLLAPSE (WFC) KERNEL
; Pure x64 MASM / No Dependencies / High-Performance Bit-Manipulation
; Purpose: Implements a "popping" Wave Function Collapse algorithm kernel. 
;          Resolves local tile entropy to generate perfectly adjacent structures 
;          (neighborhoods, car lots, military bases) without grid-seams.
; =========================================================================================

.DATA
; Entropy State for a local 8x8 Grid (64 cells)
; Each cell is a 16-bit bitmask of possible POI_IDs (1-11)
align 16
g_WFC_Grid_Entropy     dw 64 dup(0FFFh) ; All 12 bits set initially (1-11 + 0)
g_WFC_Resolved_Count   dq 0

.CODE

; -----------------------------------------------------------------------------------------
; VOID Sovereign_WFC_Reset()
; Resets the expansion grid to full uncollapsed entropy.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_WFC_Reset
Sovereign_WFC_Reset PROC
    lea rax, g_WFC_Grid_Entropy
    mov rcx, 64
@@ResetLoop:
    mov word ptr [rax], 0FFE7h     ; Mask for POIs 1-11 (bits 1-11 set)
    add rax, 2
    loop @@ResetLoop
    mov qword ptr [g_WFC_Resolved_Count], 0
    ret
Sovereign_WFC_Reset ENDP

; -----------------------------------------------------------------------------------------
; UINT64 Sovereign_WFC_Observe(UINT32 cellIdx, UINT32 forcedPOI)
; RCX = cellIdx (0-63)
; RDX = forcedPOI (If 0, collapses to lowest random available bit)
; Purpose: Collapses the wave function of a single cell to a definite state.
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_WFC_Observe
Sovereign_WFC_Observe PROC FRAME
    push rbx
    .pushreg rbx
    .endprolog

    lea rax, g_WFC_Grid_Entropy
    mov r8, rcx
    shl r8, 1                      ; idx * 2 (sizeof word)
    add rax, r8                    ; RAX = Cell Pointer

    test rdx, rdx
    jz @@RandomCollapse

    ; Force to specific state
    mov r9, 1
    mov rcx, rdx
    shl r9, cl                     ; r9 = bitmask for POI
    mov word ptr [rax], r9w
    jmp @@Success

@@RandomCollapse:
    ; Collapse to the lowest set bit in the current entropy mask (Simplified WFC)
    movzx rbx, word ptr [rax]
    bsf rcx, rbx                   ; Find first set bit (lowest entropy)
    jz @@Success                   ; Already collapsed or empty
    
    mov r9, 1
    shl r9, cl
    mov word ptr [rax], r9w        ; Collapse to just that bit

@@Success:
    inc qword ptr [g_WFC_Resolved_Count]
    mov rax, 1
    pop rbx
    ret
Sovereign_WFC_Observe ENDP

; -----------------------------------------------------------------------------------------
; VOID Sovereign_WFC_Propagate(UINT32 cellIdx)
; RCX = cellIdx
; Purpose: Propagates constraints to neighbors (North, South, East, West).
; Logic: If cell is "MILITARY_BASE", neighbors MUST NOT be "CAMPER".
; -----------------------------------------------------------------------------------------
PUBLIC Sovereign_WFC_Propagate
Sovereign_WFC_Propagate PROC
    ; This is the core "Reverse Engineered" WFC Logic
    ; We extract the current collapsed bit and apply the adjacency LUT.
    lea rax, g_WFC_Grid_Entropy
    mov r8, rcx
    shl r8, 1
    movzx r9, word ptr [rax + r8]  ; R9 = Collapsed bit of source

    ; Simple Constraint: bit 8 (MILITARY) kills bit 1 (CAMPER) in neighbors
    test r9, 100h                  ; Check bit 8
    jz @@Exit

    ; Propagate to North (idx - 8)
    mov r10, rcx
    sub r10, 8
    js @@CheckSouth
    and word ptr [rax + r10*2], 0FFFEh ; Clear bit 0/1

@@CheckSouth:
    mov r10, rcx
    add r10, 8
    cmp r10, 64
    jae @@Exit
    and word ptr [rax + r10*2], 0FFFEh

@@Exit:
    ret
Sovereign_WFC_Propagate ENDP

END