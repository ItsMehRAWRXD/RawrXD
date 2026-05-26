; kernel_dispatch.asm - ABI Bridge and Dispatch Layer
; Bridges the C++ KernelContext struct into naked ASM registers

extrn KERNEL_Q4_K_BLOCK: proc

.code

; =============================================================================
; KERNEL_DISPATCH
; RCX points to C++ KernelContext struct:
; Offset 00: Src Ptr (8 bytes)
; Offset 08: Dst Ptr (8 bytes)
; Offset 16: Count (8 bytes)
; Offset 24: End Ptr (8 bytes)
; =============================================================================
KERNEL_DISPATCH PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    ; Stage context fields into registers
    mov r8,  [rcx + 16]   ; Load Count
    mov r9,  [rcx + 24]   ; Load End Ptr

    mov rax, rcx          ; Save context base to RAX to avoid clobbering

    mov rcx, [rax + 0]    ; Load Src
    mov rdx, [rax + 8]    ; Load Dst

    ; Dispatch to hardened compute kernel
    call KERNEL_Q4_K_BLOCK

    add rsp, 28h
    ret
KERNEL_DISPATCH ENDP

END
