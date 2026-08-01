; runtime/memory.asm — Memory management for RawrXD Runtime
; Real implementations using HeapAlloc/HeapFree/RtlMoveMemory

OPTION CASEMAP:NONE

; Windows API externs
EXTERN GetProcessHeap:PROC
EXTERN HeapAlloc:PROC
EXTERN HeapFree:PROC

.code

; ===========================================================================
; RawrXD_AlignedAlloc — Allocate aligned memory via HeapAlloc
; RCX = size in bytes
; Returns: RAX = pointer, or 0 on failure
; ===========================================================================
RawrXD_AlignedAlloc PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    sub rsp, 32
    .allocstack 32
    .endprolog

    test rcx, rcx
    jz @@error
    add rcx, 64                     ; Extra space for alignment + header
    jc @@error                      ; Overflow

    ; Get process heap
    push rcx
    call GetProcessHeap
    pop rcx
    test rax, rax
    jz @@error

    ; HeapAlloc(heap, HEAP_ZERO_MEMORY, size)
    mov rdx, 8                      ; HEAP_ZERO_MEMORY
    call HeapAlloc
    test rax, rax
    jz @@error

    ; Align to 64 bytes
    mov rdx, rax
    add rax, 64
    and rax, -64                    ; Align down to 64-byte boundary
    mov QWORD PTR [rax - 8], rdx    ; Store original pointer for free
    jmp @@exit

@@error:
    xor rax, rax

@@exit:
    add rsp, 32
    pop rbp
    ret
RawrXD_AlignedAlloc ENDP

; ===========================================================================
; RawrXD_AlignedFree — Free memory allocated by RawrXD_AlignedAlloc
; RCX = aligned pointer
; ===========================================================================
RawrXD_AlignedFree PROC FRAME
    .endprolog

    test rcx, rcx
    jz @@exit

    mov rdx, QWORD PTR [rcx - 8]   ; Retrieve original pointer
    test rdx, rdx
    jz @@exit

    push rcx
    mov rcx, rdx
    call HeapFree
    pop rcx

@@exit:
    ret
RawrXD_AlignedFree ENDP

; ===========================================================================
; RawrXD_ZeroMemory — Zero a block of memory
; RCX = pointer, RDX = size in bytes
; ===========================================================================
RawrXD_ZeroMemory PROC FRAME
    .endprolog

    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit

    xor eax, eax
    mov r8, rcx
    mov r9, rdx

@@loop:
    test r9, r9
    jz @@exit
    mov BYTE PTR [r8], al
    inc r8
    dec r9
    jmp @@loop

@@exit:
    ret
RawrXD_ZeroMemory ENDP

; ===========================================================================
; RawrXD_MemCopy — Copy memory block
; RCX = dest, RDX = src, R8 = size
; ===========================================================================
RawrXD_MemCopy PROC FRAME
    .endprolog

    test rcx, rcx
    jz @@exit
    test rdx, rdx
    jz @@exit
    test r8, r8
    jz @@exit

    push rsi
    push rdi

    mov rsi, rdx                    ; src
    mov rdi, rcx                    ; dest
    mov rcx, r8                     ; count

@@loop:
    test rcx, rcx
    jz @@done
    mov al, BYTE PTR [rsi]
    mov BYTE PTR [rdi], al
    inc rsi
    inc rdi
    dec rcx
    jmp @@loop

@@done:
    pop rdi
    pop rsi

@@exit:
    ret
RawrXD_MemCopy ENDP

END
