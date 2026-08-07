; memory.asm - Runtime memory helper
; Minimal allocator using VirtualAlloc

extrn VirtualAlloc:proc
extrn VirtualFree:proc

MEM_COMMIT      EQU 0x1000
MEM_RESERVE     EQU 0x2000
MEM_RELEASE     EQU 0x8000
PAGE_READWRITE  EQU 0x04

.code

; RuntimeAlloc - Allocate memory
; RCX = size in bytes
; Returns: RAX = pointer, or NULL
RuntimeAlloc PROC
    sub rsp, 28h
    
    mov r8, rcx             ; Size
    xor ecx, ecx            ; lpAddress = NULL (let system choose)
    mov edx, MEM_COMMIT or MEM_RESERVE
    mov r9d, PAGE_READWRITE
    mov qword ptr [rsp+20h], 0  ; hFile = NULL
    call VirtualAlloc
    
    add rsp, 28h
    ret
RuntimeAlloc ENDP

; RuntimeFree - Free allocated memory
; RCX = pointer
; Returns: RAX = success (TRUE/FALSE)
RuntimeFree PROC
    sub rsp, 28h
    
    mov rdx, 0              ; dwSize = 0 (must be 0 for MEM_RELEASE)
    mov r8d, MEM_RELEASE
    call VirtualFree
    
    add rsp, 28h
    ret
RuntimeFree ENDP

; RuntimeAllocZero - Allocate zeroed memory
; RCX = size in bytes
; Returns: RAX = pointer
RuntimeAllocZero PROC
    push rbx
    push rdi
    
    mov rbx, rcx
    call RuntimeAlloc
    test rax, rax
    jz alloc_zero_done
    
    ; Zero the memory
    mov rdi, rax
    mov rcx, rbx
    shr rcx, 3              ; /8 for QWORDs
    xor eax, eax
    rep stosq
    
    mov rax, rdi
    sub rax, rbx            ; Restore original pointer
    
alloc_zero_done:
    pop rdi
    pop rbx
    ret
RuntimeAllocZero ENDP

END
