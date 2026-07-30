; memory.asm - Minimal allocator for Sovereign Universal Transpiler
; v0.1: Uses VirtualAlloc/VirtualFree

extrn VirtualAlloc:proc
extrn VirtualFree:proc

.data
    MEM_COMMIT   equ 1000h
    MEM_RESERVE  equ 2000h
    MEM_RELEASE  equ 8000h
    PAGE_READWRITE equ 4

.code

; RuntimeAlloc - Allocate memory
; RCX = size in bytes
; Returns: RAX = pointer to allocated memory (0 on failure)
RuntimeAlloc PROC
    sub rsp, 28h
    
    ; VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
    xor rcx, rcx            ; lpAddress = NULL
    ; rdx = size (passed in rdx by caller convention adjustment)
    ; Actually RCX has size, need to shift
    mov rdx, rcx            ; size
    xor rcx, rcx            ; NULL
    mov r8d, MEM_COMMIT or MEM_RESERVE
    mov r9d, PAGE_READWRITE
    call VirtualAlloc
    
    add rsp, 28h
    ret
RuntimeAlloc ENDP

; RuntimeFree - Free allocated memory
; RCX = pointer
RuntimeFree PROC
    sub rsp, 28h
    
    ; VirtualFree(ptr, 0, MEM_RELEASE)
    xor rdx, rdx            ; dwSize = 0
    mov r8d, MEM_RELEASE
    call VirtualFree
    
    add rsp, 28h
    ret
RuntimeFree ENDP

end