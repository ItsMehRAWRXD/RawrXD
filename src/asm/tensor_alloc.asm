; tensor_alloc.asm - Protected Tensor Memory Allocator
; Pure MASM64
; Uses VirtualAlloc and VirtualProtect to create true MMU-enforced RedZones.

extern VirtualAlloc: proc
extern VirtualProtect: proc
extern VirtualFree: proc

MEM_COMMIT     EQU 1000h
MEM_RESERVE    EQU 2000h
MEM_RELEASE    EQU 8000h
PAGE_READWRITE EQU 04h
PAGE_NOACCESS  EQU 01h
PAGE_SIZE      EQU 4096

.code

;==============================================================================
; Tensor_Allocate_Protected
; Allocates a buffer flanked by PAGE_NOACCESS hardware tripwires.
;
; RCX = requested size in bytes
; Returns RAX = pointer to usable tensor memory (aligned 4096)
;                 or 0 on failure.
;==============================================================================
Tensor_Allocate_Protected PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 38h
    .allocstack 38h
    .endprolog
    
    ; 1. Calculate required allocation size
    ; Align requested size up to 4096 (page boundary)
    mov rbx, rcx
    add rbx, 4095
    and rbx, -4096      ; rbx = Page-aligned requested size
    
    ; Total size = front guard (4096) + data size (rbx) + back guard (4096)
    mov rsi, rbx
    add rsi, PAGE_SIZE * 2
    
    ; 2. Allocate the entire region (read/write)
    xor rcx, rcx        ; lpAddress = NULL
    mov rdx, rsi        ; dwSize = Total size
    mov r8, MEM_COMMIT or MEM_RESERVE
    mov r9, PAGE_READWRITE
    call VirtualAlloc
    
    test rax, rax
    jz .alloc_fail      ; If allocation failed, return NULL
    
    mov rdi, rax        ; rdi = Base allocation pointer
    
    ; 3. Protect Front Guard Page (PAGE_NOACCESS)
    mov rcx, rdi        ; lpAddress = base pointer
    mov rdx, PAGE_SIZE  ; dwSize = 4096
    mov r8, PAGE_NOACCESS
    lea r9, [rsp+28h]   ; lpflOldProtect (save to scratch space on stack)
    call VirtualProtect
    
    ; 4. Protect Back Guard Page (PAGE_NOACCESS)
    lea rcx, [rdi + rbx + PAGE_SIZE] ; lpAddress = base + data_size + front_guard
    mov rdx, PAGE_SIZE               ; dwSize = 4096
    mov r8, PAGE_NOACCESS
    lea r9, [rsp+28h]                ; lpflOldProtect
    call VirtualProtect
    
    ; 5. Return pointer to usable, hardware-flanked memory
    lea rax, [rdi + PAGE_SIZE]

.alloc_fail:
    add rsp, 38h
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Tensor_Allocate_Protected ENDP

;==============================================================================
; Tensor_Free_Protected
; Frees a buffer allocated by Tensor_Allocate_Protected.
;
; RCX = usable memory pointer returned by Tensor_Allocate_Protected
;==============================================================================
Tensor_Free_Protected PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog
    
    test rcx, rcx
    jz .free_done
    
    ; Move pointer back to the actual allocation base (before front guard)
    sub rcx, PAGE_SIZE
    
    xor rdx, rdx        ; dwSize = 0 (MEM_RELEASE requires 0)
    mov r8, MEM_RELEASE
    call VirtualFree
    
.free_done:
    add rsp, 28h
    ret
Tensor_Free_Protected ENDP

END
