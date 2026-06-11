; ============================================================================
; snmalloc_stub.asm — Minimal snmalloc compatibility shim for RawrXD
; ============================================================================
; llama.cpp prebuilt DLLs expect snmalloc symbols. This stub forwards
; sn_malloc/sn_free/sn_realloc/sn_calloc to the standard CRT heap.
;
; Build: ml64.exe /c /W3 /nologo /Zi /Fo snmalloc_stub.obj snmalloc_stub.asm
; Link:  link.exe ... snmalloc_stub.obj ...
; ============================================================================

    OPTION DOTNAME
    .code

; ----------------------------------------------------------------------------
; Export table — these symbols must be visible to llama.cpp DLLs
; ----------------------------------------------------------------------------
    PUBLIC sn_malloc
    PUBLIC sn_free
    PUBLIC sn_realloc
    PUBLIC sn_calloc
    PUBLIC sn_malloc_aligned
    PUBLIC sn_free_aligned
    PUBLIC snmalloc_library_init
    PUBLIC snmalloc_library_shutdown

; ----------------------------------------------------------------------------
; snmalloc_library_init — called by llama.cpp DLL on load
; Returns: RAX = 1 (success), 0 (failure)
; ----------------------------------------------------------------------------
snmalloc_library_init PROC
    mov     rax, 1          ; Always report success — we use CRT heap
    ret
snmalloc_library_init ENDP

; ----------------------------------------------------------------------------
; snmalloc_library_shutdown — called by llama.cpp DLL on unload
; ----------------------------------------------------------------------------
snmalloc_library_shutdown PROC
    xor     rax, rax        ; Nothing to clean up
    ret
snmalloc_library_shutdown ENDP

; ----------------------------------------------------------------------------
; sn_malloc — allocate memory
; RCX = size
; Returns: RAX = pointer to allocated block
; ----------------------------------------------------------------------------
sn_malloc PROC
    mov     rcx, rcx        ; size already in RCX (Microsoft x64 calling convention)
    jmp     malloc          ; Forward to CRT malloc
sn_malloc ENDP

; ----------------------------------------------------------------------------
; sn_free — deallocate memory
; RCX = pointer
; ----------------------------------------------------------------------------
sn_free PROC
    mov     rcx, rcx        ; pointer already in RCX
    jmp     free            ; Forward to CRT free
sn_free ENDP

; ----------------------------------------------------------------------------
; sn_realloc — reallocate memory
; RCX = pointer
; RDX = new size
; Returns: RAX = pointer to reallocated block
; ----------------------------------------------------------------------------
sn_realloc PROC
    mov     rcx, rcx        ; pointer in RCX
    mov     rdx, rdx        ; size in RDX
    jmp     realloc         ; Forward to CRT realloc
sn_realloc ENDP

; ----------------------------------------------------------------------------
; sn_calloc — allocate zeroed memory
; RCX = count
; RDX = size
; Returns: RAX = pointer to allocated block
; ----------------------------------------------------------------------------
sn_calloc PROC
    mov     rcx, rcx        ; count in RCX
    mov     rdx, rdx        ; size in RDX
    jmp     calloc          ; Forward to CRT calloc
sn_calloc ENDP

; ----------------------------------------------------------------------------
; sn_malloc_aligned — allocate aligned memory
; RCX = size
; RDX = alignment
; Returns: RAX = pointer to allocated block
; ----------------------------------------------------------------------------
sn_malloc_aligned PROC
    push    rbx
    mov     rbx, rdx        ; alignment
    add     rcx, rbx        ; size + alignment
    sub     rsp, 32         ; shadow space
    call    malloc
    add     rsp, 32
    test    rax, rax
    jz      @F
    ; Align the pointer: (rax + alignment) & ~(alignment - 1)
    lea     rcx, [rax + rbx]
    dec     rbx
    not     rbx
    and     rcx, rbx
    mov     rax, rcx
@@: pop     rbx
    ret
sn_malloc_aligned ENDP

; ----------------------------------------------------------------------------
; sn_free_aligned — deallocate aligned memory
; RCX = pointer
; ----------------------------------------------------------------------------
sn_free_aligned PROC
    mov     rcx, rcx        ; pointer in RCX
    jmp     free            ; CRT free handles aligned blocks too
sn_free_aligned ENDP

; ----------------------------------------------------------------------------
; Import CRT functions
; ----------------------------------------------------------------------------
    EXTERN malloc  : PROC
    EXTERN free    : PROC
    EXTERN realloc : PROC
    EXTERN calloc  : PROC

END
