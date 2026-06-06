; snmalloc_stub.asm — Sovereign snmalloc interceptor
; Exports sn_malloc / sn_free / sn_realloc / sn_calloc
; Forwards to Windows HeapAlloc / HeapFree via GetProcessHeap
; Assemble: ml64 /c /W3 /nologo /Fo snmalloc_stub.obj snmalloc_stub.asm

OPTION DOTNAME
.CODE

; ---------------------------------------------------------------------------
; Helpers
; ---------------------------------------------------------------------------
EXTERN GetProcessHeap : PROC
EXTERN HeapAlloc      : PROC
EXTERN HeapFree       : PROC
EXTERN HeapReAlloc    : PROC

; ---------------------------------------------------------------------------
; sn_malloc(size_t size) -> void*
; ---------------------------------------------------------------------------
sn_malloc PROC EXPORT FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; RCX = size (first arg)
    mov     rdx, rcx            ; RDX = size
    xor     rcx, rcx            ; RCX = 0 (GetProcessHeap has no args, but we call it)
    call    GetProcessHeap      ; RAX = heap handle
    mov     rcx, rax            ; RCX = heap handle
    mov     r8d, 8              ; R8 = HEAP_ZERO_MEMORY (0x00000008)
    call    HeapAlloc           ; RAX = allocated block

    add     rsp, 40
    ret
sn_malloc ENDP

; ---------------------------------------------------------------------------
; sn_free(void* ptr) -> void
; ---------------------------------------------------------------------------
sn_free PROC EXPORT FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; RCX = ptr (first arg)
    test    rcx, rcx
    jz      @F                  ; NULL check — skip free

    mov     rdx, rcx            ; RDX = ptr
    xor     rcx, rcx            ; RCX = 0
    call    GetProcessHeap      ; RAX = heap handle
    mov     rcx, rax            ; RCX = heap handle
    xor     r8d, r8d            ; R8 = 0 (dwFlags)
    call    HeapFree            ; free block

@@:
    add     rsp, 40
    ret
sn_free ENDP

; ---------------------------------------------------------------------------
; sn_realloc(void* ptr, size_t size) -> void*
; ---------------------------------------------------------------------------
sn_realloc PROC EXPORT FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; RCX = ptr, RDX = size
    mov     r9, rdx             ; R9 = size
    mov     rdx, rcx            ; RDX = ptr
    xor     rcx, rcx            ; RCX = 0
    call    GetProcessHeap      ; RAX = heap handle
    mov     rcx, rax            ; RCX = heap handle
    mov     r8, r9              ; R8 = size
    mov     r9d, 8              ; R9 = HEAP_ZERO_MEMORY
    call    HeapReAlloc         ; RAX = reallocated block

    add     rsp, 40
    ret
sn_realloc ENDP

; ---------------------------------------------------------------------------
; sn_calloc(size_t nmemb, size_t size) -> void*
; ---------------------------------------------------------------------------
sn_calloc PROC EXPORT FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; RCX = nmemb, RDX = size
    mov     rax, rcx
    mul     rdx                 ; RAX = total size (nmemb * size)
    mov     rdx, rax            ; RDX = total size
    xor     rcx, rcx            ; RCX = 0
    call    GetProcessHeap      ; RAX = heap handle
    mov     rcx, rax            ; RCX = heap handle
    mov     r8d, 8              ; R8 = HEAP_ZERO_MEMORY
    call    HeapAlloc           ; RAX = allocated block

    add     rsp, 40
    ret
sn_calloc ENDP

; ---------------------------------------------------------------------------
; sn_malloc_aligned(size_t size, size_t alignment) -> void*
; ---------------------------------------------------------------------------
sn_malloc_aligned PROC EXPORT FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; RCX = size, RDX = alignment
    ; For simplicity, ignore alignment and forward to sn_malloc
    ; (HeapAlloc alignment is already 8-byte on x64)
    call    sn_malloc

    add     rsp, 40
    ret
sn_malloc_aligned ENDP

; ---------------------------------------------------------------------------
; sn_free_aligned(void* ptr, size_t alignment) -> void
; ---------------------------------------------------------------------------
sn_free_aligned PROC EXPORT FRAME
    sub     rsp, 40
    .allocstack 40
    .endprolog

    ; RCX = ptr, RDX = alignment (ignored)
    call    sn_free

    add     rsp, 40
    ret
sn_free_aligned ENDP

END
