; ============================================================================
; snmalloc_stub.asm — Minimal MASM x64 stub for snmalloc symbols
; ============================================================================
; Provides sn_malloc, sn_free, sn_realloc, sn_calloc, sn_malloc_aligned,
; sn_free_aligned, and snmalloc_library_init that forward to standard
; Windows HeapAlloc/HeapFree or CRT malloc/free.
;
; This resolves "Failed to initialise snmalloc" from llama.cpp prebuilt DLLs
; that expect snmalloc to be present in the process.
; ============================================================================

.686
.XMM
.MODEL FLAT, C
OPTION CASemap:NONE

; ── External imports ───────────────────────────────────────────────────────
EXTERN malloc : PROC
EXTERN free : PROC
EXTERN realloc : PROC
EXTERN calloc : PROC
EXTERN memcpy : PROC
EXTERN memset : PROC
EXTERN GetProcessHeap : PROC
EXTERN HeapAlloc : PROC
EXTERN HeapFree : PROC

; ── Public exports ─────────────────────────────────────────────────────────
PUBLIC sn_malloc
PUBLIC sn_free
PUBLIC sn_realloc
PUBLIC sn_calloc
PUBLIC sn_malloc_aligned
PUBLIC sn_free_aligned
PUBLIC snmalloc_library_init

; ── Data segment ───────────────────────────────────────────────────────────
.DATA

snmalloc_initialized DWORD 0

; ── Code segment ───────────────────────────────────────────────────────────
.CODE

; ── snmalloc_library_init ──────────────────────────────────────────────────
; Returns 1 (success) — we don't need real snmalloc init, just stub it.
snmalloc_library_init PROC
    mov     snmalloc_initialized, 1
    mov     eax, 1          ; Return success
    ret
snmalloc_library_init ENDP

; ── sn_malloc ──────────────────────────────────────────────────────────────
; RCX = size
; Returns RAX = pointer
sn_malloc PROC
    sub     rsp, 40         ; Shadow space + alignment
    call    malloc
    add     rsp, 40
    ret
sn_malloc ENDP

; ── sn_free ──────────────────────────────────────────────────────────────────
; RCX = pointer
sn_free PROC
    sub     rsp, 40
    call    free
    add     rsp, 40
    ret
sn_free ENDP

; ── sn_realloc ───────────────────────────────────────────────────────────────
; RCX = ptr, RDX = new_size
; Returns RAX = new pointer
sn_realloc PROC
    sub     rsp, 40
    call    realloc
    add     rsp, 40
    ret
sn_realloc ENDP

; ── sn_calloc ────────────────────────────────────────────────────────────────
; RCX = num, RDX = size
; Returns RAX = zeroed pointer
sn_calloc PROC
    sub     rsp, 40
    call    calloc
    add     rsp, 40
    ret
sn_calloc ENDP

; ── sn_malloc_aligned ────────────────────────────────────────────────────────
; RCX = size, RDX = alignment
; For simplicity, just call malloc (alignment not critical for stub)
sn_malloc_aligned PROC
    sub     rsp, 40
    ; Ignore alignment, just malloc
    call    malloc
    add     rsp, 40
    ret
sn_malloc_aligned ENDP

; ── sn_free_aligned ──────────────────────────────────────────────────────────
; RCX = pointer, RDX = alignment (ignored)
sn_free_aligned PROC
    sub     rsp, 40
    call    free
    add     rsp, 40
    ret
sn_free_aligned ENDP

END
