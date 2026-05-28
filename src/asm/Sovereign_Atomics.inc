; ==================================================================================
; ATOMIC MEMORY MODEL - PARITY LAYER
; ==================================================================================

CACHELINE EQU 64

; ------------------------------
; SPINLOCK WITH BACKOFF
; ------------------------------
ACQUIRE_LOCK MACRO addr
LOCAL spin
spin:
    mov eax, 0
    mov ecx, 1
    lock cmpxchg dword ptr [addr], ecx
    jz acquired

    pause
    pause
    jmp spin

acquired:
    lfence
ENDM

; ------------------------------
; RELEASE LOCK
; ------------------------------
RELEASE_LOCK MACRO addr
    sfence
    mov dword ptr [addr], 0
ENDM

; ------------------------------
; FULL BARRIER
; ------------------------------
MEM_BARRIER MACRO
    mfence
ENDM

; ------------------------------
; CACHELINE PAD STRUCTURE
; ------------------------------
CACHE_PAD STRUCT
    db CACHELINE DUP(?)
CACHE_PAD ENDS
