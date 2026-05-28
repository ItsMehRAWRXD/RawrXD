; ==================================================================================
; SOVEREIGN STREAMING BRIDGE
; File: Sovereign_StreamBridge.asm
; Role: Zero-copy GGUF tensor materialization layer
; Depends: Sovereign_Allocator.asm, FrameABI, Atomics
; ==================================================================================

include Sovereign_Common.inc
include Sovereign_FrameABI.inc
include Sovereign_Atomics.inc
include Sovereign_Allocator.inc

.DATA
ALIGN 64

g_MappedView        QWORD 0
g_ModelSize         QWORD 0
g_TensorBaseOffset  QWORD 0

; Optional: DAG binding table (offset → runtime pointer)
g_TensorRegistry    QWORD 0

.CODE

; ==================================================================================
; Sovereign_Stream_Init
; Maps GGUF file into virtual memory (zero-copy base layer)
; RCX = hFile
; ==================================================================================
PUBLIC Sovereign_Stream_Init
Sovereign_Stream_Init PROC
    ENTER_FRAME

    ; Create file mapping object
    mov r8, 0
    mov r9, PAGE_READONLY

    sub rsp, 32
    mov qword ptr [rsp+32], 0
    mov qword ptr [rsp+40], 0
    mov qword ptr [rsp+48], 0

    call [g_ApiTable.pCreateFileMappingA]

    test rax, rax
    jz @@Fail

    ; Map full view
    mov rcx, rax
    mov rdx, FILE_MAP_READ
    xor r8, r8
    xor r9, r9

    sub rsp, 32
    mov qword ptr [rsp+32], 0
    call [g_ApiTable.pMapViewOfFile]

    test rax, rax
    jz @@Fail

    mov [g_MappedView], rax

    EXIT_FRAME
    ret

@@Fail:
    xor rax, rax
    EXIT_FRAME
    ret
Sovereign_Stream_Init ENDP


; ==================================================================================
; Sovereign_Stream_GetTensor
; RCX = offset in file
; RDX = size
; Returns: RAX = aligned pointer (direct or allocated copy)
; ==================================================================================
PUBLIC Sovereign_Stream_GetTensor
Sovereign_Stream_GetTensor PROC
    ENTER_FRAME

    mov rbx, [g_MappedView]
    add rbx, rcx              ; raw tensor pointer

    ; ------------------------------------------------------------------
    ; FAST PATH: already 64-byte aligned → zero-copy
    ; ------------------------------------------------------------------
    mov rax, rbx
    test rax, 3Fh
    jz @@Direct

    ; ------------------------------------------------------------------
    ; SLOW PATH: alignment fix via Sovereign_Alloc
    ; ------------------------------------------------------------------

    mov rcx, rdx
    call Sovereign_Alloc
    test rax, rax
    jz @@Fail

    mov rdi, rax              ; dest
    mov rsi, rbx              ; src
    mov rcx, rdx
    rep movsb

    jmp @@Done

@@Direct:
    mov rax, rbx

@@Done:
    EXIT_FRAME
    ret

@@Fail:
    xor rax, rax
    EXIT_FRAME
    ret
Sovereign_Stream_GetTensor ENDP


; ==================================================================================
; Sovereign_Stream_BindTensor
; Binds tensor into DAG-visible execution space
; RCX = offset
; RDX = size
; R8  = registry slot index
; ==================================================================================
PUBLIC Sovereign_Stream_BindTensor
Sovereign_Stream_BindTensor PROC
    ENTER_FRAME

    ; Need to preserve registers across Sovereign_Stream_GetTensor since it might call Sovereign_Alloc
    push rcx
    push rdx
    push r8

    call Sovereign_Stream_GetTensor

    pop r8
    pop rdx
    pop rcx
    
    test rax, rax
    jz @@Fail

    ; Store pointer into registry
    mov rbx, [g_TensorRegistry]
    mov [rbx + r8*8], rax

    mov rax, 1
    EXIT_FRAME
    ret

@@Fail:
    xor rax, rax
    EXIT_FRAME
    ret
Sovereign_Stream_BindTensor ENDP


; ==================================================================================
; Sovereign_Stream_Flush
; Forces memory visibility barrier for SIMD consumers
; ==================================================================================
PUBLIC Sovereign_Stream_Flush
Sovereign_Stream_Flush PROC
    mfence
    lfence
    ret
Sovereign_Stream_Flush ENDP

END
