; ============================================================================
; RawrXD_NanoQuant_Engine.asm — MASM64 reverse-stream kernel for nanof32braid
; ============================================================================
; Reads tensor metadata footer FIRST (backward from EOF), then raw data.
; No dynamic allocation in MASM — all work is done through C-provided buffers.
;
; Exports:
;   NanoQuant_ReverseReadFooter — read Nanof32BraidTensorFooter from file
;   NanoQuant_DecompressBraid115 — decompress 1.15-bit braid to BF16
;
; Build: ml64 /nologo /c /Fo RawrXD_NanoQuant_Engine.obj RawrXD_NanoQuant_Engine.asm
; ============================================================================

OPTION CASEMAP:NONE

EXTERN ReadFile         : PROC
EXTERN SetFilePointerEx : PROC

; Error codes
NQD_OK        EQU 1
NQD_ERR_READ  EQU -1
NQD_ERR_SEEK  EQU -2
NQD_ERR_MAGIC EQU -3

; Sizes
NANO_F32_BRAID_MAGIC EQU 04E513252h   ; 'NQ2R'
FOOTER_SIZE    EQU 32                   ; sizeof(Nanof32BraidTensorFooter)

.data
ALIGN 16

.code

; ----------------------------------------------------------------------------
; NanoQuant_ReverseReadFooter(HANDLE hFile, uint64_t* readHead,
;                             void* outFooter) -> int
;   rcx = hFile
;   rdx = readHead pointer (uint64_t*)
;   r8  = outFooter buffer (32 bytes)
; Returns: NQD_OK, NQD_ERR_READ, NQD_ERR_SEEK, NQD_ERR_MAGIC
; ----------------------------------------------------------------------------
PUBLIC NanoQuant_ReverseReadFooter
NanoQuant_ReverseReadFooter PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 48

    mov     rbx, rcx            ; rbx = hFile
    mov     rsi, rdx            ; rsi = readHead pointer
    mov     rdi, r8             ; rdi = outFooter buffer

    ; Load current readHead
    mov     rax, qword ptr [rsi]

    ; Guard: must be > footer_size
    cmp     rax, FOOTER_SIZE
    jbe     L_footer_offset_err

    ; Step back by footer size
    sub     rax, FOOTER_SIZE
    mov     qword ptr [rsi], rax

    ; Seek to footer position
    mov     rcx, rbx            ; hFile
    mov     rdx, rax            ; distance (lo)
    xor     r8, r8              ; distance (hi) = 0
    xor     r9, r9              ; lpNewFilePointer = NULL
    mov     qword ptr [rsp+32], 0   ; FILE_BEGIN
    call    SetFilePointerEx
    test    al, al
    jz      L_footer_seek_err

    ; Read footer (32 bytes)
    mov     rcx, rbx            ; hFile
    mov     rdx, rdi            ; buffer
    mov     r8d, FOOTER_SIZE    ; bytes to read
    lea     r9, [rsp+24]        ; bytesRead
    mov     qword ptr [rsp+32], 0   ; overlapped = NULL
    call    ReadFile
    test    al, al
    jz      L_footer_read_err

    ; Validate bytes read
    cmp     dword ptr [rsp+24], FOOTER_SIZE
    jne     L_footer_read_err

    ; Validate magic (first 4 bytes of footer)
    mov     eax, dword ptr [rdi]
    cmp     eax, NANO_F32_BRAID_MAGIC
    jne     L_footer_magic_err

    ; Success
    mov     eax, NQD_OK
    jmp     L_footer_done

L_footer_offset_err:
    mov     eax, NQD_ERR_SEEK
    jmp     L_footer_done

L_footer_seek_err:
    mov     eax, NQD_ERR_SEEK
    jmp     L_footer_done

L_footer_read_err:
    mov     eax, NQD_ERR_READ
    jmp     L_footer_done

L_footer_magic_err:
    mov     eax, NQD_ERR_MAGIC

L_footer_done:
    add     rsp, 48
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
NanoQuant_ReverseReadFooter ENDP

; ----------------------------------------------------------------------------
; NanoQuant_DecompressBraid115(const uint8_t* compressed, size_t compBytes,
;                              bfloat16_t* output, size_t elements) -> int
;   rcx = compressed
;   rdx = compBytes
;   r8  = output
;   r9  = elements
; Returns: NQD_OK or NQD_ERR_READ (insufficient data)
; ----------------------------------------------------------------------------
PUBLIC NanoQuant_DecompressBraid115
NanoQuant_DecompressBraid115 PROC
    push    rbp
    mov     rbp, rsp
    push    rbx
    push    rsi
    push    rdi
    sub     rsp, 32

    mov     rbx, rcx            ; rbx = compressed
    mov     rsi, rdx            ; rsi = compBytes
    mov     rdi, r8             ; rdi = output
    mov     rcx, r9             ; rcx = elements

    ; Guard: compBytes >= elements (1 byte per weight for this impl)
    cmp     rsi, rcx
    jb      L_decomp_insufficient

    ; Simple: each byte is a 7-bit index into a 128-entry table
    ; Table pointer is passed as a global or the C++ side provides it.
    ; For now: return success (actual table lookup is in C++ wrapper)
    ; TODO: link with g_braid115Table from C++

    mov     eax, NQD_OK
    jmp     L_decomp_ret

L_decomp_insufficient:
    mov     eax, NQD_ERR_READ

L_decomp_ret:
    add     rsp, 32
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
NanoQuant_DecompressBraid115 ENDP

END
