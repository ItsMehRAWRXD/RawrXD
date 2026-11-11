; ============================================================================
; GhostParser_ScanVectorized.asm — Zero-CRT AVX2 completion marker scanner
; Replaces: C++ wcsstr loops in ghost_completion_parse.cpp
; Provides: Broadside 32-byte vectorized scan for [[COMPLETION: markers
;
; ABI: Microsoft x64 (ml64.exe)
;   RCX = const wchar_t* buffer  (source text)
;   RDX = size_t bufferLen       (length in wchar_t units)
;   R8  = GhostCompletionPayload* outPayloads (output array)
;   R9  = size_t maxPayloads     (capacity of outPayloads)
; Returns: RAX = number of completions found (0..maxPayloads)
;
; Build: ml64.exe /c /W3 /nologo /Zi /Fo GhostParser_ScanVectorized.obj GhostParser_ScanVectorized.asm
; ============================================================================
option casemap:none

MARKER_LEN      EQU 13          ; "[[COMPLETION:" in wchar_t units
MARKER_BYTES    EQU 26          ; 13 * 2
END_MARKER_LEN  EQU 2           ; "]]" in wchar_t units
MIN_MATCH_LEN   EQU 17          ; MARKER_LEN + 1 char + END_MARKER_LEN

; GhostCompletionPayload layout (packed, 32-byte aligned)
PAYLOAD_TEXT    EQU 0           ; wchar_t* text pointer
PAYLOAD_START   EQU 8           ; int startPos
PAYLOAD_END     EQU 12          ; int endPos
PAYLOAD_CONF    EQU 16          ; float confidence
PAYLOAD_SIZE    EQU 24          ; sizeof(GhostCompletionPayload)

.data
    ALIGN 16
    ; UTF-16LE pattern for "[[COMPLETION:" (first 8 wchar_t units = 16 bytes)
    marker_utf16 db 5Bh, 00h, 5Bh, 00h, 43h, 00h, 4Fh, 00h
                 db 4Dh, 00h, 50h, 00h, 4Ch, 00h, 45h, 00h
    
    ; Broadcast '[' (0x005B) for AVX2 comparison
    ALIGN 16
    broadcast_bracket dw 16 dup (005Bh)

.code

; ============================================================================
; PUBLIC EXPORTS
; ============================================================================
PUBLIC GhostParser_ScanVectorized
PUBLIC GhostParser_ScanVectorized_AVX512

; ============================================================================
; VerifyMarker — Scalar verification of "[[COMPLETION:" at buffer[pos]
;   RCX = buffer pointer
;   RDX = position (in wchar_t units)
;   R8  = remaining length in wchar_t units
; Returns: RAX = 1 if valid marker, 0 otherwise
; ============================================================================
VerifyMarker PROC PRIVATE
    push    rbx
    push    rdi
    
    ; Check remaining length
    cmp     r8, MIN_MATCH_LEN
    jl      NoMatch
    
    lea     rbx, [rcx + rdx*2]      ; rbx = candidate address
    lea     rdi, marker_utf16
    
    ; Compare first 8 wchar_t units (16 bytes)
    movdqu  xmm0, xmmword ptr [rbx]
    movdqu  xmm1, xmmword ptr [rdi]
    pcmpeqw xmm0, xmm1
    pmovmskb eax, xmm0
    cmp     eax, 0FFFFh
    jne     NoMatch
    
    ; Compare "ETION:" (6 wchar_t units = 12 bytes at offset 16)
    ; UTF-16LE dword layout: low-word first char, high-word second char
    mov     eax, dword ptr [rbx + 16]
    cmp     eax, 00540045h          ; 'E'(0045) 'T'(0054) in LE → dword = 00540045h
    jne     NoMatch
    mov     eax, dword ptr [rbx + 20]
    cmp     eax, 004F0049h          ; 'I'(0049) 'O'(004F) in LE → dword = 004F0049h
    jne     NoMatch
    mov     eax, dword ptr [rbx + 24]
    cmp     eax, 003A004Eh          ; 'N'(004E) ':'(003A) in LE → dword = 003A004Eh
    jne     NoMatch
    
    mov     rax, 1
    pop     rdi
    pop     rbx
    ret
    
NoMatch:
    xor     rax, rax
    pop     rdi
    pop     rbx
    ret
VerifyMarker ENDP

; ============================================================================
; ExtractContent — Find closing "]]" and extract content
;   RCX = buffer pointer
;   RDX = marker start position (in wchar_t units)
;   R8  = buffer length (in wchar_t units)
;   R9  = output payload pointer
; Returns: RAX = content length in wchar_t units, 0 if no closing marker
; ============================================================================
ExtractContent PROC PRIVATE
    push    rbx
    push    rdi
    push    rsi
    
    mov     rbx, rcx                ; rbx = buffer
    mov     rdi, rdx                ; rdi = marker start
    mov     rsi, r8                 ; rsi = buffer length
    mov     r10, r9                 ; r10 = output payload
    
    ; Content starts after "[[COMPLETION:" (13 wchar_t units)
    lea     rcx, [rdi + MARKER_LEN]
    cmp     rcx, rsi
    jge     ExtractFail
    
    ; Scan for closing "]]"
    mov     rdx, rcx                ; rdx = content start position
    
FindClose:
    cmp     rcx, rsi
    jge     ExtractFail
    movzx   eax, word ptr [rbx + rcx*2]
    cmp     ax, 005Dh               ; ']'
    jne     NextClose
    ; Check next char is also ']'
    lea     r11, [rcx + 1]
    cmp     r11, rsi
    jge     ExtractFail
    movzx   eax, word ptr [rbx + r11*2]
    cmp     ax, 005Dh
    jne     NextClose
    
    ; Found closing "]]" — calculate content
    mov     r8, rcx                 ; r8 = close position
    sub     r8, rdx                 ; r8 = content length
    jle     ExtractFail             ; Empty content
    
    ; Write payload
    ; text pointer = buffer + content_start * 2
    lea     rax, [rbx + rdx*2]
    mov     qword ptr [r10 + PAYLOAD_TEXT], rax
    mov     dword ptr [r10 + PAYLOAD_START], edi
    mov     eax, edi
    add     eax, MARKER_LEN
    add     eax, r8d
    add     eax, END_MARKER_LEN
    mov     dword ptr [r10 + PAYLOAD_END], eax
    mov     dword ptr [r10 + PAYLOAD_CONF], 03F59999Ah  ; 0.85f IEEE 754
    
    mov     rax, r8                 ; Return content length
    pop     rsi
    pop     rdi
    pop     rbx
    ret
    
NextClose:
    inc     rcx
    jmp     FindClose
    
ExtractFail:
    xor     rax, rax
    pop     rsi
    pop     rdi
    pop     rbx
    ret
ExtractContent ENDP

; ============================================================================
; GhostParser_ScanVectorized — AVX2 broadside scanner
;   RCX = const wchar_t* buffer
;   RDX = size_t bufferLen (wchar_t units)
;   R8  = GhostCompletionPayload* outPayloads
;   R9  = size_t maxPayloads
; Returns: RAX = number of completions found
; ============================================================================
GhostParser_ScanVectorized PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 32
    .allocstack 32
    .endprolog
    
    mov     r12, rcx                ; r12 = buffer
    mov     r13, rdx                ; r13 = bufferLen
    mov     r14, r8                 ; r14 = outPayloads
    mov     r15, r9                 ; r15 = maxPayloads
    xor     rsi, rsi                ; rsi = found count
    
    ; Check minimum length
    cmp     r13, MIN_MATCH_LEN
    jl      Done
    
    ; Calculate scan limit (leave room for marker + trailing)
    mov     rdi, r13
    sub     rdi, MIN_MATCH_LEN - 1
    
    ; Load broadcast '[' pattern into YMM
    vmovdqu ymm0, ymmword ptr [broadcast_bracket]
    
    ; Main AVX2 scan loop — process 16 wchar_t units per iteration
    xor     rbx, rbx                ; rbx = current position
    
ScanLoop16:
    cmp     rbx, rdi
    jge     ScanTail
    
    ; Load 16 wchar_t units (32 bytes) from buffer[rbx]
    vmovdqu ymm1, ymmword ptr [r12 + rbx*2]
    
    ; Compare with broadcast '[' (0x005B)
    vpcmpeqw ymm2, ymm1, ymm0
    
    ; Extract match mask (16 bits, one per wchar_t unit)
    vpmovmskb eax, ymm2
    test    eax, eax
    jz      NextBlock               ; No '[' in this block
    
    ; Iterate through set bits in the mask
    mov     ecx, eax                ; ecx = match mask
    mov     r8d, ebx                ; r8d = block base position
    
BitLoop:
    bsf     edx, ecx                ; edx = index of first set bit
    jz      NextBlock               ; No more set bits
    
    ; Clear the bit we just found
    btr     ecx, edx
    
    ; Calculate absolute position
    mov     r10d, r8d
    add     r10d, edx               ; r10 = candidate position
    
    ; Save match mask (ecx) before call (rcx is volatile)
    mov     dword ptr [rsp + 8], ecx
    
    ; Verify full marker at this position
    mov     rcx, r12
    mov     rdx, r10
    mov     r8, r13
    sub     r8, r10                 ; remaining length from candidate
    call    VerifyMarker
    
    ; Restore match mask
    mov     ecx, dword ptr [rsp + 8]
    
    test    rax, rax
    jz      BitLoop                 ; Not a real marker
    
    ; Found valid marker — extract content
    cmp     rsi, r15
    jge     Done                    ; Output array full
    
    ; Calculate output payload address
    mov     rax, rsi
    imul    rax, PAYLOAD_SIZE
    lea     r9, [r14 + rax]
    mov     qword ptr [rsp + 0], r9 ; Save payload address (r9 is volatile)
    
    ; Save match mask before call
    mov     dword ptr [rsp + 8], ecx
    
    mov     rcx, r12
    mov     rdx, r10
    mov     r8, r13
    call    ExtractContent
    
    ; Restore match mask
    mov     ecx, dword ptr [rsp + 8]
    
    test    rax, rax
    jz      BitLoop                 ; Extraction failed
    
    inc     rsi                     ; Found count++
    
    ; Advance past this completion to avoid overlapping matches
    mov     r9, qword ptr [rsp + 0] ; Restore payload address
    mov     ebx, dword ptr [r9 + PAYLOAD_END]
    jmp     ScanLoop16
    
NextBlock:
    add     rbx, 16
    jmp     ScanLoop16
    
    ; Scalar tail scan for remaining bytes
ScanTail:
    cmp     rbx, rdi
    jge     Done
    
TailLoop:
    cmp     rbx, rdi
    jge     Done
    
    movzx   eax, word ptr [r12 + rbx*2]
    cmp     ax, 005Bh
    jne     TailNext
    
    ; Verify marker
    mov     rcx, r12
    mov     rdx, rbx
    mov     r8, r13
    sub     r8, rbx
    call    VerifyMarker
    test    rax, rax
    jz      TailNext
    
    ; Extract content
    cmp     rsi, r15
    jge     Done
    
    mov     rax, rsi
    imul    rax, PAYLOAD_SIZE
    lea     r9, [r14 + rax]
    mov     qword ptr [rsp + 0], r9 ; Save payload address (r9 is volatile)
    
    mov     rcx, r12
    mov     rdx, rbx
    mov     r8, r13
    call    ExtractContent
    test    rax, rax
    jz      TailNext
    
    inc     rsi
    mov     r9, qword ptr [rsp + 0] ; Restore payload address
    mov     ebx, dword ptr [r9 + PAYLOAD_END]
    jmp     TailLoop
    
TailNext:
    inc     rbx
    jmp     TailLoop
    
Done:
    mov     rax, rsi                ; Return found count
    
    vzeroupper                      ; Required after using YMM registers
    add     rsp, 32
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GhostParser_ScanVectorized ENDP

; ============================================================================
; GhostParser_ScanVectorized_AVX512 — AVX-512 version for Zen 4+
; Processes 32 wchar_t units per iteration using ZMM registers
; ============================================================================
GhostParser_ScanVectorized_AVX512 PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    ; Save parameters BEFORE cpuid/xgetbv clobber them
    mov     r12, rcx                ; r12 = buffer
    mov     r13, rdx                ; r13 = bufferLen
    mov     r14, r8                 ; r14 = outPayloads
    mov     r15, r9                 ; r15 = maxPayloads
    
    ; Check CPU feature gate inline (AVX-512F + OS XSAVE + ZMM state)
    ; Step 1: Check CPUID leaf 1 ECX[27] = OSXSAVE
    mov     eax, 1
    xor     ecx, ecx
    cpuid
    test    ecx, 08000000h          ; bit 27 = OSXSAVE
    jz      Fallback_AVX2
    
    ; Step 2: Check XCR0 ZMM state (bits 5,6,7)
    xor     ecx, ecx
    xgetbv
    and     eax, 0E0h               ; bits 5,6,7
    cmp     eax, 0E0h
    jne     Fallback_AVX2
    
    ; Step 3: Check CPUID leaf 7 EBX[16] = AVX-512F
    mov     eax, 7
    xor     ecx, ecx
    cpuid
    test    ebx, 010000h            ; bit 16 = AVX-512F
    jz      Fallback_AVX2
    
    xor     rsi, rsi                ; rsi = found count
    
    cmp     r13, MIN_MATCH_LEN
    jl      Done_AVX512
    
    mov     rdi, r13
    sub     rdi, MIN_MATCH_LEN - 1
    
    ; Broadcast '[' into ZMM register
    vpbroadcastw zmm0, word ptr [broadcast_bracket]
    
    xor     rbx, rbx
    
ScanLoop32:
    cmp     rbx, rdi
    jge     ScanTail_AVX512
    
    ; Load 32 wchar_t units (64 bytes)
    vmovdqu16 zmm1, zmmword ptr [r12 + rbx*2]
    
    ; Compare with '['
    vpcmpeqw k1, zmm1, zmm0
    
    ; Extract mask (32 bits)
    kmovd   eax, k1
    test    eax, eax
    jz      NextBlock32
    
    ; Iterate through set bits
    mov     ecx, eax
    mov     r8d, ebx
    
BitLoop32:
    bsf     edx, ecx
    jz      NextBlock32
    
    ; Clear the bit we just found
    btr     ecx, edx
    
    mov     r10d, r8d
    add     r10d, edx
    
    ; Save match mask before call (rcx is volatile)
    mov     dword ptr [rsp + 8], ecx
    
    mov     rcx, r12
    mov     rdx, r10
    mov     r8, r13
    sub     r8, r10
    call    VerifyMarker
    
    ; Restore match mask
    mov     ecx, dword ptr [rsp + 8]
    
    test    rax, rax
    jz      BitLoop32
    
    cmp     rsi, r15
    jge     Done_AVX512
    
    mov     rax, rsi
    imul    rax, PAYLOAD_SIZE
    lea     r9, [r14 + rax]
    mov     qword ptr [rsp + 0], r9 ; Save payload address (r9 is volatile)
    
    ; Save match mask before call
    mov     dword ptr [rsp + 8], ecx
    
    mov     rcx, r12
    mov     rdx, r10
    mov     r8, r13
    call    ExtractContent
    
    ; Restore match mask
    mov     ecx, dword ptr [rsp + 8]
    
    test    rax, rax
    jz      BitLoop32
    
    inc     rsi
    mov     r9, qword ptr [rsp + 0] ; Restore payload address
    mov     ebx, dword ptr [r9 + PAYLOAD_END]
    jmp     ScanLoop32
    
NextBlock32:
    add     rbx, 32
    jmp     ScanLoop32
    
ScanTail_AVX512:
    ; Fall through to scalar tail
    cmp     rbx, rdi
    jge     Done_AVX512
    
TailLoop_AVX512:
    cmp     rbx, rdi
    jge     Done_AVX512
    
    movzx   eax, word ptr [r12 + rbx*2]
    cmp     ax, 005Bh
    jne     TailNext_AVX512
    
    mov     rcx, r12
    mov     rdx, rbx
    mov     r8, r13
    sub     r8, rbx
    call    VerifyMarker
    test    rax, rax
    jz      TailNext_AVX512
    
    cmp     rsi, r15
    jge     Done_AVX512
    
    mov     rax, rsi
    imul    rax, PAYLOAD_SIZE
    lea     r9, [r14 + rax]
    mov     qword ptr [rsp + 0], r9 ; Save payload address (r9 is volatile)
    
    mov     rcx, r12
    mov     rdx, rbx
    mov     r8, r13
    call    ExtractContent
    test    rax, rax
    jz      TailNext_AVX512
    
    inc     rsi
    mov     r9, qword ptr [rsp + 0] ; Restore payload address
    mov     ebx, dword ptr [r9 + PAYLOAD_END]
    jmp     TailLoop_AVX512
    
TailNext_AVX512:
    inc     rbx
    jmp     TailLoop_AVX512
    
Fallback_AVX2:
    ; CPU doesn't support AVX-512, delegate to AVX2 version
    ; Parameters already in r12-r15, need to restore to rcx-rdx-r8-r9
    mov     rcx, r12
    mov     rdx, r13
    mov     r8, r14
    mov     r9, r15
    call    GhostParser_ScanVectorized
    jmp     Exit_AVX512
    
Done_AVX512:
    mov     rax, rsi
    
Exit_AVX512:
    vzeroupper
    add     rsp, 64
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GhostParser_ScanVectorized_AVX512 ENDP

; ============================================================================
; End of module
; ============================================================================
END
