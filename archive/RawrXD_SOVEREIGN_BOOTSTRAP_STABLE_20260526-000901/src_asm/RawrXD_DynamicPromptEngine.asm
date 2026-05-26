; =============================================================================
; RawrXD_DynamicPromptEngine.asm — MASM64 Logic Kernels (Omni-Gate)
; =============================================================================
OPTION CASEMAP:NONE

.DATA
ALIGN 16
; Keyword Vectors (16-byte padded for SIMD)
Kw_Critic   db "refactor,bad code,optimize      "
Kw_Auditor  db "vuln,exploit,bypass,cve         "
Kw_Code     db "asm,masm,compile,register       "
Kw_Casual   db "yo,sup,dude,rawrxd              "
Kw_Enterp   db "synergy,align,milestone         "

.DATA?
ALIGN 16
; The Zero-Heap Output Buffer (16KB)
Prompt_Output_Buffer db 16384 dup(?)

.CODE

; --- Forward Exports (to satisfy link against .def) ---
PUBLIC Sovereign_SIMD_Scan
PUBLIC PromptGen_Interpolate_64
PUBLIC PromptGen_AnalyzeContext

; -----------------------------------------------------------------------------
; Sovereign_SIMD_Scan (SSE4.2 Hardware Acceleration)
; RDI = Pointer to User Context, RSI = Pointer to Keyword Vector
; RDX = Context Length
; Returns: R12 = Running Score
; -----------------------------------------------------------------------------
ALIGN 16
Sovereign_SIMD_Scan PROC
    movdqu xmm0, xmmword ptr [rsi]
_scan_loop:
    cmp rdx, 16
    jl _scan_tail           ; If < 16 bytes left, fallback to byte-scan
    
    movdqu xmm1, xmmword ptr [rdi]
    pcmpestri xmm0, xmm1, 0Ch
    jc _match_found
    
    add rdi, 16
    sub rdx, 16
    jmp _scan_loop

_match_found:
    add r12, 50             ; R12 = Running Score
    add rdi, rcx
    inc rdi                 ; Advance past match
    dec rdx
    jmp _scan_loop

_scan_tail:
    ret
Sovereign_SIMD_Scan ENDP

; -----------------------------------------------------------------------------
; PromptGen_Interpolate_64 (Zero-Heap QWORD String Blast)
; RSI = Selected Template Pointer, RDI = User Context Pointer
; RDX = Context Length, R8 = Length of Selected Template
; -----------------------------------------------------------------------------
ALIGN 16
PromptGen_Interpolate_64 PROC
    lea r9, Prompt_Output_Buffer
    
    ; 1. Blast Template Prefix
    mov rcx, r8
    shr rcx, 3
    push rdi
    mov rdi, r9
    rep movsq
    mov rcx, r8
    and rcx, 7
    rep movsb
    
    ; 2. Inject Marker (:\n)
    mov ax, 0A3Ah
    stosw
    
    ; 3. Blast User Context
    pop rsi
    mov rcx, rdx
    shr rcx, 3
    rep movsq
    mov rcx, rdx
    and rcx, 7
    rep movsb
    
    ; 4. Null Terminate
    xor al, al
    stosb
    
    ; Return finalized prompt pointer in RAX
    lea rax, Prompt_Output_Buffer
    ret
PromptGen_Interpolate_64 ENDP

; -----------------------------------------------------------------------------
; PromptGen_AnalyzeContext (Omni Engine)
; RCX = textPtr, RDX = textLen
; Returns: Score in High 32, Mode in Low 32 packed into RAX
; -----------------------------------------------------------------------------
ALIGN 16
PromptGen_AnalyzeContext PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push rdi
    .pushreg rdi
    push rsi
    .pushreg rsi
    .endprolog

    mov r13, rcx    ; Original textPtr
    xor r12, r12
    
    ; Critic Mode Vector
    mov rdi, rcx
    lea rsi, Kw_Critic
    call Sovereign_SIMD_Scan
    mov r10d, r12d
    
    ; Set Output Mask (Score + Mode)
    mov ecx, 1      ; Critic Mode ID
    mov eax, r10d   ; Score
    shl rcx, 32
    or rax, rcx

    pop rsi
    pop rdi
    pop r13
    pop r12
    pop rbp
    ret
PromptGen_AnalyzeContext ENDP
END
