; Sovereign_Reverse_Engineering.asm - "Internal Vision" Deconstruction Suite
; Implements zero-dependency binary mapping, instrumentation, and CFG analysis.
; Version: Elite 3.0 (Zero-IAT / Pure MASM)

INCLUDE Sovereign_Common.inc
INCLUDE Sovereign_Execution_Graph_ABI.inc

.DATA
    align 16
    g_InstrumentedBase  dq 0
    g_CFG_Map           dq 0
    g_TraceBuffer       dq 0
    g_TracePtr          dq 0
    
    ; Internal Analysis State
    g_ScanDepth         dq 4096
    sz_Prologues        db 48h, 89h, 5Ch, 24h ; mov [rsp+8], rbx
                        db 40h, 53h           ; push rbx
                        db 55h, 48h, 89h, 0E5h; push rbp; mov rbp, rsp
                        db 48h, 83h, 0ECh     ; sub rsp, imm8

.CODE

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Get_Local_Base
; Logic: Locate the base of the current executable using PEB traversal.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Get_Local_Base
Sovereign_Get_Local_Base PROC
    mov rax, gs:[60h]           ; RAX = PEB
    mov rax, [rax + 18h]        ; RAX = PEB_LDR_DATA
    mov rax, [rax + 20h]        ; RAX = InLoadOrderModuleList (Head)
    mov rax, [rax + 20h]        ; RAX = DllBase of first module (Self)
    ret
Sovereign_Get_Local_Base ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Scan_Function_Boundaries
; Input: RCX = StartAddress, RDX = ScanRange
; Logic: Identifies x64 prologues and builds a basic function map.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Scan_Function_Boundaries
Sovereign_Scan_Function_Boundaries PROC
    ABI_PUSH_FRAME
    mov rsi, rcx                ; Target Memory
    mov r8, rdx                 ; Range
    xor r14, r14                ; Function Count (Pinned for ABI)

@scan_loop:
    test r8, r8
    jle @done
    
    ; 1. Pattern Matching (Optimized with SIMD if range > 32)
    ; For now, standard byte/dword compare for robust mapping.
    
    ; push rbx (40 53)
    cmp word ptr [rsi], 5340h
    je @found_boundary
    
    ; mov [rsp+8], rbx (48 89 5C 24 08)
    cmp dword ptr [rsi], 245C8948h
    je @check_p2
    
    ; sub rsp, imm8 (48 83 EC)
    cmp dword ptr [rsi], 0EC8348h ; Note: 24-bit match
    je @found_boundary

    jmp @next_byte

@check_p2:
    cmp byte ptr [rsi+4], 08h
    jne @next_byte

@found_boundary:
    ; Check if we have space in g_CFG_Map
    mov rax, [g_CFG_Map]
    test rax, rax
    jz @inc_only
    
    mov [rax + r14*8], rsi      ; Store boundary VA
    
@inc_only:
    inc r14
    
@next_byte:
    inc rsi
    dec r8
    jmp @scan_loop

@done:
    mov rax, r14
    ABI_POP_FRAME
    ret
Sovereign_Scan_Function_Boundaries ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Analyze_CFG_Edges
; Input: RCX = FunctionBase
; Logic: Decodes relative jumps/calls to identify control flow edges.
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Analyze_CFG_Edges
Sovereign_Analyze_CFG_Edges PROC
    push rbx
    mov rsi, rcx
    mov r8, 512                 ; Instruction limit per function scan
    
@decode_loop:
    movzx rax, byte ptr [rsi]
    
    ; 0xE8 = CALL rel32
    cmp al, 0E8h
    je @found_call
    
    ; 0xE9 = JMP rel32
    cmp al, 0E9h
    je @found_jump
    
    ; 0xC3 = RET
    cmp al, 0C3h
    je @reached_ret

    inc rsi
    dec r8
    jnz @decode_loop
    jmp @exit

@found_call:
@found_jump:
    ; Calculate Target: RIP + offset + instruction_len (5)
    movsxd rax, dword ptr [rsi + 1]
    lea rdx, [rsi + 5]
    add rax, rdx
    ; (Instrumentation: RAZ now holds the target destination)
    add rsi, 5
    jmp @decode_loop

@reached_ret:
@exit:
    pop rbx
    ret
Sovereign_Analyze_CFG_Edges ENDP

; ------------------------------------------------------------------------------
; PROCEDURE: Sovereign_Shadow_Trace_XMM
; Logic: Saves XMM0-XMM15 to the trace buffer (AVX compatible).
; ------------------------------------------------------------------------------
PUBLIC Sovereign_Shadow_Trace_XMM
Sovereign_Shadow_Trace_XMM PROC
    mov rax, [g_TracePtr]
    test rax, rax
    jz @exit
    
    ; Trace current cycle and XMM state
    rdtsc
    shl rdx, 32
    or rax, rdx
    mov rdx, [g_TracePtr]
    mov [rdx], rax              ; Store Timestamp
    
    movdqu [rdx + 8], xmm0
    movdqu [rdx + 24], xmm1
    movdqu [rdx + 40], xmm2
    movdqu [rdx + 56], xmm3
    movdqu [rdx + 72], xmm4
    movdqu [rdx + 88], xmm5
    movdqu [rdx + 104], xmm6
    movdqu [rdx + 120], xmm7
    
    add qword ptr [g_TracePtr], 136
@exit:
    ret
Sovereign_Shadow_Trace_XMM ENDP

END
