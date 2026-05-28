; =====================================================================================
; SOVEREIGN CONSOLE I/O + RING BUFFER (Production Linker Resolution)
; Resolves: Sovereign_Print, Probe, Ring_Push_Atomic
; Zero CRT. Zero heap. Kernel32 only.
; ARCHITECTURE: X86-64 (MASM64)
; =====================================================================================

.DATA
    ALIGN 8
    g_hStdOut       QWORD 0
    g_hStdErr       QWORD 0
    g_ConsoleInit   BYTE  0

    STD_OUTPUT_HANDLE EQU -11
    STD_ERROR_HANDLE  EQU -12

    ; Newline constant
    szCRLF          DB 0Dh, 0Ah, 0

.CODE

; =====================================================================================
; INTERNAL: Console_Init — lazy one-time handle acquisition
; =====================================================================================
Console_Init PROC PRIVATE
    push rbx
    sub rsp, 40

    mov al, byte ptr [g_ConsoleInit]
    test al, al
    jnz ci_done

    mov ecx, STD_OUTPUT_HANDLE
    call GetStdHandle
    mov [g_hStdOut], rax

    mov ecx, STD_ERROR_HANDLE
    call GetStdHandle
    mov [g_hStdErr], rax

    mov byte ptr [g_ConsoleInit], 1

ci_done:
    add rsp, 40
    pop rbx
    ret
Console_Init ENDP

; =====================================================================================
; API: Sovereign_Print
; INPUT:  RCX = pointer to null-terminated ASCII string
; OUTPUT: RAX = bytes written, or -1 on failure
; =====================================================================================
Sovereign_Print PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 40

    call Console_Init

    mov rsi, rcx                    ; RSI = string start
    mov rdi, rcx                    ; RDI = length scan

    ; strlen inline
    xor eax, eax
    mov rcx, -1
    repne scasb
    mov rbx, rdi
    sub rbx, rsi
    dec rbx                         ; RBX = length excluding null

    ; WriteFile(g_hStdOut, buf, len, &written, NULL)
    mov rcx, [g_hStdOut]
    mov rdx, rsi
    mov r8, rbx
    lea r9, [rsp + 32]
    mov qword ptr [rsp + 48], 0
    call WriteFile

    test eax, eax
    jz sp_fail
    mov rax, qword ptr [rsp + 32]
    jmp sp_exit

sp_fail:
    mov rax, -1

sp_exit:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    ret
Sovereign_Print ENDP

; =====================================================================================
; API: Probe
; Diagnostic wrapper. Prints "[PROBE] <msg>\n" to stdout.
; INPUT:  RCX = null-terminated ASCII string
; OUTPUT: RAX = total bytes written
; =====================================================================================
Probe PROC
    push rbx
    push rsi
    sub rsp, 40

    mov rsi, rcx                    ; RSI = original message

    lea rcx, szProbePrefix
    call Sovereign_Print
    mov rbx, rax                    ; RBX = running total

    mov rcx, rsi
    call Sovereign_Print
    add rbx, rax

    lea rcx, szCRLF
    call Sovereign_Print
    add rbx, rax

    mov rax, rbx

    add rsp, 40
    pop rsi
    pop rbx
    ret
Probe ENDP

.DATA
    szProbePrefix   DB "[PROBE] ", 0

.CODE

; =====================================================================================
; API: Ring_Push_Atomic
; Lock-free single-producer ring buffer push.
; Used by Sovereign_SIMD_Scanner tail dispatch.
;
; INPUT:  RCX = ring base address (pre-allocated, aligned)
;         RDX = element size in bytes
;         R8  = pointer to source element
;         R9  = capacity (POWER OF TWO, e.g. 1024)
;         [RSP+40] = pointer to head index (volatile, updated by producer)
;         [RSP+48] = pointer to tail index (read-only for producer)
; OUTPUT: RAX = 0 (success), -1 (ring full)
; =====================================================================================
Ring_Push_Atomic PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 32

    mov rbx, rcx                    ; RBX = ring base
    mov r12, rdx                    ; R12 = element size
    mov r13, r8                     ; R13 = source element
    mov r14, r9                     ; R14 = capacity
    dec r14                         ; R14 = mask (capacity - 1)

    mov r15, qword ptr [rsp + 96]   ; R15 = head pointer
    mov rsi, qword ptr [rsp + 104]  ; RSI = tail pointer

    ; Load current head
    mov rax, qword ptr [r15]

    ; Compute next head with bitwise wrap
    lea rcx, [rax + 1]
    and rcx, r14

    ; Check full: next == tail?
    cmp rcx, qword ptr [rsi]
    je rpa_full

    ; Compute write address: base + (head * elem_size)
    mov rdx, rax
    imul rdx, r12
    lea rdi, [rbx + rdx]

    ; Copy element: qwords first, then remainder bytes
    push rsi
    push rdi
    mov rsi, r13
    mov rcx, r12
    shr rcx, 3
    rep movsq
    mov rcx, r12
    and rcx, 7
    rep movsb
    pop rdi
    pop rsi

    ; Memory fence before publishing
    sfence

    ; Advance head
    mov qword ptr [r15], rcx

    xor rax, rax
    jmp rpa_exit

rpa_full:
    mov rax, -1

rpa_exit:
    add rsp, 32
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
Ring_Push_Atomic ENDP

; =====================================================================================
; EXPORTS
; =====================================================================================
PUBLIC Sovereign_Print
PUBLIC Probe
PUBLIC Ring_Push_Atomic

; =====================================================================================
; IMPORTS
; =====================================================================================
EXTERN GetStdHandle: PROC
EXTERN WriteFile: PROC

END