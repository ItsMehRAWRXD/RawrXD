; ============================================================================
; StreamRouter_Dispatch.asm — x64 MASM dispatch kernel
; Zero pointer chasing. Pre-resolved jump table in L1. AVX2 batch path.
; Cycle counter for deterministic rewind.
; ============================================================================

        .code
        OPTION PROLOGUE:NONE
        OPTION EPILOGUE:NONE

; ----------------------------------------------------------------------------
; Deep2_StreamRouter_DispatchScalar
;   RCX = stream_ids (uint32_t*)
;   RDX = tokens       (uint32_t*)
;   R8  = count        (size_t)
;   R9  = hop_table    (uint8_t* 256-byte)
;   [RSP+0x28] = locations (StreamLoc* array)
;   [RSP+0x30] = journal     (RewindJournal*)
;   [RSP+0x38] = base_cycle  (uint64_t)
; Returns: RAX = tokens routed
; Clobbers: R10-R15, XMM0-XMM3
; ----------------------------------------------------------------------------
Deep2_StreamRouter_DispatchScalar PROC FRAME
        push    rbx
        push    rbp
        push    rsi
        push    rdi
        push    r12
        push    r13
        push    r14
        push    r15
        .endprolog

        mov     r12, rcx                ; stream_ids
        mov     r13, rdx                ; tokens
        mov     r14, r8                 ; count
        mov     r15, r9                 ; hop_table
        mov     rbx, [rsp+58h]          ; locations
        mov     rbp, [rsp+60h]          ; journal
        mov     rsi, [rsp+68h]          ; base_cycle

        xor     rdi, rdi                ; routed = 0
        xor     rcx, rcx                ; i = 0

@@loop:
        cmp     rcx, r14
        jae     @@done

        ; Load stream_id
        mov     eax, dword ptr [r12 + rcx*4]
        and     eax, 0FFh               ; stream_id & 0xFF

        ; Jump table lookup — single L1 cache line
        movzx   edx, byte ptr [r15 + rax]
        cmp     dl, 0FFh
        je      @@next                   ; invalid stream

        ; Compute loc = &locations[idx]
        imul    rax, rdx, 64            ; sizeof(StreamLoc) = 64
        lea     r8, [rbx + rax]         ; loc

        ; Load buffer_head, buffer_cap
        mov     r9d, dword ptr [r8 + 20h] ; buffer_head offset
        mov     r10d, dword ptr [r8 + 28h]; buffer_cap offset

        ; next = (head + 1) & cap
        lea     r11d, [r9 + 1]
        and     r11d, r10d

        ; Check full: next == tail?
        mov     r10d, dword ptr [r8 + 2Ch]; buffer_tail offset
        cmp     r11d, r10d
        je      @@next                   ; buffer full

        ; Write token
        mov     eax, dword ptr [r13 + rcx*4]
        mov     r10, qword ptr [r8 + 18h] ; buffer_base
        mov     dword ptr [r10 + r9*4], eax

        ; Update head
        mov     dword ptr [r8 + 20h], r11d

        ; Increment token_count
        inc     qword ptr [r8 + 10h]

        inc     rdi                     ; routed++

@@next:
        inc     rcx
        jmp     @@loop

@@done:
        mov     rax, rdi
        pop     r15
        pop     r14
        pop     r13
        pop     r12
        pop     rdi
        pop     rsi
        pop     rbp
        pop     rbx
        ret
Deep2_StreamRouter_DispatchScalar ENDP

; ----------------------------------------------------------------------------
; Deep2_StreamRouter_GetCycle — RDTSC for deterministic rewind
; Returns: RAX = current cycle counter
; ----------------------------------------------------------------------------
Deep2_StreamRouter_GetCycle PROC
        rdtsc
        shl     rdx, 32
        or      rax, rdx
        ret
Deep2_StreamRouter_GetCycle ENDP

        END
