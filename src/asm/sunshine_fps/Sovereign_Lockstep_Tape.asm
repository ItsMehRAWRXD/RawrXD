; Sovereign_Lockstep_Tape.asm
; x64 MASM — Zero Dependency
; Monotonic circular buffer for 20-byte Sovereign_Input_Frame
; Single producer (Tick Master), single consumer (replay/serializer)

.data
    ALIGN 16
    ; 8192 frames = ~136 seconds at 60Hz. Power of 2 for mask indexing.
    TAPE_FRAME_CAP      EQU     8192
    TAPE_BYTE_CAP       EQU     8192 * 20     ; 163840 bytes

    tape_buffer         DB      TAPE_BYTE_CAP DUP(0)
    tape_write_idx      DQ      0              ; Monotonic (never decrements)
    tape_read_idx       DQ      0              ; Monotonic consumer cursor
    tape_recording      DB      0              ; 1 = active

.code

; -------------------------------------------------------------------
; Sovereign_Tape_Init
; Call once before first tick. Clears state, does NOT zero buffer.
; -------------------------------------------------------------------
Sovereign_Tape_Init PROC
    mov     qword ptr [tape_write_idx], 0
    mov     qword ptr [tape_read_idx], 0
    mov     byte ptr [tape_recording], 1
    ret
Sovereign_Tape_Init ENDP

; -------------------------------------------------------------------
; Sovereign_Tape_Reset
; Stops recording, preserves buffer for readout.
; -------------------------------------------------------------------
Sovereign_Tape_Reset PROC
    mov     byte ptr [tape_recording], 0
    ret
Sovereign_Tape_Reset ENDP

; -------------------------------------------------------------------
; Sovereign_Tape_Append
; Input:  RCX = pointer to 20-byte Sovereign_Input_Frame
;         Assumes tape_recording == 1
; Output: None
; Clobbers: rax, rdx, rsi, rdi
; -------------------------------------------------------------------
Sovereign_Tape_Append PROC
    push    rsi
    push    rdi

    ; Compute write offset: (write_idx & (CAP-1)) * 20
    mov     rax, [tape_write_idx]
    and     rax, (TAPE_FRAME_CAP - 1)
    mov     rdx, 20
    mul     rdx
    lea     rdi, [tape_buffer]
    add     rdi, rax

    ; Copy 20 bytes: 2x movsq (16) + 1x movsd (4) — wait, movsq uses rcx.
    ; Manual quad + dword copy to avoid clobbering rcx.
    mov     rsi, rcx
    mov     rax, [rsi]          ; bytes 0-7
    mov     [rdi], rax
    mov     rax, [rsi+8]        ; bytes 8-15
    mov     [rdi+8], rax
    mov     eax, [rsi+16]       ; bytes 16-19
    mov     [rdi+16], eax

    inc     qword ptr [tape_write_idx]

    pop     rdi
    pop     rsi
    ret
Sovereign_Tape_Append ENDP

; -------------------------------------------------------------------
; Sovereign_Tape_Read
; Input:  RCX = destination buffer (20 bytes)
; Output: RAX = 1 if frame returned, 0 if no new data
; Clobbers: rdx, rsi, rdi
; -------------------------------------------------------------------
Sovereign_Tape_Read PROC
    push    rsi
    push    rdi

    mov     rax, [tape_read_idx]
    cmp     rax, [tape_write_idx]
    jae     L_empty

    ; Compute read offset
    and     rax, (TAPE_FRAME_CAP - 1)
    mov     rdx, 20
    mul     rdx
    lea     rsi, [tape_buffer]
    add     rsi, rax

    ; Copy 20 bytes to destination
    mov     rdi, rcx
    mov     rax, [rsi]
    mov     [rdi], rax
    mov     rax, [rsi+8]
    mov     [rdi+8], rax
    mov     eax, [rsi+16]
    mov     [rdi+16], eax

    inc     qword ptr [tape_read_idx]
    mov     rax, 1
    jmp     L_done

L_empty:
    xor     rax, rax

L_done:
    pop     rdi
    pop     rsi
    ret
Sovereign_Tape_Read ENDP

; -------------------------------------------------------------------
; Sovereign_Tape_Count
; Output: RAX = unread frame count (write - read)
; -------------------------------------------------------------------
Sovereign_Tape_Count PROC
    mov     rax, [tape_write_idx]
    sub     rax, [tape_read_idx]
    ret
Sovereign_Tape_Count ENDP

PUBLIC  Sovereign_Tape_Init
PUBLIC  Sovereign_Tape_Reset
PUBLIC  Sovereign_Tape_Append
PUBLIC  Sovereign_Tape_Read
PUBLIC  Sovereign_Tape_Count

END
