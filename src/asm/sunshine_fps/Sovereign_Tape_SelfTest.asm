; Sovereign_Tape_SelfTest.asm
; x64 MASM — Zero Dependency
; Deterministic round-trip validation. Call from entry before any HID.

.data
    test_passed     DB 0
    test_frame_1    DB 0,0,0,0,  0,0,  0,0,  0,0,  0,0,  0,0,  0,0,0,0   ; 20 bytes zero
    test_frame_2    DB 1,0,0,0,  1,0,  0,1,  0,1,  0,0,  0,0,  0,0,0,0   ; tick=1, buttons=1, move=1,1
    test_frame_3    DB 2,0,0,0,  2,0,  0,2,  0,2,  0,0,  0,0,  0,0,0,0   ; tick=2, buttons=2, move=2,2

    replay_buffer   DB 20 DUP(0)

.code
    extern Sovereign_Tape_Init:PROC
    extern Sovereign_Tape_Reset:PROC
    extern Sovereign_Tape_Append:PROC
    extern Sovereign_Tape_Read:PROC

; -------------------------------------------------------------------
; Sovereign_Tape_SelfTest
; Output: RAX = 1 if pass, 0 if fail
; Clobbers: rcx, rdx, rsi, rdi
; -------------------------------------------------------------------
Sovereign_Tape_SelfTest PROC
    push    rbx
    push    rsi
    push    rdi

    ; --- RECORD PHASE ---
    call    Sovereign_Tape_Init

    lea     rcx, [test_frame_1]
    call    Sovereign_Tape_Append

    lea     rcx, [test_frame_2]
    call    Sovereign_Tape_Append

    lea     rcx, [test_frame_3]
    call    Sovereign_Tape_Append

    ; --- PLAYBACK PHASE ---
    
    ; Frame 1
    lea     rcx, [replay_buffer]
    call    Sovereign_Tape_Read
    test    eax, eax
    jz      L_fail
    lea     rsi, [test_frame_1]
    lea     rdi, [replay_buffer]
    mov     rcx, 20
    repe    cmpsb
    jne     L_fail

    ; Frame 2
    lea     rcx, [replay_buffer]
    call    Sovereign_Tape_Read
    test    eax, eax
    jz      L_fail
    lea     rsi, [test_frame_2]
    lea     rdi, [replay_buffer]
    mov     rcx, 20
    repe    cmpsb
    jne     L_fail

    ; Frame 3
    lea     rcx, [replay_buffer]
    call    Sovereign_Tape_Read
    test    eax, eax
    jz      L_fail
    lea     rsi, [test_frame_3]
    lea     rdi, [replay_buffer]
    mov     rcx, 20
    repe    cmpsb
    jne     L_fail

    ; EOF check — next read must fail
    lea     rcx, [replay_buffer]
    call    Sovereign_Tape_Read
    test    eax, eax
    jnz     L_fail

    ; --- PASS ---
    mov     byte ptr [test_passed], 1
    mov     rax, 1
    jmp     L_done

L_fail:
    xor     rax, rax

L_done:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
Sovereign_Tape_SelfTest ENDP

PUBLIC  Sovereign_Tape_SelfTest
PUBLIC  test_passed

END