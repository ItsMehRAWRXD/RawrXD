; Sovereign_Input_Quantizer.asm
; Translates raw input to deterministic Sovereign_Input_Frame
; No floating point, strictly integers/fixed-point

.data
    ; The Canonical Input Structure
    ; 20 bytes uniform size
    Sovereign_Input_Frame STRUCT
        tick_id         DD  ?    ; 0-3
        buttons         DW  ?    ; 4-5
        move_x          SWORD ?  ; 6-7
        move_y          SWORD ?  ; 8-9
        look_x          SWORD ?  ; 10-11
        look_y          SWORD ?  ; 12-13
        weapon_slot     DB  ?    ; 14
        action_flags    DB  ?    ; 15
        crc             DD  ?    ; 16-19
    Sovereign_Input_Frame ENDS

    ; Raw Sub-tick Accumulators
    PUBLIC Accum_Move_X
    PUBLIC Accum_Move_Y
    PUBLIC Accum_Look_X
    PUBLIC Accum_Look_Y
    PUBLIC Accum_Buttons
    PUBLIC Accum_Weapon
    PUBLIC Accum_Action
    Accum_Move_X        SDWORD 0
    Accum_Move_Y        SDWORD 0
    Accum_Look_X        SDWORD 0
    Accum_Look_Y        SDWORD 0
    Accum_Buttons       WORD   0
    Accum_Weapon        DB     0
    Accum_Action        DB     0

.code
PUBLIC Sovereign_Input_Poll

; ========================================================================
; Sovereign_Input_Poll
; RCX = pointer to destination Sovereign_Input_Frame
; RDX = Current Tick ID
; Converts analog accumulated state to strictly clamped integer frame
; ========================================================================
Sovereign_Input_Poll PROC
    push rbx
    push rdi

    ; 1. Tick ID
    mov dword ptr [rcx], edx

    ; 2. Buttons
    movzx eax, word ptr [Accum_Buttons]
    mov word ptr [rcx + 4], ax

    ; 3. Move X/Y (Clamp to 16-bit signed)
    mov eax, dword ptr [Accum_Move_X]
    cmp eax, 32767
    jle clamp_move_x_low
    mov eax, 32767
    jmp set_move_x
clamp_move_x_low:
    cmp eax, -32768
    jge set_move_x
    mov eax, -32768
set_move_x:
    mov word ptr [rcx + 6], ax

    mov eax, dword ptr [Accum_Move_Y]
    cmp eax, 32767
    jle clamp_move_y_low
    mov eax, 32767
    jmp set_move_y
clamp_move_y_low:
    cmp eax, -32768
    jge set_move_y
    mov eax, -32768
set_move_y:
    mov word ptr [rcx + 8], ax

    ; 4. Look X/Y
    mov eax, dword ptr [Accum_Look_X]
    cmp eax, 32767
    jle clamp_look_x_low
    mov eax, 32767
    jmp set_look_x
clamp_look_x_low:
    cmp eax, -32768
    jge set_look_x
    mov eax, -32768
set_look_x:
    mov word ptr [rcx + 10], ax

    mov eax, dword ptr [Accum_Look_Y]
    cmp eax, 32767
    jle clamp_look_y_low
    mov eax, 32767
    jmp set_look_y
clamp_look_y_low:
    cmp eax, -32768
    jge set_look_y
    mov eax, -32768
set_look_y:
    mov word ptr [rcx + 12], ax

    ; 5. Action / Slot
    mov al, byte ptr [Accum_Weapon]
    mov byte ptr [rcx + 14], al

    mov al, byte ptr [Accum_Action]
    mov byte ptr [rcx + 15], al

    ; 6. Calculate Fast Validation Hash (Fowler-Noll-Vo variant / simple hash for now)
    ; Hashing bytes 0 to 15
    mov r8d, 2166136261     ; FNV offset basis
    xor r9, r9              ; Index
hash_loop:
    movzx eax, byte ptr [rcx + r9]
    xor r8d, eax
    imul r8d, 16777619      ; FNV prime
    inc r9
    cmp r9, 16
    jl hash_loop
    
    mov dword ptr [rcx + 16], r8d

    ; 7. Reset Accumulators for next tick (Keep holding states, drop deltas)
    xor eax, eax
    mov dword ptr [Accum_Move_X], eax
    mov dword ptr [Accum_Move_Y], eax
    mov dword ptr [Accum_Look_X], eax
    mov dword ptr [Accum_Look_Y], eax

    pop rdi
    pop rbx
    ret
Sovereign_Input_Poll ENDP

END

