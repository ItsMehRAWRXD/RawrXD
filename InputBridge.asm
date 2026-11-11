OPTION CASEMAP:NONE

EXTERN RegisterRawInputDevices : PROC
EXTERN GetRawInputData         : PROC
EXTERN WriteTape               : PROC
EXTERN GetCurrentTick          : PROC

PUBLIC Bridge_InitInput
PUBLIC Bridge_ProcessRawInput

VK_W                    EQU 57h
VK_A                    EQU 41h
VK_S                    EQU 53h
VK_D                    EQU 44h
VK_SPACE                EQU 20h

RIDEV_INPUTSINK         EQU 00000100h

RID_INPUT               EQU 10000003h

RIM_TYPEMOUSE           EQU 0
RIM_TYPEKEYBOARD        EQU 1

RI_KEY_BREAK            EQU 0001h

RI_MOUSE_LEFT_DOWN      EQU 0001h
RI_MOUSE_LEFT_UP        EQU 0002h
RI_MOUSE_RIGHT_DOWN     EQU 0004h
RI_MOUSE_RIGHT_UP       EQU 0008h
RI_MOUSE_MOVE_ABSOLUTE  EQU 0001h

RAWINPUTHEADER_SIZE     EQU 24
RAWINPUTDEVICE_SIZE     EQU 16
RAWINPUT_STACK_MAX      EQU 100h

KEYBIT_W                EQU 01h
KEYBIT_A                EQU 02h
KEYBIT_S                EQU 04h
KEYBIT_D                EQU 08h
KEYBIT_SPACE            EQU 10h

FLAG_MB1                EQU 01h
FLAG_MB2                EQU 02h

.data
ALIGN 16
; RAWINPUTDEVICE[2] for keyboard and mouse registration
RawInputDevices label byte
    dw 0001h
    dw 0006h
    dd RIDEV_INPUTSINK
    dq 0

    dw 0001h
    dw 0002h
    dd RIDEV_INPUTSINK
    dq 0

; Sovereign deterministic tape record (16 bytes)
; +0  : uint8  KeyBits
; +1  : uint8  Flags (mouse buttons)
; +2  : uint16 Padding
; +4  : int32  MouseDX
; +8  : int32  MouseDY
; +12 : uint32 Sequence
PackBuffer       db 16 dup(0)
Bridge_KeyBits   db 0
Bridge_Flags     db 0
Bridge_Pad       dw 0
Bridge_Sequence  dd 0

.code

; RCX = target HWND (or 0 for thread sink)
; Returns EAX=TRUE/FALSE from RegisterRawInputDevices
Bridge_InitInput PROC FRAME
    sub rsp, 28h
    .allocstack 28h
    .endprolog

    mov qword ptr [RawInputDevices + 8], rcx
    mov qword ptr [RawInputDevices + 24], rcx

    lea rcx, RawInputDevices
    mov edx, 2
    mov r8d, RAWINPUTDEVICE_SIZE
    call RegisterRawInputDevices

    add rsp, 28h
    ret
Bridge_InitInput ENDP

; RCX = LPARAM hRawInput from WM_INPUT
; Returns EAX = 1 when tape write succeeds, 0 otherwise
Bridge_ProcessRawInput PROC FRAME
    sub rsp, 1A8h
    .allocstack 1A8h
    .endprolog

    mov qword ptr [rsp + 28h], rcx
    mov dword ptr [rsp + 40h], 0

    ; Query required RAWINPUT payload size.
    mov rcx, qword ptr [rsp + 28h]
    mov edx, RID_INPUT
    lea r8, [rsp + 40h]
    xor r9d, r9d
    mov dword ptr [rsp + 20h], RAWINPUTHEADER_SIZE
    call GetRawInputData

    cmp eax, 0FFFFFFFFh
    je bridge_fail

    mov eax, dword ptr [rsp + 40h]
    cmp eax, RAWINPUT_STACK_MAX
    ja bridge_fail

    ; Pull the RAWINPUT payload into stack scratch buffer.
    mov rcx, qword ptr [rsp + 28h]
    mov edx, RID_INPUT
    lea r8, [rsp + 40h]
    lea r9, [rsp + 60h]
    mov dword ptr [rsp + 20h], RAWINPUTHEADER_SIZE
    call GetRawInputData

    cmp eax, 0FFFFFFFFh
    je bridge_fail

    xor eax, eax
    mov dword ptr [PackBuffer + 4], eax
    mov dword ptr [PackBuffer + 8], eax

    lea r10, [rsp + 60h]
    mov eax, dword ptr [r10 + 0]
    cmp eax, RIM_TYPEMOUSE
    je bridge_mouse
    cmp eax, RIM_TYPEKEYBOARD
    je bridge_keyboard
    jmp bridge_commit

bridge_mouse:
    movzx eax, word ptr [r10 + 24 + 0]
    test ax, RI_MOUSE_MOVE_ABSOLUTE
    jnz bridge_mouse_buttons

    mov eax, dword ptr [r10 + 24 + 12]
    mov dword ptr [PackBuffer + 4], eax
    mov eax, dword ptr [r10 + 24 + 16]
    mov dword ptr [PackBuffer + 8], eax

bridge_mouse_buttons:
    movzx eax, word ptr [r10 + 24 + 4]

    test ax, RI_MOUSE_LEFT_DOWN
    jz @F
    or byte ptr [Bridge_Flags], FLAG_MB1
@@:
    test ax, RI_MOUSE_LEFT_UP
    jz @F
    and byte ptr [Bridge_Flags], NOT FLAG_MB1
@@:
    test ax, RI_MOUSE_RIGHT_DOWN
    jz @F
    or byte ptr [Bridge_Flags], FLAG_MB2
@@:
    test ax, RI_MOUSE_RIGHT_UP
    jz @F
    and byte ptr [Bridge_Flags], NOT FLAG_MB2
@@:
    jmp bridge_commit

bridge_keyboard:
    movzx eax, word ptr [r10 + 24 + 2]
    movzx ecx, word ptr [r10 + 24 + 6]
    test ax, RI_KEY_BREAK
    jnz key_release

    cmp ecx, VK_W
    jne @F
    or byte ptr [Bridge_KeyBits], KEYBIT_W
@@:
    cmp ecx, VK_A
    jne @F
    or byte ptr [Bridge_KeyBits], KEYBIT_A
@@:
    cmp ecx, VK_S
    jne @F
    or byte ptr [Bridge_KeyBits], KEYBIT_S
@@:
    cmp ecx, VK_D
    jne @F
    or byte ptr [Bridge_KeyBits], KEYBIT_D
@@:
    cmp ecx, VK_SPACE
    jne bridge_commit
    or byte ptr [Bridge_KeyBits], KEYBIT_SPACE
    jmp bridge_commit

key_release:
    cmp ecx, VK_W
    jne @F
    and byte ptr [Bridge_KeyBits], NOT KEYBIT_W
@@:
    cmp ecx, VK_A
    jne @F
    and byte ptr [Bridge_KeyBits], NOT KEYBIT_A
@@:
    cmp ecx, VK_S
    jne @F
    and byte ptr [Bridge_KeyBits], NOT KEYBIT_S
@@:
    cmp ecx, VK_D
    jne @F
    and byte ptr [Bridge_KeyBits], NOT KEYBIT_D
@@:
    cmp ecx, VK_SPACE
    jne bridge_commit
    and byte ptr [Bridge_KeyBits], NOT KEYBIT_SPACE

bridge_commit:
    mov al, byte ptr [Bridge_KeyBits]
    mov byte ptr [PackBuffer + 0], al
    mov al, byte ptr [Bridge_Flags]
    mov byte ptr [PackBuffer + 1], al
    mov word ptr [PackBuffer + 2], 0

    mov eax, dword ptr [Bridge_Sequence]
    inc eax
    mov dword ptr [Bridge_Sequence], eax
    mov dword ptr [PackBuffer + 12], eax

    call GetCurrentTick
    mov rcx, rax
    lea rdx, PackBuffer
    call WriteTape

    add rsp, 1A8h
    ret

bridge_fail:
    xor eax, eax
    add rsp, 1A8h
    ret
Bridge_ProcessRawInput ENDP

END
