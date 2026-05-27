; =============================================================================
; FILE: Sovereign_HID_RawInput.asm
; PURPOSE:
;   Deterministic RAWINPUT ingestion layer.
;   Mouse + keyboard accumulation pipeline.
;
; TARGET:
;   SunshineFPS deterministic lockstep runtime.
;
; NOTES:
;   - Pure x64 MASM
;   - No CRT
;   - No heap
;   - No floating point
;   - Win64 ABI compliant
;
; EXPORTS:
;   Sovereign_HID_Init
;   Sovereign_HID_Process
;
; =============================================================================

OPTION CASEMAP:NONE

EXTERN RegisterRawInputDevices:PROC
EXTERN GetRawInputData:PROC

EXTERN Accum_Move_X:DWORD
EXTERN Accum_Move_Y:DWORD
EXTERN Accum_Look_X:DWORD
EXTERN Accum_Look_Y:DWORD
EXTERN Accum_Buttons:WORD
EXTERN Accum_Action:BYTE

PUBLIC Sovereign_HID_Init
PUBLIC Sovereign_HID_Process

; =============================================================================
; CONSTANTS
; =============================================================================

RID_INPUT               EQU 10000003h

RIM_TYPEMOUSE           EQU 0
RIM_TYPEKEYBOARD        EQU 1

RI_MOUSE_LEFT_BUTTON_DOWN     EQU 0001h
RI_MOUSE_LEFT_BUTTON_UP       EQU 0002h
RI_MOUSE_RIGHT_BUTTON_DOWN    EQU 0004h
RI_MOUSE_RIGHT_BUTTON_UP      EQU 0008h
RI_MOUSE_MIDDLE_BUTTON_DOWN   EQU 0010h
RI_MOUSE_MIDDLE_BUTTON_UP     EQU 0020h

VK_W                    EQU 57h
VK_A                    EQU 41h
VK_S                    EQU 53h
VK_D                    EQU 44h
VK_SPACE                EQU 20h

; =============================================================================
; RAWINPUTDEVICE
; =============================================================================

RAWINPUTDEVICE STRUCT
    usUsagePage    DW ?
    usUsage        DW ?
    dwFlags        DD ?
    hwndTarget     DQ ?
RAWINPUTDEVICE ENDS

; =============================================================================
; RAWINPUTHEADER
; =============================================================================

RAWINPUTHEADER STRUCT
    dwType         DD ?
    dwSize         DD ?
    hDevice        DQ ?
    wParam         DQ ?
RAWINPUTHEADER ENDS

; =============================================================================
; RAWMOUSE
; =============================================================================

RAWMOUSE STRUCT
    usFlags            DW ?
    ulButtons          DD ?
    ulRawButtons       DD ?
    lLastX             DD ?
    lLastY             DD ?
    ulExtraInformation DD ?
RAWMOUSE ENDS

; =============================================================================
; RAWKEYBOARD
; =============================================================================

RAWKEYBOARD STRUCT
    MakeCode           DW ?
    Flags              DW ?
    Reserved           DW ?
    VKey               DW ?
    Message            DD ?
    ExtraInformation   DD ?
RAWKEYBOARD ENDS

; =============================================================================
; RAWINPUT
; =============================================================================

RAWINPUT STRUCT
    header      RAWINPUTHEADER <>
    union_data  DQ 8 DUP(?)
RAWINPUT ENDS

; =============================================================================
; DATA
; =============================================================================

PUBLIC RawInputDevices

.DATA

ALIGN 16

RawInputDevices:

; Mouse
RAWINPUTDEVICE <1, 2, 0, 0>

; Keyboard
RAWINPUTDEVICE <1, 6, 0, 0>

ALIGN 16

RawInputBuffer RAWINPUT <>

RawInputSize DD SIZEOF RAWINPUT

; =============================================================================
; CODE
; =============================================================================

.CODE

; =============================================================================
; Sovereign_HID_Init
; =============================================================================
Sovereign_HID_Init PROC

    sub rsp, 40h

    lea rcx, RawInputDevices
    mov edx, 2
    mov r8d, SIZEOF RAWINPUTDEVICE

    call RegisterRawInputDevices

    add rsp, 40h
    ret

Sovereign_HID_Init ENDP

; =============================================================================
; Sovereign_HID_Process
;
; RCX = HRAWINPUT
;
; =============================================================================
Sovereign_HID_Process PROC

    push rbx
    push rsi
    push rdi

    sub rsp, 40h

    mov rbx, rcx

    lea r8, RawInputBuffer
    lea r9, RawInputSize

    mov rcx, rbx
    mov edx, RID_INPUT

    mov qword ptr [rsp + 20h], SIZEOF RAWINPUTHEADER

    call GetRawInputData

    test eax, eax
    jle hid_exit

    cmp dword ptr [RawInputBuffer.header.dwType], RIM_TYPEMOUSE
    je process_mouse

    cmp dword ptr [RawInputBuffer.header.dwType], RIM_TYPEKEYBOARD
    je process_keyboard

    jmp hid_exit

; =============================================================================
; MOUSE
; =============================================================================

process_mouse:

    lea rsi, RawInputBuffer.union_data

    mov eax, dword ptr [rsi + RAWMOUSE.lLastX]
    add dword ptr [Accum_Look_X], eax

    mov eax, dword ptr [rsi + RAWMOUSE.lLastY]
    add dword ptr [Accum_Look_Y], eax

    movzx eax, word ptr [rsi + 2]

    test eax, RI_MOUSE_LEFT_BUTTON_DOWN
    jz no_lmb_down

    or word ptr [Accum_Buttons], 0001h

no_lmb_down:

    test eax, RI_MOUSE_LEFT_BUTTON_UP
    jz no_lmb_up

    and word ptr [Accum_Buttons], 0FFFEh

no_lmb_up:

    test eax, RI_MOUSE_RIGHT_BUTTON_DOWN
    jz no_rmb_down

    or word ptr [Accum_Buttons], 0002h

no_rmb_down:

    test eax, RI_MOUSE_RIGHT_BUTTON_UP
    jz no_rmb_up

    and word ptr [Accum_Buttons], 0FFFDh

no_rmb_up:

    jmp hid_exit

; =============================================================================
; KEYBOARD
; =============================================================================

process_keyboard:

    lea rsi, RawInputBuffer.union_data

    movzx eax, word ptr [rsi + RAWKEYBOARD.VKey]
    movzx ebx, word ptr [rsi + RAWKEYBOARD.Flags]

    test ebx, 1
    jnz key_release

key_press:

    cmp eax, VK_W
    jne not_w_press

    add dword ptr [Accum_Move_Y], 1024

not_w_press:

    cmp eax, VK_S
    jne not_s_press

    sub dword ptr [Accum_Move_Y], 1024

not_s_press:

    cmp eax, VK_A
    jne not_a_press

    sub dword ptr [Accum_Move_X], 1024

not_a_press:

    cmp eax, VK_D
    jne not_d_press

    add dword ptr [Accum_Move_X], 1024

not_d_press:

    cmp eax, VK_SPACE
    jne hid_exit

    or byte ptr [Accum_Action], 1

    jmp hid_exit

key_release:

    cmp eax, VK_SPACE
    jne hid_exit

    and byte ptr [Accum_Action], 0FEh

; =============================================================================

hid_exit:

    add rsp, 40h

    pop rdi
    pop rsi
    pop rbx

    ret

Sovereign_HID_Process ENDP

END