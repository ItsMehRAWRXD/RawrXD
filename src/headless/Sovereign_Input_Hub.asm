; =========================================================================================
; SOVEREIGN INPUT HUB
; Win32 Raw Input API vector processor.
; Decouples OS window event messaging streams from lockstep tape entry updates.
; Captures direct mouse and keyboard hardware packets through WM_INPUT handles.
; =========================================================================================

OPTION CASEMAP:NONE

EXTERN RegisterRawInputDevices:PROC
EXTERN GetRawInputData:PROC

PUBLIC XR_Input_Register_Devices
PUBLIC XR_Input_Parse_Message
PUBLIC g_Raw_Input_Device_Base
PUBLIC g_Input_Buffer_Bytes
PUBLIC g_Mouse_Delta_X
PUBLIC g_Mouse_Delta_Y
PUBLIC g_Keyboard_State_Bitmask

; =========================================================================================
; CONFIG / WIN32 RAW INPUT CONSTANTS
; =========================================================================================

RID_INPUT                 EQU 10000003h
RIM_TYPEMOUSE             EQU 0
RIM_TYPEKEYBOARD          EQU 1
RI_KEY_BREAK              EQU 01h
RAWINPUTHEADER_BYTES      EQU 18h
MAX_RAWINPUT_STACK_BYTES  EQU 10000h

RAWINPUT_DATA_OFFSET      EQU RAWINPUTHEADER_BYTES
RAWMOUSE_LASTX_OFFSET     EQU RAWINPUT_DATA_OFFSET + 12
RAWMOUSE_LASTY_OFFSET     EQU RAWINPUT_DATA_OFFSET + 16
RAWKEYBOARD_FLAGS_OFFSET  EQU RAWINPUT_DATA_OFFSET + 2
RAWKEYBOARD_VKEY_OFFSET   EQU RAWINPUT_DATA_OFFSET + 6

RAWINPUTDEVICE STRUCT
    usUsagePage WORD ?
    usUsage     WORD ?
    dwFlags     DWORD ?
    hwndTarget  QWORD ?
RAWINPUTDEVICE ENDS

.DATA
    ALIGN 16
    g_Raw_Input_Devices     RAWINPUTDEVICE 2 DUP(<>)
    g_Raw_Input_Device_Base dq 0

    ALIGN 8
    g_Input_Buffer_Bytes     dd 0
    g_Mouse_Delta_X          dd 0
    g_Mouse_Delta_Y          dd 0
    g_Keyboard_State_Bitmask dq 4 DUP(0)

.CODE

; -----------------------------------------------------------------------------------------
; XR_Input_Register_Devices
; RCX = target HWND
; Returns RAX = registration status (1 = nominal, 0 = registration failure)
; -----------------------------------------------------------------------------------------
ALIGN 16
XR_Input_Register_Devices PROC
    sub rsp, 28h

    lea r10, g_Raw_Input_Devices
    mov [g_Raw_Input_Device_Base], r10

    mov word ptr [r10], 01h
    mov word ptr [r10 + 2], 02h
    mov dword ptr [r10 + 4], 0
    mov [r10 + 8], rcx

    mov word ptr [r10 + 16], 01h
    mov word ptr [r10 + 18], 06h
    mov dword ptr [r10 + 20], 0
    mov [r10 + 24], rcx

    lea rcx, g_Raw_Input_Devices
    mov edx, 2
    mov r8d, SIZEOF RAWINPUTDEVICE
    call RegisterRawInputDevices

    test eax, eax
    jz @@registration_fault

    mov eax, 1
    add rsp, 28h
    ret

@@registration_fault:
    xor eax, eax
    add rsp, 28h
    ret
XR_Input_Register_Devices ENDP

; -----------------------------------------------------------------------------------------
; XR_Input_Parse_Message
; RCX = lParam/HRAWINPUT handle from active WM_INPUT window message router
; Returns RAX = parse status (1 = consumed supported packet, 0 = ignored or failed)
; -----------------------------------------------------------------------------------------
ALIGN 16
XR_Input_Parse_Message PROC
    push rbp
    mov rbp, rsp
    push r12
    sub rsp, 38h

    mov [rbp - 16], rcx

    mov qword ptr [rsp + 20h], RAWINPUTHEADER_BYTES
    mov rcx, [rbp - 16]
    mov edx, RID_INPUT
    xor r8d, r8d
    lea r9, g_Input_Buffer_Bytes
    call GetRawInputData
    cmp eax, 0FFFFFFFFh
    je @@parse_fail

    mov eax, [g_Input_Buffer_Bytes]
    test eax, eax
    jz @@parse_fail
    cmp eax, MAX_RAWINPUT_STACK_BYTES
    ja @@parse_fail

    mov ecx, eax
    add rcx, 15
    and rcx, -16
    sub rsp, rcx
    mov r12, rsp

    mov qword ptr [rsp + 20h], RAWINPUTHEADER_BYTES
    mov rcx, [rbp - 16]
    mov edx, RID_INPUT
    mov r8, r12
    lea r9, g_Input_Buffer_Bytes
    call GetRawInputData
    cmp eax, 0FFFFFFFFh
    je @@parse_fail

    mov eax, dword ptr [r12]
    cmp eax, RIM_TYPEMOUSE
    je @@process_raw_mouse
    cmp eax, RIM_TYPEKEYBOARD
    je @@process_raw_keyboard
    jmp @@parse_fail

@@process_raw_mouse:
    mov eax, dword ptr [r12 + RAWMOUSE_LASTX_OFFSET]
    lock add dword ptr [g_Mouse_Delta_X], eax
    mov eax, dword ptr [r12 + RAWMOUSE_LASTY_OFFSET]
    lock add dword ptr [g_Mouse_Delta_Y], eax
    mov eax, 1
    jmp @@parse_exit

@@process_raw_keyboard:
    movzx eax, word ptr [r12 + RAWKEYBOARD_VKEY_OFFSET]
    cmp eax, 255
    ja @@parse_fail

    movzx edx, word ptr [r12 + RAWKEYBOARD_FLAGS_OFFSET]
    mov r10, rax
    shr r10, 6
    mov ecx, eax
    and ecx, 3Fh

    mov r8, 1
    shl r8, cl
    lea r11, g_Keyboard_State_Bitmask

    test edx, RI_KEY_BREAK
    jnz @@key_release_state

    lock or qword ptr [r11 + r10 * 8], r8
    mov eax, 1
    jmp @@parse_exit

@@key_release_state:
    not r8
    lock and qword ptr [r11 + r10 * 8], r8
    mov eax, 1
    jmp @@parse_exit

@@parse_fail:
    xor eax, eax

@@parse_exit:
    lea rsp, [rbp - 8]
    pop r12
    pop rbp
    ret
XR_Input_Parse_Message ENDP

END