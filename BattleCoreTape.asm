OPTION CASEMAP:NONE

PUBLIC WriteTape
PUBLIC ReadTape
PUBLIC ClearTape
PUBLIC GetTapePtr
PUBLIC GetCurrentTick
PUBLIC SetCurrentTick

MAX_TICKS  EQU 65536
FRAME_SIZE EQU 16

; InputFrame packed layout (16 bytes)
; +00 qword tick_id
; +08 byte  w
; +09 byte  a
; +10 byte  s
; +11 byte  d
; +12 byte  mouse_dx (signed)
; +13 byte  mouse_dy (signed)
; +14 byte  fire_flag
; +15 byte  reserved

.data
ALIGN 16
InputTape      db MAX_TICKS * FRAME_SIZE dup(0)
CurrentTick    dq 0

.code

; RCX=tick index, RDX=ptr to 16-byte frame
; Returns EAX=1 on success, 0 on out-of-range
WriteTape PROC
    cmp rcx, MAX_TICKS
    jae write_fail

    mov r8, rcx
    shl r8, 4
    lea r9, InputTape
    add r9, r8

    mov rax, qword ptr [rdx]
    mov qword ptr [r9], rax
    mov rax, qword ptr [rdx + 8]
    mov qword ptr [r9 + 8], rax

    mov eax, 1
    ret

write_fail:
    xor eax, eax
    ret
WriteTape ENDP

; RCX=tick index
; Returns RAX=ptr to frame, or 0 when out-of-range
ReadTape PROC
    cmp rcx, MAX_TICKS
    jae read_fail

    mov rax, rcx
    shl rax, 4
    lea rdx, InputTape
    add rax, rdx
    ret

read_fail:
    xor eax, eax
    ret
ReadTape ENDP

; Zero whole tape and reset tick
ClearTape PROC
    push rdi
    push rcx

    lea rdi, InputTape
    mov ecx, (MAX_TICKS * FRAME_SIZE) / 8
    xor eax, eax
    rep stosq

    mov qword ptr [CurrentTick], 0

    pop rcx
    pop rdi
    ret
ClearTape ENDP

GetTapePtr PROC
    lea rax, InputTape
    ret
GetTapePtr ENDP

GetCurrentTick PROC
    mov rax, qword ptr [CurrentTick]
    ret
GetCurrentTick ENDP

; RCX = tick
SetCurrentTick PROC
    mov qword ptr [CurrentTick], rcx
    ret
SetCurrentTick ENDP

END
