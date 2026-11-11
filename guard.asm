; guard.asm - Sovereign Binary Guard (x64)
; ABI: int GuardBinary(void* memory_base)
; Returns:
;   0 = PASS
;   1 = INVALID_HEADER
;   2 = WX_VIOLATION

option casemap:none

.code

GuardBinary proc
    ; RCX = memory base pointer
    test rcx, rcx
    jz invalid_header

    mov r8, rcx                         ; preserve image base

    ; 1) DOS header must be 'MZ'
    cmp word ptr [r8], 5A4Dh
    jne invalid_header

    ; 2) Locate NT headers via e_lfanew
    mov eax, dword ptr [r8+3Ch]
    mov r9, r8
    add r9, rax                         ; r9 -> IMAGE_NT_HEADERS64

    ; NT signature must be 'PE\0\0'
    cmp dword ptr [r9], 00004550h
    jne invalid_header

    ; NumberOfSections @ +0x06
    movzx r10d, word ptr [r9+06h]
    test r10d, r10d
    jz passed

    ; Section table = NT + 0x18 + SizeOfOptionalHeader
    movzx eax, word ptr [r9+14h]        ; SizeOfOptionalHeader
    lea r11, [r9+18h+rax]               ; r11 -> first IMAGE_SECTION_HEADER

section_loop:
    ; Characteristics @ +0x24 of IMAGE_SECTION_HEADER
    mov edx, dword ptr [r11+24h]

    ; W^X policy:
    ; IMAGE_SCN_MEM_EXECUTE = 0x20000000
    ; IMAGE_SCN_MEM_WRITE   = 0x80000000
    and edx, 0A0000000h
    cmp edx, 0A0000000h
    je wx_violation

    add r11, 28h                         ; sizeof(IMAGE_SECTION_HEADER)
    dec r10d
    jnz section_loop

passed:
    xor eax, eax
    ret

invalid_header:
    mov eax, 1
    ret

wx_violation:
    mov eax, 2
    ret

GuardBinary endp
end
