OPTION CASEMAP:NONE

PUBLIC CRC64_InitTable
PUBLIC CRC64_Update
PUBLIC CRC64_HashState

.data
ALIGN 16
CRC64_Table dq 256 dup(0)
CRC64_Poly  dq 0C96C5795D7870F42h

.code

; Build CRC64-ECMA table once at startup
CRC64_InitTable PROC
    push rbx
    push rdi
    push r9

    lea r9, CRC64_Table

    xor rdi, rdi

crc_outer:
    cmp rdi, 256
    jae crc_done

    mov rax, rdi
    shl rax, 56
    mov ecx, 8

crc_inner:
    test rax, rax
    jns crc_no_xor

    shl rax, 1
    xor rax, qword ptr [CRC64_Poly]
    jmp crc_next

crc_no_xor:
    shl rax, 1

crc_next:
    dec ecx
    jnz crc_inner

    mov qword ptr [r9 + rdi*8], rax
    inc rdi
    jmp crc_outer

crc_done:
    pop r9
    pop rdi
    pop rbx
    ret
CRC64_InitTable ENDP

; RCX = data pointer
; RDX = length (bytes)
; R8  = seed
; Returns RAX = crc64
CRC64_Update PROC
    push rbx
    push rsi
    push r9

    lea r9, CRC64_Table

    mov rsi, rcx
    mov rcx, rdx
    mov rax, r8
    not rax

crc_u_loop:
    test rcx, rcx
    jz crc_u_done

    movzx ebx, byte ptr [rsi]
    xor bl, al
    and ebx, 0FFh

    shr rax, 8
    xor rax, qword ptr [r9 + rbx*8]

    inc rsi
    dec rcx
    jmp crc_u_loop

crc_u_done:
    not rax

    pop r9
    pop rsi
    pop rbx
    ret
CRC64_Update ENDP

; RCX = state buffer
; RDX = state size
; Returns RAX = crc64(state)
CRC64_HashState PROC
    xor r8d, r8d
    call CRC64_Update
    ret
CRC64_HashState ENDP

END
