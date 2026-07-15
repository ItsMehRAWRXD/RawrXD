; =============================================================================
; RawrCodex_Multi_Simple.asm - Simplified Multi-Architecture Decoder
; Zero external dependencies, pure MASM64
; =============================================================================

OPTION CASEMAP:NONE

; Windows API
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC

; =============================================================================
; Constants
; =============================================================================

; Architecture types
ARCH_X86_64     EQU 1
ARCH_ARM_64     EQU 3
ARCH_MIPS_32    EQU 6
ARCH_RISCV_32   EQU 8

; =============================================================================
; Data Section
; =============================================================================

.DATA

; Test strings
msgArm64        BYTE "ARM64: mov x0, #0x1234", 13, 10, 0
msgArm64Len     EQU $ - msgArm64

msgMips         BYTE "MIPS: li $v0, 0x1234", 13, 10, 0
msgMipsLen      EQU $ - msgMips

msgRiscv        BYTE "RISC-V: addi x5, x0, 42", 13, 10, 0
msgRiscvLen     EQU $ - msgRiscv

msgUnknown      BYTE "Unknown architecture", 13, 10, 0
msgUnknownLen   EQU $ - msgUnknown

; Output buffer
outputBuffer    BYTE 256 DUP(0)

; =============================================================================
; Code Section
; =============================================================================

.CODE

; =============================================================================
; SimpleDecoder - Minimal multi-arch decoder
;   RCX = arch type (1=x64, 3=ARM64, 6=MIPS, 8=RISCV)
;   RDX = pointer to instruction bytes
;   R8  = output buffer (256 bytes)
; Returns: RAX = instruction size (0=error)
; =============================================================================
SimpleDecoder PROC EXPORT
    push rbx
    push rsi
    push rdi
    
    mov rbx, rcx        ; arch type
    mov rsi, rdx        ; instruction bytes
    mov rdi, r8         ; output buffer
    
    ; Clear output buffer
    mov rcx, 256
    mov al, 0
    rep stosb
    mov rdi, r8         ; restore output pointer
    
    ; Dispatch based on architecture
    cmp ebx, ARCH_X86_64
    je @@decode_x64
    cmp ebx, ARCH_ARM_64
    je @@decode_arm64
    cmp ebx, ARCH_MIPS_32
    je @@decode_mips
    cmp ebx, ARCH_RISCV_32
    je @@decode_riscv
    
    ; Unknown architecture
    jmp @@unknown

@@decode_x64:
    ; x64: Check first byte
    mov al, [rsi]
    cmp al, 48h         ; REX prefix
    jne @@check_basic
    
    ; REX.W + MOV r64, imm32
    mov al, [rsi+1]
    cmp al, 0C7h
    jne @@check_basic
    
    ; This is mov rax, imm32
    mov rax, 7          ; 7 bytes
    mov BYTE PTR [rdi], 'm'
    mov BYTE PTR [rdi+1], 'o'
    mov BYTE PTR [rdi+2], 'v'
    mov BYTE PTR [rdi+3], ' '
    mov BYTE PTR [rdi+4], 'r'
    mov BYTE PTR [rdi+5], 'a'
    mov BYTE PTR [rdi+6], 'x'
    mov BYTE PTR [rdi+7], ','
    mov BYTE PTR [rdi+8], ' '
    mov BYTE PTR [rdi+9], '#'
    ; Could decode immediate here
    jmp @@done

@@check_basic:
    ; Basic instruction
    mov rax, 1
    mov BYTE PTR [rdi], 'd'
    mov BYTE PTR [rdi+1], 'b'
    jmp @@done

@@decode_arm64:
    ; ARM64: 4 bytes, decode fields
    mov eax, [rsi]
    
    ; Check for MOVZ (move wide with zero) - opcode 10 1001 01
    ; Bits 23-28 = 100101 = 0x25
    mov ecx, eax
    shr ecx, 23
    and ecx, 3Fh
    cmp ecx, 25h
    jne @@arm64_check_nop
    
    ; This is MOVZ/MOVN/MOVK
    mov rax, 4          ; 4 bytes
    mov rsi, OFFSET msgArm64
    mov rcx, msgArm64Len
    call @@copy_string
    jmp @@done

@@arm64_check_nop:
    ; Check for HINT (NOP) - D5 03 20 DF
    cmp eax, 0DF2003D5h
    jne @@arm64_unknown
    
    mov rax, 4
    mov BYTE PTR [rdi], 'n'
    mov BYTE PTR [rdi+1], 'o'
    mov BYTE PTR [rdi+2], 'p'
    mov BYTE PTR [rdi+3], 13
    mov BYTE PTR [rdi+4], 10
    jmp @@done

@@arm64_unknown:
    mov rax, 4
    mov BYTE PTR [rdi], 'd'
    mov BYTE PTR [rdi+1], 'c'
    mov BYTE PTR [rdi+2], '.'
    mov BYTE PTR [rdi+3], 'w'
    jmp @@done

@@decode_mips:
    ; MIPS: 4 bytes big-endian
    mov eax, [rsi]
    bswap eax
    
    ; Check for NOP (all zeros = sll $zero, $zero, 0)
    test eax, eax
    jne @@mips_check_lui
    
    mov rax, 4          ; 4 bytes
    mov BYTE PTR [rdi], 'n'
    mov BYTE PTR [rdi+1], 'o'
    mov BYTE PTR [rdi+2], 'p'
    mov BYTE PTR [rdi+3], 13
    mov BYTE PTR [rdi+4], 10
    jmp @@done

@@mips_check_lui:
    ; Check for LUI (opcode 001111 = 0x0F)
    mov ecx, eax
    shr ecx, 26
    and ecx, 3Fh
    cmp ecx, 0Fh
    jne @@mips_unknown
    
    mov rax, 4          ; 4 bytes
    mov rsi, OFFSET msgMips
    mov rcx, msgMipsLen
    call @@copy_string
    jmp @@done

@@mips_unknown:
    mov rax, 4
    mov BYTE PTR [rdi], 'd'
    mov BYTE PTR [rdi+1], 'c'
    mov BYTE PTR [rdi+2], '.'
    mov BYTE PTR [rdi+3], 'w'
    jmp @@done

@@decode_riscv:
    ; RISC-V: Check for compressed
    movzx eax, WORD PTR [rsi]
    and eax, 3
    cmp eax, 3
    je @@riscv_32bit
    
    ; Compressed instruction (2 bytes)
    mov rax, 2
    mov BYTE PTR [rdi], 'c'
    mov BYTE PTR [rdi+1], '.'
    jmp @@done

@@riscv_32bit:
    ; Standard 4-byte instruction
    mov rax, 4
    mov rsi, OFFSET msgRiscv
    mov rcx, msgRiscvLen
    call @@copy_string
    jmp @@done

@@unknown:
    xor rax, rax        ; Return 0 for error
    mov rsi, OFFSET msgUnknown
    mov rcx, msgUnknownLen
    call @@copy_string
    jmp @@done_ret

@@copy_string:
    ; RSI = source, RCX = length, RDI = dest
    push rsi
    push rdi
    push rcx
    rep movsb
    pop rcx
    pop rdi
    pop rsi
    ret

@@done:
    ; RAX already has size
@@done_ret:
    pop rdi
    pop rsi
    pop rbx
    ret
SimpleDecoder ENDP

; =============================================================================
; GetArchitectureName - Get name for architecture type
;   RCX = arch type
;   RDX = output buffer (64 bytes)
; =============================================================================
GetArchitectureName PROC EXPORT
    push rdi
    mov rdi, rdx
    
    cmp ecx, ARCH_X86_64
    je @@name_x64
    cmp ecx, ARCH_ARM_64
    je @@name_arm64
    cmp ecx, ARCH_MIPS_32
    je @@name_mips
    cmp ecx, ARCH_RISCV_32
    je @@name_riscv
    
    mov BYTE PTR [rdi], 'u'
    mov BYTE PTR [rdi+1], 'n'
    mov BYTE PTR [rdi+2], 'k'
    mov BYTE PTR [rdi+3], 'n'
    mov BYTE PTR [rdi+4], 'o'
    mov BYTE PTR [rdi+5], 'w'
    mov BYTE PTR [rdi+6], 'n'
    mov BYTE PTR [rdi+7], 0
    jmp @@done

@@name_x64:
    mov BYTE PTR [rdi], 'x'
    mov BYTE PTR [rdi+1], '8'
    mov BYTE PTR [rdi+2], '6'
    mov BYTE PTR [rdi+3], '_'
    mov BYTE PTR [rdi+4], '6'
    mov BYTE PTR [rdi+5], '4'
    mov BYTE PTR [rdi+6], 0
    jmp @@done

@@name_arm64:
    mov BYTE PTR [rdi], 'A'
    mov BYTE PTR [rdi+1], 'R'
    mov BYTE PTR [rdi+2], 'M'
    mov BYTE PTR [rdi+3], '6'
    mov BYTE PTR [rdi+4], '4'
    mov BYTE PTR [rdi+5], 0
    jmp @@done

@@name_mips:
    mov BYTE PTR [rdi], 'M'
    mov BYTE PTR [rdi+1], 'I'
    mov BYTE PTR [rdi+2], 'P'
    mov BYTE PTR [rdi+3], 'S'
    mov BYTE PTR [rdi+4], '3'
    mov BYTE PTR [rdi+5], '2'
    mov BYTE PTR [rdi+6], 0
    jmp @@done

@@name_riscv:
    mov BYTE PTR [rdi], 'R'
    mov BYTE PTR [rdi+1], 'I'
    mov BYTE PTR [rdi+2], 'S'
    mov BYTE PTR [rdi+3], 'C'
    mov BYTE PTR [rdi+4], '-'
    mov BYTE PTR [rdi+5], 'V'
    mov BYTE PTR [rdi+6], 0
    jmp @@done

@@done:
    pop rdi
    ret
GetArchitectureName ENDP

; =============================================================================
; TestEntryPoint - Simple test that prints results
; =============================================================================
TestEntryPoint PROC EXPORT
    sub rsp, 512
    
    ; Test ARM64
    mov ecx, ARCH_ARM_64
    lea rdx, [rsp+64]       ; Output buffer
    mov r8, rdx
    call GetArchitectureName
    
    ; Print architecture name
    lea rcx, [rsp+64]
    call PrintString
    
    ; Decode ARM64 instruction
    ; NOP = D5 03 20 DF (little endian) = HINT #0x1E
    mov DWORD PTR [rsp+32], 0DF2003D5h
    mov ecx, ARCH_ARM_64
    lea rdx, [rsp+32]
    lea r8, [rsp+64]
    call SimpleDecoder
    
    ; Print result
    lea rcx, [rsp+64]
    call PrintString
    
    ; Test MIPS
    mov ecx, ARCH_MIPS_32
    lea rdx, [rsp+64]
    mov r8, rdx
    call GetArchitectureName
    lea rcx, [rsp+64]
    call PrintString
    
    ; Decode MIPS instruction
    ; NOP = sll $zero, $zero, 0 = 00000000 big-endian
    mov DWORD PTR [rsp+32], 00000000h
    mov ecx, ARCH_MIPS_32
    lea rdx, [rsp+32]
    lea r8, [rsp+64]
    call SimpleDecoder
    
    lea rcx, [rsp+64]
    call PrintString
    
    ; Exit
    xor ecx, ecx
    call ExitProcess
    
    add rsp, 512
    ret
TestEntryPoint ENDP

; =============================================================================
; PrintString - Helper to print to console
;   RCX = string pointer
; =============================================================================
PrintString PROC
    push rbx
    push rsi
    push rdi
    
    mov rsi, rcx
    
    ; Get string length
    xor ecx, ecx
@@len_loop:
    cmp BYTE PTR [rsi+rcx], 0
    je @@got_len
    inc ecx
    jmp @@len_loop
@@got_len:
    mov r8d, ecx        ; Length
    test r8d, r8d
    jz @@done           ; Empty string
    
    ; Get stdout handle
    mov ecx, -11        ; STD_OUTPUT_HANDLE
    call GetStdHandle
    
    ; WriteConsole
    mov rcx, rax        ; hConsoleOutput
    mov rdx, rsi        ; lpBuffer
    ; r8 already has length
    xor r9d, r9d        ; lpNumberOfCharsWritten (optional)
    push 0              ; lpReserved
    sub rsp, 32
    call WriteConsoleA
    add rsp, 40
    
@@done:
    pop rdi
    pop rsi
    pop rbx
    ret
PrintString ENDP

END
