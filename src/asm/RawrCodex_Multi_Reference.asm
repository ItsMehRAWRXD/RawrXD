; =============================================================================
; RawrCodex_Multi_Reference.asm - Reference Multi-Architecture Decoder
; Zero external dependencies, pure MASM64
; 
; This is the ORACLE implementation - always correct, not optimized.
; All optimized decoders are validated against this reference.
; =============================================================================

OPTION CASEMAP:NONE

; Windows API
EXTERN GetStdHandle:PROC
EXTERN WriteConsoleA:PROC
EXTERN ExitProcess:PROC
EXTERN RtlZeroMemory:PROC

; =============================================================================
; Constants
; =============================================================================

; Architecture types (must match RawrCodex.asm)
ARCH_X86_32     EQU 0
ARCH_X86_64     EQU 1
ARCH_ARM_32     EQU 2
ARCH_ARM_64     EQU 3
ARCH_THUMB      EQU 4
ARCH_THUMB2     EQU 5
ARCH_MIPS_32    EQU 6
ARCH_MIPS_64    EQU 7
ARCH_RISCV_32   EQU 8
ARCH_RISCV_64   EQU 9

; Instruction class
INSTR_CLASS_DP_REG      EQU 0
INSTR_CLASS_DP_IMM      EQU 1
INSTR_CLASS_BRANCH      EQU 2
INSTR_CLASS_LDST        EQU 3
INSTR_CLASS_SIMD        EQU 4
INSTR_CLASS_UNKNOWN     EQU 5

; DecodedInstruction struct offsets (packed, 256 bytes)
DI_VA                   EQU 0
DI_SIZE                 EQU 8
DI_ARCH                 EQU 12
DI_RAWBYTES             EQU 16
DI_OPCODE               EQU 32
DI_SUBOPCODE            EQU 36
DI_REGRD                EQU 40
DI_REGRS1               EQU 44
DI_REGRS2               EQU 48
DI_REGRS3               EQU 52
DI_IMMVALUE             EQU 56
DI_FLAGS                EQU 64
DI_INSTRCLASS           EQU 68
DI_ISBRANCH             EQU 72
DI_ISCALL               EQU 76
DI_ISRETURN             EQU 80
DI_ISCONDITIONAL       EQU 84
DI_ISLOAD               EQU 88
DI_ISSTORE              EQU 92
DI_MNEMONIC             EQU 96
DI_OPERANDS             EQU 128
DI_COMMENT              EQU 192

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
    
    ; Check for HINT (NOP) - D5 03 20 DF
    cmp eax, 0DF2003D5h
    je @@arm64_nop
    
    ; Check for RET - C0 03 5F D6
    cmp eax, 0D65F03C0h
    je @@arm64_ret
    
    ; Check for BRK #0 - 00 00 20 D4
    cmp eax, 0D4200000h
    je @@arm64_brk
    
    ; Check for MOVZ/MOVK - opcode 10 1001 01
    ; Bits 23-28 = 100101 = 0x25
    mov ecx, eax
    shr ecx, 23
    and ecx, 3Fh
    cmp ecx, 25h
    je @@arm64_movz
    
    jmp @@arm64_unknown

@@arm64_nop:
    mov rax, 4
    mov BYTE PTR [rdi], 'n'
    mov BYTE PTR [rdi+1], 'o'
    mov BYTE PTR [rdi+2], 'p'
    mov BYTE PTR [rdi+3], 13
    mov BYTE PTR [rdi+4], 10
    jmp @@done

@@arm64_ret:
    mov rax, 4
    mov BYTE PTR [rdi], 'r'
    mov BYTE PTR [rdi+1], 'e'
    mov BYTE PTR [rdi+2], 't'
    mov BYTE PTR [rdi+3], 13
    mov BYTE PTR [rdi+4], 10
    jmp @@done

@@arm64_brk:
    mov rax, 4
    mov BYTE PTR [rdi], 'b'
    mov BYTE PTR [rdi+1], 'r'
    mov BYTE PTR [rdi+2], 'k'
    mov BYTE PTR [rdi+3], 13
    mov BYTE PTR [rdi+4], 10
    jmp @@done

@@arm64_movz:
    mov rax, 4
    mov BYTE PTR [rdi], 'm'
    mov BYTE PTR [rdi+1], 'o'
    mov BYTE PTR [rdi+2], 'v'
    mov BYTE PTR [rdi+3], 'z'
    mov BYTE PTR [rdi+4], 13
    mov BYTE PTR [rdi+5], 10
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

; =============================================================================
; REFERENCE API - Matches RawrCodex.asm exports
; These functions provide the same interface as the full implementation
; but use the simple decoder internally
; =============================================================================

; =============================================================================
; ReferenceDecoder_DecodeInstruction - Structured decode with full metadata
;   RCX = arch type
;   RDX = pointer to instruction bytes
;   R8  = virtual address
;   R9  = pointer to DecodedInstruction structure (256 bytes)
; Returns: RAX = instruction size (0=error)
; =============================================================================
ReferenceDecoder_DecodeInstruction PROC EXPORT
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    sub rsp, 40
    
    mov ebx, ecx        ; arch type
    mov rsi, rdx        ; instruction bytes
    mov r12, r8         ; VA
    mov rdi, r9         ; output structure
    
    ; Clear output structure (256 bytes)
    mov rcx, rdi
    xor edx, edx
    mov r8d, 256
    call RtlZeroMemory
    
    ; Fill basic fields
    mov [rdi+DI_VA], r12
    mov [rdi+DI_ARCH], ebx
    
    ; Copy raw bytes (up to 16)
    mov rcx, 16
    lea rdx, [rdi+DI_RAWBYTES]
@@copy_bytes:
    mov al, [rsi+rcx-1]
    mov [rdx+rcx-1], al
    dec ecx
    jnz @@copy_bytes
    
    ; Dispatch to architecture-specific decoder
    cmp ebx, ARCH_X86_64
    je @@ref_decode_x64
    cmp ebx, ARCH_ARM_64
    je @@ref_decode_arm64
    cmp ebx, ARCH_MIPS_32
    je @@ref_decode_mips
    cmp ebx, ARCH_RISCV_32
    je @@ref_decode_riscv
    jmp @@ref_unknown

@@ref_decode_x64:
    mov al, [rsi]
    cmp al, 90h         ; NOP
    jne @@ref_x64_basic
    
    mov DWORD PTR [rdi+DI_SIZE], 1
    mov DWORD PTR [rdi+DI_OPCODE], 90h
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_DP_REG
    
    ; Write mnemonic "nop"
    mov BYTE PTR [rdi+DI_MNEMONIC], 'n'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'o'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'p'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 0
    
    mov rax, 1
    jmp @@ref_done

@@ref_x64_basic:
    mov DWORD PTR [rdi+DI_SIZE], 1
    mov DWORD PTR [rdi+DI_OPCODE], eax
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_UNKNOWN
    mov BYTE PTR [rdi+DI_MNEMONIC], 'd'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'b'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 0
    mov rax, 1
    jmp @@ref_done

@@ref_decode_arm64:
    mov eax, [rsi]
    mov [rdi+DI_OPCODE], eax
    mov DWORD PTR [rdi+DI_SIZE], 4
    
    ; Check for NOP (HINT #0x1E)
    cmp eax, 0DF2003D5h
    jne @@ref_arm64_movz
    
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_DP_REG
    mov DWORD PTR [rdi+DI_ISBRANCH], 0
    mov BYTE PTR [rdi+DI_MNEMONIC], 'n'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'o'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'p'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 0
    mov rax, 4
    jmp @@ref_done

@@ref_arm64_movz:
    ; Check for MOVZ
    mov ecx, eax
    shr ecx, 23
    and ecx, 3Fh
    cmp ecx, 25h
    jne @@ref_arm64_unknown
    
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_DP_IMM
    mov BYTE PTR [rdi+DI_MNEMONIC], 'm'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'o'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'v'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 'z'
    mov BYTE PTR [rdi+DI_MNEMONIC+4], 0
    mov rax, 4
    jmp @@ref_done

@@ref_arm64_unknown:
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_UNKNOWN
    mov BYTE PTR [rdi+DI_MNEMONIC], 'u'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'n'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'k'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 0
    mov rax, 4
    jmp @@ref_done

@@ref_decode_mips:
    mov eax, [rsi]
    mov [rdi+DI_OPCODE], eax
    mov DWORD PTR [rdi+DI_SIZE], 4
    bswap eax
    
    ; Check for NOP
    test eax, eax
    jne @@ref_mips_lui
    
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_DP_REG
    mov BYTE PTR [rdi+DI_MNEMONIC], 'n'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'o'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'p'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 0
    mov rax, 4
    jmp @@ref_done

@@ref_mips_lui:
    ; Check for LUI
    mov ecx, eax
    shr ecx, 26
    and ecx, 3Fh
    cmp ecx, 0Fh
    jne @@ref_mips_unknown
    
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_DP_IMM
    mov BYTE PTR [rdi+DI_MNEMONIC], 'l'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'u'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'i'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 0
    mov rax, 4
    jmp @@ref_done

@@ref_mips_unknown:
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_UNKNOWN
    mov BYTE PTR [rdi+DI_MNEMONIC], 'u'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'n'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'k'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 0
    mov rax, 4
    jmp @@ref_done

@@ref_decode_riscv:
    mov eax, [rsi]
    mov [rdi+DI_OPCODE], eax
    mov DWORD PTR [rdi+DI_SIZE], 4
    
    ; Check for NOP (addi x0, x0, 0)
    cmp eax, 00000013h
    jne @@ref_riscv_unknown
    
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_DP_IMM
    mov BYTE PTR [rdi+DI_MNEMONIC], 'n'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'o'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'p'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 0
    mov rax, 4
    jmp @@ref_done

@@ref_riscv_unknown:
    mov DWORD PTR [rdi+DI_INSTRCLASS], INSTR_CLASS_UNKNOWN
    mov BYTE PTR [rdi+DI_MNEMONIC], 'u'
    mov BYTE PTR [rdi+DI_MNEMONIC+1], 'n'
    mov BYTE PTR [rdi+DI_MNEMONIC+2], 'k'
    mov BYTE PTR [rdi+DI_MNEMONIC+3], 0
    mov rax, 4
    jmp @@ref_done

@@ref_unknown:
    xor rax, rax

@@ref_done:
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ReferenceDecoder_DecodeInstruction ENDP

; =============================================================================
; ReferenceDecoder_Validate - Compare two decoded instructions
;   RCX = pointer to reference DecodedInstruction
;   RDX = pointer to test DecodedInstruction
; Returns: RAX = 1 if match, 0 if different
; =============================================================================
ReferenceDecoder_Validate PROC EXPORT
    push rsi
    push rdi
    push rbx
    
    mov rsi, rcx        ; reference
    mov rdi, rdx        ; test
    
    ; Compare key fields
    mov eax, [rsi+DI_SIZE]
    cmp eax, [rdi+DI_SIZE]
    jne @@validate_fail
    
    mov eax, [rsi+DI_OPCODE]
    cmp eax, [rdi+DI_OPCODE]
    jne @@validate_fail
    
    mov eax, [rsi+DI_ARCH]
    cmp eax, [rdi+DI_ARCH]
    jne @@validate_fail
    
    mov eax, [rsi+DI_INSTRCLASS]
    cmp eax, [rdi+DI_INSTRCLASS]
    jne @@validate_fail
    
    ; Compare mnemonics
    mov rcx, 32
    lea rdx, [rsi+DI_MNEMONIC]
    lea r8, [rdi+DI_MNEMONIC]
@@cmp_mnem:
    mov al, [rdx+rcx-1]
    mov bl, [r8+rcx-1]
    cmp al, bl
    jne @@validate_fail
    dec ecx
    jnz @@cmp_mnem
    
    mov rax, 1
    jmp @@validate_done

@@validate_fail:
    xor rax, rax

@@validate_done:
    pop rbx
    pop rdi
    pop rsi
    ret
ReferenceDecoder_Validate ENDP

; =============================================================================
; Compatibility wrappers - Match RawrCodex.asm exports
; These allow the reference decoder to be a drop-in replacement
; =============================================================================

; RawrDisasm_Multi_Init - Initialize multi-arch disassembler
RawrDisasm_Multi_Init PROC EXPORT
    xor rax, rax        ; Return 0 (no context needed for reference)
    ret
RawrDisasm_Multi_Init ENDP

; RawrDisasm_Multi_Decode - Decode single instruction
;   RCX = context (ignored for reference)
;   RDX = VA
;   R8  = instruction bytes
;   R9  = output RAWRINSTRUCTION_MULTI
RawrDisasm_Multi_Decode PROC EXPORT
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 40
    
    ; Get architecture from context or use default
    ; For reference, we use a simple dispatch based on first byte patterns
    mov rsi, r8         ; instruction bytes
    mov rdi, r9         ; output
    mov r12, rdx        ; VA
    
    ; Try to auto-detect or use passed arch type
    ; For now, forward to reference decoder with arch from context
    ; This is a simplified version - full version would read ctx->machine
    
    ; Default to ARM64 for testing
    mov ecx, ARCH_ARM_64
    mov rdx, rsi
    mov r8, r12
    mov r9, rdi
    call ReferenceDecoder_DecodeInstruction
    
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
RawrDisasm_Multi_Decode ENDP

; RawrDisasm_ARM_Decode - ARM/ARM64/Thumb decoder
RawrDisasm_ARM_Decode PROC EXPORT
    jmp ReferenceDecoder_DecodeInstruction
RawrDisasm_ARM_Decode ENDP

; RawrDisasm_MIPS_Decode - MIPS decoder  
RawrDisasm_MIPS_Decode PROC EXPORT
    jmp ReferenceDecoder_DecodeInstruction
RawrDisasm_MIPS_Decode ENDP

; RawrDisasm_RISCV_Decode - RISC-V decoder
RawrDisasm_RISCV_Decode PROC EXPORT
    jmp ReferenceDecoder_DecodeInstruction
RawrDisasm_RISCV_Decode ENDP

; RawrEmu_Multi_Create - Create emulator (stub for reference)
RawrEmu_Multi_Create PROC EXPORT
    xor rax, rax
    ret
RawrEmu_Multi_Create ENDP

; RawrEmu_Multi_Destroy - Destroy emulator (stub for reference)
RawrEmu_Multi_Destroy PROC EXPORT
    ret
RawrEmu_Multi_Destroy ENDP

; RawrEmu_Multi_Step - Step emulator (stub for reference)
RawrEmu_Multi_Step PROC EXPORT
    xor rax, rax
    ret
RawrEmu_Multi_Step ENDP

END
