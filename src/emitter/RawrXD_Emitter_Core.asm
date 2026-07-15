; RawrXD Self-Hosted Code Emitter - Core
; Pure x64, zero dependencies, self-hosting
; Target: 2.5M lines total, 1M for AI/LSP/Debug/Collab/GUI

.code

;==============================================================================
; SECTION 1: EMITTER FOUNDATION (The Bootstrap)
;==============================================================================

; Emitter state structure
EMITTER_STATE struct
    buffer      dq ?        ; Output buffer
    bufSize     dq ?        ; Buffer size
    bufPos      dq ?        ; Current position
    section     dd ?        ; Current section (.text/.data/.rdata)
    flags       dd ?        ; Emitter flags
EMITTER_STATE ends

; Instruction encoding templates
INST_TEMPLATE struct
    opcode      db 16 dup(?) ; Opcode bytes
    opLen       db ?         ; Opcode length
    modRM       db ?         ; ModR/M byte (if needed)
    hasImm      db ?         ; Has immediate
    immSize     db ?         ; Immediate size
INST_TEMPLATE ends

.data

; Global emitter state
align 16
g_emitter EMITTER_STATE <>

; Section buffers (64MB each initially)
SECTION_TEXT_SIZE   equ 64 * 1024 * 1024
SECTION_DATA_SIZE   equ 64 * 1024 * 1024
SECTION_RDATA_SIZE  equ 64 * 1024 * 1024

;==============================================================================
; SECTION 2: CORE EMITTER FUNCTIONS
;==============================================================================

.code

; Initialize the code emitter
; rcx = buffer, rdx = size
Emitter_Init PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov g_emitter.buffer, rcx
    mov g_emitter.bufSize, rdx
    mov g_emitter.bufPos, 0
    mov g_emitter.section, 0
    mov g_emitter.flags, 0
    
    ; Zero the buffer
    mov rdi, rcx
    mov rcx, rdx
    shr rcx, 3          ; Divide by 8 for qwords
    xor rax, rax
    rep stosq
    
    mov rax, 1          ; Success
    leave
    ret
Emitter_Init ENDP

; Emit a single byte
; cl = byte to emit
Emitter_EmitByte PROC FRAME
    push rbp
    mov rbp, rsp
    
    mov rax, g_emitter.bufPos
    cmp rax, g_emitter.bufSize
    jae emit_overflow
    
    mov rdx, g_emitter.buffer
    mov [rdx + rax], cl
    inc g_emitter.bufPos
    
    mov rax, 1          ; Success
    leave
    ret
    
emit_overflow:
    xor rax, rax        ; Failure
    leave
    ret
Emitter_EmitByte ENDP

; Emit a 32-bit immediate
; ecx = immediate
Emitter_EmitDword PROC FRAME
    push rbp
    mov rbp, rsp
    
    mov rax, g_emitter.bufPos
    add rax, 4
    cmp rax, g_emitter.bufSize
    ja emit_dword_overflow
    
    mov rdx, g_emitter.buffer
    mov rax, g_emitter.bufPos
    mov [rdx + rax], ecx
    add g_emitter.bufPos, 4
    
    mov rax, 1
    leave
    ret
    
emit_dword_overflow:
    xor rax, rax
    leave
    ret
Emitter_EmitDword ENDP

; Emit a 64-bit immediate
; rcx = immediate
Emitter_EmitQword PROC FRAME
    push rbp
    mov rbp, rsp
    
    mov rax, g_emitter.bufPos
    add rax, 8
    cmp rax, g_emitter.bufSize
    ja emit_qword_overflow
    
    mov rdx, g_emitter.buffer
    mov rax, g_emitter.bufPos
    mov [rdx + rax], rcx
    add g_emitter.bufPos, 8
    
    mov rax, 1
    leave
    ret
    
emit_qword_overflow:
    xor rax, rax
    leave
    ret
Emitter_EmitQword ENDP

;==============================================================================
; SECTION 3: x64 INSTRUCTION ENCODER
;==============================================================================

; Encode REX prefix for x64
; cl = W (64-bit operand), ch = R (ModRM reg extension)
; dl = X (SIB index extension), dh = B (ModRM rm extension)
Emitter_EmitRex PROC FRAME
    push rbp
    mov rbp, rsp
    
    ; REX = 0100WRXB
    mov al, 40h         ; Base REX value
    test cl, cl
    jz rex_no_w
    or al, 08h          ; W = 1
rex_no_w:
    test ch, ch
    jz rex_no_r
    or al, 04h          ; R = 1
rex_no_r:
    test dl, dl
    jz rex_no_x
    or al, 02h          ; X = 1
rex_no_x:
    test dh, dh
    jz rex_no_b
    or al, 01h          ; B = 1
rex_no_b:
    
    mov cl, al
    call Emitter_EmitByte
    
    leave
    ret
Emitter_EmitRex ENDP

; Encode ModR/M byte
; cl = mod, ch = reg, dl = rm
Emitter_EmitModRM PROC FRAME
    push rbp
    mov rbp, rsp
    
    ; ModR/M = mod << 6 | reg << 3 | rm
    shl cl, 6
    shl ch, 3
    or cl, ch
    or cl, dl
    
    call Emitter_EmitByte
    
    leave
    ret
Emitter_EmitModRM ENDP

; Encode MOV r64, imm64
; rcx = register (0-15), rdx = immediate
Emitter_MovR64Imm64 PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; REX.W + B (if reg >= 8)
    xor r8, r8
    mov r9b, 1          ; W = 1
    cmp cl, 8
    jb mov_no_rex_b
    mov r8b, 1          ; B = 1
    sub cl, 8
mov_no_rex_b:
    mov cl, r9b
    mov ch, r8b
    xor edx, edx
    call Emitter_EmitRex
    
    ; Opcode: B8+rd (MOV r64, imm64)
    mov al, 0B8h
    add al, cl
    mov cl, al
    call Emitter_EmitByte
    
    ; Emit immediate
    mov rcx, rdx
    call Emitter_EmitQword
    
    leave
    ret
Emitter_MovR64Imm64 ENDP

; Encode MOV r32, imm32
; rcx = register (0-15), edx = immediate
Emitter_MovR32Imm32 PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    ; REX.B if reg >= 8
    cmp cl, 8
    jb mov32_no_rex
    sub cl, 8
    mov r8b, 1          ; B = 1
    xor r9b, r9b        ; W = 0
    mov cl, r9b
    mov ch, r8b
    xor edx, edx
    xor r8d, r8d
    call Emitter_EmitRex
    jmp mov32_opcode
mov32_no_rex:
    ; No REX needed for low registers
mov32_opcode:
    ; Opcode: B8+rd (MOV r32, imm32)
    mov al, 0B8h
    add al, cl
    mov cl, al
    call Emitter_EmitByte
    
    ; Emit immediate
    mov ecx, edx
    call Emitter_EmitDword
    
    leave
    ret
Emitter_MovR32Imm32 ENDP

; Encode PUSH reg
; rcx = register (0-15)
Emitter_PushReg PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    cmp cl, 8
    jae push_extended
    
    ; Standard push: 50+rd
    mov al, 50h
    add al, cl
    mov cl, al
    call Emitter_EmitByte
    jmp push_done
    
push_extended:
    ; Extended register: REX.B + FF /6
    sub cl, 8
    xor r8b, r8b
    mov r9b, 1          ; B = 1
    mov cl, r8b
    mov ch, r8b
    xor edx, edx
    mov dh, r9b
    call Emitter_EmitRex
    
    mov cl, 0FFh
    call Emitter_EmitByte
    
    ; ModR/M: mod=3, reg=6, rm=reg
    mov cl, 3           ; mod = 3 (register)
    mov ch, 6           ; reg = 6 (/6)
    mov dl, cl          ; rm = reg
    call Emitter_EmitModRM
    
push_done:
    leave
    ret
Emitter_PushReg ENDP

; Encode POP reg
; rcx = register (0-15)
Emitter_PopReg PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    cmp cl, 8
    jae pop_extended
    
    ; Standard pop: 58+rd
    mov al, 58h
    add al, cl
    mov cl, al
    call Emitter_EmitByte
    jmp pop_done
    
pop_extended:
    ; Extended register: REX.B + 8F /0
    sub cl, 8
    xor r8b, r8b
    mov r9b, 1          ; B = 1
    mov cl, r8b
    mov ch, r8b
    xor edx, edx
    mov dh, r9b
    call Emitter_EmitRex
    
    mov cl, 8Fh
    call Emitter_EmitByte
    
    ; ModR/M: mod=3, reg=0, rm=reg
    mov cl, 3
    xor ch, ch
    call Emitter_EmitModRM
    
pop_done:
    leave
    ret
Emitter_PopReg ENDP

; Encode RET
Emitter_Ret PROC FRAME
    push rbp
    mov rbp, rsp
    
    mov cl, 0C3h
    call Emitter_EmitByte
    
    leave
    ret
Emitter_Ret ENDP

; Encode CALL rel32
; ecx = relative offset
Emitter_CallRel32 PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov cl, 0E8h
    call Emitter_EmitByte
    mov ecx, ecx
    call Emitter_EmitDword
    
    leave
    ret
Emitter_CallRel32 ENDP

; Encode JMP rel32
; ecx = relative offset
Emitter_JmpRel32 PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 32
    
    mov cl, 0E9h
    call Emitter_EmitByte
    mov ecx, ecx
    call Emitter_EmitDword
    
    leave
    ret
Emitter_JmpRel32 ENDP

;==============================================================================
; SECTION 4: PE/COFF OUTPUT GENERATOR
;==============================================================================

.data

; PE headers template
align 16
pe_dos_header:
    dw 5A4Dh            ; MZ signature
    dw 0, 0, 0, 0, 0, 0, 0, 0
    dw 0, 0, 0, 0, 0, 0, 0, 0
    dw 0, 0, 0, 0, 0, 0, 0, 0
    dw 0, 0, 0, 0, 0, 0
    dd 00000080h        ; PE header offset

pe_nt_signature:
    dd 00004550h        ; PE\0\0

pe_file_header:
    dw 8664h            ; Machine (AMD64)
    dw 3                ; Number of sections (.text, .data, .rdata)
    dd 0                ; Time stamp
    dd 0                ; Symbol table (none)
    dd 0                ; Number of symbols
    dw 0                ; Size of optional header (calculated)
    dw 22h              ; Characteristics (executable, large address aware)

.code

; Generate complete PE file
; rcx = output buffer, rdx = code, r8 = codeSize, r9 = entryPoint
Emitter_GeneratePE PROC FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 256
    
    ; TODO: Full PE generation
    ; This is the foundation - will expand to 2.5M lines
    
    mov rax, 1          ; Success placeholder
    leave
    ret
Emitter_GeneratePE ENDP

;==============================================================================
; SECTION 5: SELF-HOSTING ENTRY POINT
;==============================================================================

.code

; Main entry for emitter testing
Emitter_Main PROC EXPORT FRAME
    push rbp
    mov rbp, rsp
    sub rsp, 64
    
    ; Allocate 1MB buffer for code generation
    mov rcx, 1024 * 1024
    mov rdx, 40h        ; PAGE_EXECUTE_READWRITE
    mov r8, 3000h       ; MEM_COMMIT | MEM_RESERVE
    xor r9, r9
    call VirtualAlloc
    
    test rax, rax
    jz emitter_alloc_failed
    
    ; Initialize emitter
    mov rcx, rax
    mov rdx, 1024 * 1024
    call Emitter_Init
    
    ; Generate test code:
    ; mov rax, 0x123456789ABCDEF0
    ; ret
    
    mov rcx, 0          ; rax
    mov rdx, 123456789ABCDEF0h
    call Emitter_MovR64Imm64
    
    call Emitter_Ret
    
    ; Success
    xor rax, rax
    jmp emitter_done
    
emitter_alloc_failed:
    mov rax, 1
    
emitter_done:
    leave
    ret
Emitter_Main ENDP

;==============================================================================
; EXPORTS
;==============================================================================

PUBLIC Emitter_Init
PUBLIC Emitter_EmitByte
PUBLIC Emitter_EmitDword
PUBLIC Emitter_EmitQword
PUBLIC Emitter_EmitRex
PUBLIC Emitter_EmitModRM
PUBLIC Emitter_MovR64Imm64
PUBLIC Emitter_MovR32Imm32
PUBLIC Emitter_PushReg
PUBLIC Emitter_PopReg
PUBLIC Emitter_Ret
PUBLIC Emitter_CallRel32
PUBLIC Emitter_JmpRel32
PUBLIC Emitter_GeneratePE
PUBLIC Emitter_Main

END
