; ============================================================================
; emitter_x64.asm - x64 machine code emitter for Sovereign Universal Transpiler
; v0.2 - Production: separate node counter, vreg tracking, relocations, REX.B
; Converts UIR nodes into x64 machine code with proper Win64 ABI
; ============================================================================

option casemap:none

; External declarations from uir.asm
extrn UIRCreateContext:proc
extrn UIRCreateNode:proc
extrn UIRGetNode:proc
extrn UIRAddConstant:proc
extrn UIRGetConstant:proc
extrn UIRAddRelocation:proc
extrn UIRAllocVReg:proc
extrn UIRReset:proc
extrn UIRGetNodeCount:proc
extrn UIRValidateHeader:proc

; UIR Opcodes (from uir.asm)
IR_NOP          EQU 0
IR_LOAD_CONST   EQU 1
IR_CALL         EQU 2
IR_RETURN       EQU 3
IR_EXIT         EQU 4
IR_MOVE         EQU 14

; ----------------------------------------------------------------------------
; Relocation types
; ----------------------------------------------------------------------------
RELOC_RIP32     EQU 0     ; RIP-relative disp32
RELOC_ABS64     EQU 1     ; Absolute 64-bit
RELOC_REL32     EQU 2     ; Relative call/jump disp32

; ----------------------------------------------------------------------------
; Emitter relocation record (local to emitter)
; ----------------------------------------------------------------------------
EMIT_RELOC STRUCT
    patch_offset    QWORD ?     ; Offset in .text where fixup goes
    target_section  DWORD ?     ; 0=.text, 1=.rdata
    target_offset   QWORD ?     ; Offset in target section
    reloc_type      DWORD ?     ; RELOC_RIP32 / RELOC_ABS64 / RELOC_REL32
EMIT_RELOC ENDS

; ----------------------------------------------------------------------------
; Data Section
; ----------------------------------------------------------------------------
.data
    ; Output buffer pointers
    emit_text_buf      dq 0
    emit_rdata_buf     dq 0
    emit_text_size     dq 0
    emit_rdata_size    dq 0

    ; Virtual register to rdata offset mapping (256 vregs)
    ALIGN 16
    vreg_rdata_off     QWORD 16 DUP(0FFFFFFFFFFFFFFFFh)  ; -1 = not mapped
    vreg_type          DWORD 16 DUP(0)                    ; 0=none, 1=string, 2=int

    ; Relocation table (emitter-local, max 16)
    ALIGN 16
    emit_relocs        EMIT_RELOC 16 DUP(<>)
    emit_reloc_count   DWORD 0

; ----------------------------------------------------------------------------
; Code Section
; ----------------------------------------------------------------------------
.code

; ============================================================================
; EmitAddReloc - Add a relocation record
; RCX = patch offset in .text
; RDX = target section (0=.text, 1=.rdata)
; R8  = target offset in target section
; R9  = reloc type
; Returns: RAX = reloc index (or -1 if full)
; ============================================================================
EmitAddReloc PROC
    push rbx
    push rdi

    mov eax, emit_reloc_count
    cmp eax, 1024
    jge full

    imul edi, eax, SIZEOF EMIT_RELOC
    lea rdi, [emit_relocs + rdi]

    mov [rdi].EMIT_RELOC.patch_offset, rcx
    mov [rdi].EMIT_RELOC.target_section, edx
    mov [rdi].EMIT_RELOC.target_offset, r8
    mov [rdi].EMIT_RELOC.reloc_type, r9d

    mov eax, emit_reloc_count
    inc emit_reloc_count
    jmp done

full:
    mov rax, -1

done:
    pop rdi
    pop rbx
    ret
EmitAddReloc ENDP

; ============================================================================
; EmitX64 - Convert UIR to x64 machine code
; RCX = UIR node array pointer
; RDX = node count
; R8  = text output buffer
; R9  = rdata output buffer
; Returns: RAX = total text bytes emitted
; ============================================================================
EmitX64 PROC
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 20h                ; 7 pushes (56) + 20h (32) = 88 = 0 mod 16 ✓

    mov rsi, rcx            ; UIR node array
    mov rbx, rdx            ; node count (loop bound - NEVER modified)
    mov r12, r8             ; text buffer base
    mov r13, r9             ; rdata buffer base
    xor r14, r14            ; text byte offset
    xor r15, r15            ; rdata byte offset
    xor r11, r11            ; node index (SEPARATE from text offset!)

    ; Reset relocation count
    mov emit_reloc_count, 0

    ; Reset vreg mappings to -1 (unmapped)
    push rdi
    lea rdi, [vreg_rdata_off]
    mov rax, 0FFFFFFFFFFFFFFFFh
    mov rcx, 64
    rep stosq
    pop rdi

    ; Emit prologue: sub rsp, 28h (Win64 shadow space)
    ; 48 83 EC 28
    mov byte ptr [r12 + r14], 48h
    inc r14
    mov byte ptr [r12 + r14], 83h
    inc r14
    mov byte ptr [r12 + r14], 0ECh
    inc r14
    mov byte ptr [r12 + r14], 28h
    inc r14

emit_loop:
    ; Check NODE INDEX against count (NOT text offset!)
    cmp r11, rbx
    jge emit_done

    ; Load opcode: nodes[r11].opcode = [rsi + r11*32]
    imul rax, r11, 32
    mov eax, dword ptr [rsi + rax]

    cmp eax, IR_NOP
    je emit_next
    cmp eax, IR_LOAD_CONST
    je emit_load_const
    cmp eax, IR_CALL
    je emit_call
    cmp eax, IR_RETURN
    je emit_return
    cmp eax, IR_EXIT
    je emit_exit
    cmp eax, IR_MOVE
    je emit_move
    ; Unknown opcode: skip
    jmp emit_next

emit_load_const:
    ; operand0 = string ptr, operand1 = string length, dst_vreg = vreg
    imul rax, r11, 32
    mov rcx, [rsi + rax + 8]            ; op0 = string pointer
    mov rdx, [rsi + rax + 16]           ; op1 = string length
    mov edi, [rsi + rax + 24]           ; dst_vreg (offset 24 in 32-byte node)

    ; Validate string length - guard against 0 or excessive length
    test rdx, rdx
    jz emit_next                        ; Skip 0-length strings
    cmp rdx, 4096                       ; Sanity cap at 4KB per constant
    ja emit_next                        ; Skip oversized constants

    ; Save current rdata offset for this constant
    mov r10, r15

    ; Copy string to rdata: dest=r13+r15, src=rcx, count=rdx
    push rsi
    push rdi
    push rcx
    push rdx
    lea rdi, [r13 + r15]
    mov rsi, rcx
    mov rcx, rdx
    cld                                 ; Clear direction flag for forward copy
    rep movsb
lc_skip_copy:
    pop rdx
    pop rcx
    pop rdi
    pop rsi

    add r15, rdx
    ; Align rdata to 2 bytes
    test r15, 1
    jz lc_aligned
    inc r15
lc_aligned:

    ; Record vreg -> rdata offset mapping
    cmp edi, 0
    jl lc_novreg                       ; -1 = no vreg
    cmp edi, 63
    jg lc_novreg
    mov [vreg_rdata_off + rdi*8], r10
    mov dword ptr [vreg_type + rdi*4], 1 ; type = string
lc_novreg:
    jmp emit_next

emit_call:
    ; operand0 = function ID (1=print), operand1 = arg vreg
    imul rax, r11, 32
    mov rdx, [rsi + rax + 8]            ; op0 = function ID
    mov r8d, dword ptr [rsi + rax + 24] ; op1 = arg vreg (at offset 24)

    cmp rdx, 1                          ; 1 = print
    jne emit_next

    ; Look up vreg -> rdata offset
    cmp r8, 63
    jg emit_next
    mov r9, [vreg_rdata_off + r8*8]
    cmp r9, -1
    je emit_next                        ; vreg not mapped

    ; Emit: lea rcx, [rip + disp32]  =>  48 8D 0D xx xx xx xx
    mov byte ptr [r12 + r14], 48h
    inc r14
    mov byte ptr [r12 + r14], 8Dh
    inc r14
    mov byte ptr [r12 + r14], 0Dh
    inc r14

    ; Record RIP32 relocation: patch at r14, target = .rdata at r9
    mov rcx, r14
    mov edx, 1                          ; target_section = .rdata
    mov r8, r9                          ; target_offset
    mov r9d, RELOC_RIP32
    call EmitAddReloc

    mov dword ptr [r12 + r14], 0        ; placeholder disp32
    add r14, 4

    ; Emit: call RuntimePrintString  =>  E8 xx xx xx xx
    mov byte ptr [r12 + r14], 0E8h
    inc r14

    ; Record REL32 relocation for call target
    mov rcx, r14
    mov edx, 0                          ; .text (import stub)
    mov r8, 0                           ; PE writer resolves
    mov r9d, RELOC_REL32
    call EmitAddReloc

    mov dword ptr [r12 + r14], 0        ; placeholder rel32
    add r14, 4
    jmp emit_next

emit_move:
    ; IR_MOVE: copy vreg mapping from src to dst
    imul rax, r11, 32
    mov edx, dword ptr [rsi + rax + 8]  ; op0 = src vreg (at offset 8)
    mov edi, dword ptr [rsi + rax + 24] ; dst_vreg (at offset 24)
    cmp edx, 63
    jg emit_next
    cmp edi, 63
    jg emit_next
    mov r9, [vreg_rdata_off + rdx*8]
    mov [vreg_rdata_off + rdi*8], r9
    mov eax, [vreg_type + rdx*4]
    mov [vreg_type + rdi*4], eax
    jmp emit_next

emit_return:
    ; add rsp, 28h  =>  48 83 C4 28
    mov byte ptr [r12 + r14], 48h
    inc r14
    mov byte ptr [r12 + r14], 83h
    inc r14
    mov byte ptr [r12 + r14], 0C4h
    inc r14
    mov byte ptr [r12 + r14], 28h
    inc r14
    ; ret  =>  C3
    mov byte ptr [r12 + r14], 0C3h
    inc r14
    jmp emit_next

emit_exit:
    ; xor ecx, ecx  =>  31 C9
    mov byte ptr [r12 + r14], 31h
    inc r14
    mov byte ptr [r12 + r14], 0C9h
    inc r14
    ; call ExitProcess  =>  E8 xx xx xx xx
    mov byte ptr [r12 + r14], 0E8h
    inc r14

    ; Record REL32 relocation for ExitProcess import
    mov rcx, r14
    mov edx, 0                          ; .text (import stub)
    mov r8, 8                           ; offset 8 = ExitProcess stub
    mov r9d, RELOC_REL32
    call EmitAddReloc

    mov dword ptr [r12 + r14], 0        ; placeholder
    add r14, 4
    jmp emit_next

emit_next:
    inc r11                             ; increment NODE INDEX (not text offset!)
    jmp emit_loop

emit_done:
    mov [emit_text_size], r14
    mov [emit_rdata_size], r15
    mov rax, r14                        ; return text size

    add rsp, 20h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
EmitX64 ENDP

; ============================================================================
; EmitMov - Emit MOV reg64, imm32 (sign-extended to 64)
; RCX = buffer, RDX = register (0-15), R8 = imm32 value
; Returns: RAX = bytes emitted (7 or 8)
; ============================================================================
EmitMov PROC
    push rbx
    mov ebx, edx                ; register number

    ; REX prefix: REX.W always, REX.B if reg >= 8
    mov byte ptr [rcx], 48h     ; REX.W base
    cmp ebx, 8
    jl mov_no_b
    or byte ptr [rcx], 41h      ; REX.B
mov_no_b:
    inc rcx

    ; C7 /0 = MOV r/m64, imm32
    mov byte ptr [rcx], 0C7h
    inc rcx

    ; ModRM: mod=11 (direct), reg=0 (/0), rm = reg & 7
    mov eax, ebx
    and eax, 7
    or eax, 0C0h                ; mod=11, reg=0
    mov byte ptr [rcx], al
    inc rcx

    ; imm32
    mov dword ptr [rcx], r8d
    add rcx, 4

    cmp ebx, 8
    jl mov_7
    mov rax, 8
    jmp mov_done
mov_7:
    mov rax, 7
mov_done:
    pop rbx
    ret
EmitMov ENDP

; ============================================================================
; EmitLea - Emit LEA reg64, [rip + disp32]
; RCX = buffer, RDX = register (0-15), R8 = disp32
; Returns: RAX = bytes emitted (7 or 8)
; ============================================================================
EmitLea PROC
    push rbx
    mov ebx, edx                ; register number

    ; REX prefix: REX.W, REX.R if reg >= 8
    mov byte ptr [rcx], 48h
    cmp ebx, 8
    jl lea_no_r
    or byte ptr [rcx], 44h      ; REX.W | REX.R
lea_no_r:
    inc rcx

    ; 8D = LEA
    mov byte ptr [rcx], 8Dh
    inc rcx

    ; ModRM: mod=00, reg = reg & 7, rm=101 (RIP-relative)
    mov eax, ebx
    and eax, 7
    shl eax, 3                  ; reg field
    or eax, 05h                 ; rm=101
    mov byte ptr [rcx], al
    inc rcx

    ; disp32
    mov dword ptr [rcx], r8d
    add rcx, 4

    cmp ebx, 8
    jl lea_7
    mov rax, 8
    jmp lea_done
lea_7:
    mov rax, 7
lea_done:
    pop rbx
    ret
EmitLea ENDP

; EmitCall - Emit CALL rel32
; RCX = buffer, RDX = rel32
EmitCall PROC
    mov byte ptr [rcx], 0E8h
    mov dword ptr [rcx + 1], edx
    mov rax, 5
    ret
EmitCall ENDP

; EmitRet - Emit RET
; RCX = buffer
EmitRet PROC
    mov byte ptr [rcx], 0C3h
    mov rax, 1
    ret
EmitRet ENDP

; ============================================================================
; EmitExit - Emit xor ecx,ecx + call ExitProcess
; RCX = buffer
; Returns: RAX = 7
; ============================================================================
EmitExit PROC
    mov byte ptr [rcx], 31h         ; xor
    mov byte ptr [rcx + 1], 0C9h    ; ecx, ecx
    mov byte ptr [rcx + 2], 0E8h    ; call rel32
    mov dword ptr [rcx + 3], 0      ; placeholder
    mov rax, 7
    ret
EmitExit ENDP

; ============================================================================
; EmitGetRelocCount - Get number of relocations generated
; Returns: RAX = reloc count
; ============================================================================
EmitGetRelocCount PROC
    mov eax, emit_reloc_count
    ret
EmitGetRelocCount ENDP

; ============================================================================
; EmitGetReloc - Get relocation by index
; RCX = reloc index
; Returns: RAX = pointer to EMIT_RELOC (or NULL)
; ============================================================================
EmitGetReloc PROC
    cmp ecx, emit_reloc_count
    jae invalid
    imul eax, ecx, SIZEOF EMIT_RELOC
    lea rax, [emit_relocs + rax]
    ret
invalid:
    xor rax, rax
    ret
EmitGetReloc ENDP

; ============================================================================
; EmitGetRdataSize - Get rdata section size
; Returns: RAX = rdata size
; ============================================================================
EmitGetRdataSize PROC
    mov rax, emit_rdata_size
    ret
EmitGetRdataSize ENDP

end