; ============================================================================
; RawrXD-Script VM Core (Phase 0)
; Pure x64 MASM Interpreter - Zero Dependencies
; ============================================================================
; Phase 0: Minimal dispatch loop with OP_LOAD_INT, OP_ADD, OP_RETURN
; Target: Validate register mapping and direct-threaded dispatch
; ============================================================================

; =============================================================================
; Opcode Definitions (Phase 0 Subset)
; =============================================================================
OP_LOAD_INT     EQU     0x01        ; Load 32-bit immediate into register
OP_LOAD_CONST   EQU     0x02        ; Load from constant pool (future)
OP_ADD          EQU     0x03        ; Add two registers
OP_SUB          EQU     0x04        ; Subtract (future)
OP_RETURN       EQU     0x07        ; Return value in register

; =============================================================================
; VM Register Mapping (Win64 ABI Non-Volatile)
; =============================================================================
; We use registers directly - no EQU redefinition allowed for register names
; VM State (Callee-Saved under Win64 ABI):
;   rbx = Program Counter (bytecode pointer)
;   rsi = Bytecode stream base
;   rdi = Constant pool pointer (future)
;   r12 = Global object context
;   r13 = Memory arena base
;   r14 = Arena bump pointer
;   r15 = Inline cache table (future)
;
; Virtual JS Registers (r8-r11 are volatile per Win64 ABI):
;   r8  = Virtual register 0
;   r9  = Virtual register 1
;   r10 = Virtual register 2
;   r11 = Virtual register 3
;
; Scratch/Return (Volatile):
;   rax = Scratch/Return value
;   rcx = First argument
;   rdx = Second argument

; =============================================================================
; Data Section
; =============================================================================
.data

; Dispatch table for Phase 0 opcodes (256 entries, 8 bytes each = 2KB)
; Aligned to 64-byte boundary for cache efficiency
ALIGN 64
JsDispatchTable LABEL QWORD
    ; 0x00: OP_LOAD_CONST (stub)
    QWORD offset op_unimplemented
    ; 0x01: OP_LOAD_INT
    QWORD offset op_load_int
    ; 0x02: OP_LOAD_CONST
    QWORD offset op_load_const
    ; 0x03: OP_ADD
    QWORD offset op_add
    ; 0x04: OP_SUB (stub)
    QWORD offset op_unimplemented
    ; 0x05-0x06: Reserved
    QWORD offset op_unimplemented
    QWORD offset op_unimplemented
    ; 0x07: OP_RETURN
    QWORD offset op_return
    ; 0x08-0xFF: Unimplemented (248 entries)
    ; Using DUP directive for MASM compatibility
    QWORD 248 DUP (offset op_unimplemented)

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; JsInterpreter_Run
; Main interpreter entry point
; 
; Input:  rcx = Pointer to bytecode array
;         rdx = Bytecode size (bytes)
; Output: rax = Return value (64-bit integer)
;
; Clobbers: None (all non-volatile registers preserved per Win64 ABI)
; =============================================================================
JsInterpreter_Run PROC FRAME
    ; -------------------------------------------------------------------------
    ; Prologue: Preserve Win64 ABI Non-Volatile Registers
    ; rbx, rsi, rdi, r12, r13, r14, r15 must be preserved across call
    ; -------------------------------------------------------------------------
    push    rbp
    mov     rbp, rsp
    push    rbx                     ; PC
    push    rsi                     ; CODE_BASE
    push    rdi                     ; CONST_POOL
    push    r12                     ; GLOBAL_CTX
    push    r13                     ; ARENA_BASE
    push    r14                     ; ARENA_BUMP
    push    r15                     ; IC_TABLE
    
    ; Allocate shadow space + align to 16 bytes
    sub     rsp, 40                 ; 32 bytes shadow + 8 bytes alignment
    
    .pushreg rbp
    .pushreg rbx
    .pushreg rsi
    .pushreg rdi
    .pushreg r12
    .pushreg r13
    .pushreg r14
    .pushreg r15
    .allocstack 40
    .endprolog
    
    ; -------------------------------------------------------------------------
    ; Initialize VM State
    ; -------------------------------------------------------------------------
    mov     CODE_BASE, rcx          ; rsi = bytecode base
    xor     PC, PC                  ; rbx = 0 (start at offset 0)
    xor     GLOBAL_CTX, GLOBAL_CTX  ; r12 = null (no global context yet)
    xor     ARENA_BASE, ARENA_BASE  ; r13 = null (no arena yet)
    xor     ARENA_BUMP, ARENA_BUMP  ; r14 = 0
    xor     IC_TABLE, IC_TABLE      ; r15 = null (no IC table yet)
    
    ; Clear virtual registers
    xor     V0, V0                  ; r8 = 0
    xor     V1, V1                  ; r9 = 0
    xor     V2, V2                  ; r10 = 0
    xor     V3, V3                  ; r11 = 0

; =============================================================================
; Main Dispatch Loop
; =============================================================================
dispatch_loop:
    ; Fetch opcode at PC
    movzx   rax, byte ptr [rsi + rbx]
    inc     rbx                     ; Advance PC
    
    ; Direct-threaded dispatch: jump through dispatch table
    jmp     QWORD PTR [JsDispatchTable + rax * 8]

; =============================================================================
; Opcode Handlers
; =============================================================================

; -----------------------------------------------------------------------------
; OP_LOAD_INT (0x01)
; Format: [OP:1][REG:1][IMM32:4]
; Load 32-bit immediate into virtual register
; -----------------------------------------------------------------------------
op_load_int:
    ; Fetch destination register index
    movzx   rax, byte ptr [rsi + rbx]
    inc     rbx
    
    ; Fetch 32-bit immediate
    mov     edx, ebx                ; rdx = current PC
    add     rbx, 4                  ; Advance past immediate
    mov     ecx, DWORD PTR [rsi + rdx]  ; Load 32-bit immediate
    
    ; Store to appropriate virtual register
    ; Map: 0x08=r8, 0x09=r9, 0x0A=r10, 0x0B=r11
    cmp     al, 0x08
    je      load_v0
    cmp     al, 0x09
    je      load_v1
    cmp     al, 0x0A
    je      load_v2
    cmp     al, 0x0B
    je      load_v3
    jmp     dispatch_loop           ; Invalid register, skip

load_v0:
    movsx   r8, ecx                 ; Sign-extend 32-bit to 64-bit
    jmp     dispatch_loop

load_v1:
    movsx   r9, ecx
    jmp     dispatch_loop

load_v2:
    movsx   r10, ecx
    jmp     dispatch_loop

load_v3:
    movsx   r11, ecx
    jmp     dispatch_loop

; -----------------------------------------------------------------------------
; OP_LOAD_CONST (0x02)
; Stub for future constant pool loading
; -----------------------------------------------------------------------------
op_load_const:
    ; Skip instruction bytes for now
    add     rbx, 5                  ; OP(1) + REG(1) + IDX(2) + PAD(1)
    jmp     dispatch_loop

; -----------------------------------------------------------------------------
; OP_ADD (0x03)
; Format: [OP:1][DEST:1][SRC_A:1][SRC_B:1]
; Add two virtual registers, store in destination
; -----------------------------------------------------------------------------
op_add:
    ; Fetch destination register
    movzx   ecx, byte ptr [rsi + rbx]   ; rcx = dest
    inc     rbx
    
    ; Fetch source registers
    movzx   edx, byte ptr [rsi + rbx]   ; rdx = src_a
    inc     rbx
    movzx   r8d, byte ptr [rsi + rbx]   ; r8 = src_b
    inc     rbx
    
    ; Save registers that get clobbered
    push    r8
    push    r9
    push    r10
    push    r11
    
    ; Get src_a value
    mov     eax, edx                ; rax = src_a index
    call    get_register_value      ; rax = value of src_a
    mov     r9, rax                 ; r9 = src_a value (save it)
    
    ; Get src_b value
    mov     eax, r8d                ; rax = src_b index
    call    get_register_value      ; rax = value of src_b
    
    ; Add: result = src_a + src_b
    add     rax, r9                 ; rax = src_a + src_b
    mov     rdx, rax                ; rdx = result
    mov     ecx, ecx                ; rcx = dest index
    call    set_register_value      ; Store result
    
    pop     r11
    pop     r10
    pop     r9
    pop     r8
    jmp     dispatch_loop

; -----------------------------------------------------------------------------
; OP_RETURN (0x07)
; Format: [OP:1][SRC:1]
; Return value from virtual register
; -----------------------------------------------------------------------------
op_return:
    ; Fetch source register
    movzx   eax, byte ptr [rsi + rbx]
    inc     rbx
    
    ; Get register value into rax for return
    call    get_register_value
    
    ; rax now contains return value
    jmp     vm_exit

; -----------------------------------------------------------------------------
; Unimplemented Opcode Handler
; -----------------------------------------------------------------------------
op_unimplemented:
    ; For Phase 0: just skip to next instruction
    ; In production: raise exception or trap
    inc     rbx
    jmp     dispatch_loop

; =============================================================================
; Helper Functions
; =============================================================================

; -----------------------------------------------------------------------------
; get_register_value
; Input:  SCRATCH (rax) = register index (0x08-0x0B)
; Output: SCRATCH (rax) = register value
; Clobbers: None
; -----------------------------------------------------------------------------
get_register_value PROC
    ; Input: eax = register index (0x08-0x0B)
    ; Output: rax = register value
    cmp     al, 0x08
    je      get_v0
    cmp     al, 0x09
    je      get_v1
    cmp     al, 0x0A
    je      get_v2
    cmp     al, 0x0B
    je      get_v3
    xor     rax, rax                ; Invalid register = 0
    ret

get_v0:
    mov     rax, r8
    ret

get_v1:
    mov     rax, r9
    ret

get_v2:
    mov     rax, r10
    ret

get_v3:
    mov     rax, r11
    ret
get_register_value ENDP

; -----------------------------------------------------------------------------
; set_register_value
; Input:  ARG1 (rdx) = value to store
;         ARG2 (rcx) = register index (0x08-0x0B)
; Output: None
; Clobbers: None
; -----------------------------------------------------------------------------
set_register_value PROC
    ; Input: ecx = register index (0x08-0x0B), rdx = value
    cmp     cl, 0x08
    je      set_v0
    cmp     cl, 0x09
    je      set_v1
    cmp     cl, 0x0A
    je      set_v2
    cmp     cl, 0x0B
    je      set_v3
    ret                             ; Invalid register, ignore

set_v0:
    mov     r8, rdx
    ret

set_v1:
    mov     r9, rdx
    ret

set_v2:
    mov     r10, rdx
    ret

set_v3:
    mov     r11, rdx
    ret
set_register_value ENDP

; =============================================================================
; VM Exit
; =============================================================================
vm_exit:
    ; rax already contains return value from op_return
    
    ; -------------------------------------------------------------------------
    ; Epilogue: Restore Win64 ABI Non-Volatile Registers
    ; -------------------------------------------------------------------------
    add     rsp, 40                 ; Deallocate shadow space
    
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret

JsInterpreter_Run ENDP

; =============================================================================
; Exports
; =============================================================================
PUBLIC JsInterpreter_Run

END
