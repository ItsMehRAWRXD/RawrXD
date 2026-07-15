; RawrXD-Script Function Optimization
; Phase 3: Function calls and closures
; Pure x64 MASM

.CODE

; ============================================================================
; Function Structure
; ============================================================================

; JSFunction structure:
;   +0:  Object header (shape, flags, etc.)
;   +48: uint8_t* bytecode           ; Function bytecode pointer
;   +56: uint32_t bytecode_size      ; Size of bytecode
;   +64: uint16_t param_count        ; Number of parameters
;   +66: uint16_t local_count        ; Number of local variables
;   +68: uint16_t stack_depth        ; Maximum stack depth
;   +70: uint16_t flags              ; Function flags
;   +72: JsValue* constants          ; Function constants
;   +80: uint32_t* line_info         ; Line number table
;   +88: Closure* closure            ; Closure environment (or null)
;   +96: char* name                  ; Function name (or null)

FUNC_BYTECODE       EQU 48
FUNC_BC_SIZE        EQU 56
FUNC_PARAM_COUNT    EQU 64
FUNC_LOCAL_COUNT    EQU 66
FUNC_STACK_DEPTH    EQU 68
FUNC_FLAGS          EQU 70
FUNC_CONSTANTS      EQU 72
FUNC_LINE_INFO      EQU 80
FUNC_CLOSURE        EQU 88
FUNC_NAME           EQU 96

FUNC_SIZE           EQU 104

; Function flags
FUNC_FLAG_STRICT          EQU 0x0001
FUNC_FLAG_ARROW           EQU 0x0002
FUNC_FLAG_GENERATOR       EQU 0x0004
FUNC_FLAG_ASYNC           EQU 0x0008
FUNC_FLAG_BOUND           EQU 0x0010
FUNC_FLAG_NATIVE          EQU 0x0020

; ============================================================================
; Call Frame Structure
; ============================================================================

; Call frame (on stack):
;   +0:   JsValue* prev_frame        ; Previous frame pointer
;   +8:   uint8_t* return_pc         ; Return address (bytecode)
;   +16:  JsValue* code_base         ; Code base for return
;   +24:  JsValue this_obj           ; This binding
;   +32:  JsValue function_obj       ; Function being called
;   +40:  uint16_t arg_count         ; Number of arguments
;   +42:  uint16_t local_count       ; Number of locals
;   +44:  uint32_t flags             ; Frame flags
;   +48:  JsValue locals[]           ; Local variables (variable)

FRAME_PREV          EQU 0
FRAME_RETURN_PC     EQU 8
FRAME_CODE_BASE     EQU 16
FRAME_THIS          EQU 24
FRAME_FUNCTION      EQU 32
FRAME_ARG_COUNT     EQU 40
FRAME_LOCAL_COUNT   EQU 42
FRAME_FLAGS         EQU 44
FRAME_LOCALS        EQU 48

FRAME_HEADER_SIZE   EQU 48

; ============================================================================
; Function Call with Inline Caching
; ============================================================================

; CallIC Slot Structure (24 bytes):
;   +0:  uint8_t* cached_bytecode     ; Cached function bytecode
;   +8:  uint16_t cached_param_count  ; Cached parameter count
;   +10: uint16_t cached_local_count  ; Cached local count
;   +12: uint32_t hit_count           ; Number of hits
;   +16: JsValue* cached_constants      ; Cached constants pointer
;   +24: uint8_t type                 ; IC type (mono/poly/mega)

CALLIC_BYTECODE     EQU 0
CALLIC_PARAM_COUNT  EQU 8
CALLIC_LOCAL_COUNT  EQU 10
CALLIC_HIT_COUNT    EQU 12
CALLIC_CONSTANTS    EQU 16
CALLIC_TYPE         EQU 24

CALLIC_SIZE         EQU 32

; Function_CallIC - Call function with inline caching
; Entry:  rcx = function (NaN-boxed)
;         rdx = thisArg (NaN-boxed)
;         r8  = arguments array pointer
;         r9  = argument count
;         [rsp+40] = IC slot pointer
;         [rsp+48] = arena base
; Exit:   rax = return value (NaN-boxed)
Function_CallIC PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    push r12
    .pushreg r12
    push r13
    .pushreg r13
    push r14
    .pushreg r14
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rbx, rcx        ; rbx = function
    mov r12, rdx        ; r12 = thisArg
    mov r13, r8         ; r13 = arguments
    mov r14d, r9d       ; r14d = arg count
    
    ; Extract function pointer
    mov rax, rbx
    and rax, 0x0000FFFFFFFFFFFF
    mov rbx, rax
    
    ; Get IC slot
    mov rax, [rsp + 40 + 72]    ; IC slot (accounting for saved regs)
    test rax, rax
    jz .no_ic
    
    mov rsi, rax        ; rsi = IC slot
    
    ; Check IC cache
    mov rax, [rsi + CALLIC_BYTECODE]
    mov rdx, [rbx + FUNC_BYTECODE]
    cmp rax, rdx
    jne .ic_miss
    
    ; IC hit!
    inc dword ptr [rsi + CALLIC_HIT_COUNT]
    jmp .setup_frame
    
.ic_miss:
    ; Update IC
    mov [rsi + CALLIC_BYTECODE], rdx
    movzx eax, word ptr [rbx + FUNC_PARAM_COUNT]
    mov [rsi + CALLIC_PARAM_COUNT], ax
    movzx eax, word ptr [rbx + FUNC_LOCAL_COUNT]
    mov [rsi + CALLIC_LOCAL_COUNT], ax
    mov rax, [rbx + FUNC_CONSTANTS]
    mov [rsi + CALLIC_CONSTANTS], rax
    mov byte ptr [rsi + CALLIC_TYPE], 0   ; Monomorphic
    
.no_ic:
    ; Load function info
    movzx eax, word ptr [rbx + FUNC_PARAM_COUNT]
    movzx edx, word ptr [rbx + FUNC_LOCAL_COUNT]
    
.setup_frame:
    ; Allocate frame on stack
    ; Frame header + locals + arguments
    mov ecx, [rsi + CALLIC_LOCAL_COUNT]
    add ecx, r14d           ; + arguments
    shl ecx, 3              ; * 8 bytes
    add ecx, FRAME_HEADER_SIZE
    
    sub rsp, rcx            ; Allocate frame
    mov rdi, rsp            ; rdi = frame base
    
    ; Initialize frame
    mov [rdi + FRAME_PREV], rbp    ; Previous frame
    mov [rdi + FRAME_RETURN_PC], 0 ; Will be set by caller
    mov [rdi + FRAME_CODE_BASE], 0
    mov [rdi + FRAME_THIS], r12
    mov [rdi + FRAME_FUNCTION], rbx
    mov [rdi + FRAME_ARG_COUNT], r14w
    movzx eax, word ptr [rsi + CALLIC_LOCAL_COUNT]
    mov [rdi + FRAME_LOCAL_COUNT], ax
    mov dword ptr [rdi + FRAME_FLAGS], 0
    
    ; Copy arguments to frame
    mov rcx, r14
    mov rdx, r13            ; Source arguments
    lea r8, [rdi + FRAME_LOCALS]    ; Dest locals
    
.copy_args:
    test ecx, ecx
    jz .init_locals
    mov rax, [rdx]
    mov [r8], rax
    add rdx, 8
    add r8, 8
    dec ecx
    jmp .copy_args
    
.init_locals:
    ; Initialize remaining locals to undefined
    movzx ecx, word ptr [rdi + FRAME_LOCAL_COUNT]
    sub ecx, r14d           ; Remaining locals
    
.init_loop:
    test ecx, ecx
    jz .call_function
    mov qword ptr [r8], JS_UNDEFINED
    add r8, 8
    dec ecx
    jmp .init_loop
    
.call_function:
    ; Set up VM registers for function entry
    mov rax, [rsi + CALLIC_BYTECODE]
    mov rbx, rax            ; PC = function start
    mov rsi, [rsi + CALLIC_CONSTANTS]
    mov rdi, rsi            ; CONST_POOL = function constants
    
    ; Save frame pointer
    mov rbp, rdi
    
    ; Jump to interpreter loop
    ; Note: In real implementation, this would tail-call or inline
    
    ; For now, simulate return
    mov rax, JS_UNDEFINED
    
    ; Restore stack
    mov rsp, rbp
    
.done:
    add rsp, 40
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Function_CallIC ENDP

; ============================================================================
; Closure Operations
; ============================================================================

; Closure structure:
;   +0:  uint32_t slot_count          ; Number of captured variables
;   +4:  uint32_t flags               ; Closure flags
;   +8:  JsValue* parent_closure      ; Parent closure (or null)
;   +16: JsValue captured_slots[]     ; Captured variable values

CLOS_SLOT_COUNT     EQU 0
CLOS_FLAGS          EQU 4
CLOS_PARENT         EQU 8
CLOS_SLOTS          EQU 16

CLOS_HEADER_SIZE    EQU 16

; Closure_Create - Create a closure environment
; Entry:  rcx = parent closure (or null)
;         rdx = slot count
;         r8  = arena base
; Exit:   rax = closure (not NaN-boxed)
Closure_Create PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rbx, rcx        ; rbx = parent
    mov eax, edx        ; eax = slot count
    
    ; Calculate size
    shl eax, 3          ; * 8 bytes per slot
    add eax, CLOS_HEADER_SIZE
    
    ; Allocate
    mov rcx, rax
    ; ARENA_ALLOC
    
    test rax, rax
    jz .fail
    
    ; Initialize closure
    mov [rax + CLOS_SLOT_COUNT], edx
    mov dword ptr [rax + CLOS_FLAGS], 0
    mov [rax + CLOS_PARENT], rbx
    
    ; Initialize slots to undefined
    mov ecx, edx
    mov rdx, rax
    add rdx, CLOS_SLOTS
.init_slots:
    test ecx, ecx
    jz .done
    mov qword ptr [rdx], JS_UNDEFINED
    add rdx, 8
    dec ecx
    jmp .init_slots
    
.done:
    add rsp, 40
    pop rbx
    pop rbp
    ret
    
.fail:
    xor rax, rax
    jmp .done
Closure_Create ENDP

; Closure_GetSlot - Get value from closure slot
; Entry:  rcx = closure
;         rdx = slot index
; Exit:   rax = value (NaN-boxed)
Closure_GetSlot PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Bounds check
    cmp edx, [rcx + CLOS_SLOT_COUNT]
    jae .out_of_bounds
    
    ; Load slot
    mov rax, [rcx + CLOS_SLOTS + rdx*8]
    jmp .done
    
.out_of_bounds:
    mov rax, JS_UNDEFINED
    
.done:
    add rsp, 40
    pop rbp
    ret
Closure_GetSlot ENDP

; Closure_SetSlot - Set value in closure slot
; Entry:  rcx = closure
;         rdx = slot index
;         r8  = value (NaN-boxed)
; Exit:   rax = 1 on success, 0 on failure
Closure_SetSlot PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Bounds check
    cmp edx, [rcx + CLOS_SLOT_COUNT]
    jae .fail
    
    ; Store slot
    mov [rcx + CLOS_SLOTS + rdx*8], r8
    mov rax, 1
    jmp .done
    
.fail:
    xor rax, rax
    
.done:
    add rsp, 40
    pop rbp
    ret
Closure_SetSlot ENDP

; ============================================================================
; Native Function Bridge
; ============================================================================

; Native function signature:
;   JsValue NativeFunc(JsValue thisArg, JsValue* args, int argCount, void* userData);

; NativeCall_Invoke - Call a native function
; Entry:  rcx = native function pointer
;         rdx = thisArg (NaN-boxed)
;         r8  = arguments array
;         r9  = argument count
;         [rsp+40] = userData
; Exit:   rax = return value (NaN-boxed)
NativeCall_Invoke PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rbx, rcx        ; rbx = native function
    
    ; Call native function
    ; Arguments already in rcx, rdx, r8, r9
    ; Stack aligned, shadow space reserved
    
    call rbx
    
    add rsp, 40
    pop rbx
    pop rbp
    ret
NativeCall_Invoke ENDP

; ============================================================================
; Tail Call Optimization
; ============================================================================

; Function_TailCall - Perform a tail call
; Entry:  rcx = new function
;         rdx = thisArg
;         r8  = arguments
;         r9  = arg count
; Exit:   (does not return, jumps to new function)
Function_TailCall PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; In a real implementation, this would:
    ; 1. Pop current frame
    ; 2. Reuse the current stack frame for new call
    ; 3. Jump to new function entry
    
    ; For now, just regular call
    ; TODO: Implement proper tail call optimization
    
    add rsp, 40
    pop rbp
    ret
Function_TailCall ENDP

END
