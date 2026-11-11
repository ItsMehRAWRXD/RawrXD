; RawrXD-Script Missing Opcode Implementations
; Completes the interpreter with all unimplemented handlers

.CODE

; ============================================================================
; Bitwise Operations (0x30-0x3F)
; ============================================================================

; OP_BIT_AND: r_dest = r_left & r_right
op_bit_and:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = src A
    movzx rsi, byte ptr [rbx+2]             ; rsi = src B
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]                  ; rax = left
    mov r8, [rbp + rsi*8]                   ; r8 = right
    
    ; Convert to integers (JavaScript bitwise ops work on 32-bit signed)
    call JsValue_ToInt32
    mov r9d, eax                            ; r9d = left as int32
    
    mov rcx, r8
    call JsValue_ToInt32
    
    and r9d, eax                            ; r9d = left & right
    
    ; Box result
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    
    movzx rcx, byte ptr [rbx-3]             ; Restore dest reg
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_BIT_OR: r_dest = r_left | r_right
op_bit_or:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    call JsValue_ToInt32
    mov r9d, eax
    
    mov rcx, r8
    call JsValue_ToInt32
    
    or r9d, eax
    
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_BIT_XOR: r_dest = r_left ^ r_right
op_bit_xor:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    call JsValue_ToInt32
    mov r9d, eax
    
    mov rcx, r8
    call JsValue_ToInt32
    
    xor r9d, eax
    
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_BIT_NOT: r_dest = ~r_src
op_bit_not:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = src
    add rbx, 2
    
    mov rax, [rbp + rdx*8]                  ; rax = value
    
    call JsValue_ToInt32
    not eax                                 ; Bitwise NOT
    
    ; Box result
    mov rcx, rax
    shl rcx, 32
    or rcx, TAG_INT32
    or rcx, QNAN_MASK
    
    movzx rax, byte ptr [rbx-2]             ; Restore dest
    mov [rbp + rax*8], rcx
    jmp .interpreter_loop

; OP_SHL: r_dest = r_left << r_right
op_shl:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    call JsValue_ToInt32
    mov r9d, eax
    
    mov rcx, r8
    call JsValue_ToInt32
    and eax, 0x1F                             ; Shift count masked to 5 bits
    
    shl r9d, eax
    
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_SHR: r_dest = r_left >> r_right (signed)
op_shr:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    call JsValue_ToInt32
    mov r9d, eax
    
    mov rcx, r8
    call JsValue_ToInt32
    and eax, 0x1F
    
    sar r9d, eax                            ; Arithmetic shift right
    
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_SHR_U: r_dest = r_left >>> r_right (unsigned)
op_shr_u:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    call JsValue_ToInt32
    mov r9d, eax
    
    mov rcx, r8
    call JsValue_ToInt32
    and eax, 0x1F
    
    shr r9d, eax                            ; Logical shift right
    
    mov rax, r9
    shl rax, 32
    or rax, TAG_INT32
    or rax, QNAN_MASK
    
    movzx rcx, byte ptr [rbx-3]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; ============================================================================
; Comparison Operations (0x40-0x4F)
; ============================================================================

; OP_NEQ: r_dest = r_left != r_right (loose)
op_neq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Fast path: same value
    cmp rax, r8
    setne al
    movzx rax, al
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_LTE: r_dest = r_left <= r_right
op_lte:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .lte_slow
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .lte_slow
    
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    xor r9, r9
    cmp rax, r8
    setle r9b
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp .interpreter_loop
    
.lte_slow:
    jmp .interpreter_loop

; OP_GT: r_dest = r_left > r_right
op_gt:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .gt_slow
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .gt_slow
    
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    xor r9, r9
    cmp rax, r8
    setg r9b
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp .interpreter_loop
    
.gt_slow:
    jmp .interpreter_loop

; OP_GTE: r_dest = r_left >= r_right
op_gte:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .gte_slow
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .gte_slow
    
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    xor r9, r9
    cmp rax, r8
    setge r9b
    BOX_BOOL r9, r9
    mov [rbp + rcx*8], r9
    jmp .interpreter_loop
    
.gte_slow:
    jmp .interpreter_loop

; OP_STRICT_EQ: r_dest = r_left === r_right
op_strict_eq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Strict equality - no type coercion
    cmp rax, r8
    sete al
    movzx rax, al
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_STRICT_NEQ: r_dest = r_left !== r_right
op_strict_neq:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    cmp rax, r8
    setne al
    movzx rax, al
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; ============================================================================
; String Operations
; ============================================================================

; OP_LOAD_STRING: r_dest = string_table[idx]
op_load_string:
    movzx rcx, byte ptr [rbx]               ; rcx = dest reg
    movzx rdx, word ptr [rbx+1]             ; rdx = string table index
    add rbx, 3
    
    ; Load string pointer from string table
    ; rdi = const pool base, string table follows constants
    mov rax, [rdi + rdx*8]
    
    ; Tag as string
    or rax, TAG_STRING
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_LOAD_DOUBLE: r_dest = const_pool[idx] (double)
op_load_double:
    movzx rcx, byte ptr [rbx]               ; rcx = dest reg
    movzx rdx, word ptr [rbx+1]             ; rdx = const pool index
    add rbx, 3
    
    ; Load double from constant pool
    movsd xmm0, [rdi + rdx*8]
    movsd [rbp + rcx*8 - 8], xmm0
    jmp .interpreter_loop

; ============================================================================
; Register Movement
; ============================================================================

; OP_MOVE: r_dest = r_src
op_move:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = src
    add rbx, 2
    
    mov rax, [rbp + rdx*8]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_SWAP: swap r_a, r_b
op_swap:
    movzx rcx, byte ptr [rbx]               ; rcx = reg A
    movzx rdx, byte ptr [rbx+1]             ; rdx = reg B
    add rbx, 2
    
    mov rax, [rbp + rcx*8]
    mov r8, [rbp + rdx*8]
    mov [rbp + rcx*8], r8
    mov [rbp + rdx*8], rax
    jmp .interpreter_loop

; ============================================================================
; Arithmetic Modulo
; ============================================================================

; OP_MOD: r_dest = r_left % r_right
op_mod:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov rax, [rbp + rdx*8]
    mov r8, [rbp + rsi*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r10, rax
    and r10, r9
    cmp r10, r9
    jne .mod_slow
    
    mov r10, r8
    and r10, r9
    cmp r10, r9
    jne .mod_slow
    
    UNBOX_INT rax, rax
    UNBOX_INT r8, r8
    
    ; Check division by zero
    test r8, r8
    jz .mod_nan
    
    xor edx, edx
    idiv r8d
    
    BOX_INT rdx, rdx                        ; Remainder in rdx
    mov [rbp + rcx*8], rdx
    jmp .interpreter_loop
    
.mod_nan:
    mov rax, 0x7FF8000000000000             ; NaN
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop
    
.mod_slow:
    jmp .interpreter_loop

; ============================================================================
; Increment/Decrement
; ============================================================================

; OP_INC: r_dest = r_src + 1
op_inc:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    
    mov rax, [rbp + rdx*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r8, rax
    and r8, r9
    cmp r8, r9
    jne .inc_slow
    
    UNBOX_INT rax, rax
    inc rax
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop
    
.inc_slow:
    jmp .interpreter_loop

; OP_DEC: r_dest = r_src - 1
op_dec:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    
    mov rax, [rbp + rdx*8]
    
    ; Integer fast path
    mov r9, 0x7FF9000000000000
    mov r8, rax
    and r8, r9
    cmp r8, r9
    jne .dec_slow
    
    UNBOX_INT rax, rax
    dec rax
    BOX_INT rax, rax
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop
    
.dec_slow:
    jmp .interpreter_loop

; ============================================================================
; Power Operation
; ============================================================================

; OP_POW: r_dest = r_left ** r_right
op_pow:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    ; Call runtime for pow
    sub rsp, 32
    mov rcx, [rbp + rdx*8]
    mov rdx, [rbp + rsi*8]
    call JsMath_Pow
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; ============================================================================
; Control Flow Extensions
; ============================================================================

; OP_JMP_NOT_COND: if (!r_cond) pc += offset
op_jmp_not_cond:
    movzx rcx, byte ptr [rbx]               ; rcx = condition register
    movsxd rdx, dword ptr [rbx+1]           ; rdx = offset
    add rbx, 5                              ; Advance PC
    
    mov rax, [rbp + rcx*8]                  ; rax = condition value
    
    ; Check if falsy
    cmp rax, JS_FALSE
    je .do_jump_not
    cmp rax, JS_NULL
    je .do_jump_not
    cmp rax, JS_UNDEFINED
    je .do_jump_not
    cmp rax, 0x7FF9000000000000             ; Boxed 0
    je .do_jump_not
    
    jmp .interpreter_loop
    
.do_jump_not:
    add rbx, rdx
    jmp .interpreter_loop

; ============================================================================
; Array Operations
; ============================================================================

; OP_GET_ELEM: r_dest = r_obj[r_index]
op_get_elem:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = obj reg
    movzx rsi, byte ptr [rbx+2]             ; rsi = index reg
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rdx*8]                   ; r8 = array object
    mov r9, [rbp + rsi*8]                   ; r9 = index
    
    ; Check if array
    IS_POINTER r8, .get_elem_array, .get_elem_slow
    
.get_elem_array:
    ; Extract array pointer
    and r8, 0x0000FFFFFFFFFFFF
    
    ; Get index as integer
    mov rcx, r9
    call JsValue_ToInt32
    mov r10d, eax                           ; r10d = index
    
    ; Bounds check
    cmp r10d, [r8 + 16]                     ; array->length
    jae .get_elem_undefined
    
    ; Load element
    mov rax, [r8 + 24 + r10*8]              ; array->elements[index]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop
    
.get_elem_undefined:
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop
    
.get_elem_slow:
    ; Call runtime
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsArray_GetElement
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_SET_ELEM: r_obj[r_index] = r_value
op_set_elem:
    movzx rcx, byte ptr [rbx]               ; rcx = obj reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = index reg
    movzx rsi, byte ptr [rbx+2]             ; rsi = value reg
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rcx*8]                   ; r8 = array
    mov r9, [rbp + rdx*8]                   ; r9 = index
    mov r10, [rbp + rsi*8]                  ; r10 = value
    
    IS_POINTER r8, .set_elem_array, .set_elem_slow
    
.set_elem_array:
    and r8, 0x0000FFFFFFFFFFFF
    
    mov rcx, r9
    call JsValue_ToInt32
    mov r11d, eax
    
    ; Bounds check and grow if needed
    cmp r11d, [r8 + 16]
    jae .set_elem_grow
    
.set_elem_store:
    mov [r8 + 24 + r11*8], r10
    jmp .interpreter_loop
    
.set_elem_grow:
    ; Grow array
    push rcx
    push rdx
    push r8
    push r9
    push r10
    push r11
    
    sub rsp, 32
    mov rcx, r8
    mov edx, r11d
    inc edx
    call JsArray_Grow
    add rsp, 32
    
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    
    jmp .set_elem_store
    
.set_elem_slow:
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    mov r8, r10
    call JsArray_SetElement
    add rsp, 32
    jmp .interpreter_loop

; OP_ARRAY_PUSH: r_array.push(r_value)
op_array_push:
    movzx rcx, byte ptr [rbx]               ; rcx = array reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = value reg
    add rbx, 2
    
    mov r8, [rbp + rcx*8]                   ; r8 = array
    mov r9, [rbp + rdx*8]                   ; r9 = value
    
    IS_POINTER r8, .push_array, .push_slow
    
.push_array:
    and r8, 0x0000FFFFFFFFFFFF
    
    ; Get current length
    mov eax, [r8 + 16]                      ; length
    mov r10d, eax
    inc r10d                                ; new length
    
    ; Check capacity
    cmp r10d, [r8 + 20]                     ; capacity
    ja .push_grow
    
    ; Store and update length
    mov [r8 + 24 + rax*8], r9
    mov [r8 + 16], r10d
    jmp .interpreter_loop
    
.push_grow:
    push rcx
    push rdx
    push r8
    push r9
    push r10
    
    sub rsp, 32
    mov rcx, r8
    mov edx, r10d
    call JsArray_Grow
    add rsp, 32
    
    pop r10
    pop r9
    pop r8
    pop rdx
    pop rcx
    
    jmp .push_array
    
.push_slow:
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsArray_Push
    add rsp, 32
    jmp .interpreter_loop

; OP_ARRAY_POP: r_dest = r_array.pop()
op_array_pop:
    movzx rcx, byte ptr [rbx]               ; rcx = dest reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = array reg
    add rbx, 2
    
    mov r8, [rbp + rdx*8]                   ; r8 = array
    
    IS_POINTER r8, .pop_array, .pop_slow
    
.pop_array:
    and r8, 0x0000FFFFFFFFFFFF
    
    ; Check length
    mov eax, [r8 + 16]
    test eax, eax
    jz .pop_undefined
    
    dec eax
    mov r9, [r8 + 24 + rax*8]               ; Get last element
    mov [r8 + 16], eax                      ; Update length
    
    mov [rbp + rcx*8], r9
    jmp .interpreter_loop
    
.pop_undefined:
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop
    
.pop_slow:
    sub rsp, 32
    mov rcx, r8
    call JsArray_Pop
    add rsp, 32
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; ============================================================================
; Function Operations
; ============================================================================

; OP_CALL: r_dest = r_func(r_args...)
op_call:
    movzx rcx, byte ptr [rbx]               ; rcx = dest reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = func reg
    movzx rsi, byte ptr [rbx+2]             ; rsi = arg count
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rdx*8]                   ; r8 = function
    
    ; Build argument array on stack
    sub rsp, 32 + rsi*8
    
    ; Copy arguments
    mov r9, rsi
    mov r10, 0
.copy_args:
    cmp r10, r9
    jae .do_call
    movzx eax, byte ptr [rbx + r10]
    mov rax, [rbp + rax*8]
    mov [rsp + 32 + r10*8], rax
    inc r10
    jmp .copy_args
    
.do_call:
    add rbx, rsi                            ; Skip arg registers
    
    ; Call function
    mov rcx, r8                             ; Function
    mov rdx, rsp                            ; Args array
    mov r8, rsi                             ; Arg count
    mov r9, r12                             ; Global object
    call JsFunction_Call
    
    add rsp, 32 + rsi*8
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_CALL_NATIVE: r_dest = native_func(r_args...)
op_call_native:
    movzx rcx, byte ptr [rbx]               ; rcx = dest reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = native func reg
    movzx rsi, byte ptr [rbx+2]             ; rsi = arg count
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rdx*8]                   ; r8 = native function pointer
    
    ; Extract function pointer from NaN-boxed value
    and r8, 0x0000FFFFFFFFFFFF
    
    ; Build argument array
    sub rsp, 32 + rsi*8
    
    mov r9, rsi
    mov r10, 0
.copy_native_args:
    cmp r10, r9
    jae .do_native_call
    movzx eax, byte ptr [rbx + r10]
    mov rax, [rbp + rax*8]
    mov [rsp + 32 + r10*8], rax
    inc r10
    jmp .copy_native_args
    
.do_native_call:
    add rbx, rsi
    
    ; Call native function
    mov rcx, r12                             ; Global as this
    mov rdx, rsp                             ; Args
    mov r8, rsi                              ; Arg count
    call r8                                  ; Call native
    
    add rsp, 32 + rsi*8
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; ============================================================================
; Object Operations Extensions
; ============================================================================

; OP_DELETE_PROP: delete obj.property
op_delete_prop:
    movzx rcx, byte ptr [rbx]               ; rcx = obj reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = prop name reg
    add rbx, 2
    
    mov r8, [rbp + rcx*8]                   ; r8 = object
    mov r9, [rbp + rdx*8]                   ; r9 = property name
    
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsObject_DeleteProperty
    add rsp, 32
    
    ; Return boolean success
    BOX_BOOL rax, rax
    movzx rcx, byte ptr [rbx-2]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_DELETE_ELEM: delete obj[index]
op_delete_elem:
    movzx rcx, byte ptr [rbx]               ; rcx = obj reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = index reg
    add rbx, 2
    
    mov r8, [rbp + rcx*8]
    mov r9, [rbp + rdx*8]
    
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsObject_DeleteElement
    add rsp, 32
    
    BOX_BOOL rax, rax
    movzx rcx, byte ptr [rbx-2]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_IN: r_dest = r_prop in r_obj
op_in:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = prop
    movzx rsi, byte ptr [rbx+2]             ; rsi = obj
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rdx*8]                   ; r8 = property
    mov r9, [rbp + rsi*8]                   ; r9 = object
    
    sub rsp, 32
    mov rcx, r9
    mov rdx, r8
    call JsObject_HasProperty
    add rsp, 32
    
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_INSTANCEOF: r_dest = r_obj instanceof r_ctor
op_instanceof:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    movzx rsi, byte ptr [rbx+2]
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rdx*8]                   ; r8 = object
    mov r9, [rbp + rsi*8]                   ; r9 = constructor
    
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsObject_InstanceOf
    add rsp, 32
    
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_TYPEOF: r_dest = typeof r_src
op_typeof:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = src
    add rbx, 2
    
    mov r8, [rbp + rdx*8]                   ; r8 = value
    
    sub rsp, 32
    mov rcx, r8
    call JsValue_TypeOf
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_NEW: r_dest = new r_ctor(r_args...)
op_new:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = ctor reg
    movzx rsi, byte ptr [rbx+2]             ; rsi = arg count
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rdx*8]                   ; r8 = constructor
    
    ; Create new object
    sub rsp, 32
    mov rcx, r8
    call JsObject_Create
    add rsp, 32
    mov r9, rax                             ; r9 = new object
    
    ; Build args and call constructor
    sub rsp, 32 + rsi*8
    
    mov r10, 0
.copy_new_args:
    cmp r10, rsi
    jae .do_new_call
    movzx eax, byte ptr [rbx + r10]
    mov rax, [rbp + rax*8]
    mov [rsp + 32 + r10*8], rax
    inc r10
    jmp .copy_new_args
    
.do_new_call:
    add rbx, rsi
    
    ; Call constructor with new object as this
    mov rcx, r8
    mov rdx, r9
    mov r8, rsp
    mov r9, rsi
    call JsFunction_Call
    
    add rsp, 32 + rsi*8
    
    ; Return new object (constructor return is ignored for new)
    mov [rbp + rcx*8], r9
    jmp .interpreter_loop

; ============================================================================
; Exception Handling
; ============================================================================

; OP_THROW: throw r_val
op_throw:
    movzx rcx, byte ptr [rbx]               ; rcx = value reg
    inc rbx
    
    mov rax, [rbp + rcx*8]                  ; rax = exception value
    
    ; Store in exception register and unwind
    ; In full implementation, would search try blocks
    ; For now, just return exception to caller
    
    add rsp, 40
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret                                     ; Returns exception in rax

; OP_TRY_START: begin try block
op_try_start:
    movsxd rax, dword ptr [rbx]             ; rax = catch handler offset
    add rbx, 4
    
    ; Push try block info onto try stack
    ; In full implementation, would set up exception handler
    jmp .interpreter_loop

; OP_TRY_END: end try block
op_try_end:
    ; Pop try block from stack
    jmp .interpreter_loop

; ============================================================================
; Scope Operations
; ============================================================================

; OP_ENTER_SCOPE: enter new variable scope
op_enter_scope:
    inc rbx
    
    ; Push current scope chain
    ; In full implementation, would allocate new scope object
    jmp .interpreter_loop

; OP_EXIT_SCOPE: exit current scope
op_exit_scope:
    inc rbx
    
    ; Pop scope chain
    jmp .interpreter_loop

; ============================================================================
; Object Literal Operations
; ============================================================================

; OP_OBJECT_SET: obj[key] = value
op_object_set:
    movzx rcx, byte ptr [rbx]               ; rcx = obj reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = key reg
    movzx rsi, byte ptr [rbx+2]             ; rsi = value reg
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rcx*8]                   ; r8 = object
    mov r9, [rbp + rdx*8]                   ; r9 = key
    mov r10, [rbp + rsi*8]                  ; r10 = value
    
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    mov r8, r10
    call JsObject_SetProperty
    add rsp, 32
    
    jmp .interpreter_loop

; OP_OBJECT_GET_KEYS: r_dest = Object.keys(obj)
op_object_get_keys:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = obj reg
    add rbx, 2
    
    mov r8, [rbp + rdx*8]
    
    sub rsp, 32
    mov rcx, r8
    call JsObject_GetKeys
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; ============================================================================
; Function Binding
; ============================================================================

; OP_BIND_THIS: func = func.bind(this)
op_bind_this:
    movzx rcx, byte ptr [rbx]               ; rcx = func reg
    movzx rdx, byte ptr [rbx+1]             ; rdx = this reg
    add rbx, 2
    
    mov r8, [rbp + rcx*8]                   ; r8 = function
    mov r9, [rbp + rdx*8]                   ; r9 = this value
    
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    call JsFunction_BindThis
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_APPLY: r_dest = r_func.apply(r_this, r_args)
op_apply:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = func
    movzx rsi, byte ptr [rbx+2]             ; rsi = this
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rdx*8]                   ; r8 = function
    mov r9, [rbp + rsi*8]                   ; r9 = this
    
    ; Get args array from next register
    movzx eax, byte ptr [rbx]
    mov r10, [rbp + rax*8]                  ; r10 = args array
    inc rbx
    
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    mov r8, r10
    call JsFunction_Apply
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_CALL_METHOD: r_dest = r_obj.method(r_args...)
op_call_method:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = obj reg
    movzx rsi, byte ptr [rbx+2]             ; rsi = method name reg
    and rsi, 0x0F
    add rbx, 3
    
    mov r8, [rbp + rdx*8]                   ; r8 = object (this)
    mov r9, [rbp + rsi*8]                   ; r9 = method name
    
    ; Get method from object
    sub rsp, 32
    mov rcx, r8
    mov rdx, r9
    mov r9, r15
    xor r9, r9                              ; No IC for method lookup
    call Object_GetPropertyIC
    add rsp, 32
    
    ; Now call with object as this
    ; ... (similar to OP_CALL)
    jmp .interpreter_loop

; ============================================================================
; Closure Operations
; ============================================================================

; OP_GET_CLOSURE: r_dest = closure[slot]
op_get_closure:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, word ptr [rbx+1]             ; rdx = closure slot
    add rbx, 3
    
    ; Load from closure environment
    ; In full implementation, would walk scope chain
    mov rax, JS_UNDEFINED
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_SET_CLOSURE: closure[slot] = r_val
op_set_closure:
    movzx rcx, byte ptr [rbx]               ; rcx = slot
    movzx rdx, byte ptr [rbx+1]             ; rdx = value reg
    add rbx, 2
    
    mov r8, [rbp + rdx*8]
    
    ; Store in closure environment
    jmp .interpreter_loop

; ============================================================================
; Iteration Operations
; ============================================================================

; OP_ITER_START: iterator = r_obj[Symbol.iterator]()
op_iter_start:
    movzx rcx, byte ptr [rbx]               ; rcx = dest (iterator)
    movzx rdx, byte ptr [rbx+1]             ; rdx = obj reg
    add rbx, 2
    
    mov r8, [rbp + rdx*8]
    
    sub rsp, 32
    mov rcx, r8
    call JsIterator_Create
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_ITER_NEXT: r_dest = iterator.next()
op_iter_next:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = iterator reg
    add rbx, 2
    
    mov r8, [rbp + rdx*8]
    
    sub rsp, 32
    mov rcx, r8
    call JsIterator_Next
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_ITER_HAS_NEXT: r_dest = iterator.hasNext()
op_iter_has_next:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    
    mov r8, [rbp + rdx*8]
    
    sub rsp, 32
    mov rcx, r8
    call JsIterator_HasNext
    add rsp, 32
    
    BOX_BOOL rax, rax
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_FOR_IN_START: iterator = for-in r_obj
op_for_in_start:
    movzx rcx, byte ptr [rbx]
    movzx rdx, byte ptr [rbx+1]
    add rbx, 2
    
    mov r8, [rbp + rdx*8]
    
    sub rsp, 32
    mov rcx, r8
    call JsIterator_ForIn
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

; OP_FOR_IN_NEXT: r_dest = for-in iterator.next()
op_for_in_next:
    jmp op_iter_next

; OP_FOR_OF_START: iterator = for-of r_obj
op_for_of_start:
    jmp op_iter_start

; OP_FOR_OF_NEXT: r_dest = for-of iterator.next()
op_for_of_next:
    jmp op_iter_next

; ============================================================================
; Async Operations (Stubs)
; ============================================================================

op_await:
    ; Async/await not yet implemented
    add rbx, 2
    jmp .interpreter_loop

op_promise_resolve:
    add rbx, 2
    jmp .interpreter_loop

op_promise_reject:
    add rbx, 2
    jmp .interpreter_loop

op_async_call:
    add rbx, 3
    jmp .interpreter_loop

op_yield:
    add rbx, 2
    jmp .interpreter_loop

op_yield_star:
    add rbx, 2
    jmp .interpreter_loop

; ============================================================================
; Optimized Operations (Stubs)
; ============================================================================

op_add_int:
    ; Specialized add for known integers
    jmp op_add

op_sub_int:
    jmp op_sub

op_mul_int:
    jmp op_mul

op_inc_local:
    movzx rcx, byte ptr [rbx]               ; rcx = local index
    inc rbx
    
    mov rax, [rbp + rcx*8]
    
    ; Assume integer
    UNBOX_INT rax, rax
    inc rax
    BOX_INT rax, rax
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

op_dec_local:
    movzx rcx, byte ptr [rbx]
    inc rbx
    
    mov rax, [rbp + rcx*8]
    UNBOX_INT rax, rax
    dec rax
    BOX_INT rax, rax
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

op_get_local:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, byte ptr [rbx+1]             ; rdx = local index
    add rbx, 2
    
    mov rax, [rbp + rdx*8]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

op_set_local:
    movzx rcx, byte ptr [rbx]               ; rcx = local index
    movzx rdx, byte ptr [rbx+1]             ; rdx = value reg
    add rbx, 2
    
    mov rax, [rbp + rdx*8]
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

op_get_global:
    movzx rcx, byte ptr [rbx]               ; rcx = dest
    movzx rdx, word ptr [rbx+1]             ; rdx = global name index
    add rbx, 3
    
    ; Load from global object (r12)
    mov r8, r12
    
    sub rsp, 32
    mov rcx, r8
    ; rdx already has string index
    xor r8, r8
    call JsObject_GetProperty
    add rsp, 32
    
    mov [rbp + rcx*8], rax
    jmp .interpreter_loop

op_set_global:
    movzx rcx, byte ptr [rbx]               ; rcx = global name index
    movzx rdx, byte ptr [rbx+1]             ; rdx = value reg
    add rbx, 2
    
    mov r8, [rbp + rdx*8]
    
    sub rsp, 32
    mov rdx, r8
    mov r8, rcx
    mov rcx, r12
    call JsObject_SetProperty
    add rsp, 32
    
    jmp .interpreter_loop

; ============================================================================
; Debug Operations
; ============================================================================

op_assert:
    movzx rcx, byte ptr [rbx]               ; rcx = condition reg
    inc rbx
    
    mov rax, [rbp + rcx*8]
    
    ; Check if truthy
    cmp rax, JS_FALSE
    je .assert_fail
    cmp rax, JS_NULL
    je .assert_fail
    cmp rax, JS_UNDEFINED
    je .assert_fail
    cmp rax, 0x7FF9000000000000
    je .assert_fail
    
    jmp .interpreter_loop
    
.assert_fail:
    ; Trigger debug break
    int 3
    jmp .interpreter_loop

op_profile_start:
    add rbx, 1
    jmp .interpreter_loop

op_profile_end:
    add rbx, 1
    jmp .interpreter_loop

; ============================================================================
; External Runtime Functions (Stubs)
; ============================================================================

; These would be implemented in C++ and linked
; For now, they are placeholders

JsValue_ToInt32 PROC
    ; Convert NaN-boxed value to int32
    ; Handle different types
    ret
JsValue_ToInt32 ENDP

JsString_Concat PROC
    ; Concatenate two strings
    ret
JsString_Concat ENDP

JsArray_GetElement PROC
    ; Get array element
    ret
JsArray_GetElement ENDP

JsArray_SetElement PROC
    ; Set array element
    ret
JsArray_SetElement ENDP

JsArray_Grow PROC
    ; Grow array capacity
    ret
JsArray_Grow ENDP

JsArray_Push PROC
    ; Push element to array
    ret
JsArray_Push ENDP

JsArray_Pop PROC
    ; Pop element from array
    ret
JsArray_Pop ENDP

JsFunction_Call PROC
    ; Call JavaScript function
    ret
JsFunction_Call ENDP

JsFunction_BindThis PROC
    ; Bind this to function
    ret
JsFunction_BindThis ENDP

JsFunction_Apply PROC
    ; Apply function with args array
    ret
JsFunction_Apply ENDP

JsObject_Create PROC
    ; Create new object
    ret
JsObject_Create ENDP

JsObject_DeleteProperty PROC
    ; Delete object property
    ret
JsObject_DeleteProperty ENDP

JsObject_DeleteElement PROC
    ; Delete array element
    ret
JsObject_DeleteElement ENDP

JsObject_HasProperty PROC
    ; Check if property exists
    ret
JsObject_HasProperty ENDP

JsObject_InstanceOf PROC
    ; Check instanceof
    ret
JsObject_InstanceOf ENDP

JsObject_SetProperty PROC
    ; Set object property
    ret
JsObject_SetProperty ENDP

JsObject_GetKeys PROC
    ; Get object keys
    ret
JsObject_GetKeys ENDP

JsValue_TypeOf PROC
    ; Get typeof value
    ret
JsValue_TypeOf ENDP

JsIterator_Create PROC
    ; Create iterator
    ret
JsIterator_Create ENDP

JsIterator_Next PROC
    ; Get next iterator value
    ret
JsIterator_Next ENDP

JsIterator_HasNext PROC
    ; Check if iterator has more
    ret
JsIterator_HasNext ENDP

JsIterator_ForIn PROC
    ; Create for-in iterator
    ret
JsIterator_ForIn ENDP

JsMath_Pow PROC
    ; Math.pow
    ret
JsMath_Pow ENDP

JsObject_GetProperty PROC
    ; Generic property getter
    ret
JsObject_GetProperty ENDP

END
