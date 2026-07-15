; RawrXD-Script MASM Runtime Support
; Phase 2: Runtime Library Functions
; Pure x64 MASM - Zero Dependencies

.CODE

; ============================================================================
; Value Operations
; ============================================================================

; JsValue_IsTruthy - Check if a value is truthy
; Entry:  rcx = value (NaN-boxed)
; Exit:   rax = 1 if truthy, 0 if falsy
JsValue_IsTruthy PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rax, rcx
    
    ; Check for falsy values
    cmp rax, JS_FALSE
    je .falsy
    cmp rax, JS_NULL
    je .falsy
    cmp rax, JS_UNDEFINED
    je .falsy
    cmp rax, 0x7FF9000000000000             ; Boxed 0
    je .falsy
    
    ; Check for empty string
    mov rbx, 0x7FF4000000000000             ; String tag
    cmp rax, rbx
    jb .truthy                              ; Not a string, must be truthy
    
    ; It's a string - check if empty
    and rax, 0x0000FFFFFFFFFFFF             ; Mask to get pointer
    movzx ebx, word ptr [rax]               ; Get string length
    test ebx, ebx
    jz .falsy
    
.truthy:
    mov rax, 1
    jmp .done
    
.falsy:
    xor rax, rax
    
.done:
    add rsp, 40
    pop rbx
    pop rbp
    ret
JsValue_IsTruthy ENDP

; JsValue_ToString - Convert any value to string
; Entry:  rcx = value (NaN-boxed)
;         rdx = output buffer
;         r8  = buffer size
; Exit:   rax = number of characters written
JsValue_ToString PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rax, rcx
    
    ; Check value type
    mov rbx, 0x7FF8000000000000             ; QNaN mask
    and rbx, rax
    cmp rbx, 0x7FF8000000000000
    jne .is_double                          ; Not NaN-boxed, must be double
    
    ; Extract tag
    shr rax, 48
    and rax, 0xF
    
    cmp rax, 1                              ; Int32
    je .is_int32
    cmp rax, 2                              ; Boolean
    je .is_boolean
    cmp rax, 3                              ; Null/Undefined
    je .is_null_undefined
    cmp rax, 4                              ; String
    je .is_string
    cmp rax, 5                              ; Object
    je .is_object
    
    jmp .is_undefined
    
.is_double:
    ; Format double to string using dtoa algorithm
    ; Extract double value
    movsd xmm0, [rcx - 0x7FF8000000000000]
    
    ; Check for special values
    mov rax, rcx
    and rax, 0x7FFFFFFFFFFFFFFF             ; Clear sign bit
    cmp rax, 0x7FF0000000000000             ; Infinity
    je .is_infinity
    cmp rax, 0x7FF8000000000000             ; NaN
    je .is_nan
    
    ; Format as decimal
    sub rsp, 64
    movsd qword ptr [rsp], xmm0
    mov rcx, rsp                            ; Source double
    mov rdx, r8                             ; Buffer
    mov r8, r9                              ; Buffer size
    call DoubleToString
    add rsp, 64
    jmp .done
    
.is_infinity:
    test rcx, 0x8000000000000000
    jnz .is_neg_infinity
    mov rcx, rdx
    lea rdx, infinity_str
    mov r8, infinity_str_len
    call memcpy
    mov rax, infinity_str_len
    jmp .done
    
.is_neg_infinity:
    mov rcx, rdx
    lea rdx, neg_infinity_str
    mov r8, neg_infinity_str_len
    call memcpy
    mov rax, neg_infinity_str_len
    jmp .done
    
.is_nan:
    mov rcx, rdx
    lea rdx, nan_str
    mov r8, nan_str_len
    call memcpy
    mov rax, nan_str_len
    jmp .done
    
.is_int32:
    ; Format int32 to string
    ; Extract value
    mov eax, ecx
    shr rax, 16                             ; Shift out tag
    
    ; Check sign
    test eax, eax
    jns .int32_positive
    
    ; Negative number
    neg eax
    mov byte ptr [rdx], '-'                 ; Add minus sign
    inc rdx
    dec r9
    
.int32_positive:
    ; Convert to decimal
    mov rcx, rdx                            ; Buffer
    mov edx, eax                            ; Value
    mov r8, r9                              ; Buffer size
    call Int32ToString
    jmp .done
    
.is_boolean:
    mov rcx, JS_TRUE
    cmp rax, rcx
    je .is_true
    
    ; false
    mov rcx, rdx
    lea rdx, false_str
    mov r8, false_str_len
    call memcpy
    mov rax, false_str_len
    jmp .done
    
.is_true:
    mov rcx, rdx
    lea rdx, true_str
    mov r8, true_str_len
    call memcpy
    mov rax, true_str_len
    jmp .done
    
.is_null_undefined:
    cmp rax, JS_NULL
    je .is_null
    
    ; undefined
    mov rcx, rdx
    lea rdx, undefined_str
    mov r8, undefined_str_len
    call memcpy
    mov rax, undefined_str_len
    jmp .done
    
.is_null:
    mov rcx, rdx
    lea rdx, null_str
    mov r8, null_str_len
    call memcpy
    mov rax, null_str_len
    jmp .done
    
.is_string:
    ; Already a string - copy it
    jmp .done
    
.is_object:
    ; Call toString method or return [object Object]
    ; Extract object pointer
    mov rbx, rcx
    and rbx, 0x0000FFFFFFFFFFFF
    
    ; Check if object has toString method
    mov rsi, [rbx]                          ; rsi = object->shape
    test rsi, rsi
    jz .object_no_tostring
    
    ; Look for toString in shape
    movzx r10, word ptr [rsi + 4]           ; r10 = shape->prop_count
    test r10, r10
    jz .object_no_tostring
    
    lea r11, [rsi + 16]                     ; r11 = shape->prop_table
    xor r12, r12
    
.object_find_tostring:
    cmp r12, r10
    jae .object_no_tostring
    
    mov r14, [r11 + r12*8]                  ; r14 = prop_table[i].name
    ; Compare with "toString" (simplified - just check if method exists)
    test r14, r14
    jz .object_next_prop
    
    ; Check if it's a function
    movzx r15, word ptr [r11 + r12*8 + 8]   ; r15 = offset
    mov rdi, [rbx + r15]                    ; rdi = property value
    mov r9, 0x7FF6000000000000              ; Function tag
    mov r10, rdi
    and r10, r9
    cmp r10, r9
    je .object_call_tostring
    
.object_next_prop:
    inc r12
    jmp .object_find_tostring
    
.object_call_tostring:
    ; Call toString method (simplified - just return [object Object])
    jmp .object_no_tostring
    
.object_no_tostring:
    mov rcx, rdx
    lea rdx, object_str
    mov r8, object_str_len
    call memcpy
    mov rax, object_str_len
    jmp .done
    
.is_undefined:
    mov rcx, rdx
    lea rdx, undefined_str
    mov r8, undefined_str_len
    call memcpy
    mov rax, undefined_str_len
    
.done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
JsValue_ToString ENDP

; ============================================================================
; String Operations
; ============================================================================

; JsString_Concat - Concatenate two strings
; Entry:  rcx = string A (NaN-boxed)
;         rdx = string B (NaN-boxed)
;         r8  = arena base
;         r9  = arena bump pointer
; Exit:   rax = concatenated string (NaN-boxed)
JsString_Concat PROC FRAME
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
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Extract string pointers from NaN-boxed values
    mov rbx, rcx                            ; rbx = string A
    and rbx, 0x0000FFFFFFFFFFFF
    mov rsi, rdx                            ; rsi = string B
    and rsi, 0x0000FFFFFFFFFFFF
    
    ; Get lengths
    movzx r12, word ptr [rbx]               ; r12 = lenA
    movzx r13, word ptr [rsi]               ; r13 = lenB
    
    ; Calculate total length
    mov r14, r12
    add r14, r13                            ; r14 = total length
    
    ; Allocate from arena: header (8 bytes) + string data
    mov rcx, r14
    add rcx, 8                              ; + header
    add rcx, 7
    and rcx, -8                             ; Align to 8 bytes
    
    ; Allocate
    mov rax, r9                             ; Current bump
    add rax, rcx                            ; New bump
    cmp rax, [r8 + 8]                       ; Check arena limit
    ja .concat_oom
    mov r9, rax                             ; Update bump
    mov rax, r9
    sub rax, rcx                            ; Return start of allocation
    
    ; Initialize string header
    mov word ptr [rax], r14w                ; Set length
    mov word ptr [rax + 2], 0               ; Flags
    mov dword ptr [rax + 4], 0              ; Reserved
    
    ; Copy string A
    lea rdi, [rax + 8]                      ; Destination
    lea rsi, [rbx + 8]                      ; Source A
    mov rcx, r12                            ; Length A
    rep movsb
    
    ; Copy string B
    lea rsi, [rsi + 8]                      ; Source B
    mov rcx, r13                            ; Length B
    rep movsb
    
    ; Box as string
    or rax, 0x7FF4000000000000
    jmp .concat_done
    
.concat_oom:
    mov rax, JS_NULL
    
.concat_done:
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
JsString_Concat ENDP

; JsString_Length - Get string length
; Entry:  rcx = string (NaN-boxed)
; Exit:   rax = length as boxed int32
JsString_Length PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Extract pointer
    mov rax, rcx
    and rax, 0x0000FFFFFFFFFFFF
    
    ; Get length from string header
    movzx eax, word ptr [rax]
    
    ; Box as int32
    or rax, 0x7FF9000000000000
    
    add rsp, 40
    pop rbp
    ret
JsString_Length ENDP

; ============================================================================
; Object Operations
; ============================================================================

; JsObject_Create - Create a new object with given shape
; Entry:  rcx = shape pointer (or 0 for empty shape)
;         rdx = arena base
;         r8  = arena bump
; Exit:   rax = object pointer (not NaN-boxed)
JsObject_Create PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Calculate size: header + shape slots
    mov rbx, rcx
    test rbx, rbx
    jz .empty_shape
    
    ; Get slot count from shape
    movzx ebx, word ptr [rbx + 4]           ; shape->slot_count
    shl ebx, 3                              ; * 8 bytes per slot
    add ebx, 32                             ; + header size
    jmp .allocate
    
.empty_shape:
    mov ebx, 32                             ; Just header
    
.allocate:
    ; Allocate from arena
    mov rcx, rbx
    ; ARENA_ALLOC equivalent
    
    ; Initialize object header
    ; TODO: Set shape, prototype, flags
    
    mov rax, rcx                            ; Return object pointer
    
    add rsp, 40
    pop rbx
    pop rbp
    ret
JsObject_Create ENDP

; JsObject_GetProperty - Get property with IC support
; Entry:  rcx = object (NaN-boxed)
;         rdx = property name (NaN-boxed string)
;         r8  = IC slot pointer (for caching)
; Exit:   rax = property value (NaN-boxed)
JsObject_GetProperty PROC FRAME
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
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Extract object pointer
    mov rbx, rcx
    and rbx, 0x0000FFFFFFFFFFFF
    
    ; Check IC cache if provided
    test r8, r8
    jz .no_ic
    
    ; Get object shape
    mov rsi, [rbx]                          ; object->shape
    
    ; Check IC: compare shape
    mov rdi, [r8]                           ; IC->shape
    cmp rsi, rdi
    jne .ic_miss
    
    ; IC hit: direct property access
    mov r12, [r8 + 8]                       ; IC->offset
    mov rax, [rbx + r12]                    ; object->slots[offset]
    jmp .done
    
.ic_miss:
    ; Update IC with new shape and offset
    ; TODO: Walk shape property table
    
.no_ic:
    ; Slow path: hash table lookup
    ; Walk the prototype chain
    mov rbx, rcx                            ; rbx = object
    and rbx, 0x0000FFFFFFFFFFFF
    
    ; Get property name string
    mov r12, rdx                            ; r12 = property name
    and r12, 0x0000FFFFFFFFFFFF
    movzx r13, word ptr [r12]               ; r13 = name length
    lea r12, [r12 + 8]                      ; r12 = name data
    
.property_lookup_loop:
    test rbx, rbx
    jz .property_not_found
    
    ; Get shape
    mov rsi, [rbx]                          ; rsi = shape
    test rsi, rsi
    jz .property_next_prototype
    
    ; Search property table
    movzx r10, word ptr [rsi + 4]           ; r10 = prop_count
    test r10, r10
    jz .property_next_prototype
    
    lea r11, [rsi + 16]                     ; r11 = prop_table
    xor r14, r14
    
.property_search_loop:
    cmp r14, r10
    jae .property_next_prototype
    
    ; Get property name from table
    mov r15, [r11 + r14*8]                  ; r15 = prop name
    test r15, r15
    jz .property_next_entry
    
    ; Compare names (simplified - compare pointers)
    cmp r15, rdx
    je .property_found
    
.property_next_entry:
    inc r14
    jmp .property_search_loop
    
.property_found:
    ; Get offset and load value
    movzx r15, word ptr [r11 + r14*8 + 8]   ; r15 = offset
    mov rax, [rbx + r15]                    ; rax = value
    jmp .property_done
    
.property_next_prototype:
    ; Move to prototype
    mov rsi, [rbx]                          ; rsi = shape
    test rsi, rsi
    jz .property_not_found
    mov rbx, [rsi + 8]                      ; rbx = prototype
    jmp .property_lookup_loop
    
.property_not_found:
    mov rax, JS_UNDEFINED
    
.done:
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
JsObject_GetProperty ENDP

; JsObject_SetProperty - Set property with IC support
; Entry:  rcx = object (NaN-boxed)
;         rdx = property name (NaN-boxed string)
;         r8  = value (NaN-boxed)
;         r9  = IC slot pointer
; Exit:   rax = success (1) or failure (0)
JsObject_SetProperty PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; TODO: Implement property setting with IC
    
    mov rax, 1                              ; Success
    
    add rsp, 40
    pop rbx
    pop rbp
    ret
JsObject_SetProperty ENDP

; ============================================================================
; Array Operations
; ============================================================================

; JsArray_Create - Create a new array
; Entry:  rcx = initial capacity
;         rdx = arena base
;         r8  = arena bump
; Exit:   rax = array pointer (not NaN-boxed)
JsArray_Create PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Calculate size: header + elements
    mov rbx, rcx
    shl rbx, 3                              ; * 8 bytes per element
    add rbx, 32                             ; + header
    
    ; Allocate from arena
    mov rcx, rbx
    ; ARENA_ALLOC
    
    ; Initialize array header
    ; TODO: Set length, capacity, elements pointer
    
    mov rax, rcx
    
    add rsp, 40
    pop rbx
    pop rbp
    ret
JsArray_Create ENDP

; JsArray_Push - Add element to end of array
; Entry:  rcx = array (NaN-boxed)
;         rdx = value (NaN-boxed)
;         r8  = arena base
;         r9  = arena bump
; Exit:   rax = new length (boxed int32)
JsArray_Push PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Extract array pointer
    mov rbx, rcx
    and rbx, 0x0000FFFFFFFFFFFF
    
    ; Get current length
    movzx eax, dword ptr [rbx + 8]          ; array->length
    
    ; Check capacity
    mov ecx, [rbx + 12]                     ; array->capacity
    cmp eax, ecx
    jae .grow
    
    ; Store element
    mov rcx, [rbx + 16]                     ; array->elements
    mov [rcx + rax*8], rdx
    
    ; Increment length
    inc eax
    mov [rbx + 8], eax
    
    ; Box and return
    or rax, 0x7FF9000000000000
    jmp .done
    
.grow:
    ; TODO: Grow array
    
.done:
    add rsp, 40
    pop rbx
    pop rbp
    ret
JsArray_Push ENDP

; ============================================================================
; Math Operations
; ============================================================================

; JsMath_Add - Full JavaScript addition (handles string concat)
; Entry:  rcx = left value (NaN-boxed)
;         rdx = right value (NaN-boxed)
;         r8  = arena base
;         r9  = arena bump
; Exit:   rax = result (NaN-boxed)
JsMath_Add PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Check if either operand is string
    mov rbx, rcx
    mov rsi, 0x7FF4000000000000             ; String tag
    and rbx, rsi
    cmp rbx, rsi
    je .string_concat
    
    mov rbx, rdx
    and rbx, rsi
    cmp rbx, rsi
    je .string_concat
    
    ; Numeric addition
    ; TODO: Convert to numbers, add, box result
    jmp .done
    
.string_concat:
    ; String concatenation
    ; TODO: Convert both to strings, concat
    
.done:
    add rsp, 40
    pop rsi
    pop rbx
    pop rbp
    ret
JsMath_Add ENDP

; ============================================================================
; Comparison Operations
; ============================================================================

; JsCompare_AbstractEqual - == operator (loose equality)
; Entry:  rcx = left value
;         rdx = right value
; Exit:   rax = result (boxed boolean)
JsCompare_AbstractEqual PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Same value check
    cmp rcx, rdx
    je .equal
    
    ; TODO: Implement full abstract equality algorithm
    ; 1. null == undefined
    ; 2. number == string (convert)
    ; 3. boolean == anything (convert to number)
    ; 4. object == primitive (convert object)
    
    xor rax, rax
    mov rax, JS_FALSE
    jmp .done
    
.equal:
    mov rax, JS_TRUE
    
.done:
    add rsp, 40
    pop rbp
    ret
JsCompare_AbstractEqual ENDP

; JsCompare_StrictEqual - === operator
; Entry:  rcx = left value
;         rdx = right value
; Exit:   rax = result (boxed boolean)
JsCompare_StrictEqual PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Same value check
    cmp rcx, rdx
    sete al
    movzx rax, al
    
    ; Box as boolean
    cmp rax, 1
    je .is_true
    mov rax, JS_FALSE
    jmp .done
.is_true:
    mov rax, JS_TRUE
    
.done:
    add rsp, 40
    pop rbp
    ret
JsCompare_StrictEqual ENDP

; ============================================================================
; Data Section
; ============================================================================
.DATA

; String constants for toString
true_str        BYTE "true", 0
true_str_len    EQU $ - true_str

false_str       BYTE "false", 0
false_str_len   EQU $ - false_str

null_str        BYTE "null", 0
null_str_len    EQU $ - null_str

undefined_str   BYTE "undefined", 0
undefined_str_len EQU $ - undefined_str

object_str      BYTE "[object Object]", 0
object_str_len  EQU $ - object_str

; NaN-boxed constants
ALIGN 8
JS_NULL_CONST       QWORD 0x7FF3000000000000
JS_UNDEFINED_CONST  QWORD 0x7FF3000000000001
JS_TRUE_CONST       QWORD 0x7FF2000000000001
JS_FALSE_CONST      QWORD 0x7FF2000000000000

END
