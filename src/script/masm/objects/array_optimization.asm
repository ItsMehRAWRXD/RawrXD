; RawrXD-Script Array Optimization
; Phase 3: Dense Array Fast Paths
; Pure x64 MASM

.CODE

; ============================================================================
; Array Types
; ============================================================================

; Dense Array: Contiguous indices starting at 0, no holes
;   - Fast indexed access: base + index * 8
;   - Fast length tracking
;   - Inline storage for small arrays
;
; Sparse Array: Has holes or non-contiguous indices
;   - Hash table for indexed properties
;   - Slower access but memory efficient
;
; ArrayBuffer: Typed arrays (future optimization)

; Array flags (in addition to object flags)
ARRAY_FLAG_DENSE          EQU 0x0100
ARRAY_FLAG_HOLEY          EQU 0x0200
ARRAY_FLAG_CONTIGUOUS     EQU 0x0400  ; No holes, contiguous indices

; Array header (extends object header)
;   +48: uint32_t length           ; Array length (JS semantics)
;   +52: uint32_t initial_length    ; Length when created dense
;   +56: JsValue* elements          ; Pointer to element storage
;   +64: uint32_t element_capacity  ; Capacity of elements array
;   +68: uint32_t first_hole_index  ; First hole (for holey arrays)

ARRAY_LENGTH          EQU 48
ARRAY_INIT_LENGTH   EQU 52
ARRAY_ELEMENTS      EQU 56
ARRAY_ELEM_CAPACITY EQU 64
ARRAY_FIRST_HOLE    EQU 68

ARRAY_HEADER_SIZE   EQU 72

; Dense array inline storage size (8 elements = 64 bytes)
ARRAY_INLINE_SIZE   EQU 64

; ============================================================================
; Dense Array Operations
; ============================================================================

; Array_CreateDense - Create a dense array with initial capacity
; Entry:  rcx = initial length
;         rdx = arena base
;         r8  = arena bump pointer
; Exit:   rax = array object (NaN-boxed)
Array_CreateDense PROC FRAME
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
    
    mov r12d, ecx       ; r12d = initial length
    mov rbx, rdx        ; rbx = arena base
    mov rsi, r8         ; rsi = arena bump
    
    ; Calculate allocation size
    ; Object header + array header + inline storage or external
    mov edi, ARRAY_HEADER_SIZE
    add edi, ARRAY_INLINE_SIZE
    
    cmp r12d, 8         ; Can we fit inline?
    jbe .allocate
    
    ; Need external storage
    mov eax, r12d
    add eax, 8          ; Extra capacity
    shl eax, 3          ; * 8 bytes per element
    add edi, eax
    
.allocate:
    ; Allocate from arena
    mov rcx, rdi
    ; ARENA_ALLOC
    
    test rax, rax
    jz .fail
    
    mov rdi, rax        ; rdi = array object
    
    ; Initialize object header
    mov rax, g_empty_shape
    mov [rdi + OBJ_SHAPE], rax
    mov dword ptr [rdi + OBJ_FLAGS], OBJ_FLAG_EXTENSIBLE or OBJ_FLAG_DENSE_ARRAY or ARRAY_FLAG_DENSE or ARRAY_FLAG_CONTIGUOUS
    mov dword ptr [rdi + OBJ_CAPACITY], 0   ; No named properties
    mov qword ptr [rdi + OBJ_SLOTS], 0
    mov qword ptr [rdi + OBJ_INDEXED_KEYS], 0
    mov qword ptr [rdi + OBJ_INDEXED_VALS], 0
    mov dword ptr [rdi + OBJ_INDEXED_COUNT], 0
    mov dword ptr [rdi + OBJ_INDEXED_CAP], 0
    
    ; Initialize array header
    mov [rdi + ARRAY_LENGTH], r12d
    mov [rdi + ARRAY_INIT_LENGTH], r12d
    mov dword ptr [rdi + ARRAY_FIRST_HOLE], 0xFFFFFFFF  ; No holes
    
    ; Set up elements pointer
    cmp r12d, 8
    ja .external_storage
    
    ; Inline storage
    lea rax, [rdi + ARRAY_HEADER_SIZE]
    mov [rdi + ARRAY_ELEMENTS], rax
    mov dword ptr [rdi + ARRAY_ELEM_CAPACITY], 8
    
    ; Initialize elements to holes (undefined)
    mov rcx, r12
    mov rdx, rdi
    add rdx, ARRAY_HEADER_SIZE
.init_inline:
    test ecx, ecx
    jz .done_init
    mov qword ptr [rdx], JS_UNDEFINED
    add rdx, 8
    dec ecx
    jmp .init_inline
    
.external_storage:
    ; External storage already allocated after header
    lea rax, [rdi + ARRAY_HEADER_SIZE + ARRAY_INLINE_SIZE]
    mov [rdi + ARRAY_ELEMENTS], rax
    
    mov eax, r12d
    add eax, 8
    mov [rdi + ARRAY_ELEM_CAPACITY], eax
    
    ; Initialize to undefined
    mov rcx, r12
    mov rdx, [rdi + ARRAY_ELEMENTS]
.init_external:
    test ecx, ecx
    jz .done_init
    mov qword ptr [rdx], JS_UNDEFINED
    add rdx, 8
    dec ecx
    jmp .init_external
    
.done_init:
    ; Box and return
    mov rax, rdi
    or rax, TAG_OBJECT
    
.done:
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
    
.fail:
    xor rax, rax
    jmp .done
Array_CreateDense ENDP

; Array_GetElementDense - Fast path for dense array element access
; Entry:  rcx = array (NaN-boxed)
;         rdx = index (NaN-boxed int32)
; Exit:   rax = element value (NaN-boxed)
Array_GetElementDense PROC FRAME
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
    
    ; Extract index
    mov rax, rdx
    and rax, 0x00000000FFFFFFFF       ; Unbox int32
    
    ; Bounds check
    cmp eax, [rbx + ARRAY_LENGTH]
    jae .out_of_bounds
    
    ; Check if still dense
    mov ecx, [rbx + OBJ_FLAGS]
    test ecx, ARRAY_FLAG_DENSE
    jz .slow_path
    
    ; Fast path: direct element access
    mov rcx, [rbx + ARRAY_ELEMENTS]
    mov rax, [rcx + rax*8]
    
    ; Check for hole (undefined means hole in dense arrays)
    cmp rax, JS_UNDEFINED
    je .check_prototype
    
    jmp .done
    
.out_of_bounds:
    ; Return undefined for out-of-bounds
    mov rax, JS_UNDEFINED
    jmp .done
    
.check_prototype:
    ; Hole found - need to check prototype chain
    ; For now, return undefined
    mov rax, JS_UNDEFINED
    jmp .done
    
.slow_path:
    ; Array became sparse, use hash table lookup
    ; TODO: Implement sparse array lookup
    mov rax, JS_UNDEFINED
    
.done:
    add rsp, 40
    pop rbx
    pop rbp
    ret
Array_GetElementDense ENDP

; Array_SetElementDense - Fast path for dense array element setting
; Entry:  rcx = array (NaN-boxed)
;         rdx = index (NaN-boxed int32)
;         r8  = value (NaN-boxed)
;         r9  = arena base
; Exit:   rax = 1 on success, 0 on failure
Array_SetElementDense PROC FRAME
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
    
    ; Extract array pointer
    mov rbx, rcx
    and rbx, 0x0000FFFFFFFFFFFF
    
    ; Extract index
    mov rax, rdx
    and eax, 0xFFFFFFFF
    mov edi, eax        ; edi = index
    
    ; Check if array is frozen
    mov eax, [rbx + OBJ_FLAGS]
    test eax, OBJ_FLAG_FROZEN
    jnz .fail
    
    ; Check if still dense
    test eax, ARRAY_FLAG_DENSE
    jz .slow_path
    
    ; Check if index is within current length + 1
    mov esi, [rbx + ARRAY_LENGTH]
    cmp edi, esi
    ja .become_sparse       ; Index too far, becomes sparse
    
    ; Check capacity
    cmp edi, [rbx + ARRAY_ELEM_CAPACITY]
    jae .grow
    
.store:
    ; Store element
    mov rax, [rbx + ARRAY_ELEMENTS]
    mov [rax + rdi*8], r8
    
    ; Update length if needed
    cmp edi, esi
    jb .no_length_update
    inc esi
    mov [rbx + ARRAY_LENGTH], esi
    
.no_length_update:
    mov rax, 1
    jmp .done
    
.grow:
    ; Need to grow elements array
    ; TODO: Implement grow
    jmp .store
    
.become_sparse:
    ; Array becomes sparse
    and dword ptr [rbx + OBJ_FLAGS], NOT ARRAY_FLAG_DENSE
    or dword ptr [rbx + OBJ_FLAGS], ARRAY_FLAG_SPARSE_ARRAY
    jmp .slow_path
    
.slow_path:
    ; Use sparse array hash table
    ; TODO: Implement sparse set
    mov rax, 1
    jmp .done
    
.fail:
    xor rax, rax
    
.done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Array_SetElementDense ENDP

; Array_PushDense - Optimized push for dense arrays
; Entry:  rcx = array (NaN-boxed)
;         rdx = value (NaN-boxed)
;         r8  = arena base
; Exit:   rax = new length (NaN-boxed int32)
Array_PushDense PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Extract array pointer
    mov rbx, rcx
    and rbx, 0x0000FFFFFFFFFFFF
    
    ; Check if dense
    mov eax, [rbx + OBJ_FLAGS]
    test eax, ARRAY_FLAG_DENSE
    jz .slow_path
    
    ; Get current length
    mov esi, [rbx + ARRAY_LENGTH]
    
    ; Check capacity
    cmp esi, [rbx + ARRAY_ELEM_CAPACITY]
    jae .grow
    
.store:
    ; Store at end
    mov rax, [rbx + ARRAY_ELEMENTS]
    mov [rax + rsi*8], rdx
    
    ; Increment and store length
    inc esi
    mov [rbx + ARRAY_LENGTH], esi
    
    ; Return new length
    mov eax, esi
    or rax, 0x7FF9000000000000    ; Box as int32
    jmp .done
    
.grow:
    ; Grow array
    ; TODO: Implement grow
    jmp .store
    
.slow_path:
    ; Fall back to generic set
    mov r9, r8
    mov r8, rdx
    mov rdx, [rbx + ARRAY_LENGTH]
    or rdx, 0x7FF9000000000000    ; Box length as index
    call Array_SetElementDense
    
    ; Return new length
    mov eax, [rbx + ARRAY_LENGTH]
    or rax, 0x7FF9000000000000
    
.done:
    add rsp, 40
    pop rsi
    pop rbx
    pop rbp
    ret
Array_PushDense ENDP

; Array_PopDense - Optimized pop for dense arrays
; Entry:  rcx = array (NaN-boxed)
; Exit:   rax = popped value (NaN-boxed)
Array_PopDense PROC FRAME
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
    
    ; Get length
    mov eax, [rbx + ARRAY_LENGTH]
    test eax, eax
    jz .empty
    
    dec eax
    mov [rbx + ARRAY_LENGTH], eax
    
    ; Load element
    mov rcx, [rbx + ARRAY_ELEMENTS]
    mov rax, [rcx + rax*8]
    
    ; Store undefined in popped slot
    mov qword ptr [rcx + rax*8], JS_UNDEFINED
    
    jmp .done
    
.empty:
    mov rax, JS_UNDEFINED
    
.done:
    add rsp, 40
    pop rbx
    pop rbp
    ret
Array_PopDense ENDP

; ============================================================================
; Array Length Operations
; ============================================================================

; Array_SetLength - Set array length (handles truncation)
; Entry:  rcx = array (NaN-boxed)
;         rdx = new length (NaN-boxed int32)
; Exit:   rax = 1 on success, 0 on failure
Array_SetLength PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Extract array pointer
    mov rbx, rcx
    and rbx, 0x0000FFFFFFFFFFFF
    
    ; Extract new length
    mov esi, edx
    and esi, 0xFFFFFFFF
    
    ; Get current length
    mov edi, [rbx + ARRAY_LENGTH]
    
    ; Compare
    cmp esi, edi
    ja .grow
    jb .shrink
    
    ; No change
    mov rax, 1
    jmp .done
    
.grow:
    ; Growing - need to expand
    cmp esi, [rbx + ARRAY_ELEM_CAPACITY]
    ja .need_grow
    
    ; Just update length, fill new slots with undefined
    mov ecx, edi
    mov rdx, [rbx + ARRAY_ELEMENTS]
.fill_undefined:
    cmp ecx, esi
    jae .update_length
    mov qword ptr [rdx + rcx*8], JS_UNDEFINED
    inc ecx
    jmp .fill_undefined
    
.need_grow:
    ; TODO: Grow elements array
    jmp .update_length
    
.shrink:
    ; Shrinking - truncate
    ; For dense arrays, just update length
    ; Elements beyond length become garbage (will be overwritten on next push)
    
.update_length:
    mov [rbx + ARRAY_LENGTH], esi
    mov rax, 1
    jmp .done
    
.fail:
    xor rax, rax
    
.done:
    add rsp, 40
    pop rsi
    pop rbx
    pop rbp
    ret
Array_SetLength ENDP

; ============================================================================
; Array Iteration
; ============================================================================

; Array_ForEachDense - Optimized forEach for dense arrays
; Entry:  rcx = array (NaN-boxed)
;         rdx = callback function (NaN-boxed)
;         r8  = thisArg (NaN-boxed)
;         r9  = arena base
; Exit:   rax = undefined
Array_ForEachDense PROC FRAME
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
    
    ; Extract array
    mov rbx, rcx
    and rbx, 0x0000FFFFFFFFFFFF
    
    ; Save callback and thisArg
    mov r12, rdx
    mov r13, r8
    
    ; Get length
    mov edi, [rbx + ARRAY_LENGTH]
    xor esi, esi            ; index = 0
    
    ; Get elements
    mov rcx, [rbx + ARRAY_ELEMENTS]
    
.iterate:
    cmp esi, edi
    jae .done
    
    ; Load element
    mov rax, [rcx + rsi*8]
    
    ; Skip holes (undefined)
    cmp rax, JS_UNDEFINED
    je .next
    
    ; Call callback(element, index, array)
    ; TODO: Implement call
    
.next:
    inc esi
    jmp .iterate
    
.done:
    mov rax, JS_UNDEFINED
    
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Array_ForEachDense ENDP

END
