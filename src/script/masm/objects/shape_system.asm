; RawrXD-Script Object Model
; Phase 3: Object Model + Inline Caching
; Pure x64 MASM

.CODE

; ============================================================================
; Shape System
; ============================================================================

; Shape structure:
;   +0:  uint32_t id              ; Unique shape identifier
;   +4:  uint16_t slot_count      ; Number of property slots
;   +6:  uint16_t transition_count; Number of transitions
;   +8:  void* prototype          ; Prototype object (or null)
;   +16: Shape* parent            ; Parent shape (or null)
;   +24: Transition* transitions  ; Transition table
;   +32: Property* properties       ; Property descriptor table
;   +40: uint32_t flags           ; Shape flags

SHAPE_ID            EQU 0
SHAPE_SLOT_COUNT    EQU 4
SHAPE_TRANS_COUNT   EQU 6
SHAPE_PROTOTYPE     EQU 8
SHAPE_PARENT        EQU 16
SHAPE_TRANSITIONS   EQU 24
SHAPE_PROPERTIES    EQU 32
SHAPE_FLAGS         EQU 40

SHAPE_SIZE          EQU 48

; Shape flags
SHAPE_FLAG_FROZEN       EQU 0x0001
SHAPE_FLAG_SEALED       EQU 0x0002
SHAPE_FLAG_HAS_INDEXED  EQU 0x0004  ; Has indexed properties (array-like)

; Property descriptor:
;   +0:  uint32_t key_hash        ; Hash of property name
;   +4:  uint16_t slot_index      ; Slot index in object
;   +6:  uint16_t attributes      ; Writable, Enumerable, Configurable
;   +8:  char* key_string         ; Property name string

PROP_HASH           EQU 0
PROP_SLOT           EQU 4
PROP_ATTRS          EQU 6
PROP_KEY            EQU 8

PROP_SIZE           EQU 16

; Property attributes
PROP_WRITABLE       EQU 0x01
PROP_ENUMERABLE     EQU 0x02
PROP_CONFIGURABLE   EQU 0x04

; Transition entry:
;   +0:  uint32_t key_hash        ; Hash of transition key
;   +4:  uint16_t unused          ; Padding
;   +6:  uint16_t attrs           ; Attributes for new property
;   +8:  Shape* target_shape      ; Target shape after transition
;   +16: char* key_string         ; Property name

TRANS_HASH          EQU 0
TRANS_UNUSED        EQU 4
TRANS_ATTRS         EQU 6
TRANS_TARGET        EQU 8
TRANS_KEY           EQU 16

TRANS_SIZE          EQU 24

; ============================================================================
; Object Structure
; ============================================================================

; JSObject structure:
;   +0:  Shape* shape             ; Object's shape
;   +8:  uint32_t flags           ; Object flags
;   +12: uint32_t capacity        ; Slot array capacity
;   +16: JsValue* slots           ; Property value slots
;   +24: uint32_t* indexed_keys   ; Indexed property keys (or null)
;   +32: JsValue* indexed_values  ; Indexed property values (or null)
;   +40: uint32_t indexed_count   ; Number of indexed properties
;   +44: uint32_t indexed_capacity; Capacity of indexed arrays

OBJ_SHAPE           EQU 0
OBJ_FLAGS           EQU 8
OBJ_CAPACITY        EQU 12
OBJ_SLOTS           EQU 16
OBJ_INDEXED_KEYS    EQU 24
OBJ_INDEXED_VALS    EQU 32
OBJ_INDEXED_COUNT   EQU 40
OBJ_INDEXED_CAP     EQU 44

OBJ_HEADER_SIZE     EQU 48

; Object flags
OBJ_FLAG_FROZEN         EQU 0x0001
OBJ_FLAG_SEALED         EQU 0x0002
OBJ_FLAG_EXTENSIBLE     EQU 0x0004
OBJ_FLAG_DENSE_ARRAY    EQU 0x0008  ; Array with contiguous indices
OBJ_FLAG_SPARSE_ARRAY   EQU 0x0010  ; Array with holes

; ============================================================================
; Inline Cache Structure
; ============================================================================

; IC Slot (16 bytes):
;   +0:  Shape* cached_shape      ; Cached object shape
;   +8:  uint32_t cached_offset   ; Cached property offset
;   +12: uint32_t hit_count       ; Number of hits

IC_SHAPE            EQU 0
IC_OFFSET           EQU 8
IC_HIT_COUNT        EQU 12

IC_SLOT_SIZE        EQU 16

; IC entry types
IC_TYPE_MONOMORPHIC     EQU 0   ; Single shape cached
IC_TYPE_POLYMORPHIC     EQU 1   ; Multiple shapes (2-4)
IC_TYPE_MEGAMORPHIC     EQU 2   ; Too many shapes, generic lookup
IC_TYPE_UNINITIALIZED   EQU 3   ; Never been used

; ============================================================================
; Global Shape Table
; ============================================================================

.DATA
ALIGN 8

; Root shape (empty object)
g_root_shape        QWORD 0

; Shape ID counter
g_next_shape_id     DWORD 0

; Empty shape singleton (initialized at startup)
g_empty_shape       QWORD 0

.CODE

; ============================================================================
; Shape Management
; ============================================================================

; ShapeSystem_Init - Initialize the shape system
; Entry:  rcx = arena base
; Exit:   rax = 1 on success, 0 on failure
ShapeSystem_Init PROC FRAME
    push rbp
    .pushreg rbp
    push rbx
    .pushreg rbx
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    ; Create empty shape
    mov rcx, SHAPE_SIZE
    ; ARENA_ALLOC
    
    ; Initialize empty shape
    mov rbx, rax
    mov dword ptr [rbx + SHAPE_ID], 0
    mov word ptr [rbx + SHAPE_SLOT_COUNT], 0
    mov word ptr [rbx + SHAPE_TRANS_COUNT], 0
    mov qword ptr [rbx + SHAPE_PROTOTYPE], 0
    mov qword ptr [rbx + SHAPE_PARENT], 0
    mov qword ptr [rbx + SHAPE_TRANSITIONS], 0
    mov qword ptr [rbx + SHAPE_PROPERTIES], 0
    mov dword ptr [rbx + SHAPE_FLAGS], 0
    
    ; Store as root and empty shape
    mov g_root_shape, rbx
    mov g_empty_shape, rbx
    mov g_next_shape_id, 1
    
    mov rax, 1
    
    add rsp, 40
    pop rbx
    pop rbp
    ret
ShapeSystem_Init ENDP

; Shape_Create - Create a new shape as transition from parent
; Entry:  rcx = parent shape
;         rdx = property key (string pointer)
;         r8  = attributes
;         r9  = arena base
; Exit:   rax = new shape (or null)
Shape_Create PROC FRAME
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
    
    mov rbx, rcx        ; rbx = parent shape
    mov r12, rdx        ; r12 = key string
    mov rsi, r8         ; rsi = attributes
    
    ; Check if parent already has transition for this key
    movzx ecx, word ptr [rbx + SHAPE_TRANS_COUNT]
    test ecx, ecx
    jz .create_new_shape
    
    ; Search existing transitions
    mov rdi, [rbx + SHAPE_TRANSITIONS]
    mov r8, r12
    call String_Hash
    mov r9d, eax        ; r9d = key hash
    
    mov ecx, 0
.check_transitions:
    cmp ecx, [rbx + SHAPE_TRANS_COUNT]
    jae .create_new_shape
    
    mov eax, [rdi + TRANS_HASH]
    cmp eax, r9d
    jne .next_transition
    
    ; Hash matches, check key string
    mov rcx, [rdi + TRANS_KEY]
    mov rdx, r12
    call String_Equal
    test eax, eax
    jz .next_transition
    
    ; Found existing transition, return target shape
    mov rax, [rdi + TRANS_TARGET]
    jmp .done
    
.next_transition:
    add rdi, TRANS_SIZE
    inc ecx
    jmp .check_transitions
    
.create_new_shape:
    ; Allocate new shape
    mov rcx, SHAPE_SIZE
    ; ARENA_ALLOC
    
    test rax, rax
    jz .fail
    
    mov rdi, rax        ; rdi = new shape
    
    ; Initialize shape
    mov eax, g_next_shape_id
    mov [rdi + SHAPE_ID], eax
    inc g_next_shape_id
    
    movzx eax, word ptr [rbx + SHAPE_SLOT_COUNT]
    inc eax
    mov word ptr [rdi + SHAPE_SLOT_COUNT], ax
    mov word ptr [rdi + SHAPE_TRANS_COUNT], 0
    
    mov rax, [rbx + SHAPE_PROTOTYPE]
    mov [rdi + SHAPE_PROTOTYPE], rax
    mov [rdi + SHAPE_PARENT], rbx
    mov qword ptr [rdi + SHAPE_TRANSITIONS], 0
    mov qword ptr [rdi + SHAPE_PROPERTIES], 0
    mov dword ptr [rdi + SHAPE_FLAGS], 0
    
    ; Copy properties from parent
    movzx ecx, word ptr [rbx + SHAPE_SLOT_COUNT]
    test ecx, ecx
    jz .no_parent_props
    
    ; Allocate properties table
    mov eax, ecx
    shl eax, 4              ; * PROP_SIZE
    mov rcx, rax
    ; ARENA_ALLOC
    
    mov [rdi + SHAPE_PROPERTIES], rax
    
    ; Copy parent properties
    mov rsi, [rbx + SHAPE_PROPERTIES]
    mov r8, rax
    movzx ecx, word ptr [rbx + SHAPE_SLOT_COUNT]
.copy_props:
    mov rax, [rsi]
    mov [r8], rax
    mov rax, [rsi + 8]
    mov [r8 + 8], rax
    add rsi, PROP_SIZE
    add r8, PROP_SIZE
    dec ecx
    jnz .copy_props
    
.no_parent_props:
    ; Add new property
    movzx ecx, word ptr [rbx + SHAPE_SLOT_COUNT]    ; slot index = parent's slot count
    mov r8, r12
    call String_Hash
    
    movzx r8d, word ptr [rdi + SHAPE_SLOT_COUNT]
    dec r8d
    shl r8d, 4              ; * PROP_SIZE
    add r8, [rdi + SHAPE_PROPERTIES]
    
    mov [r8 + PROP_HASH], eax
    mov word ptr [r8 + PROP_SLOT], cx
    mov word ptr [r8 + PROP_ATTRS], si
    mov [r8 + PROP_KEY], r12
    
    ; Add transition to parent
    movzx ecx, word ptr [rbx + SHAPE_TRANS_COUNT]
    inc word ptr [rbx + SHAPE_TRANS_COUNT]
    
    ; Allocate or grow transition table
    mov eax, ecx
    inc eax
    shl eax, 4              ; * TRANS_SIZE (roughly)
    ; TODO: Reallocate transition table
    
    mov rax, rdi
    
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
Shape_Create ENDP

; Shape_LookupProperty - Find property in shape hierarchy
; Entry:  rcx = shape
;         rdx = key string
; Exit:   rax = property descriptor pointer (or null)
;         rdx = slot index (if found)
Shape_LookupProperty PROC FRAME
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
    
    mov rbx, rcx        ; rbx = current shape
    mov rsi, rdx        ; rsi = key string
    
    ; Hash the key
    mov rcx, rsi
    call String_Hash
    mov edi, eax        ; edi = key hash
    
.search_loop:
    test rbx, rbx
    jz .not_found
    
    ; Search properties in this shape
    movzx ecx, word ptr [rbx + SHAPE_SLOT_COUNT]
    test ecx, ecx
    jz .check_parent
    
    mov r8, [rbx + SHAPE_PROPERTIES]
    mov edx, 0
.check_props:
    cmp edx, ecx
    jae .check_parent
    
    mov eax, [r8 + PROP_HASH]
    cmp eax, edi
    jne .next_prop
    
    ; Hash matches, check key string
    push rcx
    push r8
    push rdx
    mov rcx, [r8 + PROP_KEY]
    mov rdx, rsi
    call String_Equal
    pop rdx
    pop r8
    pop rcx
    
    test eax, eax
    jz .next_prop
    
    ; Found!
    mov rax, r8
    movzx edx, word ptr [r8 + PROP_SLOT]
    jmp .done
    
.next_prop:
    add r8, PROP_SIZE
    inc edx
    jmp .check_props
    
.check_parent:
    ; Move to parent shape
    mov rbx, [rbx + SHAPE_PARENT]
    jmp .search_loop
    
.not_found:
    xor rax, rax
    xor edx, edx
    
.done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Shape_LookupProperty ENDP

; ============================================================================
; Object Operations with Inline Caching
; ============================================================================

; Object_GetPropertyIC - Get property with inline caching
; Entry:  rcx = object (NaN-boxed)
;         rdx = property key (NaN-boxed string)
;         r8  = IC slot pointer
;         r9  = arena base
; Exit:   rax = property value (NaN-boxed)
Object_GetPropertyIC PROC FRAME
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
    
    mov rbx, rcx        ; rbx = object
    mov r12, rdx        ; r12 = key
    mov rsi, r8         ; rsi = IC slot
    
    ; Extract object pointer
    mov rax, rbx
    and rax, 0x0000FFFFFFFFFFFF
    mov rbx, rax
    
    ; Get object shape
    mov rdi, [rbx + OBJ_SHAPE]
    
    ; Check IC cache
    test rsi, rsi
    jz .no_ic
    
    mov rax, [rsi + IC_SHAPE]
    cmp rax, rdi
    jne .ic_miss
    
    ; IC hit! Direct property access
    mov eax, [rsi + IC_HIT_COUNT]
    inc eax
    mov [rsi + IC_HIT_COUNT], eax
    
    mov eax, [rsi + IC_OFFSET]
    mov rcx, [rbx + OBJ_SLOTS]
    mov rax, [rcx + rax*8]
    jmp .done
    
.ic_miss:
    ; IC miss - need to update cache
    ; Fall through to slow path but update IC
    
.no_ic:
    ; Slow path: lookup property
    mov rcx, rdi        ; shape
    mov rdx, r12        ; key
    call Shape_LookupProperty
    
    test rax, rax
    jz .undefined
    
    ; Property found
    movzx ecx, word ptr [rax + PROP_SLOT]
    shl ecx, 3          ; * 8 for slot offset
    
    ; Update IC if provided
    test rsi, rsi
    jz .no_update_ic
    
    mov [rsi + IC_SHAPE], rdi
    mov [rsi + IC_OFFSET], ecx
    mov dword ptr [rsi + IC_HIT_COUNT], 1
    
.no_update_ic:
    ; Load property value
    mov rax, [rbx + OBJ_SLOTS]
    add rax, rcx
    mov rax, [rax]
    jmp .done
    
.undefined:
    mov rax, JS_UNDEFINED
    
.done:
    add rsp, 40
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Object_GetPropertyIC ENDP

; Object_SetPropertyIC - Set property with inline caching
; Entry:  rcx = object (NaN-boxed)
;         rdx = property key (NaN-boxed string)
;         r8  = value (NaN-boxed)
;         r9  = IC slot pointer
;         [rsp+40] = arena base
; Exit:   rax = 1 on success, 0 on failure
Object_SetPropertyIC PROC FRAME
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
    
    mov rbx, rcx        ; rbx = object
    mov r12, rdx        ; r12 = key
    mov r13, r8         ; r13 = value
    mov rsi, r9         ; rsi = IC slot
    
    ; Extract object pointer
    mov rax, rbx
    and rax, 0x0000FFFFFFFFFFFF
    mov rbx, rax
    
    ; Check if object is frozen
    mov eax, [rbx + OBJ_FLAGS]
    test eax, OBJ_FLAG_FROZEN
    jnz .fail
    
    ; Get object shape
    mov rdi, [rbx + OBJ_SHAPE]
    
    ; Check IC cache
    test rsi, rsi
    jz .no_ic
    
    mov rax, [rsi + IC_SHAPE]
    cmp rax, rdi
    jne .ic_miss
    
    ; IC hit - check if writable
    mov eax, [rsi + IC_OFFSET]
    mov rcx, [rbx + OBJ_SLOTS]
    mov [rcx + rax*8], r13
    
    inc dword ptr [rsi + IC_HIT_COUNT]
    mov rax, 1
    jmp .done
    
.ic_miss:
    ; IC miss - need shape transition or new property
    
.no_ic:
    ; Lookup property
    mov rcx, rdi
    mov rdx, r12
    call Shape_LookupProperty
    
    test rax, rax
    jz .add_new_property
    
    ; Existing property
    movzx ecx, word ptr [rax + PROP_SLOT]
    shl ecx, 3
    
    ; Check writable
    movzx eax, word ptr [rax + PROP_ATTRS]
    test eax, PROP_WRITABLE
    jz .fail
    
    ; Update IC
    test rsi, rsi
    jz .no_update_ic
    mov [rsi + IC_SHAPE], rdi
    mov [rsi + IC_OFFSET], ecx
    mov dword ptr [rsi + IC_HIT_COUNT], 1
    
.no_update_ic:
    ; Store value
    mov rax, [rbx + OBJ_SLOTS]
    mov [rax + rcx], r13
    mov rax, 1
    jmp .done
    
.add_new_property:
    ; Check extensible
    mov eax, [rbx + OBJ_FLAGS]
    test eax, OBJ_FLAG_EXTENSIBLE
    jz .fail
    
    ; Create new shape with this property
    mov rcx, rdi
    mov rdx, r12
    mov r8d, PROP_WRITABLE or PROP_ENUMERABLE or PROP_CONFIGURABLE
    ; r9 = arena
    call Shape_Create
    
    test rax, rax
    jz .fail
    
    mov rdi, rax        ; rdi = new shape
    
    ; Transition object to new shape
    mov [rbx + OBJ_SHAPE], rdi
    
    ; Get slot index for new property
    movzx ecx, word ptr [rdi + SHAPE_SLOT_COUNT]
    dec ecx             ; Last slot is the new one
    shl ecx, 3
    
    ; Grow slots if needed
    mov eax, [rbx + OBJ_CAPACITY]
    shl eax, 3
    cmp ecx, eax
    jae .grow_slots
    
.store_new:
    ; Store value
    mov rax, [rbx + OBJ_SLOTS]
    mov [rax + rcx], r13
    
    ; Update IC
    test rsi, rsi
    jz .no_update_ic2
    mov [rsi + IC_SHAPE], rdi
    mov [rsi + IC_OFFSET], ecx
    mov dword ptr [rsi + IC_HIT_COUNT], 1
    
.no_update_ic2:
    mov rax, 1
    jmp .done
    
.grow_slots:
    ; TODO: Grow slots array
    jmp .store_new
    
.fail:
    xor rax, rax
    
.done:
    add rsp, 40
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Object_SetPropertyIC ENDP

; ============================================================================
; String Utilities
; ============================================================================

; String_Hash - Compute FNV-1a hash of string
; Entry:  rcx = string pointer (null-terminated)
; Exit:   rax = hash value
String_Hash PROC FRAME
    push rbp
    .pushreg rbp
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rax, 2166136261     ; FNV offset basis
    mov rdx, 16777619       ; FNV prime
    
.hash_loop:
    movzx r8d, byte ptr [rcx]
    test r8d, r8d
    jz .done
    
    xor eax, r8d
    mul edx
    inc rcx
    jmp .hash_loop
    
.done:
    add rsp, 40
    pop rbp
    ret
String_Hash ENDP

; String_Equal - Compare two strings for equality
; Entry:  rcx = string A
;         rdx = string B
; Exit:   rax = 1 if equal, 0 if not
String_Equal PROC FRAME
    push rbp
    .pushreg rbp
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 40
    .allocstack 40
    .endprolog
    
    mov rsi, rcx
    mov rdi, rdx
    
.compare_loop:
    movzx eax, byte ptr [rsi]
    movzx edx, byte ptr [rdi]
    cmp eax, edx
    jne .not_equal
    
    test eax, eax
    jz .equal
    
    inc rsi
    inc rdi
    jmp .compare_loop
    
.not_equal:
    xor rax, rax
    jmp .done
    
.equal:
    mov rax, 1
    
.done:
    add rsp, 40
    pop rdi
    pop rsi
    pop rbp
    ret
String_Equal ENDP

END
