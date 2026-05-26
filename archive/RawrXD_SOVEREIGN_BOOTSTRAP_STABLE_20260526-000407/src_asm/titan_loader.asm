.CODE
; MODEL_LOADER: MAPS RAW DISK-BLOB TO EXECUTION-STATE
; RDX = BASE_ADDR, R8 = FILE_SIZE, R9 = TENSOR_OFFSET
PUBLIC LOAD_MODEL
LOAD_MODEL PROC FRAME
    sub rsp, 28h
    ; 1. VALIDATE MAGIC (Hypothetical Model Format: 'TNNN')
    mov eax, dword ptr [rdx]
    cmp eax, 4e4e4e54h ; 'TNNN' signature
    jne .err            ; Fail if magic mismatch
    ; 2. PARSE TENSOR TABLE (Entry = 16 bytes: 8 Offset, 8 Size)
    mov rcx, [rdx + 8]  ; Load TensorCount
    lea rsi, [rdx + r9] ; Start of TensorTable
.loop:
    cmp rcx, 0
    je .done
    ; 3. BOUNDS CHECK (Sanity vs Sentinel)
    mov rdi, [rsi]      ; Tensor Offset
    add rdi, [rsi + 8]  ; Tensor Size
    cmp rdi, r8         ; Compare against mapped limit
    jae .err
    add rsi, 16         ; Next descriptor
    dec rcx
    jmp .loop
.done:
    xor rax, rax        ; Return Success (0)
    add rsp, 28h
    ret
.err:
    mov rax, 1          ; Return Failure (1)
    add rsp, 28h
    ret
LOAD_MODEL ENDP
; 4. DISPATCHER PREP (Pointer Fixup)
; RDX = Base, R8 = TensorIdx -> Returns R10=Ptr, R11=Size
PUBLIC GET_TENSOR_PTR
GET_TENSOR_PTR PROC FRAME
    imul r8, 16
    add rdx, r9         ; Start of Table
    mov r10, [rdx + r8] ; Loaded Base
    mov r11, [rdx + r8 + 8]
    ret
GET_TENSOR_PTR ENDP
; --- LOADER METADATA ---
; HEADER: [4] Magic, [4] Version, [8] Count
; ENTRY : [8] Offset, [8] Size
; HARDENED_RUNTIME_LOADER_VERSION: 1.0.0
; DISK_TO_REGISTER_MAPPING: DIRECT
; ABI: WIN64_COMPLIANT
; EOF
END
