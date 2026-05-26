; ============================================================================
; Sovereign_Model_Loader.asm - GGUF v3 Loader and Tensor Index Builder
; Zero-dependency, x64 MASM. Reads, maps, parses, and indexes GGUF tensors.
; ============================================================================
OPTION CASEMAP:NONE

include Sovereign_Common.inc

EXTERN Sovereign_Malloc : PROC

.CODE

; ----------------------------------------------------------------------------
; @skip_value - Skip a single GGUF metadata value
;   ECX = GGUF value type
;   RSI = current parse pointer (advanced on return)
; Clobbers: RAX, RDX
; ----------------------------------------------------------------------------
@skip_value PROC
    cmp ecx, 0      ; UINT8
    je  @sv_b1
    cmp ecx, 1      ; INT8
    je  @sv_b1
    cmp ecx, 2      ; UINT16
    je  @sv_b2
    cmp ecx, 3      ; INT16
    je  @sv_b2
    cmp ecx, 4      ; UINT32
    je  @sv_b4
    cmp ecx, 5      ; INT32
    je  @sv_b4
    cmp ecx, 6      ; FLOAT32
    je  @sv_b4
    cmp ecx, 7      ; BOOL
    je  @sv_b1
    cmp ecx, 8      ; STRING (uint64 len + bytes)
    je  @sv_string
    cmp ecx, 9      ; ARRAY
    je  @sv_array
    cmp ecx, 10     ; UINT64
    je  @sv_b8
    cmp ecx, 11     ; INT64
    je  @sv_b8
    cmp ecx, 12     ; FLOAT64
    je  @sv_b8
    ; Unknown: treat as 4 bytes
    add rsi, 4
    ret
@sv_b1: add rsi, 1
    ret
@sv_b2: add rsi, 2
    ret
@sv_b4: add rsi, 4
    ret
@sv_b8: add rsi, 8
    ret
@sv_string:
    mov rax, [rsi]
    lea rsi, [rsi + 8 + rax]
    ret
@sv_array:
    ; uint32 element_type, uint64 count, then count elements
    mov edx, [rsi]              ; element type
    add rsi, 4
    mov rax, [rsi]              ; element count
    add rsi, 8
@sv_arr_loop:
    test rax, rax
    jz @sv_arr_done
    push rax
    push rdx
    mov ecx, edx
    call @skip_value
    pop rdx
    pop rax
    dec rax
    jmp @sv_arr_loop
@sv_arr_done:
    ret
@skip_value ENDP

; ----------------------------------------------------------------------------
; Sovereign_LoadModel_Disk
;   RCX = ASCIIZ path to .gguf file
; Returns RAX = 0 on success, non-zero error code on failure
; ----------------------------------------------------------------------------
PUBLIC Sovereign_LoadModel_Disk
Sovereign_LoadModel_Disk PROC
    push rbp
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 96                 ; shadow + locals

    mov r15, rcx                ; r15 = path
    mov r12, [g_pGov]
    test r12, r12
    jz @ld_err_1
    mov r13, [r12].GOV_STATE.pModelState
    test r13, r13
    jz @ld_err_2

    ; --- CreateFileA ---
    mov rcx, r15
    mov edx, GENERIC_READ
    mov r8d, FILE_SHARE_READ
    xor r9, r9
    mov qword ptr [rsp+32], OPEN_EXISTING
    mov qword ptr [rsp+40], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+48], 0
    call [g_ApiTable.pCreateFileA]
    cmp rax, INVALID_HANDLE_VALUE
    je @ld_err_3
    mov [r13].MODEL_STATE.file_handle, rax
    mov r14, rax

    ; --- GetFileSizeEx ---
    mov rcx, r14
    lea rdx, [rsp+64]
    call [g_ApiTable.pGetFileSizeEx]
    test eax, eax
    jz @ld_err_4
    mov rax, [rsp+64]
    mov [r13].MODEL_STATE.weight_size, rax

    ; --- CreateFileMappingA ---
    mov rcx, r14
    xor rdx, rdx
    mov r8d, PAGE_READONLY
    xor r9, r9
    mov qword ptr [rsp+32], 0
    mov qword ptr [rsp+40], 0
    call [g_ApiTable.pCreateFileMappingA]
    test rax, rax
    jz @ld_err_5
    mov [r13].MODEL_STATE.map_handle, rax

    ; --- MapViewOfFile ---
    mov rcx, rax
    mov edx, FILE_MAP_READ
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp+32], 0
    call [g_ApiTable.pMapViewOfFile]
    test rax, rax
    jz @ld_err_6
    mov [r13].MODEL_STATE.pWeightBase, rax
    mov rbx, rax                ; rbx = base of mapped file (preserved)
    mov rsi, rax                ; rsi = parse cursor

    ; --- Validate Header ---
    mov eax, [rsi]
    cmp eax, GGUF_MAGIC
    jne @ld_err_7
    mov eax, [rsi+4]
    mov [r13].MODEL_STATE.version, eax
    cmp eax, 3
    jne @ld_err_8
    mov rax, [rsi+8]
    mov [r13].MODEL_STATE.tensor_count, rax
    mov rax, [rsi+16]
    mov [r13].MODEL_STATE.metadata_kv_count, rax
    add rsi, 24

    ; --- Skip Metadata ---
    mov r14, [r13].MODEL_STATE.metadata_kv_count
@ld_meta_loop:
    test r14, r14
    jz @ld_meta_done
    ; Key (string: uint64 len + bytes)
    mov rax, [rsi]
    lea rsi, [rsi + 8 + rax]
    ; Value type (uint32)
    mov ecx, [rsi]
    add rsi, 4
    ; Value
    call @skip_value
    dec r14
    jmp @ld_meta_loop
@ld_meta_done:

    mov [r13].MODEL_STATE.pTensorTable, rsi

    ; --- Allocate Tensor Index ---
    mov rcx, [r13].MODEL_STATE.tensor_count
    test rcx, rcx
    jz @ld_idx_skip
    imul rcx, rcx, SIZE TENSOR_INFO
    call Sovereign_Malloc
    test rax, rax
    jz @ld_err_9
    ; --- DIAG STASH ---
    mov [g_DbgMallocRet], rax
    mov [g_DbgLoaderR13], r13
    lea rdx, [r13].MODEL_STATE.pIndex
    mov [g_DbgPIdxFieldAddr], rdx
    mov [r13].MODEL_STATE.pIndex, rax
    mov rdx, [r13].MODEL_STATE.pIndex
    mov [g_DbgPIdxReadback], rdx
    ; --- /DIAG ---
    mov rdi, rax                ; rdi = index cursor

    ; --- Populate Index ---
    mov r14, [r13].MODEL_STATE.tensor_count
@ld_pop_loop:
    test r14, r14
    jz @ld_pop_done
    ; Name (uint64 len + bytes)
    mov rax, [rsi]
    add rsi, 8
    mov [rdi].TENSOR_INFO.name_len, rax
    mov [rdi].TENSOR_INFO.pName, rsi
    ; --- FNV1A64 hash of name ---
    push rsi
    push rax
    mov r10, rsi                ; ptr
    mov r11, rax                ; len
    mov rax, 0CBF29CE484222325h ; FNV offset basis
    mov r9,  100000001B3h       ; FNV prime
@ld_h_loop:
    test r11, r11
    jz  @ld_h_done
    movzx rdx, byte ptr [r10]
    xor rax, rdx
    mul r9
    inc r10
    dec r11
    jmp @ld_h_loop
@ld_h_done:
    mov [rdi].TENSOR_INFO.name_hash, rax
    pop rax
    pop rsi
    add rsi, rax
    ; n_dims (uint32)
    mov eax, [rsi]
    add rsi, 4
    mov [rdi].TENSOR_INFO.n_dims, eax
    ; Dimensions (uint64 * n_dims) -> copy up to 4 into tensor_ne
    mov ecx, eax                ; ecx = n_dims (loop counter)
    lea r8, [rdi].TENSOR_INFO.tensor_ne
    mov edx, 4                  ; max slots
@ld_dim_loop:
    test ecx, ecx
    jz  @ld_dim_done
    mov rax, [rsi]
    add rsi, 8
    test edx, edx
    jz  @ld_dim_skip
    mov [r8], rax
    add r8, 8
    dec edx
@ld_dim_skip:
    dec ecx
    jmp @ld_dim_loop
@ld_dim_done:
    ; Type (uint32)
    mov eax, [rsi]
    add rsi, 4
    mov [rdi].TENSOR_INFO.tensor_type, eax
    ; Offset (uint64)
    mov rax, [rsi]
    add rsi, 8
    mov [rdi].TENSOR_INFO.tensor_offset, rax
    add rdi, SIZE TENSOR_INFO
    dec r14
    jmp @ld_pop_loop
@ld_pop_done:

    ; --- Align to GGUF_DEFAULT_ALIGNMENT (32 bytes) past file base ---
    mov rax, rsi
    sub rax, rbx                ; offset from file base
    add rax, GGUF_DEFAULT_ALIGNMENT - 1
    and rax, -GGUF_DEFAULT_ALIGNMENT
    add rax, rbx                ; weight base = rbx + aligned offset
    ; (Note: pWeightBase currently holds file base. We instead resolve
    ;  per-tensor pData using rax as the weight region origin.)
    mov r15, rax                ; r15 = weight region origin

    ; --- Resolve pData pointers ---
    mov rdi, [r13].MODEL_STATE.pIndex
    mov r14, [r13].MODEL_STATE.tensor_count
@ld_res_loop:
    test r14, r14
    jz @ld_res_done
    mov rax, [rdi].TENSOR_INFO.tensor_offset
    add rax, r15
    mov [rdi].TENSOR_INFO.pData, rax
    add rdi, SIZE TENSOR_INFO
    dec r14
    jmp @ld_res_loop
@ld_res_done:

@ld_idx_skip:
    xor eax, eax
    jmp @ld_cleanup

@ld_err_1: mov eax, 1
    jmp @ld_cleanup
@ld_err_2: mov eax, 2
    jmp @ld_cleanup
@ld_err_3: mov eax, 3
    jmp @ld_cleanup
@ld_err_4: mov eax, 4
    jmp @ld_cleanup
@ld_err_5: mov eax, 5
    jmp @ld_cleanup
@ld_err_6: mov eax, 6
    jmp @ld_cleanup
@ld_err_7: mov eax, 7
    jmp @ld_cleanup
@ld_err_8: mov eax, 8
    jmp @ld_cleanup
@ld_err_9: mov eax, 9
    jmp @ld_cleanup

@ld_cleanup:
    add rsp, 96
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret
Sovereign_LoadModel_Disk ENDP

; ----------------------------------------------------------------------------
; Sovereign_UnloadModel - unmap + close handles
; ----------------------------------------------------------------------------
PUBLIC Sovereign_UnloadModel
Sovereign_UnloadModel PROC
    push rbx
    push rsi
    sub rsp, 40

    mov rbx, [g_pGov]
    test rbx, rbx
    jz @un_done
    mov rsi, [rbx].GOV_STATE.pModelState
    test rsi, rsi
    jz @un_done

    mov rcx, [rsi].MODEL_STATE.pWeightBase
    test rcx, rcx
    jz @un_skip_unmap
    call [g_ApiTable.pUnmapViewOfFile]
    mov [rsi].MODEL_STATE.pWeightBase, 0
@un_skip_unmap:

    mov rcx, [rsi].MODEL_STATE.map_handle
    test rcx, rcx
    jz @un_skip_mclose
    call [g_ApiTable.pCloseHandle]
    mov [rsi].MODEL_STATE.map_handle, 0
@un_skip_mclose:

    mov rcx, [rsi].MODEL_STATE.file_handle
    test rcx, rcx
    jz @un_skip_fclose
    call [g_ApiTable.pCloseHandle]
    mov [rsi].MODEL_STATE.file_handle, 0
@un_skip_fclose:

@un_done:
    add rsp, 40
    pop rsi
    pop rbx
    ret
Sovereign_UnloadModel ENDP

END
