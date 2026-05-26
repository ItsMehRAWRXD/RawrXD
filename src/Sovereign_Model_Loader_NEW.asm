; ============================================================================
; Sovereign_Model_Loader.asm — GGUF Memory Mapping
; Real CreateFileA → CreateFileMappingA → MapViewOfFile sequence
; Parses header, validates magic, builds tensor pointer table
; ============================================================================
OPTION CASEMAP:NONE

include Sovereign_Common.inc

EXTERNDEF g_ApiTable : SOVEREIGN_API_TABLE
EXTERNDEF g_pGov : QWORD

.CODE

; ----------------------------------------------------------------------------
; Sovereign_LoadModel_Disk
; RCX = ASCIIZ path to .gguf file
; Returns: RAX = 0 (success), non-zero = error code
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
    sub rsp, 104

    mov r15, rcx
    mov r12, [g_pGov]
    test r12, r12
    jz @err_1
    mov r13, [r12].GOV_STATE.pModelState
    test r13, r13
    jz @err_2

    ; CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL)
    mov rcx, r15
    mov edx, GENERIC_READ
    mov r8d, FILE_SHARE_READ
    xor r9, r9
    mov qword ptr [rsp+48], OPEN_EXISTING
    mov qword ptr [rsp+56], FILE_ATTRIBUTE_NORMAL
    mov qword ptr [rsp+64], 0
    call [g_ApiTable.pCreateFileA]
    cmp rax, INVALID_HANDLE_VALUE
    je @err_3
    mov [r13].MODEL_STATE.file_handle, rax
    mov r14, rax

    ; GetFileSizeEx(handle, &size)
    lea rdx, [rsp+72]
    mov rcx, r14
    call [g_ApiTable.pGetFileSize]
    test eax, eax
    jz @err_4
    mov rax, [rsp+72]

    ; CreateFileMappingA(handle, NULL, PAGE_READONLY, 0, 0, NULL)
    mov rcx, r14
    xor rdx, rdx
    mov r8d, PAGE_READONLY
    xor r9, r9
    mov qword ptr [rsp+48], 0
    mov qword ptr [rsp+56], 0
    call [g_ApiTable.pCreateFileMappingA]
    test rax, rax
    jz @err_5
    mov [r13].MODEL_STATE.map_handle, rax

    ; MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0)
    mov rcx, rax
    mov edx, FILE_MAP_READ
    xor r8, r8
    xor r9, r9
    mov qword ptr [rsp+48], 0
    call [g_ApiTable.pMapViewOfFile]
    test rax, rax
    jz @err_6
    mov [r13].MODEL_STATE.pWeightBase, rax
    mov rbx, rax

    ; Validate GGUF magic: 'GGUF' = 0x46554747 little-endian
    mov eax, [rbx]
    cmp eax, GGUF_MAGIC
    jne @err_7

    ; Parse version
    mov eax, [rbx+4]
    mov [r13].MODEL_STATE.version, eax

    ; Parse tensor_count
    mov rax, [rbx+8]
    mov [r13].MODEL_STATE.tensor_count, rax

    ; Parse metadata_kv_count
    mov rax, [rbx+16]
    mov [r13].MODEL_STATE.metadata_kv_count, rax

    ; Parse metadata and build tensor table
    lea rsi, [rbx+24]
    call @parse_metadata
    test eax, eax
    jnz @err_9

    ; Build tensor pointer table
    call @build_tensor_table
    test eax, eax
    jnz @err_10

    ; Lock pages
    mov rcx, [r13].MODEL_STATE.pWeightBase
    mov rdx, [rsp+72]
    call [g_ApiTable.pVirtualLock]

    mov dword ptr [r12].GOV_STATE.status, 2
    xor eax, eax
    jmp @cleanup

@err_1:  mov eax, 1;  jmp @cleanup
@err_2:  mov eax, 2;  jmp @cleanup
@err_3:  mov eax, 3;  jmp @cleanup
@err_4:  mov eax, 4;  jmp @cleanup
@err_5:  mov eax, 5;  jmp @cleanup
@err_6:  mov eax, 6;  jmp @cleanup
@err_7:  mov eax, 7;  jmp @cleanup
@err_8:  mov eax, 8;  jmp @cleanup
@err_9:  mov eax, 9;  jmp @cleanup
@err_10: mov eax, 10; jmp @cleanup

@cleanup:
    add rsp, 104
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

; ----------------------------------------------------------------------------
; Parse metadata key-value pairs, extract hyperparameters
; RSI = parse position (updated), R13 = MODEL_STATE
; Returns EAX = 0 (success)
; ----------------------------------------------------------------------------
@parse_metadata:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r12

    mov rbx, [r13].MODEL_STATE.metadata_kv_count
    test rbx, rbx
    jz @meta_done

@meta_loop:
    ; key length (uint32)
    mov r12d, [rsi]
    add rsi, 4
    ; Skip key bytes
    add rsi, r12

    ; value type (uint32)
    mov eax, [rsi]
    add rsi, 4

    cmp eax, 4
    je @meta_u32
    cmp eax, 5
    je @meta_i32
    cmp eax, 6
    je @meta_f32
    cmp eax, 7
    je @meta_bool
    cmp eax, 8
    je @meta_string
    cmp eax, 10
    je @meta_u64
    cmp eax, 0
    je @meta_u8
    cmp eax, 1
    je @meta_i8
    jmp @meta_unknown

@meta_u8:
@meta_i8:
@meta_bool:
    add rsi, 1
    jmp @meta_next
@meta_u16:
@meta_i16:
    add rsi, 2
    jmp @meta_next
@meta_u32:
@meta_i32:
@meta_f32:
    mov eax, [rsi]
    add rsi, 4
    jmp @meta_next
@meta_u64:
@meta_i64:
    add rsi, 8
    jmp @meta_next
@meta_string:
    mov ecx, [rsi]
    add rsi, 4
    add rsi, rcx
    jmp @meta_next
@meta_unknown:
    mov eax, 1
    jmp @meta_return

@meta_next:
    dec rbx
    jnz @meta_loop

@meta_done:
    xor eax, eax

@meta_return:
    pop r12
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

; ----------------------------------------------------------------------------
; Build tensor pointer table from mapped GGUF
; R13 = MODEL_STATE, RBX = mapped base, RSI = tensor data start after metadata
; Returns EAX = 0 (success)
; ----------------------------------------------------------------------------
@build_tensor_table:
    push rbx
    push rcx
    push rdx
    push rsi
    push rdi
    push r12
    push r13
    push r14

    mov r14, rsi
    mov rdi, [r13].MODEL_STATE.tensor_count
    test rdi, rdi
    jz @tensor_done

    ; Allocate tensor table via VirtualAlloc
    mov rcx, rdi
    imul rcx, SIZEOF TENSOR_INFO
    xor ecx, ecx
    mov rdx, rcx
    mov r8d, MEM_COMMIT
    mov r9d, PAGE_READWRITE
    call [g_ApiTable.pVirtualAlloc]
    test rax, rax
    jz @tensor_fail
    mov [r13].MODEL_STATE.pTensorTable, rax
    mov r12, rax

@tensor_loop:
    ; name_len (uint32)
    mov ecx, [r14]
    mov [r12].TENSOR_INFO.name_len, rcx
    add r14, 4
    mov [r12].TENSOR_INFO.pName, r14
    add r14, rcx

    ; n_dims (uint32)
    mov eax, [r14]
    mov [r12].TENSOR_INFO.n_dims, eax
    add r14, 4

    ; Dimensions (4 x uint64)
    xor ecx, ecx
@dim_loop:
    cmp ecx, [r12].TENSOR_INFO.n_dims
    jae @dim_done
    mov rax, [r14]
    mov (TENSOR_INFO PTR [r12]).gguf_ne[rcx*8], rax
    add r14, 8
    inc ecx
    jmp @dim_loop
@dim_done:

    ; type (uint32)
    mov eax, [r14]
    mov [r12].TENSOR_INFO.gguf_type, eax
    add r14, 4

    ; offset (uint64)
    mov rax, [r14]
    mov [r12].TENSOR_INFO.gguf_offset, rax
    add r14, 8

    ; Resolve pData = mapped_base + offset
    mov rbx, [r13].MODEL_STATE.pWeightBase
    add rax, rbx
    mov [r12].TENSOR_INFO.pData, rax

    add r12, SIZEOF TENSOR_INFO
    dec rdi
    jnz @tensor_loop

@tensor_done:
    xor eax, eax
    jmp @tensor_return

@tensor_fail:
    mov eax, 1

@tensor_return:
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rbx
    ret

Sovereign_LoadModel_Disk ENDP

; ----------------------------------------------------------------------------
; Sovereign_UnloadModel
; Unmaps file, closes handles, frees tensor table
; ----------------------------------------------------------------------------
PUBLIC Sovereign_UnloadModel
Sovereign_UnloadModel PROC
    push rbx
    mov rbx, [g_pGov]
    test rbx, rbx
    jz @done
    mov rax, [rbx].GOV_STATE.pModelState
    test rax, rax
    jz @done

    mov rcx, [rax].MODEL_STATE.pWeightBase
    test rcx, rcx
    jz @skip_unmap
    call [g_ApiTable.pUnmapViewOfFile]
@skip_unmap:

    mov rcx, [rax].MODEL_STATE.map_handle
    test rcx, rcx
    jz @skip_mapclose
    call [g_ApiTable.pCloseHandle]
@skip_mapclose:

    mov rcx, [rax].MODEL_STATE.file_handle
    test rcx, rcx
    jz @skip_fileclose
    call [g_ApiTable.pCloseHandle]
@skip_fileclose:

    mov rcx, [rax].MODEL_STATE.pTensorTable
    test rcx, rcx
    jz @skip_tensorfree
    xor rdx, rdx
    mov r8d, MEM_RELEASE
    call [g_ApiTable.pVirtualFree]
@skip_tensorfree:

    mov rcx, rax
    mov rdx, SIZEOF MODEL_STATE
    xor eax, eax
    rep stosb

@done:
    pop rbx
    ret
Sovereign_UnloadModel ENDP

END