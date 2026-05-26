; Sovereign_GGUF_Parser.asm - Production Audit v4 (Hardened VRAM & Layout Safety)

.code

BADF100     EQU 0BADF100h
BADF101     EQU 0BADF101h
BADF102     EQU 0BADF102h
BADF103     EQU 0BADF103h
BADF104     EQU 0BADF104h
BADF105     EQU 0BADF105h
BADF106     EQU 0BADF106h
BADF107     EQU 0BADF107h

MAX_TENSORS EQU 1024

GGUF_TYPE_UINT8    EQU 0
GGUF_TYPE_INT8     EQU 1
GGUF_TYPE_UINT16   EQU 2
GGUF_TYPE_INT16    EQU 3
GGUF_TYPE_UINT32   EQU 4
GGUF_TYPE_INT32    EQU 5
GGUF_TYPE_FLOAT32  EQU 6
GGUF_TYPE_BOOL     EQU 7
GGUF_TYPE_STRING   EQU 8
GGUF_TYPE_ARRAY    EQU 9
GGUF_TYPE_UINT64   EQU 10
GGUF_TYPE_INT64    EQU 11
GGUF_TYPE_FLOAT64  EQU 12

XR_GGUF_CONTEXT STRUCT
    PtrBase     dq ?
    PtrEnd      dq ?
    DataBase    dq ?
    AlignVal    dq ?
XR_GGUF_CONTEXT ENDS

XR_TENSOR_ENTRY STRUCT
    NamePtr         dq ?
    NameLength      dd ?
    ElementCount    dq ?
    RelativeOffset  dq ?
    AbsolutePtr     dq ?
    ByteSize        dq ?
    DimsPtr         dq ?
    NDims           dd ?
    GGMLType        dd ?
    Flags           dq ?
XR_TENSOR_ENTRY ENDS

EXTERN g_TensorRegistry : QWORD
EXTERN g_TensorCount    : QWORD

.data
PUBLIC g_GGUFAlignment
PUBLIC g_GGML_Type_Table
    g_GGUFAlignment  dq 32

    ALIGN 8
g_GGML_Type_Table LABEL QWORD
    dq 1, 4       ; 0: F32
    dq 1, 2       ; 1: F16
    dq 32, 18     ; 2: Q4_0
    dq 32, 20     ; 3: Q4_1
    dq 32, 16     ; 4: Q4_2
    dq 32, 16     ; 5: Q4_3
    dq 32, 22     ; 6: Q5_0
    dq 32, 24     ; 7: Q5_1
    dq 32, 34     ; 8: Q8_0
    dq 32, 36     ; 9: Q8_1
    dq 256, 82    ; 10: Q2_K
    dq 256, 134   ; 11: Q3_K
    dq 256, 144   ; 12: Q4_K
    dq 256, 176   ; 13: Q5_K
    dq 256, 224   ; 14: Q6_K
    dq 256, 292   ; 15: Q8_K
    dq 256, 66    ; 16: IQ2_XXS
    dq 256, 74    ; 17: IQ2_XS
    dq 256, 98    ; 18: IQ3_XXS
    dq 256, 114   ; 19: IQ1_S
    dq 256, 104   ; 20: IQ4_NL
    dq 256, 122   ; 21: IQ3_S
    dq 256, 82    ; 22: IQ2_S
    dq 256, 136   ; 23: IQ4_XS
    dq 1, 1       ; 24: I8
    dq 1, 2       ; 25: I16
    dq 1, 4       ; 26: I32
    dq 1, 8       ; 27: I64
    dq 1, 8       ; 28: F64
    dq 256, 120   ; 29: IQ1_M
    dq 1, 1       ; 30: Padding
    dq 1, 1       ; 31: Padding
    dq 0, 0       ; Sentinel

.code

; -----------------------------------------
; SafeDiv64: (RAX / RBX)
; Output:
;   RAX = quotient
;   RDX = remainder (discardable)
; Clobbers: RAX,RDX
; -----------------------------------------
SafeDiv64 PROC
    xor rdx, rdx
    div rbx
    ret
SafeDiv64 ENDP

; -----------------------------------------
; AlignUp64
; RCX = value
; RDX = alignment
; RAX = aligned result
; -----------------------------------------
AlignUp64 PROC
    mov rax, rcx
    dec rdx
    add rax, rdx
    not rdx
    and rax, rdx
    ret
AlignUp64 ENDP

XR_GGUF_ReadU32 PROC
    cmp rdx, 4
    jb @@fail
    mov eax, [rcx]
    add rcx, 4
    sub rdx, 4
    ret
@@fail:
    xor rax, rax
    ret
XR_GGUF_ReadU32 ENDP

XR_GGUF_ReadU64 PROC
    cmp rdx, 8
    jb @@fail
    mov rax, [rcx]
    add rcx, 8
    sub rdx, 8
    ret
@@fail:
    xor rax, rax
    ret
XR_GGUF_ReadU64 ENDP

; -----------------------------------------
; XR_KV_SkipStateMachine (Flat)
; RSI = cursor ptr (points to value)
; RDI = cursor end
; RETURNS:
;   RAX advanced cursor, or 0 on fail
; -----------------------------------------
XR_KV_SkipStateMachine PROC
    push rbx
    push rdi
    push rsi
    push rdx

@@next_value:
    cmp rsi, rdi
    jae @@fail

    ; 1. Bounds check before type read
    mov rax, rdi
    sub rax, rsi
    cmp rax, 4
    jb @@fail

    ; Read value type
    mov eax, dword ptr [rsi]
    add rsi, 4

@@process_type:
    cmp eax, GGUF_TYPE_UINT8
    je  @@1
    cmp eax, GGUF_TYPE_INT8
    je  @@1
    cmp eax, GGUF_TYPE_BOOL
    je  @@1
    cmp eax, GGUF_TYPE_UINT16
    je  @@2
    cmp eax, GGUF_TYPE_INT16
    je  @@2
    cmp eax, GGUF_TYPE_UINT32
    je  @@4
    cmp eax, GGUF_TYPE_INT32
    je  @@4
    cmp eax, GGUF_TYPE_FLOAT32
    je  @@4
    cmp eax, GGUF_TYPE_UINT64
    je  @@8
    cmp eax, GGUF_TYPE_INT64
    je  @@8
    cmp eax, GGUF_TYPE_FLOAT64
    je  @@8
    cmp eax, GGUF_TYPE_STRING
    je  @@str
    cmp eax, GGUF_TYPE_ARRAY
    je  @@array

    jmp @@fail

@@1:
    add rsi, 1
    jmp @@done
@@2:
    add rsi, 2
    jmp @@done
@@4:
    add rsi, 4
    jmp @@done
@@8:
    add rsi, 8
    jmp @@done
@@str:
    ; Bounds check before string length read
    mov rax, rdi
    sub rax, rsi
    cmp rax, 8
    jb @@fail

    mov r8, qword ptr [rsi]
    add rsi, 8
    
    ; Bounds check before string data skip
    mov rax, rdi
    sub rax, rsi
    cmp rax, r8
    jb @@fail
    
    add rsi, r8
    jmp @@done

@@array:
    ; Bounds check before array header read (type + count)
    mov rax, rdi
    sub rax, rsi
    cmp rax, 12
    jb @@fail

    mov ebx, dword ptr [rsi]    ; Array inner type
    add rsi, 4
    mov r9, qword ptr [rsi]     ; Array count
    add rsi, 8

@@arr_loop:
    test r9, r9
    jz @@done
    
    mov eax, ebx
    cmp eax, GGUF_TYPE_STRING
    je  @@arr_str
    
    mov r8, 1
    cmp eax, GGUF_TYPE_UINT8
    je  @@arr_fixed
    cmp eax, GGUF_TYPE_INT8
    je  @@arr_fixed
    cmp eax, GGUF_TYPE_BOOL
    je  @@arr_fixed
    mov r8, 2
    cmp eax, GGUF_TYPE_UINT16
    je  @@arr_fixed
    cmp eax, GGUF_TYPE_INT16
    je  @@arr_fixed
    mov r8, 4
    cmp eax, GGUF_TYPE_UINT32
    je  @@arr_fixed
    cmp eax, GGUF_TYPE_INT32
    je  @@arr_fixed
    cmp eax, GGUF_TYPE_FLOAT32
    je  @@arr_fixed
    mov r8, 8
    cmp eax, GGUF_TYPE_UINT64
    je  @@arr_fixed
    cmp eax, GGUF_TYPE_INT64
    je  @@arr_fixed
    cmp eax, GGUF_TYPE_FLOAT64
    je  @@arr_fixed

    jmp @@fail

@@arr_fixed:
    mov rax, r8
    imul rax, r9
    
    ; Bounds check before fixed array skip
    mov rdx, rdi
    sub rdx, rsi
    cmp rdx, rax
    jb @@fail

    add rsi, rax
    jmp @@done

@@arr_str:
    ; Bounds check before array-string length read
    mov rax, rdi
    sub rax, rsi
    cmp rax, 8
    jb @@fail

    mov r8, qword ptr [rsi]
    add rsi, 8
    
    ; Bounds check before array-string data skip
    mov rax, rdi
    sub rax, rsi
    cmp rax, r8
    jb @@fail
    
    add rsi, r8
    dec r9
    jmp @@arr_loop

@@fail:
    xor rax, rax
    pop rdx
    pop rsi
    pop rdi
    pop rbx
    ret

@@done:
    mov rax, rsi
    pop rdx
    pop rsi
    pop rdi
    pop rbx
    ret
XR_KV_SkipStateMachine ENDP

; ------------------------------------------------------------------------------
; XR_GGUF_ParseTensorDirectory
; RCX = Tensor Count
; RDX = Cursor Base
; R8  = FileEnd Bounds
; ------------------------------------------------------------------------------
PUBLIC XR_GGUF_ParseTensorDirectory
XR_GGUF_ParseTensorDirectory PROC
    push rbp
    mov rbp, rsp
    push r12
    push r13
    push r14
    push rbx
    push rsi
    push rdi

    mov r11, r8             ; R11 = FileEnd
    mov r10, rcx            ; Remaining count
    lea rdi, g_TensorRegistry
    mov r13, rdx            ; r13 cursor separated from math

L_WalkTensors:
    cmp r10, 0
    jle ProcessDone

    cmp r13, r11
    jae L_Err_Bounds
    
    mov rcx, qword ptr [r13]        ; GGUF V3 strings use 64-bit length
    mov (XR_TENSOR_ENTRY PTR [rdi]).NameLength, ecx ; Truncate to 32-bit for registry
    add r13, 8
    
    mov (XR_TENSOR_ENTRY PTR [rdi]).NamePtr, r13
    add r13, rcx                    ; Use full 64-bit rcx for skip
    cmp r13, r11
    jae L_Err_Bounds

    mov ecx, dword ptr [r13]
    mov (XR_TENSOR_ENTRY PTR [rdi]).NDims, ecx
    add r13, 4
    
    ; Bounds check NDims (Max 16 for GGUF safety)
    cmp ecx, 16
    ja  L_Err_Bounds
    
    mov (XR_TENSOR_ENTRY PTR [rdi]).DimsPtr, r13

    mov rsi, 1
    mov ecx, dword ptr (XR_TENSOR_ENTRY PTR [rdi]).NDims
    mov r14, r13            ; shape compute clone (cursor isolation)
L_MulDims:
    test ecx, ecx
    jz L_FinishDims
    mov rbx, [r14]
    imul rsi, rbx
    add r14, 8
    dec ecx
    jmp L_MulDims
L_FinishDims:
    mov (XR_TENSOR_ENTRY PTR [rdi]).ElementCount, rsi

    mov ecx, dword ptr (XR_TENSOR_ENTRY PTR [rdi]).NDims
    shl rcx, 3
    add r13, rcx

    mov ecx, dword ptr [r13]
    mov (XR_TENSOR_ENTRY PTR [rdi]).GGMLType, ecx
    add r13, 4
    
    mov rbx, [r13]
    mov (XR_TENSOR_ENTRY PTR [rdi]).RelativeOffset, rbx
    add r13, 8

    ; --- GGML Block Math ---
    mov r9d, ecx
    cmp r9d, 31                    ; Max supported GGML types in table
    ja FallbackBlock
    
    lea rbx, g_GGML_Type_Table
    mov r12, r9
    shl r12, 4                     ; r12 = index * 16 (sizeof GGML_TYPE_ENTRY)
    
    mov r8,  [rbx + r12 + 8]       ; bytes per block
    mov r12, [rbx + r12]           ; block size
    test r12, r12
    jz FallbackBlock
    jmp CalcMulti

FallbackBlock:
    mov r12, 1                     ; default block size
    mov r8, 4                      ; default bytes (float32)

CalcMulti:    
    mov rcx, (XR_TENSOR_ENTRY PTR [rdi]).ElementCount
    
    ; ByteSize = (ElementCount + BlockSize - 1) / BlockSize * BytesPerBlock
    mov rax, rcx
    add rax, r12
    dec rax
    
    xor rdx, rdx
    div r12                        ; RAX = count of blocks
    imul rax, r8                   ; RAX = total bytes
    mov (XR_TENSOR_ENTRY PTR [rdi]).ByteSize, rax

    add rdi, SIZEOF XR_TENSOR_ENTRY
    dec r10
    jmp L_WalkTensors

ProcessDone:
    mov rax, r13
    jmp L_Cleanup_TD

L_Err_Bounds:
    xor rax, rax

L_Cleanup_TD:
    pop rdi
    pop rsi
    pop rbx
    pop r14
    pop r13
    pop r12
    pop rbp
    ret
XR_GGUF_ParseTensorDirectory ENDP

; -----------------------------------------------------------------------------
; XR_Parse_GGUF_Tensors (Full Initialization pipeline)
; -----------------------------------------------------------------------------
PUBLIC XR_Parse_GGUF_Tensors
XR_Parse_GGUF_Tensors PROC
    push rbp
    mov rbp, rsp
    sub rsp, 64
    push rbx
    push rsi
    push rdi
    push r12
    push r13

    ; [rbp-32] XR_GGUF_CONTEXT structure root
    
    mov [rbp-32], rcx       ; ctx.Base
    mov rbx, rcx
    mov rdi, rdx
    add rdi, rcx            ; Absolute End Bounds
    mov [rbp-24], rdi       ; ctx.End

    mov rdx, rdi
    sub rdx, rbx
    mov rcx, rbx
    call XR_GGUF_ReadU32
    cmp eax, 046554747h
    jne @@err_magic
    mov rbx, rcx            ; Update cursor

    mov rdx, rdi
    sub rdx, rbx
    mov rcx, rbx
    call XR_GGUF_ReadU32
    cmp eax, 3
    jne @@err_version
    mov rbx, rcx            ; Update cursor

    mov rdx, rdi
    sub rdx, rbx
    mov rcx, rbx
    call XR_GGUF_ReadU64
    mov g_TensorCount, rax
    mov rbx, rcx            ; Update cursor
    
    ; Bounds check tensor count
    cmp rax, MAX_TENSORS
    ja  @@err_bounds

    mov rdx, rdi
    sub rdx, rbx
    mov rcx, rbx
    call XR_GGUF_ReadU64
    mov r12, rax            ; r12 = KV count
    mov rbx, rcx            ; Update cursor

@@kv_loop:
    test r12, r12
    jz @@kv_done

    mov rcx, rbx
    mov rdx, rdi
    sub rdx, rbx
    
    ; Ensure at least 8 bytes for string length
    cmp rdx, 8
    jb @@err_kv
    
    call XR_GGUF_ReadU64
    mov rbx, rcx            ; commit advanced cursor (passed 8 bytes)
    
    ; Bounds check string data
    mov rdx, rdi
    sub rdx, rbx
    cmp rdx, rax
    jb @@err_kv
    
    add rbx, rax            ; skipped string key

    mov rsi, rbx
    call XR_KV_SkipStateMachine
    test rax, rax
    jz @@err_kv
    mov rbx, rax            ; commit advanced cursor back

    dec r12
    jmp @@kv_loop

@@kv_done:
    ; --- THE CRITICAL FIX (Alignment for Tensor Directory) ---
    mov rax, rbx
    add rax, 31
    and rax, -32
    mov rbx, rax    ; Aligned address
    
    ; Re-read tensor count at aligned location per Sovereign spec
    mov rcx, [rbx]
    mov g_TensorCount, rcx
    add rbx, 8      ; Advance past count to first tensor entry

    ; Parse the tensor directory mapping
    mov rcx, g_TensorCount
    mov rdx, rbx
    mov r8, rdi
    call XR_GGUF_ParseTensorDirectory
    test rax, rax
    jz @@err_bounds
    mov rbx, rax
    
    ; ---------------------------------------------------------
    ; HARD DATA_BASE ANCHOR (Locked directly after Meta Header)
    ; ---------------------------------------------------------
    mov rcx, rbx
    sub rcx, [rbp-32]       ; Local file relative cursor
    mov rdx, g_GGUFAlignment
    mov [rbp-8], rdx        ; ctx.AlignVal
    
    call AlignUp64
    mov [rbp-16], rax       ; ctx.DataBase = Base Relative Map
    
    add rax, [rbp-32]       ; Convert payload offset to Memory Absolute Space
    
    ; ---------------------------------------------------------
    ; ABSOLUTE PTR VALIDATION
    ; ---------------------------------------------------------
    mov r10, g_TensorCount
    lea rsi, g_TensorRegistry
@@apply_align:
    test r10, r10
    jz @@done_align
    
    mov rbx, (XR_TENSOR_ENTRY PTR [rsi]).RelativeOffset
    add rbx, rax
    mov (XR_TENSOR_ENTRY PTR [rsi]).AbsolutePtr, rbx
    
    ; Ensure safe boundary clamping
    cmp rbx, rdi
    jae @@err_bounds
    mov r11, (XR_TENSOR_ENTRY PTR [rsi]).ByteSize
    add r11, rbx
    cmp r11, rdi
    ja @@err_bounds

    add rsi, SIZEOF XR_TENSOR_ENTRY
    dec r10
    jmp @@apply_align
    
@@done_align:
    xor eax, eax
    jmp @@exit

@@err_magic:
    mov eax, BADF100
    jmp @@exit_err
@@err_version:
    mov eax, BADF101
    jmp @@exit_err
@@err_kv:
    mov eax, BADF103
    jmp @@exit_err
@@err_bounds:
    mov eax, BADF107

@@exit_err:
@@exit:
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    add rsp, 64
    pop rbp
    ret
XR_Parse_GGUF_Tensors ENDP

END