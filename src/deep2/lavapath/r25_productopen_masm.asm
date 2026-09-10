; r25_productopen_masm.asm
; R25 no-dep x64 MASM ProductOpenSession gate for GGUF files.
; Opens + maps a GGUF, parses header/metadata, enumerates tensor infos,
; and fails closed unless tensors>0 plus embed/head-style tensors are found.
;
; ABI:
;   extern "C" uint64_t R25_ProductOpenGguf(const wchar_t* path,
;                                           R25_GGUF_PROOF* outProof);
;   extern "C" void     R25_CloseLastMapping(void);
;
; Build with MSVC tools:
;   ml64 /c /Fo:r25_productopen_masm.obj r25_productopen_masm.asm
;   link /lib /out:r25_productopen_masm.lib r25_productopen_masm.obj
;
; No CRT, no llama.cpp, no Ollama, no third-party deps.

option casemap:none
include r25_productopen_masm.inc

CreateFileW        PROTO :QWORD,:QWORD,:QWORD,:QWORD,:QWORD,:QWORD,:QWORD
CreateFileMappingW PROTO :QWORD,:QWORD,:QWORD,:QWORD,:QWORD,:QWORD
MapViewOfFile      PROTO :QWORD,:QWORD,:QWORD,:QWORD,:QWORD
UnmapViewOfFile    PROTO :QWORD
CloseHandle        PROTO :QWORD
GetFileSizeEx      PROTO :QWORD,:QWORD

GENERIC_READ       EQU 80000000h
FILE_SHARE_READ    EQU 00000001h
OPEN_EXISTING      EQU 3
PAGE_READONLY      EQU 2
FILE_MAP_READ      EQU 4
INVALID_HANDLE     EQU -1

GGUF_MAGIC         EQU 46554747h     ; 'GGUF' little endian

; GGUF value types
GGUF_U8            EQU 0
GGUF_I8            EQU 1
GGUF_U16           EQU 2
GGUF_I16           EQU 3
GGUF_U32           EQU 4
GGUF_I32           EQU 5
GGUF_F32           EQU 6
GGUF_BOOL          EQU 7
GGUF_STRING        EQU 8
GGUF_ARRAY         EQU 9
GGUF_U64           EQU 10
GGUF_I64           EQU 11
GGUF_F64           EQU 12

R25_GGUF_PROOF_status            EQU 0
R25_GGUF_PROOF_version           EQU 8
R25_GGUF_PROOF_tensor_count      EQU 16
R25_GGUF_PROOF_kv_count          EQU 24
R25_GGUF_PROOF_tensors_scanned   EQU 32
R25_GGUF_PROOF_token_embed_found EQU 40
R25_GGUF_PROOF_lm_head_found     EQU 48
R25_GGUF_PROOF_product_open      EQU 56
R25_GGUF_PROOF_file_size         EQU 64
R25_GGUF_PROOF_tensor_info_off   EQU 72
R25_GGUF_PROOF_SIZE              EQU 80

.data
lastFile QWORD 0
lastMap  QWORD 0
lastBase QWORD 0
lastSize QWORD 0

.code

ZeroProof PROC
    ; rcx=proof
    xor rax, rax
    mov r8, R25_GGUF_PROOF_SIZE / 8
zp_loop:
    mov [rcx], rax
    add rcx, 8
    dec r8
    jne zp_loop
    ret
ZeroProof ENDP

SetStatus PROC
    ; rcx=proof, rdx=status, returns rdx
    mov [rcx + R25_GGUF_PROOF_status], rdx
    mov rax, rdx
    ret
SetStatus ENDP

Need PROC
    ; rcx=cursor, rdx=end, r8=bytes -> carry set on failure
    mov rax, rdx
    sub rax, rcx
    cmp rax, r8
    jb need_bad
    clc
    ret
need_bad:
    stc
    ret
Need ENDP

Align32 PROC
    ; rcx=cursor -> rax aligned to 32 bytes
    lea rax, [rcx + 31]
    and rax, NOT 31
    ret
Align32 ENDP

SkipString PROC
    ; rcx=cursor, rdx=end -> rax=new cursor, CF fail
    mov r8, 8
    call Need
    jc ss_bad
    mov rax, [rcx]
    add rcx, 8
    mov r8, rax
    call Need
    jc ss_bad
    lea rax, [rcx + r8]
    clc
    ret
ss_bad:
    xor rax, rax
    stc
    ret
SkipString ENDP

SkipValue PROC
    ; rcx=cursor after type, rdx=end, r9d=type -> rax=new cursor, CF fail
    cmp r9d, GGUF_U8
    je sv_1
    cmp r9d, GGUF_I8
    je sv_1
    cmp r9d, GGUF_BOOL
    je sv_1
    cmp r9d, GGUF_U16
    je sv_2
    cmp r9d, GGUF_I16
    je sv_2
    cmp r9d, GGUF_U32
    je sv_4
    cmp r9d, GGUF_I32
    je sv_4
    cmp r9d, GGUF_F32
    je sv_4
    cmp r9d, GGUF_U64
    je sv_8
    cmp r9d, GGUF_I64
    je sv_8
    cmp r9d, GGUF_F64
    je sv_8
    cmp r9d, GGUF_STRING
    je sv_string
    cmp r9d, GGUF_ARRAY
    je sv_array
    stc
    xor rax, rax
    ret
sv_1:
    mov r8, 1
    jmp sv_fixed
sv_2:
    mov r8, 2
    jmp sv_fixed
sv_4:
    mov r8, 4
    jmp sv_fixed
sv_8:
    mov r8, 8
sv_fixed:
    call Need
    jc sv_bad
    lea rax, [rcx + r8]
    clc
    ret
sv_string:
    call SkipString
    ret
sv_array:
    mov r8, 12
    call Need
    jc sv_bad
    mov r10d, [rcx]       ; element type
    mov r11, [rcx + 4]    ; count
    add rcx, 12
    cmp r10d, GGUF_STRING
    je sv_arr_string
    cmp r10d, GGUF_U8
    je sv_arr_size1
    cmp r10d, GGUF_I8
    je sv_arr_size1
    cmp r10d, GGUF_BOOL
    je sv_arr_size1
    cmp r10d, GGUF_U16
    je sv_arr_size2
    cmp r10d, GGUF_I16
    je sv_arr_size2
    cmp r10d, GGUF_U32
    je sv_arr_size4
    cmp r10d, GGUF_I32
    je sv_arr_size4
    cmp r10d, GGUF_F32
    je sv_arr_size4
    cmp r10d, GGUF_U64
    je sv_arr_size8
    cmp r10d, GGUF_I64
    je sv_arr_size8
    cmp r10d, GGUF_F64
    je sv_arr_size8
    stc
    xor rax, rax
    ret
sv_arr_size1:
    mov r8, r11
    jmp sv_arr_fixed
sv_arr_size2:
    mov r8, r11
    shl r8, 1
    jmp sv_arr_fixed
sv_arr_size4:
    mov r8, r11
    shl r8, 2
    jmp sv_arr_fixed
sv_arr_size8:
    mov r8, r11
    shl r8, 3
sv_arr_fixed:
    call Need
    jc sv_bad
    lea rax, [rcx + r8]
    clc
    ret
sv_arr_string:
    test r11, r11
    jz sv_done
sv_arr_string_loop:
    push r11
    call SkipString
    pop r11
    jc sv_bad
    mov rcx, rax
    dec r11
    jne sv_arr_string_loop
sv_done:
    mov rax, rcx
    clc
    ret
sv_bad:
    xor rax, rax
    stc
    ret
SkipValue ENDP

HasNeedle PROC
    ; rcx=string ptr, rdx=len, r8=needle ptr, r9=needle len -> rax 1/0
    push rbx
    push rsi
    push rdi
    xor rax, rax
    test rdx, rdx
    jz hn_ret
    cmp rdx, r9
    jb hn_ret
    mov r10, rdx
    sub r10, r9
    inc r10
hn_pos:
    mov r11, r9
    mov rbx, rcx
    mov rsi, r8
hn_cmp:
    mov al, [rbx]
    mov dil, [rsi]
    cmp al, 'A'
    jb hn_a_ok
    cmp al, 'Z'
    ja hn_a_ok
    add al, 32
hn_a_ok:
    cmp dil, 'A'
    jb hn_d_ok
    cmp dil, 'Z'
    ja hn_d_ok
    add dil, 32
hn_d_ok:
    cmp al, dil
    jne hn_next
    inc rbx
    inc rsi
    dec r11
    jne hn_cmp
    mov rax, 1
    jmp hn_ret
hn_next:
    inc rcx
    dec r10
    jne hn_pos
    xor rax, rax
hn_ret:
    pop rdi
    pop rsi
    pop rbx
    ret
HasNeedle ENDP

.data
needle_embd BYTE "token_embd",0
needle_emb  BYTE "token_emb",0
needle_out  BYTE "output",0
needle_head BYTE "lm_head",0
needle_lm   BYTE "lmhead",0
.code

ScanTensorName PROC
    ; rcx=name ptr, rdx=len, r8=proof
    push rbx
    push rsi
    push rdi
    mov rdi, r8
    mov r8, OFFSET needle_embd
    mov r9, 10
    call HasNeedle
    test rax, rax
    jnz stn_embed
    ; reload args are lost, use stack-free saved copies unavailable -> caller calls simple names only.
    ; fall through to done if exact token_embd not present.
    jmp stn_head_check_from_saved_impossible
stn_embed:
    mov QWORD PTR [rdi + R25_GGUF_PROOF_token_embed_found], 1
stn_head_check_from_saved_impossible:
    pop rdi
    pop rsi
    pop rbx
    ret
ScanTensorName ENDP

ScanTensorNameFull PROC
    ; rcx=name ptr, rdx=len, r8=proof
    push rbx
    push rsi
    push rdi
    mov rbx, rcx
    mov rsi, rdx
    mov rdi, r8
    mov rcx, rbx
    mov rdx, rsi
    mov r8, OFFSET needle_embd
    mov r9, 10
    call HasNeedle
    test rax, rax
    jnz stnf_emb
    mov rcx, rbx
    mov rdx, rsi
    mov r8, OFFSET needle_emb
    mov r9, 9
    call HasNeedle
    test rax, rax
    jz stnf_head
stnf_emb:
    mov QWORD PTR [rdi + R25_GGUF_PROOF_token_embed_found], 1
stnf_head:
    mov rcx, rbx
    mov rdx, rsi
    mov r8, OFFSET needle_out
    mov r9, 6
    call HasNeedle
    test rax, rax
    jnz stnf_h
    mov rcx, rbx
    mov rdx, rsi
    mov r8, OFFSET needle_head
    mov r9, 7
    call HasNeedle
    test rax, rax
    jnz stnf_h
    mov rcx, rbx
    mov rdx, rsi
    mov r8, OFFSET needle_lm
    mov r9, 6
    call HasNeedle
    test rax, rax
    jz stnf_done
stnf_h:
    mov QWORD PTR [rdi + R25_GGUF_PROOF_lm_head_found], 1
stnf_done:
    pop rdi
    pop rsi
    pop rbx
    ret
ScanTensorNameFull ENDP

CloseOpenHandles PROC
    sub rsp, 28h
    mov rcx, lastBase
    test rcx, rcx
    jz coh_map
    call UnmapViewOfFile
    mov lastBase, 0
coh_map:
    mov rcx, lastMap
    test rcx, rcx
    jz coh_file
    call CloseHandle
    mov lastMap, 0
coh_file:
    mov rcx, lastFile
    test rcx, rcx
    jz coh_done
    call CloseHandle
    mov lastFile, 0
coh_done:
    add rsp, 28h
    ret
CloseOpenHandles ENDP

R25_CloseLastMapping PROC
    call CloseOpenHandles
    ret
R25_CloseLastMapping ENDP

R25_ProductOpenGguf PROC
    ; rcx=path, rdx=proof
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    ; 7 pushes leave RSP 16-aligned; sub 40h keeps RSP 16-aligned for Win64 calls.
    sub rsp, 40h

    mov r12, rcx        ; path
    mov r13, rdx        ; proof
    test r12, r12
    jz r25_arg
    test r13, r13
    jz r25_arg

    mov rcx, r13
    call ZeroProof
    call CloseOpenHandles

    mov rcx, r12
    mov rdx, GENERIC_READ
    mov r8, FILE_SHARE_READ
    xor r9, r9
    mov QWORD PTR [rsp+20h], OPEN_EXISTING
    mov QWORD PTR [rsp+28h], 0
    mov QWORD PTR [rsp+30h], 0
    call CreateFileW
    cmp rax, INVALID_HANDLE
    je r25_open
    mov lastFile, rax

    lea rdx, [rsp+38h]
    mov rcx, rax
    call GetFileSizeEx
    test rax, rax
    jz r25_open
    mov rax, [rsp+38h]
    mov [r13 + R25_GGUF_PROOF_file_size], rax
    mov lastSize, rax
    cmp rax, 32
    jb r25_bounds

    mov rcx, lastFile
    xor rdx, rdx
    mov r8, PAGE_READONLY
    xor r9, r9
    mov QWORD PTR [rsp+20h], 0
    mov QWORD PTR [rsp+28h], 0
    call CreateFileMappingW
    test rax, rax
    jz r25_map
    mov lastMap, rax

    mov rcx, rax
    mov rdx, FILE_MAP_READ
    xor r8, r8
    xor r9, r9
    mov QWORD PTR [rsp+20h], 0
    call MapViewOfFile
    test rax, rax
    jz r25_map
    mov lastBase, rax

    mov rbx, rax                 ; base
    mov r15, rax
    add r15, lastSize            ; end
    mov rsi, rbx                 ; cursor

    mov r8, 24
    mov rcx, rsi
    mov rdx, r15
    call Need
    jc r25_bounds
    mov eax, [rsi]
    cmp eax, GGUF_MAGIC
    jne r25_magic
    mov eax, [rsi + 4]
    cmp eax, 2
    jb r25_version
    cmp eax, 3
    ja r25_version
    mov [r13 + R25_GGUF_PROOF_version], rax
    mov r14, [rsi + 8]           ; tensor_count
    mov rdi, [rsi + 16]          ; kv_count
    mov [r13 + R25_GGUF_PROOF_tensor_count], r14
    mov [r13 + R25_GGUF_PROOF_kv_count], rdi
    test r14, r14
    jz r25_tensors0
    add rsi, 24

r25_kv_loop:
    test rdi, rdi
    jz r25_kv_done
    mov rcx, rsi
    mov rdx, r15
    call SkipString              ; key
    jc r25_bounds
    mov rsi, rax
    mov r8, 4
    mov rcx, rsi
    mov rdx, r15
    call Need
    jc r25_bounds
    mov r9d, [rsi]
    add rsi, 4
    mov rcx, rsi
    mov rdx, r15
    call SkipValue
    jc r25_unsupported
    mov rsi, rax
    dec rdi
    jmp r25_kv_loop

r25_kv_done:
    mov [r13 + R25_GGUF_PROOF_tensor_info_off], rsi
    mov rdi, r14
r25_tensor_loop:
    test rdi, rdi
    jz r25_tensor_done
    mov r8, 8
    mov rcx, rsi
    mov rdx, r15
    call Need
    jc r25_bounds
    mov r10, [rsi]               ; name len
    add rsi, 8
    mov r8, r10
    mov rcx, rsi
    mov rdx, r15
    call Need
    jc r25_bounds
    mov rcx, rsi
    mov rdx, r10
    mov r8, r13
    call ScanTensorNameFull
    add rsi, r10

    mov r8, 4
    mov rcx, rsi
    mov rdx, r15
    call Need
    jc r25_bounds
    mov eax, [rsi]               ; n_dimensions
    add rsi, 4
    cmp eax, 8
    ja r25_bounds
    mov ecx, eax
    shl rcx, 3
    mov r8, rcx
    mov rcx, rsi
    mov rdx, r15
    call Need
    jc r25_bounds
    add rsi, r8                  ; dimensions[u64]

    mov r8, 12                   ; type u32 + offset u64
    mov rcx, rsi
    mov rdx, r15
    call Need
    jc r25_bounds
    add rsi, 12
    inc QWORD PTR [r13 + R25_GGUF_PROOF_tensors_scanned]
    dec rdi
    jmp r25_tensor_loop

r25_tensor_done:
    cmp QWORD PTR [r13 + R25_GGUF_PROOF_tensors_scanned], 0
    je r25_tensors0
    cmp QWORD PTR [r13 + R25_GGUF_PROOF_token_embed_found], 0
    je r25_embed0
    cmp QWORD PTR [r13 + R25_GGUF_PROOF_lm_head_found], 0
    je r25_head0
    mov QWORD PTR [r13 + R25_GGUF_PROOF_product_open], 1
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_OK
    call SetStatus
    jmp r25_return

r25_arg:
    mov rax, R25_PRODUCTOPEN_ERR_ARG
    jmp r25_ret_no_proof
r25_open:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_OPEN
    call SetStatus
    jmp r25_return
r25_map:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_MAP
    call SetStatus
    jmp r25_return
r25_magic:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_MAGIC
    call SetStatus
    jmp r25_return
r25_version:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_VERSION
    call SetStatus
    jmp r25_return
r25_bounds:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_BOUNDS
    call SetStatus
    jmp r25_return
r25_unsupported:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_UNSUPPORTED
    call SetStatus
    jmp r25_return
r25_tensors0:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_TENSORS0
    call SetStatus
    jmp r25_return
r25_embed0:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_EMBED0
    call SetStatus
    jmp r25_return
r25_head0:
    mov rcx, r13
    mov rdx, R25_PRODUCTOPEN_ERR_HEAD0
    call SetStatus

r25_return:
    mov rax, [r13 + R25_GGUF_PROOF_status]
r25_ret_no_proof:
    add rsp, 40h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
R25_ProductOpenGguf ENDP

END
