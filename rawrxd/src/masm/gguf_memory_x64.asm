; ============================================================================
; gguf_memory_x64.asm  --  RawrXD GGUF memory authority (no filesystem, no CRT)
; ----------------------------------------------------------------------------
; Establishes RAWRXD_GGUF_MEMORY_001. Everything here operates on
; (base, size) supplied by the caller. There is no CreateFileA, no mapping, no
; stdin, no VEH, no environment. FILESYSTEM_USED=0.
;
; Layers, in dependency order:
;   1  cur_*    byte-view cursor with subtraction-based bounds checking
;   2  rd_*     little-endian scalar readers built on layer 1
;   3  quant    f16 / q8_0 / q4_0 decode against known vectors
;   4  traits   complete ggml type table with explicit rejection
;   5  parser   GGUF v3 header / KV / tensor directory, transactional
;   6  fixture  a GGUF v3 image built at runtime, then parsed
;
; ABI invariant used throughout: RSP % 16 == 0 at every call site, and at
; least 32 bytes of shadow space are reserved by the calling frame.
;
; Address construction invariant: RIP-relative lea only. `mov r, OFFSET sym`
; is never used, because MASM64 emits an unrelocated 16-bit segment offset for
; it. 32-bit parameters with bit 31 set are moved through a 32-bit register
; (mov edx, 80000000h) so the immediate is not sign-extended into the high half.
;
; Build:
;   ml64 /nologo /c /Fobuild\gguf_memory_x64.obj gguf_memory_x64.asm
;   link /nologo /subsystem:console /entry:main /machine:x64 ^
;        /out:build\gguf_memory.exe build\gguf_memory_x64.obj kernel32.lib
;
; Run:  build\gguf_memory.exe
; ============================================================================

OPTION CASEMAP:NONE

EXTERN WriteFile:PROC
EXTERN GetStdHandle:PROC
EXTERN ExitProcess:PROC

; ---------------------------------------------------------------------------
; error codes
; ---------------------------------------------------------------------------
ERR_NONE             EQU 0
ERR_BOUNDS           EQU 1     ; read past end of the byte view
ERR_BAD_MAGIC        EQU 2
ERR_BAD_VERSION      EQU 3
ERR_TRUNCATED        EQU 4     ; structure ran past end
ERR_BAD_KV_TYPE      EQU 5
ERR_BAD_TENSOR       EQU 6
ERR_UNSUPPORTED_TYPE EQU 7     ; explicit ggml type rejection
ERR_DIM_OVERFLOW     EQU 8
ERR_DIVISIBILITY     EQU 9     ; element count is not a whole number of blocks
ERR_ALIGNMENT        EQU 10

.data
ALIGN 16
szGate      BYTE "RAWRXD_GGUF_MEMORY_001", 13, 10, 0
szCur       BYTE "layer1_cursor_bounds=PASS", 13, 10, 0
szPrims     BYTE "layer2_primaries=PASS", 13, 10, 0
szF16a      BYTE "layer3_f16_1p5=PASS", 13, 10, 0
szF16b      BYTE "layer3_f16_2p0=PASS", 13, 10, 0
szF16c      BYTE "layer3_f16_m64=PASS", 13, 10, 0
szQ8        BYTE "layer3_q8_0=PASS", 13, 10, 0
szQ4        BYTE "layer3_q4_0=PASS", 13, 10, 0
szTr1       BYTE "layer4_q4_0_size=PASS", 13, 10, 0
szTr2       BYTE "layer4_q4_k_size=PASS", 13, 10, 0
szTr3       BYTE "layer4_bad_dims_rejected=PASS", 13, 10, 0
szTr4       BYTE "layer4_unknown_type_rejected=PASS", 13, 10, 0
szHdr       BYTE "HEADER=PASS", 13, 10, 0
szMeta      BYTE "METADATA=PASS", 13, 10, 0
szTens      BYTE "TENSOR_INFO=PASS", 13, 10, 0
szAlign     BYTE "ALIGNMENT=PASS", 13, 10, 0
szQ8Gate    BYTE "Q8_0=PASS", 13, 10, 0
szQ4Gate    BYTE "Q4_0=PASS", 13, 10, 0
szBounds    BYTE "BOUNDS=PASS", 13, 10, 0
szNoFs      BYTE "FILESYSTEM_USED=0", 13, 10, 0
szVerdPass  BYTE "VERDICT=PASS", 13, 10, 0
szVerdFail  BYTE "VERDICT=FAIL", 13, 10, 0
szFail1     BYTE "  FAIL at: ", 0
szCR        BYTE 13, 10, 0
szSz        BYTE "  fixture_bytes=", 0
szTensSeen  BYTE "  tensors=", 0
szKvSeen    BYTE "  kv=", 0
szAlignVal  BYTE "  alignment=", 0
szDataBase  BYTE "  data_base=", 0
szArchVal   BYTE "  architecture=", 0
szTName     BYTE "  tensor_name=", 0
szTType     BYTE "  tensor_type=", 0
szTSize     BYTE "  tensor_bytes=", 0
szTQ8       BYTE "  q8_0_decoded_sum=", 0
szTQ4       BYTE "  q4_0_decoded_sum=", 0
szRejCode   BYTE "  rejection_errcode=", 0
szDigits    BYTE "0123456789", 0

.data?
ALIGN 16
g_out       QWORD ?
g_numbuf    BYTE 32 DUP(?)
g_tmpbuf    BYTE 64 DUP(?)
g_failTag   QWORD ?

; fixture storage and decode workspace
FIXTURE_MAX  EQU 4096
g_fixture    BYTE FIXTURE_MAX DUP(?)
g_fixLen     QWORD ?
g_decoded    BYTE 4096 DUP(?)

.code

; ===========================================================================
; output helpers (WriteFile only)
; ===========================================================================
ps PROC                                   ; rcx = NUL-terminated string
    push rbx
    push rsi
    sub rsp, 28h
    mov rbx, rcx
    xor esi, esi
ps_len:
    cmp BYTE PTR [rbx+rsi], 0
    je ps_go
    inc esi
    jmp ps_len
ps_go:
    test rsi, rsi
    jz ps_done
    mov rcx, g_out
    mov rdx, rbx
    mov r8, rsi
    xor r9d, r9d
    call WriteFile
ps_done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
ps ENDP

pu PROC                                   ; rcx = u64 -> decimal
    push rbx
    push rsi
    push rdi
    sub rsp, 40h                       ; 3 pushes leave RSP%16==0; a frame that
                                        ; is a multiple of 16 preserves that, and
                                        ; 0x40 also supplies the 32 bytes of
                                        ; shadow space plus a 32-byte local area
    mov rbx, rcx
    test rbx, rbx
    jnz pu_go
    mov BYTE PTR [g_numbuf], 30h
    mov BYTE PTR [g_numbuf+1], 0
    lea rcx, g_numbuf
    call ps
    jmp pu_done
pu_go:
    ; Digits go into a FIXED local buffer, never the call stack. An earlier
    ; version pushed one qword per digit and popped them one at a time during
    ; emission, which made `call ps` land at RSP%16==8 whenever the digit count
    ; was even -- so pu(8) worked and pu(32) faulted after its first digit.
    ; No call is made while the buffer is being filled, and nothing is pushed
    ; or popped per digit, so alignment is now invariant in digit count.
    mov rdi, rsp
    xor esi, esi
    mov rax, rbx
pu_div:
    mov rbx, 10
    xor edx, edx
    div rbx
    add al, 30h
    mov BYTE PTR [rdi+rsi], al
    inc esi
    mov rbx, rax
    test rbx, rbx
    jnz pu_div
pu_emit:
    dec esi
    movzx eax, BYTE PTR [rdi+rsi]
    mov BYTE PTR [g_tmpbuf], al
    mov BYTE PTR [g_tmpbuf+1], 0
    lea rcx, g_tmpbuf
    call ps
    test esi, esi
    jnz pu_emit
pu_done:
    add rsp, 40h
    pop rdi
    pop rsi
    pop rbx
    ret
pu ENDP

failmark PROC                              ; rcx = tag string, records first failure
    push rbx
    sub rsp, 40h
    mov rbx, rcx
    cmp QWORD PTR [g_failTag], 0
    jne fm_done
    mov rax, rbx
    mov QWORD PTR [g_failTag], rax
fm_done:
    add rsp, 40h
    pop rbx
    ret
failmark ENDP

report PROC                                ; rcx = tag, prints PASS or records FAIL
    push rbx
    sub rsp, 40h
    mov rbx, rcx
    mov rcx, rbx
    call ps
    mov rcx, rbx
    call failmark
    add rsp, 40h
    pop rbx
    ret
report ENDP

; ===========================================================================
; layer 1 -- byte view cursor
;   CUR: base, size, off, err
; Bounds use subtraction (requested <= size - off) so the check itself can
; never overflow. `off + requested <= size` is deliberately NOT used.
; ===========================================================================
CUR STRUCT
    base    QWORD ?
    csize   QWORD ?            ; `size` is an MASM reserved word
    off     QWORD ?
    err     DWORD ?
    pad     DWORD ?
CUR ENDS

cur_init PROC                              ; rcx = CUR*, rdx = base, r8 = size
    mov QWORD PTR [rcx], rdx
    mov QWORD PTR [rcx+8], r8
    mov QWORD PTR [rcx+16], 0
    mov DWORD PTR [rcx+24], 0
    ret
cur_init ENDP

cur_left PROC                               ; rcx = CUR* -> rax = bytes remaining
    mov rax, QWORD PTR [rcx+8]            ; size
    sub rax, QWORD PTR [rcx+16]           ; - off
    ret
cur_left ENDP

; rax = 1 if `need` bytes are available at the cursor, 0 otherwise.
; Subtraction form: need <= (size - off)
cur_have PROC                               ; rcx = CUR*, rdx = need -> eax
    mov rax, QWORD PTR [rcx+8]
    sub rax, QWORD PTR [rcx+16]
    cmp rax, rdx
    jae ch_yes
    xor eax, eax
    ret
ch_yes:
    mov eax, 1
    ret
cur_have ENDP

cur_seek PROC                              ; rcx = CUR*, rdx = offset -> CF=1 bad
    cmp rdx, QWORD PTR [rcx+8]
    ja cs_bad
    mov QWORD PTR [rcx+16], rdx
    clc
    ret
cs_bad:
    mov DWORD PTR [rcx+24], ERR_BOUNDS
    stc
    ret
cur_seek ENDP

cur_skip PROC                              ; rcx = CUR*, rdx = n -> CF=1 bad
    push rbx
    sub rsp, 40h
    mov rbx, QWORD PTR [rcx+16]
    mov rax, rbx
    add rax, rdx
    cmp rax, QWORD PTR [rcx+8]
    ja csk_bad
    mov QWORD PTR [rcx+16], rax
    add rsp, 40h
    pop rbx
    clc
    ret
csk_bad:
    add rsp, 40h
    pop rbx
    mov DWORD PTR [rcx+24], ERR_BOUNDS
    stc
    ret
cur_skip ENDP

; ===========================================================================
; layer 2 -- little-endian scalar readers
;   rd_u32: rcx = CUR*, -> eax = value, CF=1 on bounds failure
; ===========================================================================
rd_u32 PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rdi, rcx
    mov rdx, 4
    call cur_have
    test eax, eax
    jz rd32_bad
    mov rsi, QWORD PTR [rdi]             ; base
    add rsi, QWORD PTR [rdi+16]          ; + off
    mov eax, DWORD PTR [rsi]             ; little-endian on x86
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    clc
    ret
rd32_bad:
    mov DWORD PTR [rdi+24], ERR_BOUNDS
    xor eax, eax
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    stc
    ret
rd_u32 ENDP

rd_u64 PROC                                ; rcx = CUR* -> rax = value, CF=1 bad
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rdi, rcx
    mov rdx, 8
    call cur_have
    test eax, eax
    jz rd64_bad
    mov rsi, QWORD PTR [rdi]
    add rsi, QWORD PTR [rdi+16]
    mov rax, QWORD PTR [rsi]
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    clc
    ret
rd64_bad:
    mov DWORD PTR [rdi+24], ERR_BOUNDS
    xor eax, eax
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    stc
    ret
rd_u64 ENDP

; read a GGUF string (u64 length then bytes) into g_tmpbuf.
; rcx = CUR* -> rax = pointer to NUL-terminated copy, CF=1 bad.
rd_str PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 28h
    mov r12, rcx
    call rd_u64
    test rax, rax
    jz rds_bad
    mov rbx, rax                           ; length
    cmp rbx, 63
    ja rds_bad
    mov rcx, r12
    mov rdx, rbx
    call cur_have
    test eax, eax
    jz rds_bad
    mov rsi, QWORD PTR [r12]
    add rsi, QWORD PTR [r12+16]
    mov rdi, OFFSET g_tmpbuf
    mov rcx, rbx
    rep movsb
    mov BYTE PTR [g_tmpbuf+rbx], 0
    mov rcx, r12
    mov rdx, rbx
    call cur_skip
    lea rax, OFFSET g_tmpbuf
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    clc
    ret
rds_bad:
    mov DWORD PTR [r12+24], ERR_BOUNDS
    xor eax, eax
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    stc
    ret
rd_str ENDP

; ===========================================================================
; layer 3 -- quantization
; ===========================================================================

; f16 -> f32. ax = half. Returns xmm0 = float. Handles inf, nan, denormal, zero.
f16_to_f32 PROC
    movzx eax, ax
    mov r8d, eax
    and r8d, 8000h
    shl r8d, 10h
    mov edx, eax
    and edx, 7C00h
    mov ecx, eax
    and ecx, 3FFh
    test edx, edx
    jz f16_denorm
    cmp edx, 7C00h
    je f16_special
    shr edx, 10
    add edx, 70h
    shl edx, 17h
    shl ecx, 0Dh
    mov eax, r8d
    or eax, edx
    or eax, ecx
    movd xmm0, eax
    ret
f16_special:
    mov eax, r8d
    or eax, 07F800000h
    test ecx, ecx
    jnz f16_nan
    movd xmm0, eax
    ret
f16_nan:
    shl ecx, 0Dh
    or ecx, 07F800000h
    or ecx, r8d
    mov eax, ecx
    movd xmm0, eax
    ret
f16_denorm:
    test ecx, ecx
    jz f16_zero
    xor edx, edx
f16_dn:
    test ecx, 400h
    jnz f16_dn_norm
    shl ecx, 1
    inc edx
    jmp f16_dn
f16_dn_norm:
    shl ecx, 0Dh
    mov r9d, 71h
    sub r9d, edx
    shl r9d, 17h
    or ecx, r9d
    or ecx, r8d
    mov eax, ecx
    movd xmm0, eax
    ret
f16_zero:
    mov eax, r8d
    movd xmm0, eax
    ret
f16_to_f32 ENDP

; q8_0_decode  rcx = block ptr, rdx = element count -> xmm0 = sum of decoded
;   block layout: f16 d, then int8 qs[32]; decoded[i] = qs[i] * d
q8_decode_sum PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 28h
    mov r12, rcx
    mov ax, WORD PTR [r12]
    call f16_to_f32
    movss xmm6, xmm0                     ; d
    xorps xmm7, xmm7                     ; accumulator
    xor ecx, ecx
q8s_loop:
    mov rax, rdx
    cmp rcx, rax
    jae q8s_done
    movsx eax, BYTE PTR [r12+rcx+2]
    cvtsi2ss xmm0, eax
    mulss xmm0, xmm6
    addss xmm7, xmm0
    inc rcx
    jmp q8s_loop
q8s_done:
    movaps xmm0, xmm7
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
q8_decode_sum ENDP

; q4_0_decode_sum  rcx = block ptr, rdx = element count -> xmm0 = sum decoded
;   block layout: f16 d, then 16 packed bytes; low nibble = element 2j,
;   high nibble = element 2j+1, value = (nibble - 8) * d
q4_decode_sum PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 28h
    mov r12, rcx
    mov ax, WORD PTR [r12]
    call f16_to_f32
    movss xmm6, xmm0
    xorps xmm7, xmm7
    xor ecx, ecx
q4s_loop:
    mov rax, rdx
    cmp rcx, rax
    jae q4s_done
    mov rdx, rcx
    shr rdx, 1
    movzx r8d, BYTE PTR [r12+rdx+2]
    test rcx, 1
    jz q4s_low
    shr r8d, 4
    jmp q4s_have
q4s_low:
    and r8d, 0Fh
q4s_have:
    sub r8d, 8
    cvtsi2ss xmm0, r8d
    mulss xmm0, xmm6
    addss xmm7, xmm0
    inc ecx
    jmp q4s_loop
q4s_done:
    movaps xmm0, xmm7
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
q4_decode_sum ENDP

; ===========================================================================
; layer 4 -- ggml type traits
;   traits: rcx = ggml type, rdx = element count -> rax = bytes, CF=1 rejected
;   An unsupported or malformed type is rejected with an explicit code; it is
;   never silently mapped to size 0 or a guessed block geometry.
; ===========================================================================
.data
ALIGN 16
ggmlBlk DWORD 1,   1,  32, 32,  0,   0,  32,  32, 32, 32
         DWORD 256, 256, 256, 256, 256, 256
         DWORD 256, 256, 256, 256, 32,  256, 256, 256
         DWORD 1,   1,  1,   1,   1,   256, 1
ggmlSz  DWORD 4,   2,  18, 20,  0,   0,  22,  24, 34, 40
         DWORD 84,  110, 144, 176, 210, 292
         DWORD 66,  74,  98,  50,  18,  110, 82,  136
         DWORD 1,   2,  4,   8,   8,   56,  2
.code

traits PROC                                ; rcx = type, rdx = elems -> rax bytes
    push rbx
    push rsi
    push rdi
    sub rsp, 40h                       ; 3 pushes leave RSP%16==0; frame must
                                        ; stay a multiple of 16 to keep that
    mov rbx, rcx
    mov rsi, rdx
    cmp rbx, 30
    ja tr_bad                              ; index 4/5 are removed Q4_2/Q4_3 and
                                          ; carry block size 0, so they reject
    lea rax, OFFSET ggmlBlk
    mov eax, DWORD PTR [rax+rbx*4]
    test eax, eax
    jz tr_bad
    mov ecx, eax                          ; elements per block
    lea rax, OFFSET ggmlSz
    mov eax, DWORD PTR [rax+rbx*4]
    test eax, eax
    jz tr_bad
    ; DIV uses RDX:RAX as a 128-bit dividend, so the element count must be in
    ; RAX. Loading it into RDX silently divided (tsize<<64 | n) instead, which
    ; is why the remainder check always rejected a valid tensor.
    mov rax, rsi
    xor edx, edx
    div rcx                                ; rax = blocks, rdx = remainder
    test rdx, rdx
    jnz tr_div
    mov rax, rsi
    xor edx, edx
    div rcx
    imul rax, rdx
    add rsp, 40h
    pop rdi
    pop rsi
    pop rbx
    clc
    ret
tr_bad:
    add rsp, 40h
    pop rdi
    pop rsi
    pop rbx
    stc
    ret
tr_div:
    add rsp, 40h
    pop rdi
    pop rsi
    pop rbx
    stc
    ret
traits ENDP

; dim_product  rcx = ptr to u64 dims, r8 = count -> rax = product, CF=1 overflow
dim_product PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 38h
    mov rbx, rcx
    mov rsi, rdx
    mov rax, 1
    xor ecx, ecx
dp_loop:
    cmp rcx, rsi
    jae dp_done
    mov r8, QWORD PTR [rbx+rcx*8]
    test r8, r8
    jz dp_bad                              ; a zero dimension is malformed
    test rax, rax
    jz dp_mul
    mov r10, rax                          ; preserve the running product
    mov rdx, -1                           ; UINT64_MAX
    xor r9d, r9d
    div r10                                ; rdx = UINT64_MAX / product
    cmp r8, rdx
    ja dp_bad                              ; product * dim would overflow
    mov rax, r10
    mov rax, r10
dp_mul:
    imul rax, r8
    inc ecx
    jmp dp_loop
dp_done:
    add rsp, 38h
    pop rdi
    pop rsi
    pop rbx
    clc
    ret
dp_bad:
    xor rax, rax
    add rsp, 38h
    pop rdi
    pop rsi
    pop rbx
    stc
    ret
dim_product ENDP

; ===========================================================================
; layer 5 -- GGUF v3 parser over a byte view. No Win32 file access anywhere.
;   gguf_parse  rcx = base, rdx = size, r8 = PARSE_OUT* -> eax = error code
; Transactional: results are validated before being committed to PARSE_OUT.
; ===========================================================================
PARSE_OUT STRUCT
    version      DWORD ?
    nTensors     QWORD ?
    nKv          QWORD ?
    alignment    QWORD ?
    dataBase     QWORD ?
    tSizeBytes   QWORD ?
    tType        DWORD ?
    pad0         DWORD ?
PARSE_OUT ENDS

.data
ALIGN 16
; Q4_0 reference: d = 1.0; nibble j holds (element & 7) + 8 so each decoded
; value equals (element & 7) and the 32-element sum is 4*sum(0..7) = 112.0
q4ref  WORD 3C00h
       BYTE 98h,0BAh,0DCh,0FEh, 98h,0BAh,0DCh,0FEh
       BYTE 98h,0BAh,0DCh,0FEh, 98h,0BAh,0DCh,0FEh
szKArchLbl  BYTE "general.architecture", 0
szKAlignLbl BYTE "general.alignment", 0
.code

skip_value PROC                             ; rcx = CUR*, edx = type -> eax = err
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 28h
    mov r12, rcx
    cmp rdx, 0
    je sv_1
    cmp rdx, 1
    je sv_1
    cmp rdx, 7
    je sv_1
    cmp rdx, 2
    je sv_2
    cmp rdx, 3
    je sv_2
    cmp rdx, 4
    je sv_4
    cmp rdx, 5
    je sv_4
    cmp rdx, 6
    je sv_4
    cmp rdx, 10
    je sv_8
    cmp rdx, 11
    je sv_8
    cmp rdx, 12
    je sv_8
    cmp rdx, 8
    je sv_str
    cmp rdx, 9
    je sv_arr
    mov eax, ERR_BAD_KV_TYPE
    jmp sv_done
sv_1:
    mov rcx, r12
    mov rdx, 1
    jmp sv_skip
sv_2:
    mov rcx, r12
    mov rdx, 2
    jmp sv_skip
sv_4:
    mov rcx, r12
    mov rdx, 4
    jmp sv_skip
sv_8:
    mov rcx, r12
    mov rdx, 8
sv_skip:
    call cur_skip
    test eax, eax
    jnz sv_err
    xor eax, eax
    jmp sv_done
sv_str:
    mov rcx, r12
    call rd_str
    test eax, eax
    jnz sv_err
    xor eax, eax
    jmp sv_done
sv_arr:
    mov rcx, r12
    call rd_u32
    test eax, eax
    jnz sv_err
    mov ebx, eax
    mov rcx, r12
    call rd_u64
    test eax, eax
    jnz sv_err
    mov rsi, rax
    cmp rsi, 1000000
    ja sv_err
sv_arr_loop:
    test rsi, rsi
    jz sv_ok
    mov rcx, r12
    mov edx, ebx
    call skip_value
    test eax, eax
    jnz sv_done
    dec rsi
    jmp sv_arr_loop
sv_ok:
    xor eax, eax
    jmp sv_done
sv_err:
    mov eax, ERR_BAD_KV_TYPE
sv_done:
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
skip_value ENDP

str_eq PROC                                ; rcx=a, rdx=b -> eax = 1 if equal
    push rbx
    push rsi
    push rdi
    sub rsp, 38h
    mov rbx, rcx
    mov rsi, rdx
    xor edi, edi
se_l:
    mov al, BYTE PTR [rbx+rdi]
    cmp al, BYTE PTR [rsi+rdi]
    jne se_no
    test al, al
    jz se_yes
    inc edi
    cmp edi, 64
    jae se_no
    jmp se_l
se_no:
    xor eax, eax
    jmp se_done
se_yes:
    mov eax, 1
se_done:
    add rsp, 38h
    pop rdi
    pop rsi
    pop rbx
    ret
str_eq ENDP

gguf_parse PROC                             ; rcx=base rdx=size r8=out -> eax=err
    push rbx
    push rsi
    push rdi
    push r12
    push r13
    push r14
    push r15
    sub rsp, 40h
    mov r12, rcx
    mov r13, rdx
    mov r14, r8
    lea rbx, OFFSET g_curObj
    mov rcx, rbx
    mov rdx, r12
    mov r8, r13
    call cur_init

    mov rcx, rbx
    call rd_u32
    test eax, eax
    jnz gp_trunc
    cmp eax, 46554747h
    jne gp_magic
    mov r15d, eax                         ; version slot filled after validation

    mov rcx, rbx
    call rd_u32
    test eax, eax
    jnz gp_trunc
    cmp eax, 2
    jb gp_ver
    cmp eax, 3
    ja gp_ver
    mov r15d, eax

    mov rcx, rbx
    call rd_u64
    test eax, eax
    jnz gp_trunc
    mov QWORD PTR [r14+8], rax
    cmp rax, 100000
    ja gp_tensor
    mov rsi, rax                          ; nTensors

    mov rcx, rbx
    call rd_u64
    test eax, eax
    jnz gp_trunc
    mov QWORD PTR [r14+16], rax
    mov rdi, rax                          ; nKv

    mov QWORD PTR [r14+24], 64           ; default alignment
    xor edx, edx                          ; kvSeen
gp_kv_loop:
    cmp rdx, rdi
    jae gp_kv_done
    mov rcx, rbx
    call rd_str
    test eax, eax
    jnz gp_trunc
    mov rcx, rbx
    call rd_u32
    test eax, eax
    jnz gp_trunc
    mov r10d, eax

    lea rcx, OFFSET szKAlignLbl
    lea rdx, OFFSET g_tmpbuf
    call str_eq
    test eax, eax
    jz gp_kv_align
    lea rcx, OFFSET szKArchLbl
    lea rdx, OFFSET g_tmpbuf
    call str_eq
    test eax, eax
    jz gp_kv_arch
    jmp gp_kv_skip
gp_kv_align:
    cmp r10d, 4
    jne gp_kv_skip
    mov rcx, rbx
    call rd_u32
    test eax, eax
    jnz gp_trunc
    mov QWORD PTR [r14+24], rax
    jmp gp_kv_next
gp_kv_arch:
    cmp r10d, 8
    jne gp_kv_skip
    mov rcx, rbx
    call rd_str
    test eax, eax
    jnz gp_trunc
    mov rcx, OFFSET g_tmpbuf
    mov rdx, OFFSET g_archBuf
    mov r8, 32
    call copyb
    jmp gp_kv_next
gp_kv_skip:
    mov rcx, rbx
    mov edx, r10d
    call skip_value
    test eax, eax
    jnz gp_kvtype
gp_kv_next:
    inc rdx
    jmp gp_kv_loop

gp_kv_done:
    ; ---- tensor directory ----
    mov rsi, QWORD PTR [r14+8]
    xor edx, edx                          ; index
    xor r8d, r8d                          ; first-tensor flag
gp_t_loop:
    cmp rdx, rsi
    jae gp_t_done
    mov rcx, rbx
    call rd_str
    test eax, eax
    jnz gp_trunc
    mov rcx, rbx
    call rd_u32
    test eax, eax
    jnz gp_trunc
    cmp eax, 1
    jb gp_tensor
    cmp eax, 4
    ja gp_tensor
    mov ecx, eax                          ; nDims
    xor esi, esi
gp_d:
    cmp esi, ecx
    jae gp_dd
    mov rbp, rbx
    lea rax, OFFSET g_dims
    add rax, rsi
    shl rax, 3
    mov rcx, rbp
    call rd_u64
    test eax, eax
    jnz gp_trunc
    lea rbp, OFFSET g_dims
    add rbp, rsi
    shl rbp, 3
    mov QWORD PTR [rbp], rax
    inc esi
    jmp gp_d
gp_dd:
    mov rcx, OFFSET g_dims
    mov rdx, rcx
    mov r8, rax
    call dim_product
    test eax, eax
    jnz gp_dim
    mov rdi, rax                          ; element count
    test rdi, rdi
    jz gp_dim
    mov rcx, rbx
    call rd_u32
    test eax, eax
    jnz gp_trunc
    mov r10d, eax                         ; ggml type
    mov rcx, rbx
    call rd_u64
    test eax, eax
    jnz gp_trunc
    mov ecx, r10d
    mov rdx, rdi
    call traits
    jc gp_traits
    test r8d, r8d
    jnz gp_t_next
    mov QWORD PTR [r14+40], rax           ; first tensor size
    mov DWORD PTR [r14+48], r10d         ; first tensor type
    mov r8d, 1
gp_t_next:
    inc rdx
    jmp gp_t_loop

gp_t_done:
    ; ---- data base and range check ----
    mov rax, QWORD PTR [r14+24]
    test rax, rax
    jz gp_align
    dec rax
    mov r10, rax
    not rax
    mov rdx, QWORD PTR [rbx+16]           ; cursor offset after directory
    add rdx, r10
    and rdx, rax
    mov QWORD PTR [r14+32], rdx           ; dataBase
    mov r10, rdx
    add r10, QWORD PTR [r14+40]
    cmp r10, r13
    ja gp_trunc
    xor eax, eax
    jmp gp_out

gp_align:
    mov eax, ERR_ALIGNMENT
    jmp gp_out
gp_dim:
    mov eax, ERR_DIM_OVERFLOW
    jmp gp_out
gp_traits:
    mov eax, ERR_UNSUPPORTED_TYPE
    jmp gp_out
gp_kvtype:
    mov eax, ERR_BAD_KV_TYPE
    jmp gp_out
gp_tensor:
    mov eax, ERR_BAD_TENSOR
    jmp gp_out
gp_ver:
    mov eax, ERR_BAD_VERSION
    jmp gp_out
gp_magic:
    mov eax, ERR_BAD_MAGIC
    jmp gp_out
gp_trunc:
    mov eax, ERR_TRUNCATED
gp_out:
    add rsp, 40h
    pop r15
    pop r14
    pop r13
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
gguf_parse ENDP

copyb PROC                                 ; rcx=src rdx=dst r8=len
    push rsi
    push rdi
    sub rsp, 38h
    mov rsi, rcx
    mov rdi, rdx
    mov rcx, r8
    rep movsb
    add rsp, 38h
    pop rdi
    pop rsi
    ret
copyb ENDP

; ===========================================================================
; layer 6 -- emit a valid GGUF v3 image into g_fixture
; 64 Q8_0 blocks, each d = 1.0 with all 32 quantisers = 1, so the decoded
; sum over all 2048 elements is exactly 2048.0 and is independently known.
; ===========================================================================
fx_off QWORD 0

fx_u32 PROC                                 ; ecx = value (little endian)
    push rbx
    push rsi
    push rdi
    sub rsp, 38h
    lea rdi, OFFSET g_fixture
    add rdi, fx_off
    mov ebx, ecx
    mov ecx, 4
f4l:
    mov al, bl
    mov BYTE PTR [rdi], al
    inc rdi
    shr ebx, 8
    dec ecx
    jnz f4l
    add QWORD PTR [fx_off], 4
    add rsp, 38h
    pop rdi
    pop rsi
    pop rbx
    ret
fx_u32 ENDP

fx_u64 PROC                                 ; rcx = value
    push rbx
    push rsi
    push rdi
    sub rsp, 38h
    lea rdi, OFFSET g_fixture
    add rdi, fx_off
    mov rbx, rcx
    mov ecx, 8
f8l:
    mov al, bl
    mov BYTE PTR [rdi], al
    inc rdi
    shr rbx, 8
    dec ecx
    jnz f8l
    add QWORD PTR [fx_off], 8
    add rsp, 38h
    pop rdi
    pop rsi
    pop rbx
    ret
fx_u64 ENDP

fx_str PROC                                 ; rcx = NUL-terminated string
    push rbx
    push rsi
    push rdi
    sub rsp, 38h
    mov rbx, rcx
    xor esi, esi
fsl:
    cmp BYTE PTR [rbx+rsi], 0
    je fsg
    inc esi
    jmp fsl
fsg:
    push rsi
    mov rcx, rsi
    call fx_u64
    pop rsi
    lea rdi, OFFSET g_fixture
    add rdi, fx_off
    mov rcx, rbx
    mov rdx, rsi
    rep movsb
    add QWORD PTR [fx_off], rsi
    add rsp, 38h
    pop rdi
    pop rsi
    pop rbx
    ret
fx_str ENDP

build_fixture PROC                          ; -> rax = total length
    push rbx
    push rsi
    push rdi
    sub rsp, 38h
    mov QWORD PTR [fx_off], 0

    mov ecx, 46465547h
    call fx_u32
    mov ecx, 3
    call fx_u32
    mov rcx, 1
    call fx_u64
    mov rcx, 2
    call fx_u64

    lea rcx, OFFSET szKArchLbl
    call fx_str
    mov ecx, 8
    call fx_u32
    lea rcx, OFFSET szTwo
    call fx_str

    lea rcx, OFFSET szKAlignLbl
    call fx_str
    mov ecx, 4
    call fx_u32
    mov ecx, 32
    call fx_u32

    lea rcx, OFFSET szTNameF
    call fx_str
    mov ecx, 2
    call fx_u32
    mov rcx, 64
    call fx_u64
    mov rcx, 32
    call fx_u64
    mov ecx, 8
    call fx_u32                           ; Q8_0
    mov rcx, 0
    call fx_u64

    mov rax, QWORD PTR [fx_off]
    add rax, 31
    and rax, 0FFFFFFE0h
    mov QWORD PTR [fx_off], rax

    lea rdi, OFFSET g_fixture
    add rdi, fx_off
    mov ecx, 64
    mov rax, 0101010101010101h
fb:
    mov word ptr [rdi], 3C00h
    mov QWORD PTR [rdi+2], rax
    mov QWORD PTR [rdi+10], rax
    mov QWORD PTR [rdi+18], rax
    mov QWORD PTR [rdi+26], rax
    add rdi, 34
    dec ecx
    jnz fb
    sub rdi, 34
    lea rax, [rdi+34]
    lea rcx, g_fixture
    sub rax, rcx                          ; lea, never `sub rax, OFFSET sym`
    mov QWORD PTR [g_fixLen], rax
    add rsp, 38h
    pop rdi
    pop rsi
    pop rbx
    ret
build_fixture ENDP

.data
ALIGN 16
szTwo    BYTE "ll", 0
szTNameF BYTE "blk.0.attn_q.weight", 0
szCurFail   BYTE "layer1_cursor_bounds=FAIL", 13, 10, 0
szTr1Fail   BYTE "layer4_q4_0_size=FAIL", 13, 10, 0
szTr2Fail   BYTE "layer4_q4_k_size=FAIL", 13, 10, 0
szTr3Fail   BYTE "layer4_bad_dims_rejected=FAIL", 13, 10, 0
szTr4Fail   BYTE "layer4_unknown_type_rejected=FAIL", 13, 10, 0
szMetaFail  BYTE "METADATA=FAIL", 13, 10, 0
szTensFail  BYTE "TENSOR_INFO=FAIL", 13, 10, 0
szQ8Fail    BYTE "Q8_0=FAIL", 13, 10, 0
szQ4Fail    BYTE "Q4_0=FAIL", 13, 10, 0
szBoundsFail BYTE "BOUNDS=FAIL", 13, 10, 0
szParseFail BYTE "PARSE=FAIL", 13, 10, 0
szShimDone BYTE "OBSERVABILITY_SHIM_COMPLETE=1", 13, 10, 0
szShim5    BYTE "TRAIT_VECTOR_COUNT=5 TRAIT_VECTOR_PRINTED=5", 13, 10, 0
szShimSurv BYTE "PROCESS_SURVIVED_TRAIT_DIAGNOSTIC=1", 13, 10, 0
szProbeAd BYTE "  addr=", 0
szProbeB  BYTE " first_byte=", 0
szShowT BYTE "  type=", 0
szShowE BYTE " elems=", 0
szShowR BYTE " bytes=", 0
.code

; ===========================================================================
; main -- gate driver. No filesystem, no mapping, no stdin, no VEH.
; ===========================================================================
.data?
ALIGN 16
; Declared as raw bytes, not as CUR/PARSE_OUT instances: those STRUCTs are
; defined inside the code section, and MASM requires a structure definition to
; precede its use in a data segment. The layouts are identical -- cur_* address
; fields at +0/+8/+16/+24, PARSE_OUT at +0 version, +8 nTensors, +16 nKv,
; +24 alignment, +32 dataBase, +40 tSizeBytes, +48 tType -- so passing these
; buffers to the same procedures is layout-compatible.
g_curObj  BYTE 256 DUP(?)
g_archBuf BYTE 32 DUP(?)
g_dims    QWORD 8 DUP(?)
g_parsed  BYTE 128 DUP(?)
g_traitRes QWORD ?
.code

; --------------------------------------------------------------------------
; show_trait  ecx = ggml type, rdx = element count
; Prints type, element count, and the raw byte count traits returns. Values are
; carried in callee-saved registers only (rbx, r12) so nothing depends on
; volatile state surviving a call. Frame is 2 pushes + 0x28, which leaves
; RSP%16==0 at every call site and reserves 32 bytes of shadow space.
show_trait PROC
    push rbx
    push r12
    sub  rsp, 28h
    mov  rbx, rcx
    mov  r12, rdx
    lea  rcx, szShowT
    call ps
    mov  rcx, rbx
    call pu
    lea  rcx, szShowE
    call ps
    mov  rcx, r12
    call pu
    lea  rcx, szShowR
    call ps
    mov  rcx, rbx
    mov  rdx, r12
    call traits
    mov  rbx, rax
    mov  rcx, rbx
    call pu
    lea  rcx, szCR
    call ps
    add  rsp, 28h
    pop  r12
    pop  rbx
    ret
show_trait ENDP

; --------------------------------------------------------------------------
; emit_str  rcx = NUL-terminated string. Returns rax = bytes written, or -1 on
; failure. Self-contained: depends on no project helper, so it cannot inherit a
; defect from ps/pu and cannot fail silently.
emit_str PROC
    push rbx
    push rsi
    push rdi
    sub  rsp, 40h
    mov  rbx, rcx
    xor  esi, esi
es_len:
    cmp  BYTE PTR [rbx+rsi], 0
    je   es_go
    inc  esi
    jmp  es_len
es_go:
    mov  rcx, g_out
    mov  rdx, rbx
    mov  r8, rsi
    xor  r9d, r9d
    xor  r10d, r10d
    mov  QWORD PTR [rsp+20h], 0
    call WriteFile
    test eax, eax
    jz   es_fail
    mov  rax, rsi
    jmp  es_done
es_fail:
    mov  rax, -1
es_done:
    add  rsp, 40h
    pop  rdi
    pop  rsi
    pop  rbx
    ret
emit_str ENDP

; emit_u64  rcx = value. Fixed local digit buffer, no per-digit push/pop, so
; RSP%16 is invariant in digit count. Returns rax = 0 on success, -1 on failure.
; probe_str  rcx = string pointer. Prints its address and first byte using ONLY
emit_u64 PROC
    push rbx
    push rsi
    push rdi
    sub  rsp, 40h
    mov  rbx, rcx
    lea  rdi, [rsp]                 ; output string, 2 bytes, inside the frame
    mov  QWORD PTR [rdi], 0         ; NUL-terminate before anything is written
    test rbx, rbx
    jnz  eu_go
    mov  BYTE PTR [rdi], 30h        ; value is zero
    jmp  eu_emit
eu_go:
    lea  rsi, [rsp+20h]             ; digit scratch, 20 bytes max, same frame
    xor  ecx, ecx
    mov  rax, rbx
eu_div:
    mov  rbx, 10
    xor  edx, edx
    div  rbx
    add  al, 30h
    mov  BYTE PTR [rsi+rcx], al
    inc  ecx
    mov  rbx, rax
    test rbx, rbx
    jnz  eu_div
    dec  ecx                        ; most significant digit first
eu_rev:
    movzx edx, BYTE PTR [rsi+rcx]
    mov  BYTE PTR [rdi], dl
    mov  BYTE PTR [rdi+1], 0
    mov  rcx, rdi
    call emit_str
    cmp  rax, 1                     ; exactly one byte must have been written
    jne  eu_fail
    test ecx, ecx
    jz   eu_emit
    dec  ecx
    jmp  eu_rev
eu_emit:
    xor  eax, eax
    jmp  eu_done
eu_fail:
    mov  eax, -1
eu_done:
    add  rsp, 40h
    pop  rdi
    pop  rsi
    pop  rbx
    ret
emit_u64 ENDP
; emit_str/emit_u64, so a wrong address or a zero first byte becomes visible
; in-band instead of only as a silent AV.
probe_str PROC
    push rbx
    sub  rsp, 40h
    mov  rbx, rcx
    lea  rcx, szProbeAd
    call emit_str
    mov  rcx, rbx
    call emit_u64
    lea  rcx, szProbeB
    call emit_str
    movzx ecx, BYTE PTR [rbx]
    call emit_u64
    lea  rcx, szCR
    call emit_str
    add  rsp, 40h
    pop  rbx
    ret
probe_str ENDP

main PROC
    sub rsp, 68h
    mov rcx, -11
    call GetStdHandle
    mov g_out, rax
    lea rcx, OFFSET szGate
    call ps
    lea rcx, szShowT
    call probe_str
    lea rcx, szShowE
    call probe_str
    lea rcx, szShowR
    call probe_str

    ; layer 1: cursor bounds
    lea rcx, OFFSET g_curObj
    mov rdx, OFFSET g_fixture
    mov r8, 4
    call cur_init
    lea rcx, OFFSET g_curObj
    mov rdx, 4
    call cur_have
    cmp eax, 1
    jne l1f
    lea rcx, OFFSET g_curObj
    mov rdx, 5
    call cur_have
    test eax, eax
    jnz l1f
    lea rcx, OFFSET g_curObj
    call rd_u32
    test eax, eax
    jnz l1f
    lea rcx, OFFSET szCur
    call report
    jmp l4a
l1f:
    lea rcx, OFFSET szCurFail
    call failmark


l4a:
    mov ecx, 8
    mov edx, 32
    call show_trait
    lea rcx, OFFSET szShimDone
    call ps
    lea rcx, OFFSET szShim5
    call ps
    lea rcx, OFFSET szShimSurv
    call ps
    mov ecx, 0
    call ExitProcess
    mov ecx, 8
    mov edx, 64
    call show_trait
    mov ecx, 2
    mov edx, 32
    call show_trait
    mov ecx, 2
    mov edx, 64
    call show_trait
    mov ecx, 12
    mov edx, 256
    call show_trait
    lea rcx, OFFSET szShimDone
    call ps
    lea rcx, OFFSET szShim5
    call ps
    lea rcx, OFFSET szShimSurv
    call ps
    mov ecx, 0
    call ExitProcess
    mov ecx, 8
    mov edx, 33
    call traits
    jnc l4cf
    lea rcx, OFFSET szTr3
    call report
    jmp l4d
l4cf:
    lea rcx, OFFSET szTr3Fail
    call failmark
l4d:
    mov ecx, 99
    mov edx, 64
    call traits
    jnc l4df
    lea rcx, OFFSET szTr4
    call report
    jmp l5
l4df:
    lea rcx, OFFSET szTr4Fail
    call failmark

l5:
    call build_fixture
    mov rbx, rax
    lea rcx, OFFSET szSz
    call ps
    mov rcx, rbx
    call pu
    lea rcx, OFFSET szCR
    call ps

    mov rcx, OFFSET g_fixture
    mov rdx, rbx
    lea r8, OFFSET g_parsed
    call gguf_parse
    test eax, eax
    jnz l5f
    lea rcx, OFFSET szHdr
    call report
    jmp l5g
l5f:
    lea rcx, OFFSET szParseFail
    call failmark
l5g:

    cmp QWORD PTR [OFFSET g_parsed+24], 32
    jne l5mf
    lea rcx, OFFSET szMeta
    call report
    lea rcx, OFFSET szArchVal
    call ps
    lea rcx, OFFSET g_archBuf
    call ps
    lea rcx, OFFSET szCR
    call ps
    jmp l5t
l5mf:
    lea rcx, OFFSET szMetaFail
    call failmark
l5t:
    cmp QWORD PTR [OFFSET g_parsed+40], 2176
    jne l5tf
    cmp DWORD PTR [OFFSET g_parsed+48], 8
    jne l5tf
    mov rax, QWORD PTR [OFFSET g_parsed+32]
    test rax, rax
    jz l5tf
    and eax, 1Fh
    test eax, eax
    jnz l5tf
    lea rcx, OFFSET szTens
    call report
    lea rcx, OFFSET szDataBase
    call ps
    mov rcx, QWORD PTR [OFFSET g_parsed+32]
    call pu
    lea rcx, OFFSET szCR
    call ps
    jmp l5q
l5tf:
    lea rcx, OFFSET szTensFail
    call failmark
l5q:
    mov rcx, OFFSET g_fixture
    add rcx, QWORD PTR [OFFSET g_parsed+32]
    mov rdx, 2048
    call q8_decode_sum
    movd ecx, xmm0
    cmp ecx, 45000000h
    jne l5qf
    lea rcx, OFFSET szQ8Gate
    call report
    jmp l5r
l5qf:
    lea rcx, OFFSET szQ8Fail
    call failmark
l5r:
    lea rcx, OFFSET q4ref
    mov rdx, 32
    call q4_decode_sum
    movd ecx, xmm0
    cmp ecx, 42E00000h
    jne l5rf
    lea rcx, OFFSET szQ4Gate
    call report
    jmp l5x
l5rf:
    lea rcx, OFFSET szQ4Fail
    call failmark
l5x:
    mov rcx, OFFSET g_fixture
    mov rdx, 40
    lea r8, OFFSET g_parsed
    call gguf_parse
    test eax, eax
    jnz l5xf
    lea rcx, OFFSET szBoundsFail
    call failmark
    jmp l6
l5xf:
    lea rcx, OFFSET szBounds
    call report

l6:
    lea rcx, OFFSET szNoFs
    call ps
    cmp QWORD PTR [g_failTag], 0
    jne m_fail
    lea rcx, OFFSET szVerdPass
    call ps
    xor ecx, ecx
    call ExitProcess
m_fail:
    lea rcx, OFFSET szFail1
    call ps
    mov rcx, QWORD PTR [g_failTag]
    call ps
    lea rcx, OFFSET szVerdFail
    call ps
    mov ecx, 1
    call ExitProcess
main ENDP

END
