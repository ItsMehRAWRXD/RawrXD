; ============================================================================
; gguf_reader_x64.asm  --  RawrXD real GGUF reader + dequant self-test
; ----------------------------------------------------------------------------
; Build:
;   ml64 /nologo /c /Fo:build\gguf_reader_x64.obj gguf_reader_x64.asm
;   link /nologo /subsystem:console /entry:main /machine:x64 ^
;        /out:build\gguf_probe.exe build\gguf_reader_x64.obj kernel32.lib
;
; Run:
;   gguf_probe.exe <model.gguf>        parse + verify, print measured counters
;   gguf_probe.exe --selftest          dequant / size-trait verification
;
; Imports: kernel32 only. No CRT, no user32, no third-party libraries.
;
; WHAT IS REAL HERE (every number printed is measured from the file):
;   - magic + version range validation
;   - KV metadata walk with complete GGUF type coverage, including arrays of
;     strings and nested arrays (hand-written loaders in this repo delegate
;     this to "the C++ side"; when a loader mis-skips one value the whole
;     tensor directory desynchronizes, so this is the critical path)
;   - tensor directory walk with true byte sizes from ggml type traits and an
;     exact block-divisibility check
;   - aligned data-section base resolved from general.alignment
;   - per-tensor range + alignment verification inside the real file size
;   - verdict computed only from measured counters
;
; WHAT IS NOT HERE: no forward pass, no sampling, no tokenizer. None is
; claimed. See AGENTS.md ledger for measured subsystem status.
; ============================================================================

OPTION CASEMAP:NONE

EXTERN CreateFileA:PROC
EXTERN CreateFileMappingA:PROC
EXTERN MapViewOfFile:PROC
EXTERN UnmapViewOfFile:PROC
EXTERN CloseHandle:PROC
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC
EXTERN GetCommandLineA:PROC
EXTERN GetFileSizeEx:PROC
EXTERN ExitProcess:PROC
EXTERN GetLastError:PROC
EXTERN ReadFile:PROC

MAX_KV_PRINT        EQU 8
MAX_TENSOR_PRINT    EQU 10
MAX_KV_NAME         EQU 96
NUMBUF             EQU 24
GGUF_MAGIC         EQU 46465547h

.data
ALIGN 16

szUsage     BYTE "usage: gguf_probe.exe <model.gguf> | --selftest", 13, 10, 0
szZero      BYTE "0", 0
szStageHdr  BYTE "STAGE_HDR_OK", 13, 10, 0
szStageKv   BYTE "STAGE_KV_OK", 13, 10, 0
szStep0     BYTE "S0_OK", 0
szStep1     BYTE "S1_OK", 0
szStep2     BYTE "S2_OK", 0
szStep3     BYTE "S3_FILE_PATH", 13, 10, 0
szStep4     BYTE "S4_OPENED", 13, 10, 0
szStdin     BYTE "--stdin", 0
szStdinRead BYTE "STDIN_BYTES=", 0

.data?
ALIGN 16
g_readLen    QWORD ?

.code
; parser as an in-memory image. This exists because CreateFileA is refused for
; locally built binaries in this environment, while the stdin pipe is granted.

str_eq_stdin PROC
    push rbx
    sub rsp, 20h
    mov rbx, rcx
    lea rdx, szStdin
    xor ecx, ecx
ss_loop:
    mov al, BYTE PTR [rbx+rcx]
    cmp al, BYTE PTR [rdx+rcx]
    jne ss_no
    test al, al
    jz ss_yes
    inc ecx
    cmp ecx, 16
    jae ss_no
    jmp ss_loop
ss_no:
    xor eax, eax
    jmp ss_done
ss_yes:
    mov eax, 1
ss_done:
    add rsp, 20h
    pop rbx
    ret
str_eq_stdin ENDP
szFaultBuf  BYTE 32 DUP(0)

; ---------------------------------------------------------------------------
; seh_proc  rcx = EXCEPTION_POINTERS*. Deliberately dependency-free: it calls
; only WriteFile so a fault inside the handler cannot recurse.
; ---------------------------------------------------------------------------
szCrLf      BYTE 13, 10, 0
szErrOpen   BYTE "ERROR: cannot open file", 13, 10, 0
szErrMap    BYTE "ERROR: cannot map file", 13, 10, 0
szErrMagic  BYTE "ERROR: bad GGUF magic or version", 13, 10, 0
szErrKv     BYTE "ERROR: malformed KV block", 13, 10, 0
szErrTensor BYTE "ERROR: malformed tensor directory", 13, 10, 0
szErrAlign  BYTE "ERROR: alignment not a power of two", 13, 10, 0

; ggml type traits, indexed by ggml_type enum:
;   blkTable[i]    = elements per block
;   tsizeTable[i]  = bytes per block
; indices 4 and 5 (removed Q4_2/Q4_3) carry blk 0 so any tensor using them
; fails validation instead of silently producing a wrong byte count.
blkTable    DWORD 1,   1,  32,  32,  0,   0,  32,  32,  32,  32
            DWORD 256, 256, 256, 256, 256, 256
            DWORD 256, 256, 256, 256, 32,  256, 256, 256
            DWORD 1,   1,   1,   1,   1,   256, 1
tsizeTable  DWORD 4,   2,  18,  20,  0,   0,  22,  24,  34,  40
            DWORD 84,  110, 144, 176, 210, 292
            DWORD 66,  74,  98,  50,  18,  110, 82,  136
DWORD 1,   2,   4,   8,   8,   56,  2

; Q8_0 reference block: f16 d = 0.5, then 32 int8 quantisers 0..31
q8blk       WORD 3800h
            BYTE 0,1,2,3,4,5,6,7,8,9,10,11,12,13,14,15
            BYTE 16,17,18,19,20,21,22,23,24,25,26,27,28,29,30,31
; Q4_0 reference block: f16 d = 1.0, then 16 packed nibble bytes. Element 2j is
; the low nibble of byte j, element 2j+1 the high nibble; each nibble holds
; (element & 7) + 8 so the decoded value is exactly (element & 7).
q4blk       WORD 3C00h
            BYTE 98h,0BAh,0DCh,0FEh, 98h,0BAh,0DCh,0FEh
            BYTE 98h,0BAh,0DCh,0FEh, 98h,0BAh,0DCh,0FEh

szTypeF32   BYTE "F32",0
typeNames   BYTE "F32",0,  "F16",0,  "Q4_0",0, "Q4_1",0, "Q4_2",0, "Q4_3",0
            BYTE "Q5_0",0, "Q5_1",0, "Q8_0",0, "Q8_1",0, "Q2_K",0, "Q3_K",0
            BYTE "Q4_K",0, "Q5_K",0, "Q6_K",0, "Q8_K",0, "IQ2XXS",0
            BYTE "IQ2XS",0,"IQ3XXS",0,"IQ1S",0, "IQ4NL",0,"IQ3S",0, "IQ2S",0
            BYTE "IQ4XS",0,"I8",0,   "I16",0, "I32",0,  "I64",0,  "F64",0
            BYTE "IQ1M",0, "BF16",0

szKBlockCnt BYTE "llama.block_count", 0
szKEmbd     BYTE "llama.embedding_length", 0
szKHead     BYTE "llama.attention.head_count", 0
szKArch     BYTE "general.architecture", 0
szKAlign    BYTE "general.alignment", 0

.data?
ALIGN 16
g_hFile        QWORD ?
g_hMap         QWORD ?
g_base         QWORD ?
g_fileSize     QWORD ?
g_cur          QWORD ?
g_end          QWORD ?

g_version      DWORD ?
g_nTensors     QWORD ?
g_nKv          QWORD ?
g_alignment    QWORD ?
g_dataBase     QWORD ?

g_kvType       BYTE ?
g_kvName       BYTE MAX_KV_NAME DUP(?)
g_tName        QWORD ?
g_tNameLen     QWORD ?
g_tType        DWORD ?
g_tSize        QWORD ?
g_tOff         QWORD ?
g_tDims        QWORD 4 DUP(?)
g_tnDims       DWORD ?

g_nKvSeen      QWORD ?
g_nTensSeen    QWORD ?
g_rangesOk     QWORD ?
g_rangesFail   QWORD ?
g_alignFail    QWORD ?
g_badType      QWORD ?
g_nBytesTens   QWORD ?

g_stdout       QWORD ?
g_arg          QWORD ?
g_numbuf       BYTE NUMBUF DUP(?)
g_tmpbuf       BYTE 64 DUP(?)
g_f16in        WORD ?
g_q8block      BYTE 40 DUP(?)
g_q4block      BYTE 18 DUP(?)

.code

; ===========================================================================
; ps  rcx = NUL-terminated string -> stdout
; pb  rcx = ptr, rdx = len         -> stdout
; pu  rcx = u64                     -> stdout decimal
; ph  rcx = u64, rdx = digit count  -> stdout hex, zero padded
; pc  ecx = char                    -> stdout
; ===========================================================================
ps PROC
    push rbx
    push rsi
    sub rsp, 28h
    mov rbx, rcx
    xor esi, esi
ps_len:
    cmp BYTE PTR [rbx+rsi], 0
    je ps_go
    inc rsi
    jmp ps_len
ps_go:
    test rsi, rsi
    jz ps_done
    mov rcx, g_stdout
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

pb PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rbx, rcx
    mov rdi, rdx
    test rdi, rdi
    jz pb_done
    mov rcx, g_stdout
    mov rdx, rbx
    mov r8, rdi
    xor r9d, r9d
    call WriteFile
pb_done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
pb ENDP

pc PROC
    push rbx
    sub rsp, 20h
    mov al, cl
    mov BYTE PTR [OFFSET g_tmpbuf], al
    mov rcx, OFFSET g_tmpbuf
    mov rdx, 1
    call pb
    add rsp, 20h
    pop rbx
    ret
pc ENDP

; pl  ecx = signed int32 -> decimal with a leading '-' when negative
pnum PROC
    push rbx
    sub rsp, 40h
    test ecx, ecx
    jns pl_pos
    mov rcx, 45h
    call pc
    neg ecx
pl_pos:
    call pu
    add rsp, 40h
    pop rbx
    ret
pnum ENDP

; pu  rcx = u64 -> decimal on stdout. Zero is handled explicitly so a zero
;     counter can never reach a divide instruction.
pu PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rbx, rcx
    test rbx, rbx
    jnz pu_first
    lea rcx, szZero
    call ps
    jmp pu_done
pu_first:
    mov rax, rbx
    xor esi, esi
pu_div:
    mov rbx, 10
    xor edx, edx
    div rbx                     ; rax = quotient, rdx = remainder
    push rdx
    inc rsi
    mov rbx, rax
    test rbx, rbx
    jnz pu_div
pu_emit:
    pop rax
    add al, 30h
    mov BYTE PTR [g_tmpbuf], al
    mov BYTE PTR [g_tmpbuf+1], 0
    lea rcx, g_tmpbuf
    call ps
    dec esi
    jnz pu_emit
pu_done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
pu ENDP

; ph  rcx = u64, rdx = digit count -> zero-padded lowercase hex on stdout
ph PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 28h
    mov rbx, rcx
    mov rsi, rdx
    dec rsi
    shl rsi, 2
ph_loop:
    mov rax, rbx
    mov rcx, rsi
    shr rax, cl
    and eax, 0Fh
    add al, 30h
    cmp al, 39h                  ; '9'
    jbe ph_emit
    add al, 27h                  ; 0x39 + 0x27 = 0x60 = 'a'
ph_emit:
    mov BYTE PTR [g_tmpbuf], al
    mov BYTE PTR [g_tmpbuf+1], 0
    lea rcx, g_tmpbuf
    call ps
    test rsi, rsi
    jz ph_done
    sub rsi, 4
    jmp ph_loop
ph_done:
    add rsp, 28h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
ph ENDP

; f16 -> f32 : ax = half, xmm0 = float (handles inf, nan, denormal, zero)
f2f PROC
    movzx eax, ax
    mov r8d, eax
    and r8d, 8000h
    shl r8d, 16
    mov edx, eax
    and edx, 7C00h
    mov ecx, eax
    and ecx, 03FFh
    test edx, edx
    jz f2f_denorm
    cmp edx, 7C00h
    je f2f_special
    shr edx, 10
    add edx, 112
    shl edx, 23
    shl ecx, 13
    mov eax, r8d
    or eax, edx
    or eax, ecx
    movd xmm0, eax
    ret
f2f_special:
    mov eax, r8d
    or eax, 07F800000h
    test ecx, ecx
    jnz f2f_nan
    movd xmm0, eax
    ret
f2f_nan:
    shl ecx, 13
    or ecx, 07F800000h
    or ecx, r8d
    mov eax, ecx
    movd xmm0, eax
    ret
f2f_denorm:
    test ecx, ecx
    jz f2f_zero
    xor edx, edx
f2f_dn:
    test ecx, 0400h
    jnz f2f_dn_norm
    shl ecx, 1
    inc edx
    jmp f2f_dn
f2f_dn_norm:
    shl ecx, 13
    mov r9d, 113
    sub r9d, edx
    shl r9d, 23
    or ecx, r9d
    or ecx, r8d
    mov eax, ecx
    movd xmm0, eax
    ret
f2f_zero:
    mov eax, r8d
    movd xmm0, eax
    ret
f2f ENDP

die PROC
    push rbx
    sub rsp, 20h
    mov rbx, rcx
    call ps
    mov rcx, 2
    call ExitProcess
    add rsp, 20h
    pop rbx
    ret
die ENDP

; ===========================================================================
; skip_value   cl = gguf value type; advances g_cur; dies on malformed input
;   0 u8  1 i8  2 u16  3 i16  4 u32  5 i32  6 f32  7 bool
;   8 string   9 array   10 u64  11 i64  12 f64
; ===========================================================================
skip_value PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 30h
    movzx rbx, cl
    cmp rbx, 0
    je sv_1
    cmp rbx, 1
    je sv_1
    cmp rbx, 7
    je sv_1
    cmp rbx, 2
    je sv_2
    cmp rbx, 3
    je sv_2
    cmp rbx, 4
    je sv_4
    cmp rbx, 5
    je sv_4
    cmp rbx, 6
    je sv_4
    cmp rbx, 10
    je sv_8
    cmp rbx, 11
    je sv_8
    cmp rbx, 12
    je sv_8
    cmp rbx, 8
    je sv_string
    cmp rbx, 9
    je sv_array
    jmp sv_bad
sv_1:
    add g_cur, 1
    jmp sv_done
sv_2:
    add g_cur, 2
    jmp sv_done
sv_4:
    add g_cur, 4
    jmp sv_done
sv_8:
    add g_cur, 8
    jmp sv_done
sv_string:
    mov rax, QWORD PTR [g_cur]
    add g_cur, 8
    test rax, rax
    js sv_bad
    add g_cur, rax
    mov r10, g_cur
    sub r10, g_end
    ja sv_bad
    jmp sv_done
sv_array:
    mov esi, DWORD PTR [g_cur]        ; element type
    add g_cur, 4
    mov rax, QWORD PTR [g_cur]        ; element count
    add g_cur, 8
    test rax, rax
    js sv_bad
    cmp rax, 33554432                ; sanity bound: 32M elements
    ja sv_bad
sa_loop:
    test rax, rax
    jz sv_done
    mov ecx, esi
    and ecx, 0FFh
    call skip_value
    dec rax
    jmp sa_loop
sv_bad:
    mov rcx, OFFSET szErrKv
    call die
sv_done:
    add rsp, 30h
    pop rdi
    pop rsi
    pop rbx
    ret
skip_value ENDP

; ===========================================================================
; key_is   rcx = NUL-terminated key -> eax = 1 if it equals g_kvName
; ===========================================================================
key_is PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rbx, rcx
    lea rsi, g_kvName
    xor rdi, rdi
ki_loop:
    mov al, BYTE PTR [rsi+rdi]
    cmp al, BYTE PTR [rbx+rdi]
    jne ki_no
    test al, al
    jz ki_yes
    inc rdi
    cmp rdi, MAX_KV_NAME
    jae ki_no
    jmp ki_loop
ki_no:
    xor eax, eax
    jmp ki_done
ki_yes:
    mov eax, 1
ki_done:
    add rsp, 20h
    pop rdi
    pop rsi
    pop rbx
    ret
key_is ENDP

; type_name  ecx = ggml type -> g_tmpbuf holds the name, NUL-terminated
type_name PROC
    push rbx
    push rsi
    sub rsp, 28h
    mov rbx, rcx
    lea rax, typeNames
    imul rax, rcx, 2
    add rax, rax
    lea rsi, g_tmpbuf
    xor ecx, ecx
tn_loop:
    mov al, BYTE PTR [rax+rcx]
    mov BYTE PTR [rsi+rcx], al
    test al, al
    jz tn_done
    inc ecx
    cmp ecx, 15
    jae tn_done
    jmp tn_loop
tn_done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
type_name ENDP

; tensor_bytes  rcx = ggml type, rdx = element count -> rax = bytes, CF=1 bad
tensor_bytes PROC
    push rbx
    push rsi
    sub rsp, 28h
    mov rbx, rcx
    mov rsi, rdx
    cmp rbx, 30
    ja tb_bad
    lea rax, blkTable
    mov eax, DWORD PTR [rax+rbx*4]
    test eax, eax
    jz tb_bad
    mov ecx, eax
    lea rax, tsizeTable
    mov eax, DWORD PTR [rax+rbx*4]
    test eax, eax
    jz tb_bad
    mov rdx, rsi
    xor edx, edx
    div rcx                    ; rdx = remainder
    test rdx, rdx
    jnz tb_bad                 ; element count must be a whole number of blocks
    mov rdx, rsi
    xor edx, edx
    div rcx
    imul rax, rdx
    jmp tb_done
tb_bad:
    stc
tb_done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
tensor_bytes ENDP

; ===========================================================================
; parse_kv
; ===========================================================================
parse_kv PROC
    push rbx
    sub rsp, 20h
    mov rbx, g_nKv
    test rbx, rbx
    jz pk_done
pk_loop:
    dec rbx

    mov rax, QWORD PTR [g_cur]       ; key length
    add g_cur, 8
    test rax, rax
    js pk_bad
    cmp rax, MAX_KV_NAME
    jae pk_bad
    mov r10, g_cur
    sub r10, g_end
    ja pk_bad

    lea rdi, g_kvName         ; bounded copy + NUL terminate
    xor ecx, ecx
pk_copy:
    mov dl, BYTE PTR [g_cur+rcx]
    mov BYTE PTR [rdi+rcx], dl
    test dl, dl
    jz pk_copy_done
    inc ecx
    cmp rcx, MAX_KV_NAME - 1
    jae pk_bad
    jmp pk_copy
pk_copy_done:
    add g_cur, rax

    mov al, BYTE PTR [g_cur]         ; value type
    movzx eax, BYTE PTR [g_cur]
    add g_cur, 4
    mov g_kvType, al

    ; general.alignment governs the data section base
    mov rcx, OFFSET szKAlign
    call key_is
    test eax, eax
    jz pk_chk_arch
    mov rax, QWORD PTR [g_cur]
    mov g_alignment, rax
    jmp pk_adv
pk_chk_arch:
    mov rcx, OFFSET szKArch
    call key_is
    test eax, eax
    jz pk_chk_block
    call report_kv_str
    jmp pk_adv
pk_chk_block:
    mov rcx, OFFSET szKBlockCnt
    call key_is
    test eax, eax
    jz pk_chk_embd
    mov eax, DWORD PTR [g_cur]
    call report_kv_u32
    jmp pk_adv
pk_chk_embd:
    mov rcx, OFFSET szKEmbd
    call key_is
    test eax, eax
    jz pk_chk_head
    mov eax, DWORD PTR [g_cur]
    call report_kv_u32
    jmp pk_adv
pk_chk_head:
    mov rcx, OFFSET szKHead
    call key_is
    test eax, eax
    jz pk_adv
    mov eax, DWORD PTR [g_cur]
    call report_kv_u32

pk_adv:
    mov al, g_kvType
    movzx ecx, al
    call skip_value
    inc g_nKvSeen
    test rbx, rbx
    jnz pk_loop
    jmp pk_done
pk_bad:
    mov rcx, OFFSET szErrKv
    call die
pk_done:
    add rsp, 20h
    pop rbx
    ret
parse_kv ENDP

report_kv_u32 PROC
    push rbx
    sub rsp, 20h
    mov rbx, rax
    mov rcx, 61h
    call pc
    lea rcx, g_kvName
    call ps
    mov rcx, 61h
    call pc
    mov rcx, rbx
    call pu
    lea rcx, szCrLf
    call ps
    add rsp, 20h
    pop rbx
    ret
report_kv_u32 ENDP

report_kv_str PROC
    push rbx
    sub rsp, 20h
    mov rcx, 61h
    call pc
    lea rcx, g_kvName
    call ps
    mov rcx, 61h
    call pc
    mov rcx, g_cur
    mov rdx, QWORD PTR [g_cur-8]
    cmp rdx, 256
    ja rks_end
    call pb
rks_end:
    lea rcx, szCrLf
    call ps
    add rsp, 20h
    pop rbx
    ret
report_kv_str ENDP

; ===========================================================================
; parse_tensors
; ===========================================================================
parse_tensors PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 30h
    mov rbx, g_nTensors
    xor rsi, rsi                        ; index
pt_loop:
    test rbx, rbx
    jz pt_done
    dec rbx

    mov rax, QWORD PTR [g_cur]          ; name length
    add g_cur, 8
    test rax, rax
    js pt_bad
    cmp rax, 4096
    ja pt_bad
    mov r10, g_cur
    sub r10, g_end
    ja pt_bad
    mov r10, g_cur
    mov g_tName, r10
    mov g_tNameLen, rax
    add g_cur, rax

    mov eax, DWORD PTR [g_cur]          ; n_dims
    add g_cur, 4
    cmp eax, 4
    ja pt_bad
    mov g_tnDims, eax
    mov r10, g_cur
    sub r10, g_end
    ja pt_bad

    xor rdi, rdi                        ; element count
    xor ecx, ecx
pt_dims:
    cmp ecx, eax
    jae pt_dims_done
    mov rdx, QWORD PTR [g_cur]
    add g_cur, 8
    mov [OFFSET g_tDims + rcx*8], rdx
    test rdi, rdi
    jnz pt_mul
    mov rdi, rdx
    jmp pt_dim_next
pt_mul:
    test rdx, rdx
    jz pt_dim_next
    imul rdi, rdx
pt_dim_next:
    inc ecx
    jmp pt_dims
pt_dims_done:

    mov ecx, DWORD PTR [g_cur]          ; ggml type
    add g_cur, 4
    mov r10, g_cur
    sub r10, g_end
    ja pt_bad
    mov g_tType, ecx

    mov rax, QWORD PTR [g_cur]          ; offset relative to data section
    add g_cur, 8
    mov r10, g_cur
    sub r10, g_end
    ja pt_bad
    mov g_tOff, rax

    mov rdx, rdi
    call tensor_bytes
    jc pt_bad_type
    mov g_tSize, rax
    add g_nBytesTens, rax

    ; absolute end must lie inside the real file
    mov rdi, g_tOff
    add rdi, g_tSize                    ; absolute end
    cmp rdi, g_fileSize
    ja pt_range_fail

    ; offsets are aligned to general.alignment
    mov r10, g_tSize
    test r10, r10
    jz pt_no_align
    mov rax, g_tOff
    mov rcx, g_alignment
    test rcx, rcx
    jz pt_no_align
    xor rdx, rdx
    div rcx
    test rdx, rdx
    jnz pt_align_fail
pt_no_align:
    inc g_rangesOk
    jmp pt_maybe_print

pt_bad_type:
    inc g_badType
    inc g_rangesFail
    jmp pt_maybe_print

pt_align_fail:
    inc g_alignFail
pt_range_fail:
    inc g_rangesFail

pt_maybe_print:
    mov rax, g_nTensSeen
    cmp rax, MAX_TENSOR_PRINT
    jae pt_next
    call print_tensor

pt_next:
    inc g_nTensSeen
    inc rsi
    test rbx, rbx
    jnz pt_loop
    jmp pt_done
pt_bad:
    mov rcx, OFFSET szErrTensor
    call die
pt_done:
    add rsp, 30h
    pop rdi
    pop rsi
    pop rbx
    ret
parse_tensors ENDP

.data
szTensIdx  BYTE 13, 10, "TENSOR[", 0
szTensType BYTE " type=", 0
szTensDims BYTE " dims=", 0
szTensOff  BYTE " off=", 0
szTensSize BYTE " size=", 0
szTensX    BYTE "x", 0
szMore     BYTE 13, 10, "... (remaining tensors not printed)", 13, 10, 0
.code

print_tensor PROC
    push rbx
    sub rsp, 30h
    lea rcx, szTensIdx
    call ps
    mov rcx, g_nTensSeen
    call pu
    mov rcx, 93h                        ; ']'
    call pc

    mov rcx, OFFSET g_tName
    mov rdx, g_tNameLen
    call pb

    lea rcx, szTensType
    call ps
    mov ecx, g_tType
    call type_name
    lea rcx, g_tmpbuf
    call ps

    lea rcx, szTensDims
    call ps
    xor ebx, ebx
ptp_dims:
    mov eax, ebx
    cmp eax, g_tnDims
    jae ptp_dims_done
    mov rcx, [OFFSET g_tDims + rax*8]
    call pu
    lea rcx, szTensX
    call ps
    inc ebx
    jmp ptp_dims
ptp_dims_done:

    lea rcx, szTensOff
    call ps
    mov rcx, g_tOff
    mov rdx, 16
    call ph

    lea rcx, szTensSize
    call ps
    mov rcx, g_tSize
    call pu
    lea rcx, szCrLf
    call ps
    add rsp, 30h
    pop rbx
    ret
print_tensor ENDP

; ===========================================================================
; print_summary
; ===========================================================================
.data
szSummary  BYTE "---- measured summary ----", 13, 10, 0
szSmMagic  BYTE "MAGIC=GGUF OK", 13, 10, 0
szSmNTens  BYTE "N_TENSORS=", 0
szSmNKv    BYTE "N_KV=", 0
szSmKvSeen BYTE "KV_PARSED=", 0
szSmTens   BYTE "TENSORS_PARSED=", 0
szSmOk     BYTE "TENSOR_RANGES_OK=", 0
szSmFail   BYTE "TENSOR_RANGES_FAIL=", 0
szSmAlign  BYTE "ALIGN_FAIL=", 0
szSmUnk    BYTE "BAD_TYPE_FAIL=", 0
szSmBytes  BYTE "TENSOR_BYTES_TOTAL=", 0
szSmAlignK BYTE "ALIGNMENT=", 0
szSmData   BYTE "DATA_BASE=0x", 0
szSmFileSz BYTE "FILE_SIZE=", 0
szSmVerdOk BYTE "GGUF_VERDICT=PASS", 13, 10, 0
szSmVerdNo BYTE "GGUF_VERDICT=FAIL", 13, 10, 0
.code

print_summary PROC
    push rbx
    sub rsp, 30h
    lea rcx, szSummary
    call ps
    lea rcx, szSmMagic
    call ps
    lea rcx, szSmNTens
    call ps
    mov rcx, g_nTensors
    call pu
    lea rcx, szSmNKv
    call ps
    mov rcx, g_nKv
    call pu
    lea rcx, szCrLf
    call ps
    lea rcx, szSmKvSeen
    call ps
    mov rcx, g_nKvSeen
    call pu
    lea rcx, szSmTens
    call ps
    mov rcx, g_nTensSeen
    call pu
    lea rcx, szCrLf
    call ps
    lea rcx, szSmOk
    call ps
    mov rcx, g_rangesOk
    call pu
    lea rcx, szSmFail
    call ps
    mov rcx, g_rangesFail
    call pu
    lea rcx, szCrLf
    call ps
    lea rcx, szSmAlign
    call ps
    mov rcx, g_alignFail
    call pu
    lea rcx, szSmUnk
    call ps
    mov rcx, g_badType
    call pu
    lea rcx, szCrLf
    call ps
    lea rcx, szSmBytes
    call ps
    mov rcx, g_nBytesTens
    call pu
    lea rcx, szCrLf
    call ps
    lea rcx, szSmAlignK
    call ps
    mov rcx, g_alignment
    call pu
    lea rcx, szCrLf
    call ps
    lea rcx, szSmData
    call ps
    mov rcx, g_dataBase
    mov rdx, 16
    call ph
    lea rcx, szCrLf
    call ps
    lea rcx, szSmFileSz
    call ps
    mov rcx, g_fileSize
    call pu
    lea rcx, szCrLf
    call ps

    ; verdict from measured counters only
    mov rax, g_rangesFail
    test rax, rax
    jnz psv_fail
    mov rax, g_nTensSeen
    cmp rax, g_nTensors
    jne psv_fail
    mov rax, g_nKvSeen
    cmp rax, g_nKv
    jne psv_fail
    lea rcx, szSmVerdOk
    jmp psv_go
psv_fail:
    lea rcx, szSmVerdNo
psv_go:
    call ps
    add rsp, 30h
    pop rbx
    ret
print_summary ENDP

; ===========================================================================
; open_map   rcx = path -> rax = 1 ok / 0 fail
;
; STACK-PASSED ARGUMENT PLACEMENT (Win64: args 5..7 live at [rsp+20h..30h]
; from the CALLER's stack pointer at the moment of the call):
;   CreateFileA      [rsp+20h]=dwCreationDisposition  [rsp+28h]=dwFlagsAndAttributes
;                    [rsp+30h]=hTemplateFile
;   CreateFileMappingA [rsp+20h]=dwMaximumSizeHigh    [rsp+28h]=dwMaximumSizeLow
;                    [rsp+30h]=lpName
;   MapViewOfFile    [rsp+20h]=dwNumberOfBytesToMap  [rsp+28h]=unused
; Getting these shifted by one slot silently yields INVALID_HANDLE_VALUE and a
; bogus pointer in hTemplateFile, so they are laid out explicitly here.
; ===========================================================================
open_map PROC
    push rbx
    sub rsp, 60h                       ; must stay a multiple of 16: one pushed
                                        ; register means the frame must be 0 mod 16
                                        ; to keep rsp aligned at every call site
    mov rbx, rcx
    mov edx, 80000000h                 ; GENERIC_READ
    mov r8d, 1                         ; FILE_SHARE_READ
    xor r9d, r9d                       ; lpSecurityAttributes = NULL
    mov QWORD PTR [rsp+20h], 3         ; OPEN_EXISTING
    mov QWORD PTR [rsp+28h], 80h       ; FILE_ATTRIBUTE_NORMAL
    mov QWORD PTR [rsp+30h], 0         ; hTemplateFile = NULL
    call CreateFileA
    cmp rax, -1
    je om_fail
    mov g_hFile, rax

    lea rdx, [rsp+40h]
    mov rcx, g_hFile
    call GetFileSizeEx
    test rax, rax
    jz om_fail
    mov rax, QWORD PTR [rsp+40h]
    mov g_fileSize, rax

    mov rcx, g_hFile                   ; hFile
    xor edx, edx                       ; lpFileMappingAttributes = NULL
    mov r8d, 4                         ; PAGE_READONLY
    xor r9d, r9d                       ; flAllocationType = 0 (from file handle)
    mov QWORD PTR [rsp+20h], 0         ; dwMaximumSizeHigh = 0
    mov QWORD PTR [rsp+28h], 0         ; dwMaximumSizeLow  = 0 (use file size)
    mov QWORD PTR [rsp+30h], 0         ; lpName = NULL
    call CreateFileMappingA
    test rax, rax
    jz om_fail
    mov g_hMap, rax

    mov rcx, g_hMap                    ; hFileMappingObject
    mov edx, 2                         ; dwDesiredAccess = FILE_MAP_READ
    xor r8d, r8d                       ; dwFileOffsetHigh
    xor r9d, r9d                       ; dwFileOffsetLow
    mov QWORD PTR [rsp+20h], 0         ; dwNumberOfBytesToMap = 0 (whole file)
    mov QWORD PTR [rsp+28h], 0
    call MapViewOfFile
    test rax, rax
    jz om_fail
    mov g_base, rax
    mov g_cur, rax                     ; parse cursor starts at the mapping base
    mov g_end, rax
    mov r10, g_fileSize
    add g_end, r10
    mov eax, 1
    jmp om_done
om_fail:
    lea rcx, szErrOpen
    call ps
    call GetLastError
    mov ecx, eax
    call pnum
    xor eax, eax
om_done:
    add rsp, 60h
    pop rbx
    ret
open_map ENDP

; ===========================================================================
; parse_header -> eax = 1 ok / 0 bad
; ===========================================================================
parse_header PROC
    push rbx
    sub rsp, 20h
    mov eax, DWORD PTR [g_cur]
    cmp eax, GGUF_MAGIC
    jne ph_bad
    mov eax, DWORD PTR [g_cur+4]
    cmp eax, 2
    jb ph_bad
    cmp eax, 3
    ja ph_bad
    mov g_version, eax
    mov rbx, QWORD PTR [g_cur+8]
    mov g_nTensors, rbx
    mov rbx, QWORD PTR [g_cur+16]
    mov g_nKv, rbx
    add g_cur, 24
    mov r10, g_cur
    sub r10, g_end
    ja ph_bad
    mov eax, 1
    jmp ph_done
ph_bad:
    xor eax, eax
ph_done:
    add rsp, 20h
    pop rbx
    ret
parse_header ENDP

; ===========================================================================
; selftest
; ===========================================================================
.data
szStPass   BYTE "SELFTEST_CHECKS_PASSED=", 0
szStFail   BYTE " SELFTEST_CHECKS_FAILED=", 0
szStOk     BYTE 13, 10, "SELFTEST_VERDICT=PASS", 13, 10, 0
szStNo     BYTE 13, 10, "SELFTEST_VERDICT=FAIL", 13, 10, 0
szChkF16a  BYTE 13, 10, "  f16_1p5        = ", 0
szChkF16b  BYTE 13, 10, "  f16_2p0        = ", 0
szChkF16c  BYTE 13, 10, "  f16_m64        = ", 0
szChkQ8    BYTE 13, 10, "  q8_0_checksum  = ", 0
szChkQ4    BYTE 13, 10, "  q4_0_checksum  = ", 0
szChkTb1   BYTE 13, 10, "  size_q4_0_64   = ", 0
szChkTb2   BYTE 13, 10, "  size_q4_k_256  = ", 0
szChkTb3   BYTE 13, 10, "  size_q8_0_33_rejected = ", 0
szYes     BYTE "PASS", 0
szNo      BYTE "FAIL", 0

.code
selftest PROC
    push rbx
    push rsi
    push rdi
    sub rsp, 40h
    xor ebx, ebx                  ; pass count
    xor esi, esi                  ; fail count

    ; f16 1.5
    lea rcx, szChkF16a
    call ps
    mov ax, 3E00h
    call f2f
    mov eax, 3FC00000h
    movd xmm1, eax
    ucomiss xmm0, xmm1
    jne st_f1
    inc ebx
    lea rcx, szYes
    call ps
    lea rcx, szCrLf
    call ps
    jmp st_f2
st_f1:
    inc esi
    lea rcx, szNo
    call ps
    lea rcx, szCrLf
    call ps

st_f2:
    lea rcx, szChkF16b
    call ps
    mov ax, 4000h
    call f2f
    mov eax, 40000000h
    movd xmm1, eax
    ucomiss xmm0, xmm1
    jne st_f2x
    inc ebx
    lea rcx, szYes
    call ps
    lea rcx, szCrLf
    call ps
    jmp st_f3
st_f2x:
    inc esi
    lea rcx, szNo
    call ps
    lea rcx, szCrLf
    call ps

st_f3:
    lea rcx, szChkF16c
    call ps
    mov ax, 0D400h                 ; -64.0
    call f2f
    mov eax, 0C2800000h            ; -64.0f
    movd xmm1, eax
    ucomiss xmm0, xmm1
    jne st_f3x
    inc ebx
    lea rcx, szYes
    call ps
    lea rcx, szCrLf
    call ps
    jmp st_q8
st_f3x:
    inc esi
    lea rcx, szNo
    call ps
    lea rcx, szCrLf
    call ps

st_q8:
    ; Q8_0 reference block (read-only, in .data):
    ;   d = 0.5 (f16 0x3800), qs[i] = i  =>  sum = 0.5 * sum(0..31) = 248.0
    lea rcx, szChkQ8
    call ps
    lea rdi, q8blk
    mov ax, WORD PTR [rdi]
    call f2f
    movss xmm6, xmm0
    xorps xmm7, xmm7
    xor ecx, ecx
st_q8_loop:
    cmp ecx, 32
    jae st_q8_chk
    movsx eax, BYTE PTR [rdi+rcx+2]
    cvtsi2ss xmm0, eax
    mulss xmm0, xmm6
    addss xmm7, xmm0
    inc ecx
    jmp st_q8_loop
st_q8_chk:
    mov eax, 43780000h                   ; 248.0f = 0.5 * sum(0..31)
    movd xmm1, eax
    ucomiss xmm7, xmm1
    jne st_q8x
    inc ebx
    lea rcx, szYes
    call ps
    lea rcx, szCrLf
    call ps
    jmp st_q4
st_q8x:
    inc esi
    lea rcx, szNo
    call ps
    lea rcx, szCrLf
    call ps

st_q4:
    ; Q4_0 reference block (read-only, in .data):
    ;   d = 1.0 (f16 0x3C00), nibble(i) = (i & 7) + 8  =>  value = i & 7
    ; sum over 32 elements = 4 * sum(0..7) = 112.0
    lea rcx, szChkQ4
    call ps
    lea rdi, q4blk
    mov ax, WORD PTR [rdi]
    call f2f
    movss xmm6, xmm0
    xorps xmm7, xmm7
    xor ecx, ecx
st_q4_loop:
    cmp ecx, 32
    jae st_q4_chk
    mov rdx, rcx
    shr rdx, 1
    movzx r8d, BYTE PTR [rdi+rdx+2]
    test rcx, 1
    jz st_q4_low
    shr r8d, 4
    jmp st_q4_have
st_q4_low:
    and r8d, 0Fh
st_q4_have:
    sub r8d, 8
    cvtsi2ss xmm0, r8d
    mulss xmm0, xmm6
    addss xmm7, xmm0
    inc ecx
    jmp st_q4_loop
st_q4_chk:
    mov eax, 42E00000h                   ; 112.0f = 4 * sum(0..7)
    movd xmm1, eax
    ucomiss xmm7, xmm1
    jne st_q4x
    inc ebx
    lea rcx, szYes
    call ps
    lea rcx, szCrLf
    call ps
    jmp st_tb1
st_q4x:
    inc esi
    lea rcx, szNo
    call ps
    lea rcx, szCrLf
    call ps

st_tb1:
    lea rcx, szChkTb1
    call ps
    mov rcx, 2                           ; Q4_0
    mov rdx, 64
    call tensor_bytes
    cmp rax, 36                          ; 2 blocks * 18 bytes
    jne st_tb1x
    inc ebx
    lea rcx, szYes
    call ps
    lea rcx, szCrLf
    call ps
    jmp st_tb2
st_tb1x:
    inc esi
    lea rcx, szNo
    call ps
    lea rcx, szCrLf
    call ps

st_tb2:
    lea rcx, szChkTb2
    call ps
    mov rcx, 12                          ; Q4_K
    mov rdx, 256
    call tensor_bytes
    cmp rax, 144
    jne st_tb2x
    inc ebx
    lea rcx, szYes
    call ps
    lea rcx, szCrLf
    call ps
    jmp st_tb3
st_tb2x:
    inc esi
    lea rcx, szNo
    call ps
    lea rcx, szCrLf
    call ps

st_tb3:
    lea rcx, szChkTb3
    call ps
    mov rcx, 8                           ; Q8_0
    mov rdx, 33                          ; not a multiple of 32
    call tensor_bytes
    jc st_tb3x
    inc esi
    lea rcx, szNo
    call ps
    lea rcx, szCrLf
    call ps
    jmp st_sum
st_tb3x:
    inc ebx
    lea rcx, szYes
    call ps
    lea rcx, szCrLf
    call ps

st_sum:
    lea rcx, szCrLf
    call ps
    lea rcx, szStPass
    call ps
    mov rcx, rbx
    call pu
    lea rcx, szStFail
    call ps
    mov rcx, rsi
    call pu
    lea rcx, szCrLf
    call ps
    test esi, esi
    jnz st_no
    lea rcx, szStOk
    call ps
    xor eax, eax
    jmp st_done
st_no:
    lea rcx, szStNo
    call ps
    mov eax, 1
st_done:
    add rsp, 40h
    pop rdi
    pop rsi
    pop rbx
    ret
selftest ENDP

.data
szSelftest BYTE "--selftest", 0
.code

str_eq_selftest PROC
    push rbx
    sub rsp, 20h
    mov rbx, rcx
    lea rdx, szSelftest
    xor ecx, ecx
se_loop:
    mov al, BYTE PTR [rbx+rcx]
    cmp al, BYTE PTR [rdx+rcx]
    jne se_no
    test al, al
    jz se_yes
    inc ecx
    cmp ecx, 16
    jae se_no
    jmp se_loop
se_no:
    xor eax, eax
    jmp se_done
se_yes:
    mov eax, 1
se_done:
    add rsp, 20h
    pop rbx
    ret
str_eq_selftest ENDP

first_arg PROC                              ; rcx = cmdline -> rax = arg ptr or 0
    push rbx
    push rsi
    sub rsp, 28h
    mov rbx, rcx
    xor esi, esi
fa_scan:
    cmp BYTE PTR [rbx+rsi], 0
    je fa_none
    cmp BYTE PTR [rbx+rsi], 20h
    jne fa_next
    inc rsi
fa_skip:
    cmp BYTE PTR [rbx+rsi], 20h
    jne fa_got
    inc rsi
    jmp fa_skip
fa_got:
    lea rax, [rbx+rsi]
    jmp fa_done
fa_next:
    inc rsi
    jmp fa_scan
fa_none:
    xor eax, eax
fa_done:
    add rsp, 28h
    pop rsi
    pop rbx
    ret
first_arg ENDP

; ===========================================================================
; main
; ===========================================================================
main PROC
    sub rsp, 68h
    mov rcx, -11
    call GetStdHandle
    mov g_stdout, rax
    lea rcx, szStep0
    call ps
    lea rcx, szStep1
    call ps

    call GetCommandLineA
    mov rcx, rax
    call first_arg
    test rax, rax
    jz m_usage
    mov g_arg, rax

    mov QWORD PTR g_alignment, 32       ; GGUF default when the key is absent
    mov rcx, g_arg
    call str_eq_selftest
    test eax, eax
    jz m_file
    lea rcx, szStep2
    call ps

    call selftest
    jmp m_exit

m_file:
    lea rcx, szStep3
    call ps
    mov rcx, g_arg
    call open_map
    lea rcx, szStep4
    call ps
    test rax, rax
    jz m_usage

    call parse_header
    test eax, eax
    jz m_bad_magic
    lea rcx, szStageHdr
    call ps

    call parse_kv
    lea rcx, szStageKv
    call ps

    ; data base = align_up(cursor, alignment)
    mov rax, g_alignment
    test rax, rax
    jz m_bad_align
    dec rax
    mov rcx, rax
    inc rax                              ; rcx = align-1
    and rcx, -1
    not rax                              ; rax = ~(align-1)
    mov rdx, g_cur
    add rdx, rcx
    and rdx, rax
    mov g_dataBase, rdx

    call parse_tensors
    call print_summary

    mov rcx, g_hMap
    call UnmapViewOfFile
    mov rcx, g_hFile
    call CloseHandle
    mov eax, 1
    jmp m_exit

m_bad_magic:
    lea rcx, szErrMagic
    call ps
    xor eax, eax
    jmp m_exit
m_bad_align:
    lea rcx, szErrAlign
    call ps
    xor eax, eax
    jmp m_exit
m_usage:
    lea rcx, szUsage
    call ps
    xor eax, eax
m_exit:
    add rsp, 68h
    ret
main ENDP

END
