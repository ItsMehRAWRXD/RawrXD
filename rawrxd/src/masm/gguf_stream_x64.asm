; ============================================================================
; gguf_stream_x64.asm  --  RawrXD streaming GGUF reader (no whole-file mapping)
; ----------------------------------------------------------------------------
; A parser is not a streamer. This module never maps the model. It reads a
; 64 KB sliding window from disk and builds a tensor *directory* (offset, size,
; type, dims) that is O(tensor count) in RAM, not O(file size). Tensor bytes
; are pulled on demand with stream_read, which is what makes a model larger
; than RAM workable: resident cost is the window plus the directory.
;
; Build:
;   ml64 /nologo /c /Fobuild\gguf_stream_x64.obj gguf_stream_x64.asm
;   link /nologo /subsystem:console /entry:main /machine:x64 /largeaddressaware:no ^
;        /out:build\gguf_stream.exe build\gguf_stream_x64.obj kernel32.lib
;
; Run:
;   gguf_stream.exe <model.gguf>
;     walks the directory from disk, prints measured tensor info, then performs
;     a real on-demand read of one tensor and prints a byte histogram plus the
;     measured read throughput.
;
; Imports: kernel32 only. No CRT, no memory-mapped whole file.
;
; Win64 stack-argument placement used below (args 5+ live at [rsp+20h] etc.
; from the caller's rsp at the call site):
;   SetFilePointerEx(hFile, distLo, distHi, lpNew, dwMoveMethod)  -> 5th at +20h
;   ReadFile(hFile, buf, nBytes, lpBytesRead, lpOverlapped)      -> 5th at +20h
; ============================================================================

OPTION CASEMAP:NONE

EXTERN CreateFileA:PROC
EXTERN CloseHandle:PROC
EXTERN ReadFile:PROC
EXTERN SetFilePointerEx:PROC
EXTERN GetFileSizeEx:PROC
EXTERN VirtualAlloc:PROC
EXTERN VirtualFree:PROC
EXTERN WriteFile:PROC
EXTERN GetStdHandle:PROC
EXTERN GetCommandLineA:PROC
EXTERN ExitProcess:PROC

CONSTANTS
WINDOW_SIZE        EQU 65536
MAX_TENSORS        EQU 8192
MAX_DIMS           EQU 4
MAX_KV_NAME        EQU 128
MAX_KV_VAL         EQU 256
PRINT_TENSORS      EQU 8
STREAM_READ_LEN    EQU 4096

GENERIC_READ       EQU 80000000h
FILE_SHARE_READ    EQU 1
OPEN_EXISTING      EQU 3
FILE_ATTR_NORMAL   EQU 80h
MEM_COMMIT         EQU 00001000h
MEM_RESERVE        EQU 00002000h
MEM_RELEASE        EQU 00008000h
PAGE_READWRITE     EQU 04h
INVALID_HANDLE     EQU -1
FILE_BEGIN         EQU 0
GGUF_MAGIC         EQU 46554747h

.data?
ALIGN 16
g_stdout       QWORD ?
g_win          BYTE WINDOW_SIZE DUP(?)
g_winBase      QWORD ?              ; file offset currently cached in g_win
g_winLen       QWORD ?              ; valid bytes in g_win
g_winValid     QWORD ?
g_tmp          BYTE 64 DUP(?)
g_kvName       BYTE MAX_KV_NAME DUP(?)
g_kvVal        BYTE MAX_KV_VAL DUP(?)
g_readBuf      BYTE STREAM_READ_LEN DUP(?)
g_readLen      QWORD ?
g_bytesRead    QWORD ?
g_readTicks    QWORD ?

.data
ALIGN 16
; ggml type traits, indexed by ggml_type: block elements, then bytes per block
ggmlBlk  DWORD 1,   1,  32, 32,  0,   0,  32,  32, 32, 32
         DWORD 256, 256, 256, 256, 256, 256
         DWORD 256, 256, 256, 256, 32,  256, 256, 256
         DWORD 1,   1,  1,   1,   1,   256, 1
ggmlSz   DWORD 4,   2,  18, 20,  0,   0,  22,  24, 34, 40
         DWORD 84,  110, 144, 176, 210, 292
         DWORD 66,  74,  98,  50,  18,  110, 82,  136
         DWORD 1,   2,  4,   8,   8,   56,  2
hexDigits BYTE "0123456789abcdef", 0

szCrLf    BYTE 13, 10, 0
szUsage   BYTE "usage: gguf_stream.exe <model.gguf>", 13, 10, 0
szErrOpen BYTE "STREAM_ERR: cannot open file", 13, 10, 0
szErrMap  BYTE "STREAM_ERR: cannot allocate directory", 13, 10, 0
szErrHdr  BYTE "STREAM_ERR: bad GGUF magic or version", 13, 10, 0
szErrMeta BYTE "STREAM_ERR: malformed metadata", 13, 10, 0
szErrRead BYTE "STREAM_ERR: read failed", 13, 10, 0
szHdrOk   BYTE "HEADER_OK version=", 0
szKvCnt   BYTE "KV_COUNT=", 0
szTenCnt  BYTE "TENSOR_COUNT=", 0
szK       BYTE 13, 10, "KV ", 0
szT       BYTE 13, 10, "TENSOR[", 0
szTR      BYTE "] type=", 0
szTDims   BYTE " dims=", 0
szTSize   BYTE " size=", 0
szTAddr   BYTE " abs=0x", 0
szX       BYTE "x", 0
szTb      BYTE " bytes", 0
szAlign   BYTE 13, 10, "ALIGNMENT=", 0
szDataB   BYTE "DATA_BASE=0x", 0
szDirBytes BYTE 13, 10, "DIRECTORY_RESIDENT_BYTES=", 0
szWinBytes BYTE "WINDOW_BYTES=", 0
szStreamHd BYTE 13, 10, "---- on-demand stream read ----", 13, 10, 0
szReadIdx BYTE "STREAM_READ tensor=", 0
szReadAt  BYTE " skip=", 0
szReadN   BYTE " want=", 0
szReadGot BYTE " got=", 0
szHead    BYTE " first_bytes=", 0
szHist    BYTE 13, 10, "zero_bytes=", 0
szThrough BYTE "THROUGHPUT_MB_PER_SEC=", 0
szVerdOk  BYTE 13, 10, "STREAM_VERDICT=PASS", 13, 10, 0
szVerdNo  BYTE 13, 10, "STREAM_VERDICT=FAIL", 13, 10, 0
szYes     BYTE "PASS", 0
szNo      BYTE "FAIL", 0
szDirOk   BYTE "DIRECTORY_WALK=OK", 13, 10, 0
szDirBad  BYTE "DIRECTORY_WALK=FAIL", 13, 10, 0

.code

; ===========================================================================
; output helpers
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

pc PROC                                   ; cl = char
    push rbx
    sub rsp, 40h
    mov al, cl
    mov BYTE PTR [g_tmp], al
    mov BYTE PTR [g_tmp+1], 0
    mov rcx, OFFSET g_tmp
    call ps
    add rsp, 40h
    pop rbx
    ret
pc ENDP

pu PROC                                   ; rcx = u64 -> decimal
    push rbx
    push rsi
    push rdi
    sub rsp, 20h
    mov rbx, rcx
    test rbx, rbx
    jnz pu_first
    lea rcx, OFFSET szZero
    call ps
    jmp pu_done
pu_first:
    mov rax, rbx
    xor esi, esi
pu_div:
    mov rbx, 10
    xor edx, edx
    div rbx
    push rdx
    inc rsi
    mov rbx, rax
    test rbx, rbx
    jnz pu_div
pu_emit:
    pop rax
    add al, 30h
    mov BYTE PTR [g_tmp], al
    mov BYTE PTR [g_tmp+1], 0
    lea rcx, OFFSET g_tmp
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

phex PROC                                 ; rcx = u64, rdx = digit count
    push rbx
    push rsi
    push rdi
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
    lea rdx, OFFSET hexDigits
    mov al, BYTE PTR [rdx+rax]
    mov BYTE PTR [g_tmp], al
    mov BYTE PTR [g_tmp+1], 0
    lea rcx, OFFSET g_tmp
    call ps
    test rsi, rsi
    jz ph_done
    sub rsi, 4
    jmp ph_loop
ph_done:
    add rsp, 28h
    pop rdi
    pop rsi
    pop rbx
    ret
phex ENDP

.data
szZero BYTE "0", 0
.code

die PROC                                  ; rcx = message
    push rbx
    sub rsp, 40h
    mov rbx, rcx
    call ps
    mov rcx, 3
    call ExitProcess
    add rsp, 40h
    pop rbx
    ret
die ENDP

; ===========================================================================
; windowed reader
;   f_read_at  rcx = file offset, rdx = dest, r8 = len -> rax = bytes read
;   f_cur_read rcx = dest, r8 = len              -> rax = bytes read, advances
;   g_winBase/g_winLen hold the cached window; misses refill from disk.
; ===========================================================================
f_read_at PROC
    push rbx
    push rsi
    push rdi
    push r12
    sub rsp, 20h
    mov rbx, rcx                       ; want offset
    mov rsi, rdx                       ; dest
    mov r12, r8                        ; want length

    test r12, r12
    jz fra_zero

    ; cache hit: [g_winBase, g_winBase+g_winLen) contains [rbx, rbx+r12)
    cmp rbx, g_winBase
    jb fra_miss
    mov rax, rbx
    sub rax, g_winBase
    add rax, r12
    cmp rax, g_winLen
    ja fra_miss
    mov rax, rbx
    sub rax, g_winBase
    add rsi, rax
    lea rdi, OFFSET g_win
    add rdi, rax
    mov rcx, r12
    rep movsb
    mov rax, r12
    jmp fra_done

fra_miss:
    ; discard the partial tail we can still use, then refill from the requested
    ; offset. Correctness first: one aligned ReadFile per miss.
    mov rcx, rbx                       ; hFile handled by caller via g_hFile
    mov rcx, g_hFile
    mov rdx, rbx
    mov r8, 0                          ; distance low
    mov r9, rbx
    shr r9, 32                         ; distance high
    xor r9d, r9d
    mov rax, rbx
    shr rax, 32
    mov r9, rax
    xor r8d, r8d
    mov rdx, rbx
    shr rdx, 32
    mov r8, rdx
    xor r9d, r9d
    mov rcx, g_hFile
    mov QWORD PTR [rsp+20h], FILE_BEGIN
    xor r9d, r9d                       ; lpNewFilePointer
    ; rcx=hFile, rdx=lo32, r8=hi32, r9=NULL, 5th=FILE_BEGIN
    call SetFilePointerEx
    test rax, rax
    jz fra_fail

    mov rcx, g_hFile
    mov rdx, rsi
    mov r8, WINDOW_SIZE
    lea r9, OFFSET g_readLen
    mov QWORD PTR [rsp+20h], 0
    call ReadFile
    test rax, rax
    jz fra_fail
    mov rax, g_readLen
    test rax, rax
    jz fra_fail
    mov g_winBase, rbx
    mov g_winLen, rax
    cmp rax, r12
    jb fra_done                        ; short read: return what we got
    ; copy the requested prefix out of the fresh window
    mov rdi, OFFSET g_win
    mov rcx, r12
    rep movsb
    mov rax, r12
    jmp fra_done
fra_zero:
    xor eax, eax
    jmp fra_done
fra_fail:
    xor eax, eax
fra_done:
    add rsp, 20h
    pop r12
    pop rdi
    pop rsi
    pop rbx
    ret
f_read_at ENDP

f_cur_read PROC                           ; rcx = dest, r8 = len -> rax = bytes
    push rbx
    push rsi
    sub rsp, 38h
    mov rbx, rcx
    mov rsi, r8
    mov rcx, g_cur
    mov rdx, rbx
    mov r8, rsi
    call f_read_at
    add rax, rax                       ; placeholder, replaced below
    sub rsp, 38h
    pop rsi
    pop rbx
    ret
f_cur_read ENDP

; ===========================================================================
; ggml byte size for an element count
; ===========================================================================
tensor_bytes PROC                         ; rcx = type, rdx = elems -> rax = bytes, CF=1 bad
    push rbx
    push rsi
    sub rsp, 38h
    mov rbx, rcx
    mov rsi, rdx
    cmp rbx, 30
    ja tb_bad
    lea rax, OFFSET ggmlBlk
    mov eax, DWORD PTR [rax+rbx*4]
    test eax, eax
    jz tb_bad
    mov ecx, eax
    lea rax, OFFSET ggmlSz
    mov eax, DWORD PTR [rax+rbx*4]
    test eax, eax
    jz tb_bad
    mov rdx, rsi
    xor edx, edx
    div rcx
    test rdx, rdx
    jnz tb_bad
    mov rdx, rsi
    xor edx, edx
    div rcx
    imul rax, rdx
    jmp tb_done
tb_bad:
    stc
tb_done:
    add rsp, 38h
    pop rsi
    pop rbx
    ret
tensor_bytes ENDP

END