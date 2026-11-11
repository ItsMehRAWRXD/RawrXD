; ============================================================================
; VwaRangeX64.asm
;
; RawrXD RMV -> physical quant-block range core
;
; x64 MASM
; no CRT
; no C++ runtime
; no STL
; no GGUF parsing
; no tensor name lookup
; no mount API
;
; Only Win32 file APIs are imported for real physical fulfillment.
;
; ABI: Microsoft x64
; ============================================================================

OPTION CASEMAP:NONE

; ---------------------------------------------------------------------------
; Win32
; ---------------------------------------------------------------------------
EXTERN SetFilePointerEx : PROC
EXTERN ReadFile         : PROC
EXTERN GetLastError     : PROC

; ---------------------------------------------------------------------------
; Exported routines
; ---------------------------------------------------------------------------
PUBLIC VwaResolveBlocks
PUBLIC VwaFulfillExactSync

; ===========================================================================
; Status
; ===========================================================================
VWA_OK                 EQU 0
VWA_E_NULL             EQU 1
VWA_E_NOT_FILE_BACKED  EQU 2
VWA_E_BAD_GEOMETRY     EQU 3
VWA_E_EMPTY_REQUEST    EQU 4
VWA_E_INTEGER_OVERFLOW EQU 5
VWA_E_OUT_OF_RANGE     EQU 6
VWA_E_BUFFER_TOO_SMALL EQU 7
VWA_E_SEEK_FAILED      EQU 8
VWA_E_READ_FAILED      EQU 9
VWA_E_SHORT_READ       EQU 10
VWA_E_BAD_HANDLE       EQU 11

VWA_PHYS_FILE_BACKED   EQU 00000001h
VWA_READ_CHUNK_MAX     EQU 7FFFF000h

; ===========================================================================
; VwaMountedPhysical
; ===========================================================================
VMP_DATA_ABS           EQU 0
VMP_TENSOR_BYTES       EQU 8
VMP_BLOCK_BYTES        EQU 16
VMP_FLAGS              EQU 20
VMP_SHARD_ID           EQU 24
VMP_GENERATION         EQU 32

; ===========================================================================
; VwaBlockRange
; ===========================================================================
VBR_FIRST_BLOCK        EQU 0
VBR_BLOCK_COUNT        EQU 8

; ===========================================================================
; VwaPhysicalRange
; ===========================================================================
VPR_ABS_FILE_OFFSET    EQU 0
VPR_BYTE_COUNT         EQU 8
VPR_TENSOR_REL_OFFSET  EQU 16
VPR_FIRST_BLOCK        EQU 24
VPR_BLOCK_COUNT        EQU 32
VPR_GENERATION         EQU 40
VPR_SHARD_ID           EQU 48
VPR_FLAGS              EQU 52

; ===========================================================================
; VwaIoBuffer
; ===========================================================================
VIO_DATA               EQU 0
VIO_CAPACITY           EQU 8
VIO_BYTES_WRITTEN      EQU 16
VIO_WIN32_ERROR        EQU 24
VIO_RESERVED0          EQU 28

_TEXT SEGMENT

; ===========================================================================
; unsigned long
; VwaResolveBlocks(
;     const VwaMountedPhysical* mounted,  ; RCX
;     const VwaBlockRange* requested,     ; RDX
;     VwaPhysicalRange* resolved);        ; R8
;
; Exact law:
;   rel = firstBlock * blockBytes
;   len = blockCount * blockBytes
;   rel + len <= tensorByteSize
;   abs = dataAbsOffset + rel
;
; No rounded byte slices.
; No reading beyond tensor payload.
; Every arithmetic operation is overflow checked.
; ===========================================================================
VwaResolveBlocks PROC
    test    rcx, rcx
    jz      VRB_Null
    test    rdx, rdx
    jz      VRB_Null
    test    r8, r8
    jz      VRB_Null

    mov     r9,  rdx
    mov     r10, r8

    ; Clear complete output. Failed resolve cannot leak stale range.
    xor     eax, eax
    mov     qword ptr [r10 + 0],  rax
    mov     qword ptr [r10 + 8],  rax
    mov     qword ptr [r10 + 16], rax
    mov     qword ptr [r10 + 24], rax
    mov     qword ptr [r10 + 32], rax
    mov     qword ptr [r10 + 40], rax
    mov     qword ptr [r10 + 48], rax

    test    dword ptr [rcx + VMP_FLAGS], VWA_PHYS_FILE_BACKED
    jz      VRB_NotFileBacked

    mov     r8d, dword ptr [rcx + VMP_BLOCK_BYTES]
    test    r8d, r8d
    jz      VRB_BadGeometry

    cmp     qword ptr [r9 + VBR_BLOCK_COUNT], 0
    je      VRB_EmptyRequest

    ; relOffset = firstBlock * blockBytes
    mov     rax, qword ptr [r9 + VBR_FIRST_BLOCK]
    mul     r8
    test    rdx, rdx
    jnz     VRB_Overflow
    mov     r11, rax

    ; byteCount = blockCount * blockBytes
    mov     rax, qword ptr [r9 + VBR_BLOCK_COUNT]
    mul     r8
    test    rdx, rdx
    jnz     VRB_Overflow
    mov     r8, rax
    test    r8, r8
    jz      VRB_Overflow

    ; endRelative = relOffset + byteCount
    mov     rdx, r11
    add     rdx, r8
    jc      VRB_Overflow

    ; Entire request must fit inside tensor payload.
    cmp     rdx, qword ptr [rcx + VMP_TENSOR_BYTES]
    ja      VRB_OutOfRange

    ; absoluteFileOffset = tensorDataAbsolute + relOffset
    mov     rdx, qword ptr [rcx + VMP_DATA_ABS]
    add     rdx, r11
    jc      VRB_Overflow

    ; Prove absolute end cannot wrap.
    mov     rax, rdx
    add     rax, r8
    jc      VRB_Overflow

    ; Commit resolved record only after validation succeeds.
    mov     qword ptr [r10 + VPR_ABS_FILE_OFFSET],   rdx
    mov     qword ptr [r10 + VPR_BYTE_COUNT],        r8
    mov     qword ptr [r10 + VPR_TENSOR_REL_OFFSET], r11
    mov     rax, qword ptr [r9 + VBR_FIRST_BLOCK]
    mov     qword ptr [r10 + VPR_FIRST_BLOCK], rax
    mov     rax, qword ptr [r9 + VBR_BLOCK_COUNT]
    mov     qword ptr [r10 + VPR_BLOCK_COUNT], rax
    mov     rax, qword ptr [rcx + VMP_GENERATION]
    mov     qword ptr [r10 + VPR_GENERATION], rax
    mov     eax, dword ptr [rcx + VMP_SHARD_ID]
    mov     dword ptr [r10 + VPR_SHARD_ID], eax
    mov     eax, dword ptr [rcx + VMP_FLAGS]
    mov     dword ptr [r10 + VPR_FLAGS], eax

    mov     eax, VWA_OK
    ret

VRB_Null:
    mov     eax, VWA_E_NULL
    ret
VRB_NotFileBacked:
    mov     eax, VWA_E_NOT_FILE_BACKED
    ret
VRB_BadGeometry:
    mov     eax, VWA_E_BAD_GEOMETRY
    ret
VRB_EmptyRequest:
    mov     eax, VWA_E_EMPTY_REQUEST
    ret
VRB_Overflow:
    mov     eax, VWA_E_INTEGER_OVERFLOW
    ret
VRB_OutOfRange:
    mov     eax, VWA_E_OUT_OF_RANGE
    ret
VwaResolveBlocks ENDP


; ===========================================================================
; unsigned long
; VwaFulfillExactSync(
;     void* shardHandle,                  ; RCX
;     const VwaPhysicalRange* range,      ; RDX
;     VwaIoBuffer* destination);          ; R8
;
; REAL fulfillment:
;   1. Uses an ALREADY OPEN shard HANDLE.
;   2. Seeks to the resolved absolute physical offset.
;   3. Reads EXACTLY range.byteCount bytes.
;   4. Supports >DWORD ranges via exact chunking.
;   5. Rejects short read.
;   6. Never opens a path.
;   7. Never discovers a tensor.
;
; IMPORTANT:
; SetFilePointerEx changes the handle's shared file position.
; This direct synchronous path requires a dedicated handle or caller-side
; serialization. Production VWA async should feed VwaPhysicalRange into the
; existing IOCP path where absolute offsets remain explicit.
; ===========================================================================
VwaFulfillExactSync PROC
    test    rcx, rcx
    jz      VFE_BadHandleFast
    cmp     rcx, -1
    je      VFE_BadHandleFast
    test    rdx, rdx
    jz      VFE_NullFast
    test    r8, r8
    jz      VFE_NullFast

    ; Win64 ABI:
    ; entry RSP is 8 mod 16.
    ; Five pushes = 40 bytes -> aligned.
    ; 64 local bytes include 32 bytes shadow space.
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    sub     rsp, 64

    mov     rbx, rcx        ; HANDLE
    mov     rsi, rdx        ; VwaPhysicalRange*
    mov     rdi, r8         ; VwaIoBuffer*

    xor     eax, eax
    mov     qword ptr [rdi + VIO_BYTES_WRITTEN], rax
    mov     dword ptr [rdi + VIO_WIN32_ERROR],   eax
    mov     dword ptr [rdi + VIO_RESERVED0],     eax

    mov     r12, qword ptr [rdi + VIO_DATA]
    test    r12, r12
    jz      VFE_Null

    mov     r13, qword ptr [rsi + VPR_BYTE_COUNT]
    test    r13, r13
    jz      VFE_EmptyRequest

    cmp     qword ptr [rdi + VIO_CAPACITY], r13
    jb      VFE_BufferTooSmall

    ; BOOL SetFilePointerEx(HANDLE, LARGE_INTEGER, LARGE_INTEGER*, DWORD)
    mov     rcx, rbx
    mov     rdx, qword ptr [rsi + VPR_ABS_FILE_OFFSET]
    xor     r8d, r8d
    xor     r9d, r9d
    call    SetFilePointerEx
    test    eax, eax
    jz      VFE_SeekFailed

VFE_ReadLoop:
    test    r13, r13
    jz      VFE_Success

    mov     rax, r13
    cmp     rax, VWA_READ_CHUNK_MAX
    jbe     VFE_UseRemaining
    mov     r8d, VWA_READ_CHUNK_MAX
    jmp     VFE_HaveChunk

VFE_UseRemaining:
    mov     r8d, eax

VFE_HaveChunk:
    ; ReadFile(HANDLE, buffer, DWORD bytes, DWORD* read, OVERLAPPED* null)
    mov     rcx, rbx
    mov     rdx, r12
    lea     r9, qword ptr [rsp + 40]
    mov     dword ptr [rsp + 40], 0
    mov     qword ptr [rsp + 32], 0
    call    ReadFile
    test    eax, eax
    jz      VFE_ReadFailed

    mov     eax, dword ptr [rsp + 40]
    test    eax, eax
    jz      VFE_ShortRead

    mov     edx, eax
    cmp     rdx, r13
    ja      VFE_ShortRead

    add     r12, rdx
    sub     r13, rdx
    add     qword ptr [rdi + VIO_BYTES_WRITTEN], rdx
    jmp     VFE_ReadLoop

VFE_Success:
    mov     eax, VWA_OK
    jmp     VFE_Return

VFE_SeekFailed:
    call    GetLastError
    mov     dword ptr [rdi + VIO_WIN32_ERROR], eax
    mov     eax, VWA_E_SEEK_FAILED
    jmp     VFE_Return

VFE_ReadFailed:
    call    GetLastError
    mov     dword ptr [rdi + VIO_WIN32_ERROR], eax
    mov     eax, VWA_E_READ_FAILED
    jmp     VFE_Return

VFE_ShortRead:
    mov     eax, VWA_E_SHORT_READ
    jmp     VFE_Return

VFE_BufferTooSmall:
    mov     eax, VWA_E_BUFFER_TOO_SMALL
    jmp     VFE_Return

VFE_EmptyRequest:
    mov     eax, VWA_E_EMPTY_REQUEST
    jmp     VFE_Return

VFE_Null:
    mov     eax, VWA_E_NULL

VFE_Return:
    add     rsp, 64
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret

VFE_BadHandleFast:
    mov     eax, VWA_E_BAD_HANDLE
    ret

VFE_NullFast:
    mov     eax, VWA_E_NULL
    ret

VwaFulfillExactSync ENDP

_TEXT ENDS
END
