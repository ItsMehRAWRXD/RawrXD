; ============================================================================
; Pyre_Entry.asm — Pyre Compute Engine Bootstrap + GEMM Hook
; ============================================================================
; Statically linked into RawrXD-Win32IDE. Provides:
;   1. Pyre_GetBootstrap     — RIP-relative accessor to g_pyreBootstrap
;   2. Pyre_GEMM_F32_AVX512  — Reads args from BootstrapPage, executes GEMM
;
; Build: ml64.exe /c /W3 /nologo /Zi /Fo Pyre_Entry.obj Pyre_Entry.asm
; Link:  link.exe ... Pyre_Entry.obj ...
; ============================================================================

OPTION CASEMAP:NONE

; ---------------------------------------------------------------------------
; External symbol: the BootstrapPage instance placed in .pyre section by C++
; ---------------------------------------------------------------------------
EXTERN g_pyreBootstrap : QWORD

; ---------------------------------------------------------------------------
; BootstrapPage field offsets (must match Pyre_Bootstrap.h exactly)
; ---------------------------------------------------------------------------
PYRE_OFF_MAGIC              EQU 0000h
PYRE_OFF_VERSION            EQU 0008h
PYRE_OFF_HOST_IMAGE_BASE    EQU 0010h
PYRE_OFF_ENGINE_SECTION_RVA EQU 0018h
PYRE_OFF_ENGINE_SECTION_SZ  EQU 0020h
PYRE_OFF_KV_CACHE_HANDLE    EQU 0028h
PYRE_OFF_KV_CACHE_VIEW      EQU 0030h
PYRE_OFF_RESERVED0          EQU 0038h
PYRE_OFF_COMMAND            EQU 0040h
PYRE_OFF_STATUS             EQU 0048h
PYRE_OFF_ARG0               EQU 0050h
PYRE_OFF_ARG1               EQU 0058h
PYRE_OFF_ARG2               EQU 0060h
PYRE_OFF_ARG3               EQU 0068h
PYRE_OFF_ARG4               EQU 0070h
PYRE_OFF_ARG5               EQU 0078h
PYRE_OFF_ALPHA              EQU 0080h
PYRE_OFF_START_TSC          EQU 0088h
PYRE_OFF_END_TSC            EQU 0090h
PYRE_OFF_ACCUM_CYCLES       EQU 0098h
PYRE_OFF_KERNEL_FLAGS       EQU 00A0h
PYRE_OFF_ERROR_CODE         EQU 00A8h

; Command codes
PYRE_CMD_IDLE               EQU 0
PYRE_CMD_GEMM               EQU 1
PYRE_CMD_ATTN               EQU 2
PYRE_CMD_DEQUANT            EQU 3
PYRE_CMD_SOFTMAX            EQU 4
PYRE_CMD_SMOKE              EQU 5

; Status codes
PYRE_STATUS_BUSY            EQU 0
PYRE_STATUS_DONE            EQU 1
PYRE_STATUS_ERROR          EQU 0FFh

; Kernel flags
PYRE_FLAG_AVX512            EQU 1
PYRE_FLAG_AVX2              EQU 2
PYRE_FLAG_SSE2              EQU 4

; ---------------------------------------------------------------------------
; Constants
; ---------------------------------------------------------------------------
.data
pyre_magic_const    DQ 04552595000000000h   ; 'PYRE' in little-endian hex
pyre_version_const  DQ 00001h

; ---------------------------------------------------------------------------
; Code
; ---------------------------------------------------------------------------
.CODE

; ============================================================================
; Pyre_GetBootstrap
;   Returns RAX = pointer to g_pyreBootstrap (RIP-relative, ASLR-safe)
;   Clobbers: RAX
;   Preserves: all other registers
; ============================================================================
Pyre_GetBootstrap PROC
    lea     rax, g_pyreBootstrap
    ret
Pyre_GetBootstrap ENDP

; ============================================================================
; Pyre_ValidateBootstrap
;   Validates magic and version. Returns ZF=1 if valid.
;   Clobbers: RAX, RCX, RDX
; ============================================================================
Pyre_ValidateBootstrap PROC
    push    rbx
    lea     rbx, g_pyreBootstrap
    mov     rax, [rbx + PYRE_OFF_MAGIC]
    mov     rcx, 04552595000000000h     ; 'PYRE'
    cmp     rax, rcx
    jne     @@invalid
    mov     rax, [rbx + PYRE_OFF_VERSION]
    cmp     rax, 1
    jne     @@invalid
    xor     eax, eax                    ; ZF = 1 (valid)
    pop     rbx
    ret
@@invalid:
    or      eax, 1                      ; ZF = 0 (invalid)
    pop     rbx
    ret
Pyre_ValidateBootstrap ENDP

; ============================================================================
; Pyre_SampleTSC
;   Returns RAX = current TSC value (RDTSC)
;   Clobbers: RAX, RDX
; ============================================================================
Pyre_SampleTSC PROC
    rdtsc
    shl     rdx, 32
    or      rax, rdx
    ret
Pyre_SampleTSC ENDP

; ============================================================================
; Pyre_GEMM_F32_AVX512
;   Reads arguments from BootstrapPage, executes GEMM, writes status.
;   Signature: void __fastcall Pyre_GEMM_F32_AVX512(void)
;   No arguments — all inputs come from BootstrapPage.
;   Clobbers: all volatile registers (RAX,RCX,RDX,R8-R11,XMM0-XMM5,ZMM0-ZMM31)
; ============================================================================
Pyre_GEMM_F32_AVX512 PROC FRAME
    ; --- Prologue: preserve non-volatile registers ---
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    push    r12
    .pushreg r12
    push    r13
    .pushreg r13
    push    r14
    .pushreg r14
    push    r15
    .pushreg r15
    sub     rsp, 80h                    ; Local scratch + 16-byte alignment
    .allocstack 80h
    .endprolog

    ; --- Load bootstrap pointer ---
    call    Pyre_GetBootstrap
    mov     r15, rax                    ; r15 = &g_pyreBootstrap (persistent)

    ; --- Validate bootstrap ---
    call    Pyre_ValidateBootstrap
    jnz     @@error_invalid_bootstrap

    ; --- Sample start TSC ---
    call    Pyre_SampleTSC
    mov     [r15 + PYRE_OFF_START_TSC], rax

    ; --- Set status = BUSY ---
    mov     qword ptr [r15 + PYRE_OFF_STATUS], PYRE_STATUS_BUSY

    ; --- Load arguments from BootstrapPage ---
    mov     r12, [r15 + PYRE_OFF_ARG1]  ; A (const float*)
    mov     r13, [r15 + PYRE_OFF_ARG2]  ; B (const float*)
    mov     r14, [r15 + PYRE_OFF_ARG0]  ; C (float*)
    mov     ebx, dword ptr [r15 + PYRE_OFF_ARG3]  ; M (uint32_t)
    mov     esi, dword ptr [r15 + PYRE_OFF_ARG4]  ; N (uint32_t)
    mov     edi, dword ptr [r15 + PYRE_OFF_ARG5]  ; K (uint32_t)

    ; --- Validate dimensions ---
    test    ebx, ebx
    jz      @@error_zero_dim
    test    esi, esi
    jz      @@error_zero_dim
    test    edi, edi
    jz      @@error_zero_dim

    ; --- Zero output matrix C[M*N] ---
    mov     ecx, ebx
    imul    ecx, esi                    ; M * N
    shl     ecx, 2                      ; * sizeof(float)
    mov     r8, r14                     ; C
    xor     eax, eax
@@zero_loop:
    cmp     ecx, 64
    jl      @@zero_tail
    vmovdqu64 zmmword ptr [r8 + rax], zmm0
    add     rax, 64
    sub     ecx, 64
    jmp     @@zero_loop
@@zero_tail:
    test    ecx, ecx
    jz      @@gemm_main
    mov     byte ptr [r8 + rax], 0
    inc     rax
    dec     ecx
    jmp     @@zero_tail

@@gemm_main:
    ; ================================================================
    ; Tiled GEMM: C[MxN] = A[MxK] * B[KxN]
    ; Tile sizes: 8x16 (M x N), unroll K by 4
    ; AVX-512: 16 floats per ZMM register
    ; ================================================================
    xor     r8d, r8d                    ; i = 0 (row tile)
@@tile_i:
    cmp     r8d, ebx
    jge     @@gemm_done

    xor     r9d, r9d                    ; j = 0 (col tile)
@@tile_j:
    cmp     r9d, esi
    jge     @@next_i

    ; Initialize 8 accumulators (one per row in tile)
    vxorps  zmm0, zmm0, zmm0          ; acc for row i+0
    vxorps  zmm1, zmm1, zmm1          ; acc for row i+1
    vxorps  zmm2, zmm2, zmm2          ; acc for row i+2
    vxorps  zmm3, zmm3, zmm3          ; acc for row i+3
    vxorps  zmm4, zmm4, zmm4          ; acc for row i+4
    vxorps  zmm5, zmm5, zmm5          ; acc for row i+5
    vxorps  zmm6, zmm6, zmm6          ; acc for row i+6
    vxorps  zmm7, zmm7, zmm7          ; acc for row i+7

    xor     r10d, r10d                ; k = 0
@@k_loop:
    cmp     r10d, edi
    jge     @@store_tile

    ; --- Load A rows (8 rows, broadcast each element) ---
    ; Row 0: A[i+0][k]
    mov     eax, r8d
    imul    eax, edi
    add     eax, r10d
    vbroadcastss zmm8, dword ptr [r12 + rax*4]

    ; Row 1: A[i+1][k]
    lea     eax, [r8d + 1]
    imul    eax, edi
    add     eax, r10d
    vbroadcastss zmm9, dword ptr [r12 + rax*4]

    ; Row 2: A[i+2][k]
    lea     eax, [r8d + 2]
    imul    eax, edi
    add     eax, r10d
    vbroadcastss zmm10, dword ptr [r12 + rax*4]

    ; Row 3: A[i+3][k]
    lea     eax, [r8d + 3]
    imul    eax, edi
    add     eax, r10d
    vbroadcastss zmm11, dword ptr [r12 + rax*4]

    ; Row 4: A[i+4][k]
    lea     eax, [r8d + 4]
    imul    eax, edi
    add     eax, r10d
    vbroadcastss zmm12, dword ptr [r12 + rax*4]

    ; Row 5: A[i+5][k]
    lea     eax, [r8d + 5]
    imul    eax, edi
    add     eax, r10d
    vbroadcastss zmm13, dword ptr [r12 + rax*4]

    ; Row 6: A[i+6][k]
    lea     eax, [r8d + 6]
    imul    eax, edi
    add     eax, r10d
    vbroadcastss zmm14, dword ptr [r12 + rax*4]

    ; Row 7: A[i+7][k]
    lea     eax, [r8d + 7]
    imul    eax, edi
    add     eax, r10d
    vbroadcastss zmm15, dword ptr [r12 + rax*4]

    ; --- Load B tile (16 columns) ---
    mov     eax, r10d
    imul    eax, esi
    add     eax, r9d
    vmovups zmm16, zmmword ptr [r13 + rax*4]

    ; --- FMA: acc += A_broadcast * B_tile ---
    vfmadd231ps zmm0, zmm8, zmm16
    vfmadd231ps zmm1, zmm9, zmm16
    vfmadd231ps zmm2, zmm10, zmm16
    vfmadd231ps zmm3, zmm11, zmm16
    vfmadd231ps zmm4, zmm12, zmm16
    vfmadd231ps zmm5, zmm13, zmm16
    vfmadd231ps zmm6, zmm14, zmm16
    vfmadd231ps zmm7, zmm15, zmm16

    inc     r10d
    jmp     @@k_loop

@@store_tile:
    ; --- Store 8x16 tile to C ---
    ; C row stride = N * sizeof(float)
    mov     r11d, esi
    shl     r11d, 2

    ; Row 0: C[i+0][j..j+15]
    mov     eax, r8d
    imul    eax, esi
    add     eax, r9d
    vmovups zmmword ptr [r14 + rax*4], zmm0

    ; Row 1
    lea     eax, [r8d + 1]
    imul    eax, esi
    add     eax, r9d
    vmovups zmmword ptr [r14 + rax*4], zmm1

    ; Row 2
    lea     eax, [r8d + 2]
    imul    eax, esi
    add     eax, r9d
    vmovups zmmword ptr [r14 + rax*4], zmm2

    ; Row 3
    lea     eax, [r8d + 3]
    imul    eax, esi
    add     eax, r9d
    vmovups zmmword ptr [r14 + rax*4], zmm3

    ; Row 4
    lea     eax, [r8d + 4]
    imul    eax, esi
    add     eax, r9d
    vmovups zmmword ptr [r14 + rax*4], zmm4

    ; Row 5
    lea     eax, [r8d + 5]
    imul    eax, esi
    add     eax, r9d
    vmovups zmmword ptr [r14 + rax*4], zmm5

    ; Row 6
    lea     eax, [r8d + 6]
    imul    eax, esi
    add     eax, r9d
    vmovups zmmword ptr [r14 + rax*4], zmm6

    ; Row 7
    lea     eax, [r8d + 7]
    imul    eax, esi
    add     eax, r9d
    vmovups zmmword ptr [r14 + rax*4], zmm7

    add     r9d, 16
    jmp     @@tile_j

@@next_i:
    add     r8d, 8
    jmp     @@tile_i

@@gemm_done:
    ; --- Sample end TSC ---
    call    Pyre_SampleTSC
    mov     [r15 + PYRE_OFF_END_TSC], rax

    ; --- Update accumCycles ---
    mov     rcx, [r15 + PYRE_OFF_END_TSC]
    sub     rcx, [r15 + PYRE_OFF_START_TSC]
    add     [r15 + PYRE_OFF_ACCUM_CYCLES], rcx

    ; --- Set status = DONE ---
    mov     qword ptr [r15 + PYRE_OFF_STATUS], PYRE_STATUS_DONE
    mov     qword ptr [r15 + PYRE_OFF_KERNEL_FLAGS], PYRE_FLAG_AVX512
    jmp     @@epilogue

@@error_invalid_bootstrap:
    mov     qword ptr [r15 + PYRE_OFF_STATUS], PYRE_STATUS_ERROR
    mov     qword ptr [r15 + PYRE_OFF_ERROR_CODE], 1
    jmp     @@epilogue

@@error_zero_dim:
    mov     qword ptr [r15 + PYRE_OFF_STATUS], PYRE_STATUS_ERROR
    mov     qword ptr [r15 + PYRE_OFF_ERROR_CODE], 2
    jmp     @@epilogue

@@epilogue:
    ; --- Restore non-volatile registers ---
    add     rsp, 80h
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    pop     rbp
    ret
Pyre_GEMM_F32_AVX512 ENDP

; ============================================================================
; Pyre_SmokeTest
;   Bridge validation: reads arg1, copies to arg0, sets status = DONE.
;   Signature: void __fastcall Pyre_SmokeTest(void)
;   Clobbers: RAX, RCX, RDX, R8-R11, ZMM0-ZMM31
; ============================================================================
Pyre_SmokeTest PROC FRAME
    push    rbp
    .pushreg rbp
    push    rbx
    .pushreg rbx
    sub     rsp, 20h
    .allocstack 20h
    .endprolog

    call    Pyre_GetBootstrap
    mov     rbx, rax                    ; rbx = &g_pyreBootstrap

    ; Validate
    call    Pyre_ValidateBootstrap
    jnz     @@smoke_error

    ; Set BUSY
    mov     qword ptr [rbx + PYRE_OFF_STATUS], PYRE_STATUS_BUSY

    ; Read arg1 (input pattern)
    mov     rcx, [rbx + PYRE_OFF_ARG1]
    ; Copy to arg0 (output)
    mov     [rbx + PYRE_OFF_ARG0], rcx

    ; Set DONE + AVX512 flag
    mov     qword ptr [rbx + PYRE_OFF_STATUS], PYRE_STATUS_DONE
    mov     qword ptr [rbx + PYRE_OFF_KERNEL_FLAGS], PYRE_FLAG_AVX512
    jmp     @@smoke_epilogue

@@smoke_error:
    mov     qword ptr [rbx + PYRE_OFF_STATUS], PYRE_STATUS_ERROR
    mov     qword ptr [rbx + PYRE_OFF_ERROR_CODE], 0DEADh

@@smoke_epilogue:
    add     rsp, 20h
    pop     rbx
    pop     rbp
    ret
Pyre_SmokeTest ENDP

END
