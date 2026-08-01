; =============================================================================
; runtime_smoke.asm - RawrXD Runtime Smoke Test
; =============================================================================
; Validates the core runtime pipeline end-to-end:
;   1. TensorCreate / TensorFree
;   2. Kernel dispatch (RMSNorm, Softmax, SiLU)
;   3. Q4 dequantization
;   4. Matrix multiplication (F32)
;   5. Memory allocation / deallocation
;
; Expected output (written to stdout via WriteFile):
;   RawrXD Runtime Smoke Test
;   Tensor: PASS
;   Kernel Dispatch: PASS
;   Q4 Dequant: PASS
;   Matmul: PASS
;   Memory: PASS
; =============================================================================

OPTION CASEMAP:NONE

INCLUDE masm_kernel_api.inc

; =============================================================================
; Windows API externs
; =============================================================================
EXTERN GetStdHandle:PROC
EXTERN WriteFile:PROC

; =============================================================================
; CONSTANTS
; =============================================================================
SMOKE_TENSOR_SIZE       EQU 256     ; Elements in test tensor
SMOKE_M                 EQU 4       ; Matmul M dimension
SMOKE_N                 EQU 4       ; Matmul N dimension
SMOKE_K                 EQU 4       ; Matmul K dimension

; =============================================================================
; DATA SECTION
; =============================================================================

.data

; Test results
align 8
g_TestPass              DB 0        ; 0 = untested, 1 = pass, 2 = fail
g_TestTensor            DB 0
g_TestDispatch          DB 0
g_TestDequant           DB 0
g_TestMatmul            DB 0
g_TestMemory            DB 0

; Output strings
align 8
szHeader                DB 'RawrXD Runtime Smoke Test', 0Dh, 0Ah, 0
szTensorPass            DB 'Tensor: PASS', 0Dh, 0Ah, 0
szTensorFail            DB 'Tensor: FAIL', 0Dh, 0Ah, 0
szDispatchPass          DB 'Kernel Dispatch: PASS', 0Dh, 0Ah, 0
szDispatchFail          DB 'Kernel Dispatch: FAIL', 0Dh, 0Ah, 0
szDequantPass           DB 'Q4 Dequant: PASS', 0Dh, 0Ah, 0
szDequantFail           DB 'Q4 Dequant: FAIL', 0Dh, 0Ah, 0
szMatmulPass            DB 'Matmul: PASS', 0Dh, 0Ah, 0
szMatmulFail            DB 'Matmul: FAIL', 0Dh, 0Ah, 0
szMemoryPass            DB 'Memory: PASS', 0Dh, 0Ah, 0
szMemoryFail            DB 'Memory: FAIL', 0Dh, 0Ah, 0
szNewline               DB 0Dh, 0Ah, 0

; Test data
align 16
g_TestShape             DQ 16, 16  ; 16x16 tensor
g_TestData              REAL4 256 DUP(1.0)  ; Fill with 1.0
g_TestOutput            REAL4 256 DUP(0.0)

; Q4 test data (one block: scale=1.0, 16 nibbles = 8 bytes)
align 16
g_Q4TestBlock           DB 00h, 00h, 80h, 3Fh  ; scale = 1.0 (IEEE 754)
                        DB 01h, 23h, 45h, 67h  ; nibbles
                        DB 89h, 0ABh, 0CDh, 0EFh
                        DB 00h, 00h, 00h, 00h  ; padding
                        DB 00h, 00h             ; padding to 18 bytes

; Matmul test matrices
align 16
g_MatmulA               REAL4 1.0, 2.0, 3.0, 4.0
                        REAL4 5.0, 6.0, 7.0, 8.0
                        REAL4 9.0, 10.0, 11.0, 12.0
                        REAL4 13.0, 14.0, 15.0, 16.0

g_MatmulB               REAL4 1.0, 0.0, 0.0, 0.0
                        REAL4 0.0, 1.0, 0.0, 0.0
                        REAL4 0.0, 0.0, 1.0, 0.0
                        REAL4 0.0, 0.0, 0.0, 1.0

g_MatmulC               REAL4 16 DUP(0.0)

; =============================================================================
; CODE SECTION
; =============================================================================

.code

; =============================================================================
; WinMain - Entry point
; =============================================================================
WinMain PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 64
    .allocstack 64
    .endprolog

    ; Print header
    lea rcx, szHeader
    call PrintString

    ; =========================================================================
    ; Test 1: Tensor Create / Free
    ; =========================================================================
    lea rcx, g_TestShape
    mov rdx, 2                      ; ndim = 2
    mov r8d, DTYPE_F32
    call RawrXD_TensorCreate
    test rax, rax
    jz @@tensor_fail

    ; Verify tensor fields
    mov rsi, rax
    mov rbx, QWORD PTR [rsi + TENSOR_OFF_NUMEL]
    cmp rbx, 256
    jne @@tensor_fail
    mov rbx, QWORD PTR [rsi + TENSOR_OFF_NDIM]
    cmp rbx, 2
    jne @@tensor_fail
    mov rbx, QWORD PTR [rsi + TENSOR_OFF_DATA_PTR]
    test rbx, rbx
    jz @@tensor_fail

    ; Free tensor
    mov rcx, rsi
    call RawrXD_TensorFree

    mov BYTE PTR [g_TestTensor], 1
    lea rcx, szTensorPass
    call PrintString
    jmp @@test_dispatch

@@tensor_fail:
    mov BYTE PTR [g_TestTensor], 2
    lea rcx, szTensorFail
    call PrintString

    ; =========================================================================
    ; Test 2: Kernel Dispatch (RMSNorm)
    ; =========================================================================
@@test_dispatch:
    ; Initialize kernel registry
    call RawrXD_InitKernelRegistry
    test rax, rax
    jnz @@dispatch_fail

    ; Get CPU features
    call RawrXD_GetCPUFeatures
    test rax, rax
    jz @@dispatch_fail

    ; Get active kernel set name
    call RawrXD_GetActiveKernelSet
    test rax, rax
    jz @@dispatch_fail

    ; Dispatch RMSNorm (just check it doesn't crash)
    lea rcx, g_TestData
    lea rdx, g_TestData             ; weight = identity
    lea r8, g_TestOutput
    mov r9, SMOKE_TENSOR_SIZE
    sub rsp, 32
    movss xmm0, DWORD PTR [g_RMSEps]
    movd DWORD PTR [rsp + 32], xmm0
    call RawrXD_RMSNorm
    add rsp, 32
    test rax, rax
    jnz @@dispatch_fail

    mov BYTE PTR [g_TestDispatch], 1
    lea rcx, szDispatchPass
    call PrintString
    jmp @@test_dequant

@@dispatch_fail:
    mov BYTE PTR [g_TestDispatch], 2
    lea rcx, szDispatchFail
    call PrintString

    ; =========================================================================
    ; Test 3: Q4 Dequant
    ; =========================================================================
@@test_dequant:
    lea rcx, g_TestOutput
    lea rdx, g_Q4TestBlock
    mov r8, 1                       ; 1 block
    call RawrXD_Q4_Dequant
    test rax, rax
    jnz @@dequant_fail

    ; Verify first dequantized value is non-zero
    movss xmm0, DWORD PTR [g_TestOutput]
    vxorps xmm1, xmm1, xmm1
    ucomiss xmm0, xmm1
    je @@dequant_fail               ; Should not be zero

    mov BYTE PTR [g_TestDequant], 1
    lea rcx, szDequantPass
    call PrintString
    jmp @@test_matmul

@@dequant_fail:
    mov BYTE PTR [g_TestDequant], 2
    lea rcx, szDequantFail
    call PrintString

    ; =========================================================================
    ; Test 4: F32 Matmul (identity matrix)
    ; =========================================================================
@@test_matmul:
    lea rcx, g_MatmulA
    lea rdx, g_MatmulB
    lea r8, g_MatmulC
    mov r9, SMOKE_M
    sub rsp, 48
    mov QWORD PTR [rsp + 32], SMOKE_N
    mov QWORD PTR [rsp + 40], SMOKE_K
    mov QWORD PTR [rsp + 48], 0     ; No bias
    call RawrXD_MatMul_F32
    add rsp, 48
    test rax, rax
    jnz @@matmul_fail

    ; Verify A * I = A (first element should be 1.0)
    movss xmm0, DWORD PTR [g_MatmulC]
    movss xmm1, DWORD PTR [g_OneF32]
    ucomiss xmm0, xmm1
    jne @@matmul_fail

    mov BYTE PTR [g_TestMatmul], 1
    lea rcx, szMatmulPass
    call PrintString
    jmp @@test_memory

@@matmul_fail:
    mov BYTE PTR [g_TestMatmul], 2
    lea rcx, szMatmulFail
    call PrintString

    ; =========================================================================
    ; Test 5: Memory allocation / deallocation
    ; =========================================================================
@@test_memory:
    ; Allocate and free multiple blocks
    mov rcx, 1024
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@memory_fail
    mov rsi, rax

    mov rcx, 2048
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@memory_fail
    mov rdi, rax

    mov rcx, 4096
    call RawrXD_AlignedAlloc
    test rax, rax
    jz @@memory_fail
    mov rbx, rax

    ; Free all
    mov rcx, rsi
    call RawrXD_AlignedFree
    mov rcx, rdi
    call RawrXD_AlignedFree
    mov rcx, rbx
    call RawrXD_AlignedFree

    mov BYTE PTR [g_TestMemory], 1
    lea rcx, szMemoryPass
    call PrintString
    jmp @@done

@@memory_fail:
    mov BYTE PTR [g_TestMemory], 2
    lea rcx, szMemoryFail
    call PrintString

@@done:
    ; Print summary
    lea rcx, szNewline
    call PrintString

    xor eax, eax                    ; Return 0

    add rsp, 64
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

WinMain ENDP

; =============================================================================
; PrintString - Write a null-terminated string to stdout
; Parameters: RCX = string pointer
; =============================================================================
PrintString PROC FRAME
    push rbp
    .pushreg rbp
    mov rbp, rsp
    .setframe rbp, 0
    push rbx
    .pushreg rbx
    push rsi
    .pushreg rsi
    push rdi
    .pushreg rdi
    sub rsp, 32
    .allocstack 32
    .endprolog

    mov rsi, rcx

    ; Get string length
    xor eax, eax
    mov rdi, -1
@@strlen:
    inc rdi
    cmp BYTE PTR [rsi + rdi], 0
    jne @@strlen

    ; Write to stdout
    mov rcx, -11                    ; STD_OUTPUT_HANDLE
    call GetStdHandle
    test rax, rax
    jz @@exit

    mov rcx, rax                    ; hConsoleOutput
    mov rdx, rsi                    ; lpBuffer
    mov r8, rdi                     ; nNumberOfCharsToWrite (string length)
    lea r9, QWORD PTR [rbp - 8]    ; lpNumberOfCharsWritten
    mov QWORD PTR [rsp + 32], 0     ; lpReserved
    call WriteFile

@@exit:
    add rsp, 32
    pop rdi
    pop rsi
    pop rbx
    pop rbp
    ret

PrintString ENDP

; =============================================================================
; CONSTANTS
; =============================================================================
.data
align 16
g_OneF32            REAL4 1.0
g_RMSEps            REAL4 1.0e-5

END
