; ============================================================================
; BlockedGemm_Single.asm - C-Callable Entry Point for Blocked GEMM
; ============================================================================
; Provides a clean assembly interface for the Forward_QKV router.
; Bridges the tensor abstraction to the cache-blocked GEMM kernel.
;
; Windows x64 ABI:
;   RCX = TensorDesc* A    (Input tensor with descriptor)
;   RDX = TensorDesc* B    (Weight tensor with descriptor)  
;   R8  = TensorDesc* C    (Output tensor with descriptor)
;
; Tensor descriptor layout (16 bytes preceding data pointer):
;   [tensor - 16] = rows (M)
;   [tensor - 12] = cols (K for A, N for B)
;   [tensor - 8]  = stride
;   [tensor - 4]  = flags
;
; Returns: RAX = 0 on success, non-zero on failure
; ============================================================================

.code

; ============================================================================
; BlockedGemm_Single
; C-callable entry point for blocked GEMM
; ============================================================================
BlockedGemm_Single PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 80                 ; Local variables + shadow space
    .allocstack 80
    .endprolog
    
    ; Save parameters to stack
    mov     [rbp - 8],  rcx        ; A pointer
    mov     [rbp - 16], rdx        ; B pointer
    mov     [rbp - 24], r8         ; C pointer
    mov     [rbp - 32], r9         ; M dimension
    
    ; Load stack parameters (accounting for rbp push)
    mov     rax, [rbp + 48 + 8]    ; N dimension
    mov     [rbp - 40], rax
    mov     rax, [rbp + 56 + 8]    ; K dimension
    mov     [rbp - 48], rax
    
    ; Load alpha and beta (floats passed on stack)
    movss   xmm0, dword ptr [rbp + 64 + 8]  ; alpha
    movss   xmm1, dword ptr [rbp + 72 + 8]  ; beta
    movss   dword ptr [rbp - 56], xmm0
    movss   dword ptr [rbp - 60], xmm1
    
    ; Validate data pointers
    cmp     qword ptr [rbp - 8], 0   ; A pointer
    je      InvalidTensorData
    cmp     qword ptr [rbp - 16], 0  ; B pointer
    je      InvalidTensorData
    cmp     qword ptr [rbp - 24], 0  ; C pointer
    je      InvalidTensorData
    
    ; Validate dimensions
    cmp     dword ptr [rbp - 32], 0  ; M
    je      InvalidDimension
    cmp     dword ptr [rbp - 40], 0  ; N
    je      InvalidDimension
    cmp     dword ptr [rbp - 48], 0  ; K
    je      InvalidDimension
    
    ; Allocate packed buffers
    ; A_packed: MC × KC = 128 × 256 = 32768 floats = 128KB
    ; B_packed: KC × NC = 256 × 128 = 32768 floats = 128KB
    
    ; For now, we'll call the C++ implementation which handles allocation
    ; This assembly wrapper validates parameters and sets up the call
    
    ; Call C++ implementation with extracted parameters
    mov     rcx, [rbp - 8]         ; A pointer
    mov     rdx, [rbp - 16]        ; B pointer
    mov     r8,  [rbp - 24]        ; C pointer
    mov     r9d, [rbp - 32]        ; M
    
    ; Push N, K, alpha=1.0, beta=0.0 on stack
    mov     eax, [rbp - 40]        ; N
    push    rax
    mov     eax, [rbp - 48]        ; K
    push    rax
    mov     eax, 3F800000h         ; IEEE-754 1.0f
    push    rax
    xor     eax, eax               ; IEEE-754 0.0f
    push    rax
    
    ; Allocate shadow space
    sub     rsp, 32
    
    ; Call C++ implementation
    extern BlockedGemm_CPP:PROC
    call    BlockedGemm_CPP
    
    ; Clean up stack
    add     rsp, 64
    
    ; Return success
    xor     rax, rax
    jmp     Done
    
InvalidTensorData:
    mov     rax, 2
    jmp     Done
    
InvalidDimension:
    mov     rax, 2
    jmp     Done
    
Done:
    mov     rsp, rbp
    pop     rbp
    ret
BlockedGemm_Single ENDP

; ============================================================================
; BlockedGemm_Single_Tensor
; Tensor descriptor mode - extracts dimensions from tensor structs
; ============================================================================
BlockedGemm_Single_Tensor PROC FRAME
    ; Prologue
    push    rbp
    .pushreg rbp
    mov     rbp, rsp
    .setframe rbp, 0
    sub     rsp, 64
    .allocstack 64
    .endprolog
    
    ; Save tensor pointers
    mov     [rbp - 8],  rcx        ; A tensor
    mov     [rbp - 16], rdx        ; B tensor
    mov     [rbp - 24], r8         ; C tensor
    
    ; Validate tensor pointers
    cmp     qword ptr [rbp - 8],  0
    je      InvalidTensorPointer
    cmp     qword ptr [rbp - 16], 0
    je      InvalidTensorPointer
    cmp     qword ptr [rbp - 24], 0
    je      InvalidTensorPointer
    
    ; Extract data pointers from tensors
    ; Tensor layout: dims[4], strides[4], data, elem_count, flags, dtype, padding[16]
    ; data is at offset 64 (4×8 + 4×8 = 64 bytes)
    
    mov     rcx, [rbp - 8]         ; A tensor
    mov     rax, [rcx + 64]        ; A->data
    mov     [rbp - 32], rax
    
    mov     rdx, [rbp - 16]        ; B tensor
    mov     rax, [rdx + 64]        ; B->data
    mov     [rbp - 40], rax
    
    mov     r8,  [rbp - 24]        ; C tensor
    mov     rax, [r8 + 64]         ; C->data
    mov     [rbp - 48], rax
    
    ; Validate data pointers
    cmp     qword ptr [rbp - 32], 0
    je      InvalidTensorData
    cmp     qword ptr [rbp - 40], 0
    je      InvalidTensorData
    cmp     qword ptr [rbp - 48], 0
    je      InvalidTensorData
    
    ; Extract dimensions
    ; A: [M, K] - dims[0] = M, dims[1] = K
    ; B: [K, N] - dims[0] = K, dims[1] = N
    ; C: [M, N] - dims[0] = M, dims[1] = N
    
    mov     rcx, [rbp - 8]         ; A tensor
    mov     rax, [rcx + 0]         ; A->dims[0] = M
    mov     [rbp - 52], eax        ; Store M (as 32-bit)
    
    mov     rax, [rcx + 8]         ; A->dims[1] = K
    mov     [rbp - 56], eax        ; Store K
    
    mov     rdx, [rbp - 16]        ; B tensor
    mov     rax, [rdx + 8]         ; B->dims[1] = N
    mov     [rbp - 60], eax        ; Store N
    
    ; Validate dimension compatibility
    mov     rcx, [rbp - 8]         ; A tensor
    mov     rax, [rcx + 8]         ; A->dims[1] = K
    mov     rdx, [rbp - 16]        ; B tensor
    mov     rbx, [rdx + 0]         ; B->dims[0] = K
    cmp     rax, rbx
    jne     DimensionMismatch
    
    ; Call BlockedGemm_Single with extracted parameters
    mov     rcx, [rbp - 32]        ; A->data
    mov     rdx, [rbp - 40]        ; B->data
    mov     r8,  [rbp - 48]        ; C->data
    mov     r9d, [rbp - 52]        ; M
    
    ; Push parameters in reverse order (last parameter first)
    ; beta (8th parameter)
    xor     eax, eax                ; 0.0f
    push    rax
    
    ; alpha (7th parameter)
    mov     eax, 3F800000h         ; 1.0f IEEE-754
    push    rax
    
    ; K (6th parameter)
    mov     eax, [rbp - 56]        ; K
    push    rax
    
    ; N (5th parameter)
    mov     eax, [rbp - 60]        ; N
    push    rax
    
    ; Allocate shadow space
    sub     rsp, 32
    
    ; Call BlockedGemm_CPP
    call    BlockedGemm_CPP
    
    ; Clean up stack
    add     rsp, 64
    
    ; Return success
    xor     rax, rax
    jmp     TensorDone
    
InvalidTensorPointer:
    mov     rax, 1
    jmp     TensorDone
    
InvalidTensorData:
    mov     rax, 2
    jmp     TensorDone
    
DimensionMismatch:
    mov     rax, 3
    jmp     TensorDone
    
TensorDone:
    mov     rsp, rbp
    pop     rbp
    ret
BlockedGemm_Single_Tensor ENDP

END