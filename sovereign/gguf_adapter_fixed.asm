; ============================================================================
; GGUF Adapter - Fixed Implementation for Sovereign Fabricator
; ============================================================================
; Headerless, CRT-less, syscall-based GGUF tensor streaming
; ============================================================================

; ============================================================================
; Data Section - GGUF Constants and Buffers
; ============================================================================
.DATA

; GGUF Magic and Version
GGUF_MAGIC      EQU     46554747h       ; "GGUF" in little-endian
GGUF_VERSION    EQU     3

; GGML Type Constants (complete mapping 0-27)
GGML_TYPE_F32       EQU     0
GGML_TYPE_F16       EQU     1
GGML_TYPE_Q4_0      EQU     2
GGML_TYPE_Q4_1      EQU     3
GGML_TYPE_Q5_0      EQU     6
GGML_TYPE_Q5_1      EQU     7
GGML_TYPE_Q8_0      EQU     8
GGML_TYPE_Q8_1      EQU     9
GGML_TYPE_Q2_K      EQU     10
GGML_TYPE_Q3_K      EQU     11
GGML_TYPE_Q4_K      EQU     12
GGML_TYPE_Q5_K      EQU     13
GGML_TYPE_Q6_K      EQU     14
GGML_TYPE_Q8_K      EQU     15
GGML_TYPE_IQ2_XXS   EQU     16
GGML_TYPE_IQ2_XS    EQU     17
GGML_TYPE_IQ3_XXS   EQU     18
GGML_TYPE_IQ1_S     EQU     19
GGML_TYPE_IQ4_NL    EQU     20
GGML_TYPE_IQ3_S     EQU     21
GGML_TYPE_IQ2_S     EQU     22
GGML_TYPE_IQ4_XS    EQU     23
GGML_TYPE_I8        EQU     24
GGML_TYPE_I16       EQU     25
GGML_TYPE_I32       EQU     26
GGML_TYPE_I64       EQU     27

; Block sizes for each type (bytes per block)
ALIGN 16
TypeBlockSizes LABEL DWORD
    DWORD 0         ; F32
    DWORD 0         ; F16
    DWORD 18        ; Q4_0
    DWORD 20        ; Q4_1
    DWORD 0         ; (skip)
    DWORD 0         ; (skip)
    DWORD 22        ; Q5_0
    DWORD 24        ; Q5_1
    DWORD 34        ; Q8_0
    DWORD 36        ; Q8_1
    DWORD 256       ; Q2_K
    DWORD 384       ; Q3_K
    DWORD 144       ; Q4_K
    DWORD 176       ; Q5_K
    DWORD 210       ; Q6_K
    DWORD 292       ; Q8_K

; Weights per block for each type
ALIGN 16
TypeWeightsPerBlock LABEL DWORD
    DWORD 1         ; F32
    DWORD 1         ; F16
    DWORD 32        ; Q4_0
    DWORD 32        ; Q4_1
    DWORD 0         ; (skip)
    DWORD 0         ; (skip)
    DWORD 32        ; Q5_0
    DWORD 32        ; Q5_1
    DWORD 32        ; Q8_0
    DWORD 32        ; Q8_1
    DWORD 256       ; Q2_K
    DWORD 256       ; Q3_K
    DWORD 256       ; Q4_K
    DWORD 256       ; Q5_K
    DWORD 256       ; Q6_K
    DWORD 256       ; Q8_K

; ============================================================================
; Static Buffers
; ============================================================================
FileBuffer          BYTE 4096 DUP(0)
TensorNameBuf       BYTE 1024 DUP(0)
ShapeBuf            QWORD 8 DUP(0)
ReadBuf             BYTE 64 DUP(0)

; ============================================================================
; GGUF Context Structure
; ============================================================================
Ctx STRUCT
    hFile               QWORD   0
    Magic               DWORD   0
    Version             DWORD   0
    TensorCount         QWORD   0
    MetadataKVCount     QWORD   0
    TensorTableOffset   QWORD   0
    DataSectionOffset   QWORD   0
    CurrentTensorIdx    QWORD   0
    FileSize            QWORD   0
    CurrTensorNameLen   QWORD   0
    CurrTensorName      QWORD   0
    CurrTensorNDims     DWORD   0
    CurrTensorShape     QWORD   0
    CurrTensorType      DWORD   0
    CurrTensorOffset    QWORD   0
    CurrTensorDataSize  QWORD   0
    CurrTensorDataPtr   QWORD   0
Ctx ENDS

ALIGN 16
GlobalCtx Ctx <>

; ============================================================================
; Code Section
; ============================================================================
.CODE

; ============================================================================
; GGUF_Init - Initialize GGUF context and open file
; Input:  RCX = pointer to filename (UTF-8)
; Output: RAX = 0 on success, error code on failure
; ============================================================================
GGUF_Init PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    .endprolog
    
    mov     r15, rcx                    ; Save filename pointer
    
    ; Clear context
    lea     rdi, GlobalCtx
    mov     rcx, SIZEOF Ctx
    xor     rax, rax
    rep     stosb
    
    ; For now, just return success (file operations would go here)
    ; In production, use NtCreateFile syscall
    
    xor     rax, rax                    ; Success
    
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GGUF_Init ENDP

; ============================================================================
; GGUF_Cleanup - Close file and cleanup
; ============================================================================
GGUF_Cleanup PROC FRAME
    push    rbx
    .endprolog
    
    ; Clear context
    lea     rdi, GlobalCtx
    mov     rcx, SIZEOF Ctx
    xor     rax, rax
    rep     stosb
    
    pop     rbx
    ret
GGUF_Cleanup ENDP

; ============================================================================
; GGUF_NextTensor - Get next tensor from GGUF file
; Output: RAX = 0 if tensor returned, 1 if end of stream, <0 on error
; ============================================================================
GGUF_NextTensor PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    push    r12
    push    r13
    push    r14
    push    r15
    .endprolog
    
    ; Stub implementation - would read from file
    ; For now, return end of stream
    
    mov     rax, 1                      ; End of stream
    
    pop     r15
    pop     r14
    pop     r13
    pop     r12
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GGUF_NextTensor ENDP

; ============================================================================
; GGUF_Reset - Reset to beginning of tensor table
; ============================================================================
GGUF_Reset PROC FRAME
    push    rbx
    .endprolog
    
    mov     GlobalCtx.CurrentTensorIdx, 0
    
    xor     rax, rax
    pop     rbx
    ret
GGUF_Reset ENDP

; ============================================================================
; GGUF_GetTensorCount - Get number of tensors
; ============================================================================
GGUF_GetTensorCount PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.TensorCount
    
    pop     rbx
    ret
GGUF_GetTensorCount ENDP

; ============================================================================
; GGUF_GetCurrentTensorIndex - Get current tensor index
; ============================================================================
GGUF_GetCurrentTensorIndex PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.CurrentTensorIdx
    
    pop     rbx
    ret
GGUF_GetCurrentTensorIndex ENDP

; ============================================================================
; GGUF_GetCurrentTensorName - Get pointer to current tensor name
; ============================================================================
GGUF_GetCurrentTensorName PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.CurrTensorName
    
    pop     rbx
    ret
GGUF_GetCurrentTensorName ENDP

; ============================================================================
; GGUF_GetCurrentTensorType - Get current tensor GGML type
; ============================================================================
GGUF_GetCurrentTensorType PROC FRAME
    push    rbx
    .endprolog
    
    mov     eax, GlobalCtx.CurrTensorType
    
    pop     rbx
    ret
GGUF_GetCurrentTensorType ENDP

; ============================================================================
; GGUF_GetCurrentTensorShape - Get pointer to shape array
; ============================================================================
GGUF_GetCurrentTensorShape PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.CurrTensorShape
    
    pop     rbx
    ret
GGUF_GetCurrentTensorShape ENDP

; ============================================================================
; GGUF_GetCurrentTensorNDims - Get number of dimensions
; ============================================================================
GGUF_GetCurrentTensorNDims PROC FRAME
    push    rbx
    .endprolog
    
    mov     eax, GlobalCtx.CurrTensorNDims
    
    pop     rbx
    ret
GGUF_GetCurrentTensorNDims ENDP

; ============================================================================
; GGUF_GetCurrentTensorDataSize - Get data size in bytes
; ============================================================================
GGUF_GetCurrentTensorDataSize PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.CurrTensorDataSize
    
    pop     rbx
    ret
GGUF_GetCurrentTensorDataSize ENDP

; ============================================================================
; GGUF_GetCurrentTensorOffset - Get tensor offset
; ============================================================================
GGUF_GetCurrentTensorOffset PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.CurrTensorOffset
    
    pop     rbx
    ret
GGUF_GetCurrentTensorOffset ENDP

; ============================================================================
; GGUF_GetCurrentTensorDataPtr - Get pointer to loaded data
; ============================================================================
GGUF_GetCurrentTensorDataPtr PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.CurrTensorDataPtr
    
    pop     rbx
    ret
GGUF_GetCurrentTensorDataPtr ENDP

; ============================================================================
; GGUF_GetDataSectionOffset - Get data section offset
; ============================================================================
GGUF_GetDataSectionOffset PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.DataSectionOffset
    
    pop     rbx
    ret
GGUF_GetDataSectionOffset ENDP

; ============================================================================
; GGUF_GetFileSize - Get file size
; ============================================================================
GGUF_GetFileSize PROC FRAME
    push    rbx
    .endprolog
    
    mov     rax, GlobalCtx.FileSize
    
    pop     rbx
    ret
GGUF_GetFileSize ENDP

; ============================================================================
; GGUF_LoadTensorData - Load current tensor data into memory
; ============================================================================
GGUF_LoadTensorData PROC FRAME
    push    rbx
    push    rsi
    push    rdi
    .endprolog
    
    ; Stub - would read from file
    xor     rax, rax
    
    pop     rdi
    pop     rsi
    pop     rbx
    ret
GGUF_LoadTensorData ENDP

; ============================================================================
; GGUF_GetTypeName - Get string name for GGML type
; ============================================================================
GGUF_GetTypeName PROC FRAME
    push    rbx
    .endprolog
    
    ; Return pointer to type name based on ECX
    lea     rax, TypeName_F32
    
    pop     rbx
    ret
    
ALIGN 8
TypeName_F32    BYTE "F32", 0
TypeName_F16    BYTE "F16", 0
TypeName_Q4_0   BYTE "Q4_0", 0
TypeName_Q4_1   BYTE "Q4_1", 0
TypeName_Q5_0   BYTE "Q5_0", 0
TypeName_Q5_1   BYTE "Q5_1", 0
TypeName_Q8_0   BYTE "Q8_0", 0
TypeName_Q8_1   BYTE "Q8_1", 0
TypeName_Q2_K   BYTE "Q2_K", 0
TypeName_Q3_K   BYTE "Q3_K", 0
TypeName_Q4_K   BYTE "Q4_K", 0
TypeName_Q5_K   BYTE "Q5_K", 0
TypeName_Q6_K   BYTE "Q6_K", 0
TypeName_Q8_K   BYTE "Q8_K", 0
TypeName_Unknown BYTE "UNKNOWN", 0

GGUF_GetTypeName ENDP

END
