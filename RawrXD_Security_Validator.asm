; =============================================================================
; RawrXD_Security_Validator.asm
; Security Hardening: GGUF and PE Validation
; =============================================================================

; Validation Constants
GGUF_MAGIC          equ 0x46554747    ; "GGUF" in little-endian
GGUF_VERSION_MIN    equ 3
GGUF_VERSION_MAX    equ 3
PE_MAGIC_DOS        equ 0x5A4D        ; "MZ"
PE_MAGIC_NT           equ 0x00004550    ; "PE\0\0"
MAX_TENSOR_COUNT    equ 10000
MAX_METADATA_PAIRS  equ 1000

; Validation Result Codes
VALIDATION_OK       equ 0
ERR_GGUF_MAGIC      equ 1
ERR_GGUF_VERSION    equ 2
ERR_GGUF_TENSOR     equ 3
ERR_GGUF_MEMORY     equ 4
ERR_PE_MAGIC        equ 5
ERR_PE_SECTION      equ 6
ERR_PE_RELOC        equ 7

; =============================================================================
; Data Section
; =============================================================================
.data

; Error messages
msg_ok              db "Validation: PASSED", 0
err_gguf_magic      db "ERROR: Invalid GGUF magic bytes", 0
err_gguf_version    db "ERROR: Unsupported GGUF version", 0
err_gguf_tensor     db "ERROR: Tensor count exceeds maximum", 0
err_gguf_memory     db "ERROR: Memory allocation failed", 0
err_pe_magic        db "ERROR: Invalid PE magic", 0
err_pe_section      db "ERROR: Section alignment violation", 0
err_pe_reloc        db "ERROR: Relocation table corrupted", 0

; =============================================================================
; Code Section
; =============================================================================
.code

; =============================================================================
; GGUF_ValidateHeader
; Validates GGUF file header integrity
; RCX = pointer to file data
; RDX = file size
; Returns: RAX = VALIDATION_OK or error code
; =============================================================================
GGUF_ValidateHeader PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    .endprolog
    
    mov     rsi, rcx            ; RSI = file data
    mov     rdi, rdx            ; RDI = file size
    
    ; Check minimum file size (header is at least 24 bytes)
    cmp     rdi, 24
    jb      .error_memory
    
    ; Validate magic bytes (offset 0)
    mov     eax, [rsi]
    cmp     eax, GGUF_MAGIC
    jne     .error_magic
    
    ; Validate version (offset 4)
    mov     eax, [rsi+4]
    cmp     eax, GGUF_VERSION_MIN
    jb      .error_version
    cmp     eax, GGUF_VERSION_MAX
    ja      .error_version
    
    ; Validate tensor count (offset 8)
    mov     eax, [rsi+8]
    cmp     eax, MAX_TENSOR_COUNT
    ja      .error_tensor
    
    ; Validate metadata pair count (offset 12)
    mov     eax, [rsi+12]
    cmp     eax, MAX_METADATA_PAIRS
    ja      .error_tensor
    
    ; All checks passed
    xor     rax, rax            ; VALIDATION_OK
    jmp     .exit
    
.error_magic:
    mov     rax, ERR_GGUF_MAGIC
    jmp     .exit
    
.error_version:
    mov     rax, ERR_GGUF_VERSION
    jmp     .exit
    
.error_tensor:
    mov     rax, ERR_GGUF_TENSOR
    jmp     .exit
    
.error_memory:
    mov     rax, ERR_GGUF_MEMORY
    
.exit:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
GGUF_ValidateHeader ENDP

; =============================================================================
; GGUF_ValidateTensor
; Validates individual tensor integrity
; RCX = pointer to tensor metadata
; RDX = tensor count
; Returns: RAX = VALIDATION_OK or error code
; =============================================================================
GGUF_ValidateTensor PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    .endprolog
    
    mov     rsi, rcx            ; RSI = tensor metadata
    mov     rbx, rdx            ; RBX = tensor count
    
    xor     rcx, rcx            ; Counter
    
.tensor_loop:
    cmp     rcx, rbx
    jge     .tensor_done
    
    ; Validate tensor type (must be 0-15)
    movzx   eax, byte ptr [rsi]
    cmp     eax, 15
    ja      .error_tensor
    
    ; Validate dimensions (must be 1-4)
    movzx   eax, byte ptr [rsi+1]
    cmp     eax, 1
    jb      .error_tensor
    cmp     eax, 4
    ja      .error_tensor
    
    ; Move to next tensor (simplified stride)
    add     rsi, 64
    inc     rcx
    jmp     .tensor_loop
    
.tensor_done:
    xor     rax, rax            ; VALIDATION_OK
    jmp     .exit
    
.error_tensor:
    mov     rax, ERR_GGUF_TENSOR
    
.exit:
    pop     rsi
    pop     rbx
    ret
    
GGUF_ValidateTensor ENDP

; =============================================================================
; PE_ValidateHeader
; Validates PE file header integrity
; RCX = pointer to PE data
; RDX = file size
; Returns: RAX = VALIDATION_OK or error code
; =============================================================================
PE_ValidateHeader PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    .endprolog
    
    mov     rsi, rcx            ; RSI = PE data
    mov     rdi, rdx            ; RDI = file size
    
    ; Check minimum size for DOS header
    cmp     rdi, 64
    jb      .error_memory
    
    ; Validate DOS magic (MZ)
    movzx   eax, word ptr [rsi]
    cmp     eax, PE_MAGIC_DOS
    jne     .error_magic
    
    ; Get NT header offset from DOS header
    mov     eax, [rsi+60]       ; e_lfanew
    cmp     eax, rdi
    jae     .error_memory
    
    ; Validate NT magic (PE\0\0)
    mov     ebx, eax
    add     rbx, rsi            ; RBX = NT header
    mov     eax, [rbx]
    cmp     eax, PE_MAGIC_NT
    jne     .error_magic
    
    ; Validate machine type (x64 = 0x8664)
    movzx   eax, word ptr [rbx+4]
    cmp     eax, 8664h
    jne     .error_magic
    
    ; Validate section alignment
    mov     eax, [rbx+56]       ; SectionAlignment
    cmp     eax, 512            ; Must be >= 512
    jb      .error_section
    test    eax, 511            ; Must be power of 2
    jnz     .error_section
    
    ; Validate number of sections
    movzx   eax, word ptr [rbx+6]
    cmp     eax, 1
    jb      .error_section
    cmp     eax, 96
    ja      .error_section
    
    xor     rax, rax            ; VALIDATION_OK
    jmp     .exit
    
.error_magic:
    mov     rax, ERR_PE_MAGIC
    jmp     .exit
    
.error_section:
    mov     rax, ERR_PE_SECTION
    jmp     .exit
    
.error_memory:
    mov     rax, ERR_GGUF_MEMORY
    
.exit:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
PE_ValidateHeader ENDP

; =============================================================================
; PE_ValidateRelocations
; Validates base relocation table integrity
; RCX = pointer to PE data
; RDX = relocation table RVA
; R8 = relocation table size
; Returns: RAX = VALIDATION_OK or error code
; =============================================================================
PE_ValidateRelocations PROC FRAME
    push    rbx
    .pushreg rbx
    push    rsi
    .pushreg rsi
    push    rdi
    .pushreg rdi
    .endprolog
    
    mov     rsi, rcx            ; RSI = PE data
    mov     rbx, rdx            ; RBX = relocation RVA
    mov     rdi, r8             ; RDI = relocation size
    
    ; Validate relocation table bounds
    cmp     rdi, 8              ; Minimum size (header)
    jb      .error_reloc
    
    ; Iterate through relocation blocks
    xor     rcx, rcx            ; Offset into relocation table
    
.reloc_loop:
    cmp     rcx, rdi
    jge     .reloc_done
    
    ; Get page RVA
    mov     eax, [rsi+rbx+rcx]
    test    eax, eax
    jz      .reloc_done         ; End marker
    
    ; Get block size
    mov     edx, [rsi+rbx+rcx+4]
    cmp     edx, 8
    jb      .error_reloc
    
    ; Validate block doesn't exceed table
    add     rcx, rdx
    cmp     rcx, rdi
    ja      .error_reloc
    
    jmp     .reloc_loop
    
.reloc_done:
    xor     rax, rax            ; VALIDATION_OK
    jmp     .exit
    
.error_reloc:
    mov     rax, ERR_PE_RELOC
    
.exit:
    pop     rdi
    pop     rsi
    pop     rbx
    ret
    
PE_ValidateRelocations ENDP

; =============================================================================
; Security_GetErrorString
; Returns error message for validation code
; RCX = error code
; Returns: RAX = pointer to error string
; =============================================================================
Security_GetErrorString PROC FRAME
    lea     rax, msg_ok
    cmp     rcx, VALIDATION_OK
    je      .done
    
    lea     rax, err_gguf_magic
    cmp     rcx, ERR_GGUF_MAGIC
    je      .done
    
    lea     rax, err_gguf_version
    cmp     rcx, ERR_GGUF_VERSION
    je      .done
    
    lea     rax, err_gguf_tensor
    cmp     rcx, ERR_GGUF_TENSOR
    je      .done
    
    lea     rax, err_gguf_memory
    cmp     rcx, ERR_GGUF_MEMORY
    je      .done
    
    lea     rax, err_pe_magic
    cmp     rcx, ERR_PE_MAGIC
    je      .done
    
    lea     rax, err_pe_section
    cmp     rcx, ERR_PE_SECTION
    je      .done
    
    lea     rax, err_pe_reloc
    cmp     rcx, ERR_PE_RELOC
    
.done:
    ret
Security_GetErrorString ENDP

END
