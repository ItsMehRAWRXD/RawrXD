

; Sovereign_Final_Linkage.asm - Corrected Entry Point
; Zero-CRT, Win64, kernel32.lib only
; No includes, no MASM32 dependencies

.CODE

PUBLIC XR_Production_Entry
XR_Production_Entry PROC
    sub rsp, 40

    ; --- Phase 0: Dispatch Ingestion Pipeline ---
    call XR_Acquire_LargePage_Privilege
    call XR_Dispatch_Ingest
    cmp rax, 2
    je ingest_createfile_failure
    cmp rax, 3
    je ingest_mapping_failure
    cmp rax, 4
    je ingest_view_failure

    ; Verify mapped base is valid
    mov rcx, [g_MappedBase]
    test rcx, rcx
    jz privilege_failure

    ; Validate GGUF magic and version
    call XR_Verify_GGUF
    test rax, rax
    jz ingest_failure

    ; Parse tensor index
    mov rcx, [g_MappedBase]
    call XR_Parse_GGUF_Tensors
    test rax, rax
    jz parse_failure

    ; Enter TITAN_LOOP with proper arguments
    xor ecx, ecx                    ; TokenIndex = 0 (BOS)
    lea rdx, [output_sequence]      ; OutputBuffer
    mov r8d, 128                    ; MaxTokens
    call TITAN_LOOP
    cmp eax, 0DEAD0001h
    je titan_fault

    ; Success: exit with 0xCAFEBABE
    mov ecx, 0CAFEBABEh
    call ExitProcess

ingest_createfile_failure:
    mov ecx, 0BADF004h      ; CreateFileW failed
    call ExitProcess

ingest_mapping_failure:
    mov ecx, 0BADF003h      ; CreateFileMappingW failed
    call ExitProcess

ingest_view_failure:
    mov ecx, 0BADF002h      ; MapViewOfFileEx failed
    call ExitProcess

privilege_failure:
    mov ecx, 0BADF001h
    call ExitProcess

ingest_failure:
    mov ecx, 0BADF002h
    call ExitProcess

parse_failure:
    mov ecx, 0BADF004h
    call ExitProcess

titan_fault:
    mov ecx, 0DEAD0001h
    call ExitProcess
XR_Production_Entry ENDP

PUBLIC XR_Verify_GGUF
XR_Verify_GGUF PROC
    ; RCX = mapped GGUF base
    mov edx, [rcx]                  ; Magic at offset 0
    cmp edx, 46554747h              ; "GGUF" little-endian
    jne invalid

    mov edx, [rcx+4]                ; Version at offset 4
    cmp edx, 3
    jne invalid

    mov rax, 1
    ret

invalid:
    xor rax, rax
    ret
XR_Verify_GGUF ENDP

PUBLIC XR_Parse_GGUF_Tensors
XR_Parse_GGUF_Tensors PROC
    ; RCX = mapped GGUF base
    ; Simple: skip header, point to tensor data at +4096
    lea rax, [rcx+1000h]            ; +4096 bytes past header
    mov [g_TensorBase], rax
    mov rax, 1
    ret
XR_Parse_GGUF_Tensors ENDP

PUBLIC XR_FaultHandler_Resolve
XR_FaultHandler_Resolve PROC
    ret
XR_FaultHandler_Resolve ENDP

EXTERN g_MappedBase : QWORD
EXTERN g_TensorBase : QWORD
EXTERN XR_Acquire_LargePage_Privilege : PROC
EXTERN XR_Dispatch_Ingest : PROC
EXTERN TITAN_LOOP : PROC
EXTERN ExitProcess : PROC

.DATA
align 8
output_sequence     dd 128 dup(0)
END
